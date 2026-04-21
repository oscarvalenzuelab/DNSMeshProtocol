"""DNS-discoverable bootstrap records for user-domain → cluster routing.

A *bootstrap record* is a signed TXT record published at a well-known
name under a user's domain (e.g. `_dmp.example.com`) that points at one
or more DMP clusters. It is the analogue of an SMTP MX record: given an
address like `alice@example.com`, a client can query DNS once to learn
which cluster(s) handle that domain's mailboxes, then proceed to the
usual cluster-mode fetch (ClusterManifest at
`cluster.<cluster_base_domain>`).

Trust anchor. The signer here is the *zone operator* of the user's
domain — the party with authority to publish under `_dmp.example.com`.
This is a different role from the cluster operator whose key signs the
cluster manifest. In a self-hosted deployment the two keys may be the
same; in a multi-tenant deployment the zone operator lists clusters run
by third parties. Distribution of the zone operator's Ed25519 key is
out of scope for this record — it must be obtained out-of-band (e.g. a
published fingerprint, a well-known HTTPS endpoint, or a future DNSSEC-
anchored extension). M3.2 will wire this into the client and sort out
the key-distribution story.

Wire format mirrors ClusterManifest: a ``v=dmp1;t=bootstrap;`` prefix
followed by base64'd ``body || sig``. Body layout:

    magic:             b"DMPBS01"             (7 bytes)
    seq:               uint64 big-endian      (8 bytes)
    exp:               uint64 big-endian      (8 bytes)
    signer_spk:        32 bytes               (32 bytes; echoed for cross-check)
    user_domain_len:   uint8                  (1 byte)
    user_domain:       utf-8 bytes            (var, <= 64)
    entry_count:       uint8                  (1 byte, 1..16)
    per entry:
        priority:          uint16 big-endian  (2 bytes)
        base_domain_len:   uint8              (1 byte)
        base_domain:       utf-8 bytes        (var, <= 64)
        operator_spk:      32 bytes           (32 bytes)

Followed by a 64-byte Ed25519 signature over the body.

Per the leaf-module guidance in the task, we re-import
``_validate_dns_name`` from ``dmp.core.cluster`` rather than duplicating
the logic. The semantics are identical (publishable DNS owner name) and
drift between the two would be a footgun.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import List, Optional

from dmp.core.crypto import DMPCrypto

# Same DNS-name validator ClusterManifest uses. Importing rather than
# duplicating keeps the two record types in lockstep: a name that
# validates for one must validate for the other.
from dmp.core.cluster import _validate_dns_name

RECORD_PREFIX = "v=dmp1;t=bootstrap;"

_MAGIC = b"DMPBS01"
_SIG_LEN = 64
_SIGNER_SPK_LEN = 32
_OPERATOR_SPK_LEN = 32

# Per-field protocol caps. Tight enough that a 16-entry record with
# realistic base-domain widths fits comfortably under MAX_WIRE_LEN.
MAX_USER_DOMAIN_LEN = 64
MAX_BASE_DOMAIN_LEN = 64
MAX_ENTRY_COUNT = 16

# Absolute wire-length cap, symmetric with ClusterManifest. 1200 bytes
# is a comfortable ~4 TXT strings worth of base64'd payload. Multi-
# string TXT is handled by all publishers (dnsupdate/Cloudflare/
# Route53/dnsmasq/in-memory).
MAX_WIRE_LEN = 1200


def bootstrap_rrset_name(user_domain: str) -> str:
    """Return the TXT RRset name where this user-domain's bootstrap lives.

    Convention: ``_dmp.<user_domain>``. Kept as a function so we can
    evolve the convention without churning call sites (mirrors
    ``cluster_rrset_name``).

    Applies the same DNS-name validation BootstrapRecord enforces, so a
    direct caller gets the same early rejection (empty, leading dot,
    doubled trailing dots, non-ASCII, bad characters, over-long labels)
    instead of silently constructing an invalid owner name.
    """
    _validate_dns_name(user_domain)
    normalized = user_domain[:-1] if user_domain.endswith(".") else user_domain
    return f"_dmp.{normalized}"


@dataclass
class BootstrapEntry:
    """One cluster choice inside a bootstrap record.

    Lower `priority` is preferred (like SMTP MX). The same
    `(priority, cluster_base_domain)` pair must not repeat within a
    record — duplicate priorities with distinct base domains are fine
    (SMTP MX allows that and clients pick arbitrarily).
    """

    priority: int  # 0..65535, lower is preferred
    cluster_base_domain: str  # DNS name where cluster.<X> manifest lives
    operator_spk: bytes  # 32-byte Ed25519 public key to trust for <X>

    def _validate(self) -> None:
        if not isinstance(self.priority, int) or not (0 <= self.priority <= 0xFFFF):
            raise ValueError("priority must be an int in [0, 65535]")
        if (
            not isinstance(self.cluster_base_domain, str)
            or not self.cluster_base_domain
        ):
            raise ValueError("cluster_base_domain must be a non-empty string")
        # Cluster base domain ends up as the `cluster_name` of a
        # ClusterManifest; apply the same DNS-name rules.
        _validate_dns_name(self.cluster_base_domain)
        # Canonicalize: strip at most one trailing dot. Doubled trailing
        # dot is caught by _validate_dns_name above.
        if self.cluster_base_domain.endswith("."):
            self.cluster_base_domain = self.cluster_base_domain[:-1]
        if not self.cluster_base_domain:
            raise ValueError("cluster_base_domain must be a non-empty string")
        base_bytes = self.cluster_base_domain.encode("utf-8")
        if len(base_bytes) > MAX_BASE_DOMAIN_LEN:
            raise ValueError(
                f"cluster_base_domain too long (max {MAX_BASE_DOMAIN_LEN} utf-8 bytes)"
            )
        if (
            not isinstance(self.operator_spk, (bytes, bytearray))
            or len(self.operator_spk) != _OPERATOR_SPK_LEN
        ):
            raise ValueError("operator_spk must be 32 bytes")

    def to_body_bytes(self) -> bytes:
        self._validate()
        base_bytes = self.cluster_base_domain.encode("utf-8")
        return (
            self.priority.to_bytes(2, "big")
            + len(base_bytes).to_bytes(1, "big")
            + base_bytes
            + bytes(self.operator_spk)
        )

    @classmethod
    def from_body_bytes(cls, body: bytes, offset: int) -> "tuple[BootstrapEntry, int]":
        """Unpack one entry starting at `offset`; return (entry, new_offset).

        Raises ValueError on any truncation or length-cap violation.
        """
        # priority(2) + base_domain_len(1) = 3 bytes minimum header.
        if offset + 3 > len(body):
            raise ValueError("truncated entry: missing priority/base_domain_len")
        priority = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        base_len = body[offset]
        offset += 1
        if base_len == 0 or base_len > MAX_BASE_DOMAIN_LEN:
            raise ValueError("invalid cluster_base_domain length")
        if offset + base_len > len(body):
            raise ValueError("truncated entry: cluster_base_domain")
        try:
            base_domain = body[offset : offset + base_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("cluster_base_domain not utf-8") from e
        offset += base_len
        if offset + _OPERATOR_SPK_LEN > len(body):
            raise ValueError("truncated entry: operator_spk")
        operator_spk = bytes(body[offset : offset + _OPERATOR_SPK_LEN])
        offset += _OPERATOR_SPK_LEN
        # Validate DNS name on receive too — a signed record whose entry
        # carries an unpublishable base_domain is unusable downstream.
        _validate_dns_name(base_domain)
        # Normalize trailing dot so externally-produced records compare
        # equal to ours.
        if base_domain.endswith("."):
            base_domain = base_domain[:-1]
        return (
            cls(
                priority=priority,
                cluster_base_domain=base_domain,
                operator_spk=operator_spk,
            ),
            offset,
        )


@dataclass
class BootstrapRecord:
    """DNS-discoverable pointer from a user domain to 1..N clusters.

    Published at ``_dmp.<user_domain>`` TXT, signed by the OPERATOR of
    that user domain (zone-authorized key, NOT a cluster-operator key).
    The signing key must itself be pre-agreed or resolvable — this
    mirrors DNSSEC: the zone's operator is the trust anchor.

    Clients use this to translate ``alice@example.com`` into a concrete
    cluster (base_domain + operator_spk) without prior configuration.
    """

    user_domain: str  # e.g. "example.com"
    signer_spk: bytes  # 32-byte Ed25519 public key of the zone operator
    entries: List[BootstrapEntry] = field(default_factory=list)
    seq: int = 0  # monotonic; higher wins on refresh
    exp: int = 0  # unix ts seconds

    def _validate(self) -> None:
        # user_domain: non-empty, DNS-name-valid, within byte cap.
        if not isinstance(self.user_domain, str) or not self.user_domain:
            raise ValueError("user_domain must be a non-empty string")
        # Canonicalize: strip at most ONE trailing dot. Doubled trailing
        # dot signals a typo and is rejected.
        if self.user_domain.endswith(".."):
            raise ValueError("user_domain contains empty label at the end")
        if self.user_domain.endswith("."):
            self.user_domain = self.user_domain[:-1]
        if not self.user_domain:
            raise ValueError("user_domain must have at least one label")
        name_bytes = self.user_domain.encode("utf-8")
        if len(name_bytes) > MAX_USER_DOMAIN_LEN:
            raise ValueError(
                f"user_domain too long (max {MAX_USER_DOMAIN_LEN} utf-8 bytes)"
            )
        _validate_dns_name(self.user_domain)

        # signer_spk: 32 bytes.
        if (
            not isinstance(self.signer_spk, (bytes, bytearray))
            or len(self.signer_spk) != _SIGNER_SPK_LEN
        ):
            raise ValueError("signer_spk must be 32 bytes")

        # entries: 1..MAX_ENTRY_COUNT. An empty list is a silent-data-
        # loss footgun (clients given an empty record would fall back
        # to... nothing), so reject. Publish "no cluster" by not
        # publishing a bootstrap record at all.
        if not isinstance(self.entries, list):
            raise ValueError("entries must be a list")
        if len(self.entries) == 0:
            raise ValueError(
                "bootstrap record must contain at least one entry; "
                "publish 'no cluster' by not publishing a bootstrap record at all"
            )
        if len(self.entries) > MAX_ENTRY_COUNT:
            raise ValueError(
                f"too many entries (max {MAX_ENTRY_COUNT}); "
                "shard across multiple user-domains or reduce entries"
            )

        # Per-entry validation + duplicate detection. Duplicate priorities
        # alone are allowed (SMTP MX allows ties); exact
        # (priority, cluster_base_domain) duplicates are not — they waste
        # space and indicate a publisher mistake.
        seen: set[tuple[int, str]] = set()
        for entry in self.entries:
            entry._validate()
            key = (entry.priority, entry.cluster_base_domain.casefold())
            if key in seen:
                raise ValueError(
                    f"duplicate entry (priority={entry.priority}, "
                    f"cluster_base_domain={entry.cluster_base_domain!r}) "
                    f"in bootstrap record"
                )
            seen.add(key)

        if not (0 <= self.seq < (1 << 64)):
            raise ValueError("seq out of range")
        if not (0 <= self.exp < (1 << 64)):
            raise ValueError("exp out of range")

        # Sort entries by priority ascending so best_entry() is
        # deterministic. Python's sort is stable, so on priority ties
        # the original insertion order is preserved — clients facing
        # ties should try entries[0] first and fall back to entries[1]
        # on failure.
        self.entries.sort(key=lambda e: e.priority)

    def to_body_bytes(self) -> bytes:
        self._validate()
        name_bytes = self.user_domain.encode("utf-8")
        parts: List[bytes] = [
            _MAGIC,
            self.seq.to_bytes(8, "big"),
            self.exp.to_bytes(8, "big"),
            bytes(self.signer_spk),
            len(name_bytes).to_bytes(1, "big"),
            name_bytes,
            len(self.entries).to_bytes(1, "big"),
        ]
        for entry in self.entries:
            parts.append(entry.to_body_bytes())
        return b"".join(parts)

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "BootstrapRecord":
        # Fixed header: magic(7) + seq(8) + exp(8) + signer_spk(32) + name_len(1) = 56
        min_header = len(_MAGIC) + 8 + 8 + _SIGNER_SPK_LEN + 1
        if len(body) < min_header:
            raise ValueError("body too short for header")
        off = 0
        if body[off : off + len(_MAGIC)] != _MAGIC:
            raise ValueError("bad magic")
        off += len(_MAGIC)
        seq = int.from_bytes(body[off : off + 8], "big")
        off += 8
        exp = int.from_bytes(body[off : off + 8], "big")
        off += 8
        signer_spk = bytes(body[off : off + _SIGNER_SPK_LEN])
        off += _SIGNER_SPK_LEN
        name_len = body[off]
        off += 1
        if off + name_len > len(body):
            raise ValueError("truncated user_domain")
        # A correctly-signed manifest may preserve a canonical FQDN
        # trailing dot on the wire; allow MAX+1 when the last byte is '.'.
        has_trailing_dot = name_len > 0 and body[off + name_len - 1] == 0x2E
        effective_len = name_len - (1 if has_trailing_dot else 0)
        if effective_len == 0 or effective_len > MAX_USER_DOMAIN_LEN:
            raise ValueError("invalid user_domain length")
        try:
            user_domain = body[off : off + name_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("user_domain not utf-8") from e
        _validate_dns_name(user_domain)
        if user_domain.endswith("."):
            user_domain = user_domain[:-1]
        off += name_len

        if off + 1 > len(body):
            raise ValueError("truncated: missing entry_count")
        entry_count = body[off]
        off += 1
        if entry_count == 0:
            # Same silent-data-loss reasoning as sign(); reject.
            raise ValueError("bootstrap record must contain at least one entry")
        if entry_count > MAX_ENTRY_COUNT:
            raise ValueError("entry_count exceeds protocol max")

        entries: List[BootstrapEntry] = []
        seen: set[tuple[int, str]] = set()
        for _ in range(entry_count):
            entry, off = BootstrapEntry.from_body_bytes(body, off)
            key = (entry.priority, entry.cluster_base_domain.casefold())
            if key in seen:
                raise ValueError(
                    f"duplicate entry (priority={entry.priority}, "
                    f"cluster_base_domain={entry.cluster_base_domain!r}) "
                    f"in bootstrap record"
                )
            seen.add(key)
            entries.append(entry)

        if off != len(body):
            raise ValueError("trailing bytes after last entry")

        # Sort on parse too, so a correctly-signed but mis-ordered
        # record (e.g. from a buggy publisher) still yields a
        # deterministic best_entry().
        entries.sort(key=lambda e: e.priority)

        return cls(
            user_domain=user_domain,
            signer_spk=signer_spk,
            entries=entries,
            seq=seq,
            exp=exp,
        )

    def sign(self, crypto: DMPCrypto) -> str:
        """Serialize to a TXT-friendly wire format, sign, return string.

        Enforces the 1200-byte wire cap. Raises ValueError if the
        resulting record would exceed it — callers should either drop
        entries or shorten base_domain values.
        """
        # Sanity check: signing key matches the declared signer_spk.
        if crypto.get_signing_public_key_bytes() != bytes(self.signer_spk):
            raise ValueError("signing key does not match declared signer_spk")
        body = self.to_body_bytes()
        signature = crypto.sign_data(body)
        encoded = base64.b64encode(body + signature).decode("ascii")
        wire = f"{RECORD_PREFIX}{encoded}"
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            raise ValueError(
                f"bootstrap record wire size {len(wire.encode('utf-8'))} "
                f"exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}; reduce entry count "
                "or base_domain lengths"
            )
        return wire

    @classmethod
    def parse_and_verify(
        cls,
        wire: str,
        signer_spk: bytes,
        *,
        now: Optional[int] = None,
        expected_user_domain: Optional[str] = None,
    ) -> Optional["BootstrapRecord"]:
        """Parse, verify signature, reject expired/tampered/wrong-signer.

        Returns the record on success, ``None`` on any failure:
        - Missing/wrong prefix
        - Oversized wire
        - Base64 decode errors
        - Signature verification failure
        - ``signer_spk`` in the wire doesn't match the arg (defense in depth)
        - Expiry in the past (if `now` provided; defaults to time.time())
        - Malformed fields (wrong types, truncation, etc.)
        - ``expected_user_domain`` (if provided) doesn't match the signed
          ``user_domain`` after trailing-dot and case normalization

        Parse order enforces the invariant that the signature is the
        only trust anchor: prefix -> base64 -> split body|sig -> verify
        sig with the caller's ``signer_spk`` arg -> THEN unpack body
        fields -> THEN cross-check embedded signer_spk -> THEN bind to
        the expected user domain if supplied.
        """
        # 1. Prefix.
        if not isinstance(wire, str) or not wire.startswith(RECORD_PREFIX):
            return None

        # 1a. Wire-length cap — symmetric with sign().
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            return None

        # 2. Base64.
        try:
            blob = base64.b64decode(wire[len(RECORD_PREFIX) :], validate=True)
        except Exception:
            return None

        # 3. Split body|sig. Signature is the trailing 64 bytes.
        if len(blob) < _SIG_LEN + len(_MAGIC):
            return None
        body = blob[:-_SIG_LEN]
        signature = blob[-_SIG_LEN:]

        # 4. Verify signature against the caller-supplied signer key.
        if (
            not isinstance(signer_spk, (bytes, bytearray))
            or len(signer_spk) != _SIGNER_SPK_LEN
        ):
            return None
        if not DMPCrypto.verify_signature(body, signature, bytes(signer_spk)):
            return None

        # 5. Unpack body.
        try:
            record = cls.from_body_bytes(body)
        except ValueError:
            return None

        # 6. Embedded signer_spk must match the caller's arg. Defense in
        # depth: even if a sig format leaks, a record signed by a
        # different key won't silently deserialize.
        if bytes(record.signer_spk) != bytes(signer_spk):
            return None

        # 7. Expiry.
        now_ts = int(time.time()) if now is None else int(now)
        if record.exp < now_ts:
            return None

        # 8. If the caller specified the expected user domain, bind the
        # parsed record to it. DNS owner names are case-insensitive, so
        # we casefold both sides; also normalize a single trailing dot.
        if expected_user_domain is not None:
            expected_norm = (
                expected_user_domain[:-1]
                if expected_user_domain.endswith(".")
                else expected_user_domain
            )
            if record.user_domain.casefold() != expected_norm.casefold():
                return None

        return record

    def best_entry(self) -> BootstrapEntry:
        """Return the lowest-priority (most preferred) entry.

        Entries are sorted by priority at sign/parse time so this is
        always ``entries[0]``. Provided as a helper so callers don't
        have to remember the ordering contract. On priority ties, the
        sort is stable and returns the earliest-inserted entry; clients
        facing ties should fall back to ``entries[1]`` on failure.
        """
        return self.entries[0]

    def is_expired(self, now: Optional[int] = None) -> bool:
        now_ts = int(time.time()) if now is None else int(now)
        return now_ts > self.exp
