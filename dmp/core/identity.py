"""Signed identity records for DMP.

An identity record lets a contact look someone up by DNS name instead of
pasting a 64-char hex pubkey. The record is signed by the identity's
Ed25519 key so a node can't forge an identity record for a user it
doesn't have keys for.

Wire format — binary, base64'd, fits a single 255-byte DNS TXT string:

    v=dmp1;t=identity;d=<b64(body || sig)>

body:
    username_len(1) || username(≤64 bytes utf-8)
    || x25519_pk(32)     # encryption pubkey
    || ed25519_spk(32)   # signing pubkey
    || ts(8)             # unix seconds when published
    || [optional] versions_len(1) || versions(versions_len × 1)

The optional ``versions`` suffix advertises the protocol versions this
client supports as receiver. Each byte is a single protocol version
number; values are sorted-and-deduplicated by the writer for a canonical
encoding. **A record with no suffix means "v1 only"** — that's how old
records published before the field existed are interpreted, so adding
the field is fully backward compatible. New writers omit the suffix when
versions == (1,) so a v1-only record is bit-identical to the historical
format.

sig = Ed25519 signature over body.

Recipient verifies: signature against the embedded ed25519_spk, and (for
Trust on First Use) remembers the (username, x25519_pk, ed25519_spk)
tuple. A later lookup with a different x25519 or ed25519 pubkey is a
red flag that should prompt the user, not auto-replace the stored key.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional, Tuple

from dmp.core.crypto import DMPCrypto

RECORD_PREFIX = "v=dmp1;t=identity;d="
_SIG_LEN = 64
_X25519_LEN = 32
_ED25519_LEN = 32
_TS_LEN = 8
_USERNAME_MAX = 64

# Protocol versions the local code understands. The publisher writes its
# own support set into the record; the receiver reads the remote support
# set to decide which wire features to emit toward that peer. Keep in
# sync with whatever versions the send/receive paths can speak.
SUPPORTED_VERSIONS: Tuple[int, ...] = (1, 2)


def _normalize_versions(versions: Iterable[int]) -> Tuple[int, ...]:
    """Sort, dedupe, and validate a versions iterable.

    Each version is a u8 (0–255). Empty input raises — callers that mean
    "v1 only" should pass ``(1,)`` explicitly, not an empty iterable, so
    a typo can't silently produce a record that advertises nothing.
    """
    result = tuple(sorted({int(v) for v in versions}))
    if not result:
        raise ValueError("versions must include at least one entry")
    for v in result:
        if not 0 <= v <= 255:
            raise ValueError(f"version {v} out of range 0..255")
    return result


def identity_domain(username: str, base_domain: str) -> str:
    """Where to publish / query `username`'s identity record.

    Uses a SHA-256 hash of the username so the DNS label reveals only the
    hash, not the plaintext username. Matches the existing
    DNSEncoder.encode_identity_domain helper.

    This is the *unanchored* form used under a shared mesh domain. Squatting
    is only mitigated by signature verification plus the CLI's
    `--accept-fingerprint` dance. For real squat resistance publish under
    a domain you control — see `zone_anchored_identity_name`.
    """
    name_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]
    return f"id-{name_hash}.{base_domain.rstrip('.')}"


def zone_anchored_identity_name(identity_domain_str: str) -> str:
    """Identity DNS name under a user-controlled zone.

    Convention: `dmp.<your-domain>` holds the TXT record. Anyone who can
    resolve DNS reads it; squat resistance comes from the fact that only
    the owner of `<your-domain>` can put records there. Works with any
    standard DNS zone — Cloudflare, Route53, BIND, etc.

    Addresses look like `alice@alice.example.com`: the left half is the
    username carried in the record body, the right half is the zone that
    anchors ownership. See `parse_address`.
    """
    return f"dmp.{identity_domain_str.rstrip('.')}"


def parse_address(address: str) -> Optional[Tuple[str, str]]:
    """Parse `user@host` into (user, host). Returns None on malformed input.

    Used to turn the human-readable address from `dnsmesh identity fetch
    alice@alice.example.com` into the DNS name `dmp.alice.example.com`.
    """
    if "@" not in address:
        return None
    user, _, host = address.partition("@")
    user = user.strip()
    host = host.strip().rstrip(".")
    if not user or not host:
        return None
    return user, host


@dataclass
class IdentityRecord:
    """A signed claim that (username, x25519_pk, ed25519_spk) belong together."""

    username: str
    x25519_pk: bytes  # 32-byte X25519 encryption pubkey
    ed25519_spk: bytes  # 32-byte Ed25519 signing pubkey
    ts: int  # unix seconds at publication
    versions: Tuple[int, ...] = (1,)
    """Protocol versions the publishing client supports as a receiver.

    Senders read this to decide which wire features to use when writing
    to this identity. A missing suffix on the wire (old records, records
    from clients that predate this field) is interpreted as ``(1,)``,
    matching today's behavior. To advertise v2 support, publish
    ``versions=(1, 2)`` (or call ``make_record`` which defaults to
    ``SUPPORTED_VERSIONS``).
    """

    def to_body_bytes(self) -> bytes:
        name = self.username.encode("utf-8")
        if not name:
            raise ValueError("username must not be empty")
        if len(name) > _USERNAME_MAX:
            raise ValueError(f"username too long (max {_USERNAME_MAX} utf-8 bytes)")
        if len(self.x25519_pk) != _X25519_LEN:
            raise ValueError("x25519_pk must be 32 bytes")
        if len(self.ed25519_spk) != _ED25519_LEN:
            raise ValueError("ed25519_spk must be 32 bytes")
        body = (
            len(name).to_bytes(1, "big")
            + name
            + self.x25519_pk
            + self.ed25519_spk
            + self.ts.to_bytes(_TS_LEN, "big")
        )
        # Only emit the versions suffix when the record advertises
        # something beyond v1. Omitting it for v1-only records keeps the
        # wire format bit-identical to the pre-versions historical
        # encoding — old verifiers (and old caches keyed on body hash)
        # continue to round-trip unchanged.
        versions = _normalize_versions(self.versions)
        if versions != (1,):
            body += len(versions).to_bytes(1, "big") + bytes(versions)
        return body

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "IdentityRecord":
        if len(body) < 1 + _X25519_LEN + _ED25519_LEN + _TS_LEN + 1:
            raise ValueError("identity body too short")
        name_len = body[0]
        if name_len == 0 or name_len > _USERNAME_MAX:
            raise ValueError("invalid username length")
        v1_end = 1 + name_len + _X25519_LEN + _ED25519_LEN + _TS_LEN
        if len(body) < v1_end:
            raise ValueError("identity body length mismatch")
        offset = 1
        name = body[offset : offset + name_len].decode("utf-8")
        offset += name_len
        x25519_pk = body[offset : offset + _X25519_LEN]
        offset += _X25519_LEN
        ed25519_spk = body[offset : offset + _ED25519_LEN]
        offset += _ED25519_LEN
        ts = int.from_bytes(body[offset : offset + _TS_LEN], "big")
        offset += _TS_LEN
        # Optional versions suffix. Absent → v1-only (the pre-versions
        # historical encoding). Present → length-prefixed list of u8
        # version numbers; the writer sorted-and-deduplicated them so a
        # well-formed record's encoding is deterministic.
        versions: Tuple[int, ...] = (1,)
        if offset < len(body):
            versions_len = body[offset]
            offset += 1
            if versions_len == 0:
                raise ValueError("identity body has empty versions suffix")
            if offset + versions_len != len(body):
                raise ValueError("identity body length mismatch (versions suffix)")
            raw = tuple(body[offset : offset + versions_len])
            versions = _normalize_versions(raw)
            if versions != raw:
                raise ValueError("identity versions must be sorted and unique")
        elif offset != len(body):
            raise ValueError("identity body length mismatch")
        return cls(
            username=name,
            x25519_pk=x25519_pk,
            ed25519_spk=ed25519_spk,
            ts=ts,
            versions=versions,
        )

    def sign(self, crypto: DMPCrypto) -> str:
        """Return the wire-format TXT record string, signed by `crypto`."""
        body = self.to_body_bytes()
        signature = crypto.sign_data(body)
        return f"{RECORD_PREFIX}{base64.b64encode(body + signature).decode('ascii')}"

    @classmethod
    def parse_and_verify(cls, record: str) -> Optional[Tuple["IdentityRecord", bytes]]:
        """Parse and verify an identity TXT record.

        Returns (record, signature) on success, or None on malformed input
        or signature failure. Caller still decides trust policy
        (TOFU / pin / discard).
        """
        if not record.startswith(RECORD_PREFIX):
            return None
        try:
            wire = base64.b64decode(record[len(RECORD_PREFIX) :])
        except Exception:
            return None
        if len(wire) < _SIG_LEN + 1:
            return None
        body = wire[:-_SIG_LEN]
        signature = wire[-_SIG_LEN:]
        try:
            record_obj = cls.from_body_bytes(body)
        except ValueError:
            return None
        if not DMPCrypto.verify_signature(body, signature, record_obj.ed25519_spk):
            return None
        return record_obj, signature

    def wire_name(self, base_domain: str) -> str:
        return identity_domain(self.username, base_domain)


def make_record(
    crypto: DMPCrypto,
    username: str,
    ts: Optional[int] = None,
    *,
    versions: Tuple[int, ...] = (1,),
) -> IdentityRecord:
    """Build an unsigned identity record.

    ``versions`` defaults to ``(1,)`` so the wire bytes produced by this
    function are byte-identical to the pre-versions historical encoding.
    A pre-versions client running on `main` validates an identity record
    by comparing its body length to the exact v1 expected length — any
    trailing suffix rejects, so silently flipping the default to
    ``SUPPORTED_VERSIONS`` would break sends from un-upgraded peers
    until they all upgraded too. Senders advertise v2 capability
    explicitly: pass ``versions=SUPPORTED_VERSIONS`` (or a CLI flag
    plumbed through to here) once the parser-relaxation in this commit
    has had time to propagate through the alpha install base.
    """
    return IdentityRecord(
        username=username,
        x25519_pk=crypto.get_public_key_bytes(),
        ed25519_spk=crypto.get_signing_public_key_bytes(),
        ts=int(time.time()) if ts is None else ts,
        versions=_normalize_versions(versions),
    )
