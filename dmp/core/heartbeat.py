"""Signed node heartbeats for the M5.8 discovery directory.

Every opted-in node periodically emits a ``HeartbeatRecord`` asserting
"I am <endpoint>, operated by <operator_spk>, running version
<version>, capabilities <bitfield>, claim_provider_zone <zone>, as of
<ts>, valid until <exp>." Peers store received heartbeats in a local
seen-store and re-export them so aggregators (including a central
directory website) can render "which nodes are reachable right now"
without introducing a new trust anchor: every entry in the aggregated
list is a verifiable signature under the operator key.

In M9 (0.5.0) the heartbeat record subsumes the M8 ``/v1/info``
endpoint — peers fetch it directly from DNS at
``_dnsmesh-heartbeat.<zone>`` instead of HTTP-polling, and the
``claim_provider_zone`` field that lived only in the JSON ``/v1/info``
response now travels in the signed wire.

Wire format — flat binary, same style as ``ClusterManifest`` /
``RotationRecord``. Base64 of ``body || sig`` with a
``v=dmp1;t=heartbeat;`` prefix. Fits in a single DNS TXT.

Body layout (all integers big-endian):

    magic                       b"DMPHB03"          7 bytes
    endpoint_len                uint16              2 bytes
    endpoint                    utf-8 bytes         var, 1..MAX_ENDPOINT_LEN
    operator_spk                bytes               32 bytes (Ed25519 pubkey)
    version_len                 uint8               1 byte
    version                     utf-8 bytes         0..MAX_VERSION_LEN
    capabilities                uint16              2 bytes (bitfield, M8.2+)
    claim_provider_zone_len     uint8               1 byte
    claim_provider_zone         utf-8 bytes         0..MAX_ZONE_LEN  (M9)
    ts                          uint64              8 bytes (unix seconds)
    exp                         uint64              8 bytes (unix seconds)
    signature                   bytes               64 bytes

The operator key is the same Ed25519 key that signs
``ClusterManifest`` / ``BootstrapRecord`` — heartbeat does not add
a new trust anchor, and a leaked operator key's blast radius is
unchanged.

**Capabilities (M8.2):** bit 0 (``CAP_CLAIM_PROVIDER``) advertises
that this node hosts the M8 first-contact claim namespace under its
own zone. Defaults ON in production heartbeat workers; operators who
don't want to host claims for arbitrary recipients opt out via
``DMP_CLAIM_PROVIDER=0``. The bitfield carries 15 reserved bits for
future capabilities (e.g. directory aggregator, rendezvous
operator) — pre-M8.2 nodes that read a v=DMPHB02 record but don't
understand a given bit should ignore unknown bits, not reject the
record.

Magic was bumped from ``DMPHB01`` to ``DMPHB02`` for this format
change; pre-M8.2 nodes will fail to parse v=DMPHB02 records and
vice versa. This is acceptable for the alpha — no production
deployments rely on the v01 wire today.
"""

from __future__ import annotations

import base64
import ipaddress
import struct
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from dmp.core.crypto import DMPCrypto
from dmp.core.ed25519_points import is_low_order as _is_low_order

# Wire prefix. v1 because the whole family of signed DMP records uses
# v=dmp1; jumping to v=dmp2 is a flag day across everything post-audit.
RECORD_PREFIX = "v=dmp1;t=heartbeat;"

_MAGIC = b"DMPHB03"
# M9 rolling-upgrade compatibility (codex round-3 P1): the wire-format
# magic was bumped from DMPHB02 -> DMPHB03 for the new
# claim_provider_zone field. We continue PARSING legacy DMPHB02 wires
# (treating claim_provider_zone as empty) so a 0.5 node can still
# verify heartbeats from peers that haven't upgraded yet, and so a
# 0.5 node ingesting its own pre-upgrade SeenStore rows doesn't lose
# every peer until they republish. We sign new wires with DMPHB03
# only — there's no legacy emission path.
_LEGACY_MAGIC = b"DMPHB02"
_KNOWN_MAGICS = (_MAGIC, _LEGACY_MAGIC)
_SPK_LEN = 32
_SIG_LEN = 64

# Capability bits advertised in the ``capabilities`` field. Bit 0 is
# claim-provider (M8.2); subsequent bits are reserved. Use the
# constants rather than literals to keep grep-ability and avoid
# typos.
CAP_CLAIM_PROVIDER = 1 << 0
# Mask of all bits this code understands. Unknown bits in a parsed
# record are tolerated (forward-compat) but a node won't act on
# capabilities it doesn't have a constant for.
CAP_KNOWN_MASK = CAP_CLAIM_PROVIDER

# Cap on the embedded claim_provider_zone DNS name. Same ceiling as
# claim records' MAX_MAILBOX_DOMAIN_LEN — keeps the heartbeat wire
# inside a single 255-byte DNS TXT after sig + base64 overhead.
MAX_CLAIM_PROVIDER_ZONE_LEN = 64

# Size caps. Deliberately tight — a heartbeat is a discovery record,
# not a carrier for arbitrary metadata. Callers who want to hang
# richer data off a node (capacity, region, contact email) should
# expose it on a separate endpoint indexed by the operator_spk.
MAX_ENDPOINT_LEN = 255
MAX_VERSION_LEN = 32
MAX_WIRE_LEN = 1200  # matches ClusterManifest / RotationRecord

# Freshness policy. ts must verify-to-now within this window to limit
# replay of a captured heartbeat. 5 minutes tolerates clock drift +
# network queuing but not an attacker sitting on an old heartbeat.
_DEFAULT_TS_SKEW_SECONDS = 300

# Low-order Ed25519 pubkey rejection delegates to
# dmp.core.ed25519_points so registration + heartbeat + any future
# signed-record consumer share a single authoritative list.

# Basic URL shape check. DMP endpoints are https://<host>[:port], no
# path/query/fragment allowed; the consumer appends /v1/... itself.
# Intentionally strict: an attacker inserting file://, javascript:,
# or unicode spoofs in a heartbeat is an obvious red flag, and
# accepting one into the seen-store lets a crawling aggregator hit
# it. SSRF vectors (userinfo host-confusion, IP literals in private
# ranges, localhost aliases) are rejected here — an aggregator can
# re-check at connect time but the defense-in-depth starts in the
# wire parser.
_ALLOWED_URL_SCHEMES = ("https", "http")

# Hostnames that resolve to the host itself. Block all case-
# variants at the wire layer because even though 'localhost' is
# just a hostname, every reasonable resolver maps it to 127.0.0.1 /
# ::1 and therefore it is an SSRF vector on the crawler side.
_LOCALHOST_ALIASES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def _validate_endpoint(endpoint: str) -> None:
    """Shape-check ``endpoint``. Raise ValueError on malformed input.

    Rules (in order of check):

      1. Non-empty string, <= MAX_ENDPOINT_LEN, ASCII-only, no
         whitespace / control chars.
      2. Parses under urllib.parse.urlsplit with an allowed scheme
         (``https`` or ``http``).
      3. No userinfo (rejects ``https://public@127.0.0.1`` style
         host-confusion: `requests` connects to the parsed host,
         not the label left of ``@``).
      4. Non-empty hostname.
      5. No path / query / fragment (endpoint is the publish-API
         base; clients append ``/v1/...`` themselves).
      6. If the hostname is an IP literal, reject any loopback /
         private / link-local / multicast / reserved / unspecified
         address (blocks direct SSRF vectors). Covers both v4 and
         bracketed v6 literals.
      7. Reject case-insensitive ``localhost`` and its aliases.

    Hostnames that resolve via DNS to private IPs at crawl time
    are the *aggregator*'s responsibility to refuse at connect
    time — a wire parser can't see the future resolution. This
    function is the first line of defense, not the only one.
    """
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("endpoint must be a non-empty string")
    if len(endpoint) > MAX_ENDPOINT_LEN:
        raise ValueError(
            f"endpoint length {len(endpoint)} > MAX_ENDPOINT_LEN {MAX_ENDPOINT_LEN}"
        )
    try:
        endpoint.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"endpoint must be ASCII; non-ASCII at position {exc.start}"
        ) from exc
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in endpoint):
        raise ValueError("endpoint contains whitespace or control characters")

    # urlsplit handles bracketed IPv6, userinfo, port, path, query,
    # fragment correctly — defer to it rather than hand-rolling the
    # parser. urlsplit itself never raises; missing fields come back
    # as ''.
    parts = urlsplit(endpoint)
    if parts.scheme.lower() not in _ALLOWED_URL_SCHEMES:
        raise ValueError(
            f"endpoint scheme must be one of {_ALLOWED_URL_SCHEMES}; "
            f"got {parts.scheme!r}"
        )
    if parts.username is not None or parts.password is not None:
        # `https://user@dmp.example.com` is the canonical SSRF-via-
        # userinfo vector: a reader skimming the URL thinks the host
        # is "dmp.example.com" but requests connects to whatever's
        # after the @. Refuse outright.
        raise ValueError("endpoint must not carry userinfo (user:pass@...)")
    host = parts.hostname or ""
    if not host:
        raise ValueError("endpoint must include a host")
    # urlsplit preserves path/query/fragment. None must be present
    # (the endpoint is the authority-only base).
    if parts.path or parts.query or parts.fragment:
        raise ValueError(
            "endpoint must be <scheme>://<host>[:port], no path / query / fragment"
        )

    # Localhost and its aliases resolve to loopback on every
    # reasonable system — block them at the wire layer.
    if host.lower() in _LOCALHOST_ALIASES:
        raise ValueError(f"endpoint host {host!r} is a localhost alias")

    # If the host is an IP literal, refuse any non-public range.
    # ipaddress.ip_address raises on non-literals (hostnames); we
    # fall through in that case — hostname resolution is the
    # aggregator's SSRF defense, not ours.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError(
                f"endpoint host {host!r} is a {type(ip).__name__} in a "
                "non-public range (loopback / private / link-local / "
                "multicast / reserved / unspecified)"
            )


def _validate_version(version: str) -> None:
    """Shape-check the version string."""
    if not isinstance(version, str):
        raise ValueError("version must be a string")
    if len(version) > MAX_VERSION_LEN:
        raise ValueError(
            f"version length {len(version)} > MAX_VERSION_LEN {MAX_VERSION_LEN}"
        )
    try:
        version.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("version must be ASCII") from exc


@dataclass(frozen=True)
class HeartbeatRecord:
    """Signed node heartbeat.

    Immutable; construct via ``__init__`` + ``sign()``, or parse via
    :meth:`parse_and_verify`. The record is signed by ``operator_spk``
    (the Ed25519 key the node operator already uses for cluster
    manifests / bootstrap records).

    ``capabilities`` is a uint16 bitfield (M8.2+). Bit 0 is
    ``CAP_CLAIM_PROVIDER``; the rest are reserved. A node that reads
    a heartbeat with bits it doesn't recognize must ignore the unknown
    bits rather than refusing the record (forward-compat).
    """

    endpoint: str
    operator_spk: bytes
    version: str
    ts: int
    exp: int
    capabilities: int = 0
    # M9: claim provider zone the node serves under. Empty string when
    # the node isn't acting as a claim provider (CAP_CLAIM_PROVIDER bit
    # off, or no DMP_DOMAIN configured). Carries the same data the
    # legacy /v1/info HTTP endpoint reports, but inside the signed
    # heartbeat wire — peers query this from DNS at
    # _dnsmesh-heartbeat.<zone> to learn each other's role + zone in
    # one round trip.
    claim_provider_zone: str = ""

    # ------------------------------------------------------------------
    # body layout
    # ------------------------------------------------------------------

    def to_body_bytes(self) -> bytes:
        """Serialize the signable body (everything except the signature)."""
        _validate_endpoint(self.endpoint)
        _validate_version(self.version)
        if not isinstance(self.operator_spk, (bytes, bytearray)):
            raise ValueError("operator_spk must be bytes")
        if len(self.operator_spk) != _SPK_LEN:
            raise ValueError(
                f"operator_spk must be {_SPK_LEN} bytes, got {len(self.operator_spk)}"
            )
        if not isinstance(self.ts, int) or self.ts < 0 or self.ts >= (1 << 63):
            raise ValueError("ts must be a non-negative int64")
        if not isinstance(self.exp, int) or self.exp < 0 or self.exp >= (1 << 63):
            raise ValueError("exp must be a non-negative int64")
        if self.exp <= self.ts:
            raise ValueError("exp must be strictly greater than ts")
        if (
            not isinstance(self.capabilities, int)
            or self.capabilities < 0
            or self.capabilities > 0xFFFF
        ):
            raise ValueError("capabilities must be a uint16 (0..65535)")
        if not isinstance(self.claim_provider_zone, str):
            raise ValueError("claim_provider_zone must be a string")
        if len(self.claim_provider_zone) > MAX_CLAIM_PROVIDER_ZONE_LEN:
            raise ValueError(
                f"claim_provider_zone length "
                f"{len(self.claim_provider_zone)} > "
                f"MAX_CLAIM_PROVIDER_ZONE_LEN {MAX_CLAIM_PROVIDER_ZONE_LEN}"
            )
        if self.claim_provider_zone:
            try:
                self.claim_provider_zone.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError(
                    "claim_provider_zone must be ASCII"
                ) from exc
            if any(
                ord(c) < 0x21 or ord(c) == 0x7F
                for c in self.claim_provider_zone
            ):
                raise ValueError(
                    "claim_provider_zone contains whitespace or control characters"
                )

        endpoint_bytes = self.endpoint.encode("utf-8")
        version_bytes = self.version.encode("utf-8")
        zone_bytes = self.claim_provider_zone.encode("utf-8")
        return (
            _MAGIC
            + struct.pack(">H", len(endpoint_bytes))
            + endpoint_bytes
            + bytes(self.operator_spk)
            + struct.pack(">B", len(version_bytes))
            + version_bytes
            + struct.pack(">H", self.capabilities)
            + struct.pack(">B", len(zone_bytes))
            + zone_bytes
            + struct.pack(">Q", self.ts)
            + struct.pack(">Q", self.exp)
        )

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "HeartbeatRecord":
        """Parse the signable body. Raises ValueError on structural issues.

        Does NOT verify the signature — the caller is responsible for
        that. Use :meth:`parse_and_verify` for the complete check.
        """
        if len(body) < len(_MAGIC) + 2:
            raise ValueError("body too short for magic+endpoint_len")
        magic = body[: len(_MAGIC)]
        if magic not in _KNOWN_MAGICS:
            raise ValueError("bad magic")
        is_legacy = magic == _LEGACY_MAGIC
        off = len(_MAGIC)

        (endpoint_len,) = struct.unpack(">H", body[off : off + 2])
        off += 2
        if endpoint_len == 0 or endpoint_len > MAX_ENDPOINT_LEN:
            raise ValueError(f"endpoint_len out of range: {endpoint_len}")
        if off + endpoint_len > len(body):
            raise ValueError("body truncated in endpoint")
        try:
            endpoint = body[off : off + endpoint_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"endpoint not valid utf-8: {exc}") from exc
        off += endpoint_len

        if off + _SPK_LEN > len(body):
            raise ValueError("body truncated in operator_spk")
        operator_spk = bytes(body[off : off + _SPK_LEN])
        off += _SPK_LEN

        if off + 1 > len(body):
            raise ValueError("body truncated in version_len")
        (version_len,) = struct.unpack(">B", body[off : off + 1])
        off += 1
        if version_len > MAX_VERSION_LEN:
            raise ValueError(f"version_len out of range: {version_len}")
        if off + version_len > len(body):
            raise ValueError("body truncated in version")
        try:
            version = body[off : off + version_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"version not valid utf-8: {exc}") from exc
        off += version_len

        if off + 2 > len(body):
            raise ValueError("body truncated in capabilities")
        (capabilities,) = struct.unpack(">H", body[off : off + 2])
        off += 2

        # M9: claim_provider_zone (uint8 length-prefixed utf-8). Empty
        # string for nodes that don't host claims; up to
        # MAX_CLAIM_PROVIDER_ZONE_LEN otherwise.
        # Legacy DMPHB02 wires don't carry this field — treat as
        # empty so cross-version verification keeps working through
        # the rolling upgrade.
        if is_legacy:
            claim_provider_zone = ""
        else:
            if off + 1 > len(body):
                raise ValueError("body truncated in claim_provider_zone_len")
            (zone_len,) = struct.unpack(">B", body[off : off + 1])
            off += 1
            if zone_len > MAX_CLAIM_PROVIDER_ZONE_LEN:
                raise ValueError(
                    f"claim_provider_zone_len out of range: {zone_len}"
                )
            if off + zone_len > len(body):
                raise ValueError("body truncated in claim_provider_zone")
            try:
                claim_provider_zone = body[off : off + zone_len].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"claim_provider_zone not valid utf-8: {exc}"
                ) from exc
            off += zone_len

        if off + 16 > len(body):
            raise ValueError("body truncated in ts/exp")
        (ts,) = struct.unpack(">Q", body[off : off + 8])
        off += 8
        (exp,) = struct.unpack(">Q", body[off : off + 8])
        off += 8

        if off != len(body):
            raise ValueError(f"trailing body bytes: off={off} len={len(body)}")

        # Re-validate through the shape checks so a malformed body
        # can't produce a Python-level HeartbeatRecord that later
        # blows up somewhere downstream.
        _validate_endpoint(endpoint)
        _validate_version(version)

        if exp <= ts:
            raise ValueError("exp must be strictly greater than ts")

        return cls(
            endpoint=endpoint,
            operator_spk=operator_spk,
            version=version,
            ts=ts,
            exp=exp,
            capabilities=capabilities,
            claim_provider_zone=claim_provider_zone,
        )

    # ------------------------------------------------------------------
    # sign / verify
    # ------------------------------------------------------------------

    def sign(self, operator_crypto: DMPCrypto) -> str:
        """Serialize, sign with ``operator_crypto``, return wire text.

        The operator keypair must match ``self.operator_spk`` exactly
        — a mismatch catches a common footgun where a caller signs a
        heartbeat with the wrong key and confuses verifiers downstream.
        """
        if operator_crypto.get_signing_public_key_bytes() != bytes(self.operator_spk):
            raise ValueError(
                "operator_crypto signing key does not match declared operator_spk"
            )
        body = self.to_body_bytes()
        sig = operator_crypto.sign_data(body)
        encoded = base64.b64encode(body + sig).decode("ascii")
        wire = f"{RECORD_PREFIX}{encoded}"
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            raise ValueError(
                f"heartbeat wire size {len(wire.encode('utf-8'))} "
                f"exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}"
            )
        return wire

    @classmethod
    def parse_and_verify(
        cls,
        wire: str,
        *,
        now: Optional[int] = None,
        ts_skew_seconds: int = _DEFAULT_TS_SKEW_SECONDS,
    ) -> Optional["HeartbeatRecord"]:
        """Parse + verify signature + enforce freshness. Never raises.

        Returns ``None`` on:
          - Wrong prefix / shape / magic / truncation / trailing bytes.
          - Wire exceeds ``MAX_WIRE_LEN``.
          - Base64 decode failure.
          - Signature verification failure.
          - ``operator_spk`` is an Ed25519 low-order point (degenerate).
          - ``ts`` is outside ``±ts_skew_seconds`` of ``now``.
          - ``exp`` is at or before ``now`` (record is expired).
          - ``exp <= ts`` (caller produced garbage).

        The ts-skew guard catches naive replay of captured heartbeats.
        An attacker who has a 10-minute-old wire cannot re-inject it
        because the ``ts`` value is now > 5 minutes in the past. Real
        replays need the operator key to produce a fresh ``ts``.
        """
        if not isinstance(wire, str) or not wire.startswith(RECORD_PREFIX):
            return None
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            return None
        try:
            blob = base64.b64decode(wire[len(RECORD_PREFIX) :], validate=True)
        except Exception:
            return None
        # magic + endpoint_len + operator_spk + version_len + capabilities
        # [+ claim_provider_zone_len for DMPHB03] + ts + exp + signature.
        # Smallest legal DMPHB02 body is 1 byte shorter than DMPHB03 (no
        # zone_len byte); use the lower bound here so a legacy wire
        # passes the size gate. ``from_body_bytes`` does the per-version
        # structural validation downstream.
        if len(blob) < len(_MAGIC) + _SIG_LEN + 2 + _SPK_LEN + 1 + 2 + 16:
            return None
        body = blob[:-_SIG_LEN]
        sig = blob[-_SIG_LEN:]

        try:
            record = cls.from_body_bytes(body)
        except ValueError:
            return None

        # Low-order pubkey guard — identity point (01 00..00) with
        # any sig verifies every message under permissive RFC 8032;
        # other small-order points allow grinding forgeries on subsets.
        # Shared block list with dmp.server.registration.
        if _is_low_order(bytes(record.operator_spk)):
            return None

        if not DMPCrypto.verify_signature(body, sig, bytes(record.operator_spk)):
            return None

        now = now if now is not None else int(time.time())
        if abs(record.ts - now) > ts_skew_seconds:
            return None
        if record.exp <= now:
            return None

        return record
