"""Signed cluster manifests for DMP node federation.

A *cluster* is a set of DMP nodes run by one or more operators that
collectively serve the same mailbox data. Today's client points at one
node; M2 will let it fan out reads/writes across N. M2.1 — this module —
is the foundation: a signed, DNS-publishable record type listing the
cluster's node set. M2.2 (fan-out writer) and M2.3 (union reader) will
consume it.

A client configures the cluster-operator Ed25519 public key once
(pinning) and re-fetches the manifest to learn the current node set.
Sequence numbers let operators roll out changes; expiry keeps stale
clients from using revoked node sets.

Wire format — binary, base64'd, published under a well-known DNS name
(`cluster.<cluster_name>` TXT). Because a 6-node manifest exceeds one
255-byte TXT string, the wire format is permitted to span multiple TXT
strings within a single RRset — dnspython callers already concatenate
`b"".join(rdata.strings)` when reading, so on-the-wire encoding is just
"one long base64 string; let the RRset split it". Hard cap: 1200 bytes
of wire encoded text (≈ 4 TXT strings of 255 chars + small headroom).

Wire layout for the signed body:

    magic:             b"DMPCL01"                 (7 bytes)
    seq:               uint64 big-endian          (8 bytes)
    exp:               uint64 big-endian          (8 bytes)
    operator_spk:      32 bytes                   (32 bytes)
    cluster_name_len:  uint8                      (1 byte)
    cluster_name:      utf-8 bytes                (var, ≤ 64)
    node_count:        uint8                      (1 byte)
    per node:
        node_id_len:       uint8                  (1 byte)
        node_id:           ascii bytes            (var, ≤ 16)
        http_endpoint_len: uint16 big-endian      (2 bytes)
        http_endpoint:     utf-8 bytes            (var, ≤ 128)
        dns_endpoint_len:  uint16 big-endian      (2 bytes; 0 == absent)
        dns_endpoint:      utf-8 bytes            (var, ≤ 64)

Followed by a 64-byte Ed25519 signature over the body, computed with the
cluster operator's signing key. `parse_and_verify` treats the signature
as the only trust anchor: it parses the prefix, base64-decodes, splits
body|sig, verifies the signature against the caller-supplied operator
pubkey, *then* unpacks body fields. An attacker who rewrites any field
(including node_count) breaks verification.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import List, Optional

from dmp.core.crypto import DMPCrypto

RECORD_PREFIX = "v=dmp1;t=cluster;"

_MAGIC = b"DMPCL01"
_SIG_LEN = 64
_OPERATOR_SPK_LEN = 32

# Per-field hard caps. These are protocol-level, not config. They are
# tight enough that a 6-node manifest with realistic endpoints fits
# comfortably under the 1200-byte wire cap, and loose enough that an
# operator is not forced into awkward abbreviations.
MAX_NODE_ID_LEN = 16
MAX_HTTP_ENDPOINT_LEN = 128
MAX_DNS_ENDPOINT_LEN = 64
MAX_CLUSTER_NAME_LEN = 64
MAX_NODE_COUNT = 32  # protocol ceiling; sign() still enforces MAX_WIRE_LEN

# Absolute wire-length cap, enforced at sign() time. 1200 bytes is a
# comfortable ~4 TXT strings worth of base64'd payload. Records exceeding
# this are rejected rather than silently truncated; operators who
# genuinely need bigger clusters should shard across multiple manifests.
MAX_WIRE_LEN = 1200


def cluster_rrset_name(cluster_name: str) -> str:
    """Return the TXT RRset name where this cluster's manifest lives.

    Convention: `cluster.<cluster_name>`. Kept as a function so we can
    evolve it (e.g., to `_dmp-cluster.<cluster_name>` SRV-style) without
    churning call sites.
    """
    return f"cluster.{cluster_name.rstrip('.')}"


@dataclass
class ClusterNode:
    """One node entry in a cluster manifest."""

    # A stable human-readable node id (not a hostname; used for logs / dedupe).
    node_id: str  # <= 16 ASCII chars
    # HTTP ingress for writes and direct API calls.
    http_endpoint: str  # e.g. "https://node1.example.com:8053"
    # Optional DNS ingress if the node exposes its own DNS port.
    # None means "use the normal DNS system for reads" (i.e. query upstream DNS).
    dns_endpoint: Optional[str] = None  # e.g. "203.0.113.10:53"

    def _validate(self) -> None:
        # node_id: non-empty, ASCII, <= MAX_NODE_ID_LEN.
        if not isinstance(self.node_id, str) or not self.node_id:
            raise ValueError("node_id must be a non-empty string")
        try:
            id_bytes = self.node_id.encode("ascii")
        except UnicodeEncodeError as e:
            raise ValueError("node_id must be ASCII") from e
        if len(id_bytes) > MAX_NODE_ID_LEN:
            raise ValueError(f"node_id too long (max {MAX_NODE_ID_LEN} ascii bytes)")

        # http_endpoint: non-empty, utf-8 encodable, within hard cap.
        if not isinstance(self.http_endpoint, str) or not self.http_endpoint:
            raise ValueError("http_endpoint must be a non-empty string")
        http_bytes = self.http_endpoint.encode("utf-8")
        if len(http_bytes) > MAX_HTTP_ENDPOINT_LEN:
            raise ValueError(
                f"http_endpoint too long (max {MAX_HTTP_ENDPOINT_LEN} utf-8 bytes)"
            )

        # dns_endpoint: optional; if present, utf-8 encodable and within cap.
        if self.dns_endpoint is not None:
            if not isinstance(self.dns_endpoint, str) or not self.dns_endpoint:
                raise ValueError(
                    "dns_endpoint must be a non-empty string when provided"
                )
            dns_bytes = self.dns_endpoint.encode("utf-8")
            if len(dns_bytes) > MAX_DNS_ENDPOINT_LEN:
                raise ValueError(
                    f"dns_endpoint too long (max {MAX_DNS_ENDPOINT_LEN} utf-8 bytes)"
                )

    def to_body_bytes(self) -> bytes:
        self._validate()
        id_bytes = self.node_id.encode("ascii")
        http_bytes = self.http_endpoint.encode("utf-8")
        dns_bytes = self.dns_endpoint.encode("utf-8") if self.dns_endpoint else b""
        return (
            len(id_bytes).to_bytes(1, "big")
            + id_bytes
            + len(http_bytes).to_bytes(2, "big")
            + http_bytes
            + len(dns_bytes).to_bytes(2, "big")
            + dns_bytes
        )

    @classmethod
    def from_body_bytes(cls, body: bytes, offset: int) -> "tuple[ClusterNode, int]":
        """Unpack one node entry starting at `offset`; return (node, new_offset).

        Raises ValueError on any truncation or length-cap violation.
        """
        if offset + 1 > len(body):
            raise ValueError("truncated node: missing node_id length")
        id_len = body[offset]
        offset += 1
        if id_len == 0 or id_len > MAX_NODE_ID_LEN:
            raise ValueError("invalid node_id length")
        if offset + id_len > len(body):
            raise ValueError("truncated node: node_id")
        try:
            node_id = body[offset : offset + id_len].decode("ascii")
        except UnicodeDecodeError as e:
            raise ValueError("node_id not ASCII") from e
        offset += id_len

        if offset + 2 > len(body):
            raise ValueError("truncated node: missing http_endpoint length")
        http_len = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        if http_len == 0 or http_len > MAX_HTTP_ENDPOINT_LEN:
            raise ValueError("invalid http_endpoint length")
        if offset + http_len > len(body):
            raise ValueError("truncated node: http_endpoint")
        try:
            http_endpoint = body[offset : offset + http_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("http_endpoint not utf-8") from e
        offset += http_len

        if offset + 2 > len(body):
            raise ValueError("truncated node: missing dns_endpoint length")
        dns_len = int.from_bytes(body[offset : offset + 2], "big")
        offset += 2
        if dns_len > MAX_DNS_ENDPOINT_LEN:
            raise ValueError("invalid dns_endpoint length")
        dns_endpoint: Optional[str] = None
        if dns_len > 0:
            if offset + dns_len > len(body):
                raise ValueError("truncated node: dns_endpoint")
            try:
                dns_endpoint = body[offset : offset + dns_len].decode("utf-8")
            except UnicodeDecodeError as e:
                raise ValueError("dns_endpoint not utf-8") from e
            offset += dns_len

        return (
            cls(
                node_id=node_id,
                http_endpoint=http_endpoint,
                dns_endpoint=dns_endpoint,
            ),
            offset,
        )


@dataclass
class ClusterManifest:
    """Signed list of nodes that make up a DMP cluster.

    Published at a well-known DNS name (e.g. `cluster.mesh.example.com` TXT)
    and signed by a cluster-operator Ed25519 key. A client configures
    the operator pubkey once (pinning) and re-fetches the manifest to
    learn the current node set. Sequence numbers let operators roll out
    changes; expiry keeps stale clients from using revoked node sets.
    """

    cluster_name: str  # e.g. "mesh.example.com"; display/log purposes
    operator_spk: bytes  # Ed25519 public key, 32 bytes; echoed in wire for sanity
    nodes: List[ClusterNode]
    seq: int  # monotonic; higher wins when multiple manifests surface
    exp: int  # unix ts seconds; parse_and_verify returns None if past

    def _validate(self) -> None:
        if not isinstance(self.cluster_name, str) or not self.cluster_name:
            raise ValueError("cluster_name must be a non-empty string")
        name_bytes = self.cluster_name.encode("utf-8")
        if len(name_bytes) > MAX_CLUSTER_NAME_LEN:
            raise ValueError(
                f"cluster_name too long (max {MAX_CLUSTER_NAME_LEN} utf-8 bytes)"
            )
        if (
            not isinstance(self.operator_spk, (bytes, bytearray))
            or len(self.operator_spk) != _OPERATOR_SPK_LEN
        ):
            raise ValueError("operator_spk must be 32 bytes")
        if not isinstance(self.nodes, list):
            raise ValueError("nodes must be a list")
        if len(self.nodes) > MAX_NODE_COUNT:
            raise ValueError(
                f"too many nodes (max {MAX_NODE_COUNT}); "
                "shard the cluster across multiple manifests"
            )
        if not (0 <= self.seq < (1 << 64)):
            raise ValueError("seq out of range")
        if not (0 <= self.exp < (1 << 64)):
            raise ValueError("exp out of range")

    def to_body_bytes(self) -> bytes:
        self._validate()
        name_bytes = self.cluster_name.encode("utf-8")
        parts: List[bytes] = [
            _MAGIC,
            self.seq.to_bytes(8, "big"),
            self.exp.to_bytes(8, "big"),
            bytes(self.operator_spk),
            len(name_bytes).to_bytes(1, "big"),
            name_bytes,
            len(self.nodes).to_bytes(1, "big"),
        ]
        for node in self.nodes:
            parts.append(node.to_body_bytes())
        return b"".join(parts)

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "ClusterManifest":
        # Fixed header: magic(7) + seq(8) + exp(8) + operator_spk(32) + name_len(1) = 56
        min_header = len(_MAGIC) + 8 + 8 + _OPERATOR_SPK_LEN + 1
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
        operator_spk = bytes(body[off : off + _OPERATOR_SPK_LEN])
        off += _OPERATOR_SPK_LEN
        name_len = body[off]
        off += 1
        if name_len == 0 or name_len > MAX_CLUSTER_NAME_LEN:
            raise ValueError("invalid cluster_name length")
        if off + name_len > len(body):
            raise ValueError("truncated cluster_name")
        try:
            cluster_name = body[off : off + name_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("cluster_name not utf-8") from e
        off += name_len

        if off + 1 > len(body):
            raise ValueError("truncated: missing node_count")
        node_count = body[off]
        off += 1
        if node_count > MAX_NODE_COUNT:
            raise ValueError("node_count exceeds protocol max")

        nodes: List[ClusterNode] = []
        for _ in range(node_count):
            node, off = ClusterNode.from_body_bytes(body, off)
            nodes.append(node)

        if off != len(body):
            # Trailing bytes in a signed body indicate a malformed
            # manifest (or an attempt to append unsigned data after the
            # last parsed node). Reject.
            raise ValueError("trailing bytes after last node")

        return cls(
            cluster_name=cluster_name,
            operator_spk=operator_spk,
            nodes=nodes,
            seq=seq,
            exp=exp,
        )

    def sign(self, crypto: DMPCrypto) -> str:
        """Serialize to a TXT-friendly wire format, sign, return string.

        Enforces the 1200-byte wire cap. Raises ValueError if the
        resulting record would exceed it — callers should either drop
        nodes or shard into multiple manifests.
        """
        # Sanity check: signing key matches the declared operator_spk.
        if crypto.get_signing_public_key_bytes() != bytes(self.operator_spk):
            raise ValueError("signing key does not match declared operator_spk")
        body = self.to_body_bytes()
        signature = crypto.sign_data(body)
        encoded = base64.b64encode(body + signature).decode("ascii")
        wire = f"{RECORD_PREFIX}{encoded}"
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            raise ValueError(
                f"cluster manifest wire size {len(wire.encode('utf-8'))} "
                f"exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}; reduce node count "
                "or endpoint lengths"
            )
        return wire

    @classmethod
    def parse_and_verify(
        cls,
        wire: str,
        operator_spk: bytes,
        *,
        now: Optional[int] = None,
    ) -> Optional["ClusterManifest"]:
        """Parse and verify. Returns the manifest or None on any failure.

        Failures that return None (not raise):
        - Missing/wrong prefix
        - Base64 decode errors
        - Signature verification failure
        - operator_spk in the wire doesn't match the expected operator_spk arg
        - Expiry in the past (if `now` provided; defaults to time.time())
        - Malformed fields (wrong types, truncation, etc.)

        Parse order enforces the security invariant that the signature is
        the only trust anchor: prefix → base64 → split body|sig → verify
        sig with the caller's `operator_spk` arg → THEN unpack body fields
        → THEN cross-check the embedded operator_spk matches the arg.
        """
        # 1. Prefix.
        if not isinstance(wire, str) or not wire.startswith(RECORD_PREFIX):
            return None

        # 2. Base64.
        try:
            blob = base64.b64decode(wire[len(RECORD_PREFIX) :], validate=True)
        except Exception:
            return None

        # 3. Split body|sig. Signature must be the trailing 64 bytes.
        if len(blob) < _SIG_LEN + len(_MAGIC):
            return None
        body = blob[:-_SIG_LEN]
        signature = blob[-_SIG_LEN:]

        # 4. Verify signature against the caller-supplied operator key.
        # This is the trust anchor — we do NOT parse body fields first.
        if (
            not isinstance(operator_spk, (bytes, bytearray))
            or len(operator_spk) != _OPERATOR_SPK_LEN
        ):
            return None
        if not DMPCrypto.verify_signature(body, signature, bytes(operator_spk)):
            return None

        # 5. Unpack body.
        try:
            manifest = cls.from_body_bytes(body)
        except ValueError:
            return None

        # 6. Embedded operator_spk must match the caller's expectation.
        # Defense in depth: even if a sig format leaks, a manifest signed
        # by a different key won't silently deserialize.
        if bytes(manifest.operator_spk) != bytes(operator_spk):
            return None

        # 7. Expiry. If exp is in the past (relative to `now` or
        # time.time()), the manifest is stale and must be rejected.
        now_ts = int(time.time()) if now is None else int(now)
        if manifest.exp < now_ts:
            return None

        return manifest

    def is_expired(self, now: Optional[int] = None) -> bool:
        now_ts = int(time.time()) if now is None else int(now)
        return now_ts > self.exp
