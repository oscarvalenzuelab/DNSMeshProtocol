"""Lightweight Ed25519-only signer for operator-scoped records.

``DMPCrypto`` in this codebase derives its Ed25519 signing key from
its X25519 private bytes via domain-separated SHA-256 — the right
shape for user identity where both keypairs are owned by the same
person and derived from one passphrase. Operator-scoped records
(``ClusterManifest``, ``BootstrapRecord``, and the M5.8
``HeartbeatRecord``) have no X25519 half; they just need an
Ed25519 private seed the operator manages separately (typically
output by ``docker/cluster/generate-cluster-manifest.py``).

``OperatorSigner`` wraps one Ed25519 key and implements the
duck-typed signing surface that ``HeartbeatRecord.sign``,
``ClusterManifest.sign``, etc. consume:

    .get_signing_public_key_bytes() -> bytes
    .sign_data(data: bytes) -> bytes

Nothing else. Loading this directly from a 32-byte seed skips the
X25519 derivation the heartbeat path doesn't use, and keeps the
heartbeat key material aligned with the existing cluster-operator
key-handling story (operator stores the seed offline, mounts it
into the node via env).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class OperatorSigner:
    """Operator-key signer. 32-byte Ed25519 seed in, .sign_data out."""

    __slots__ = ("_signing_key", "_pub_bytes")

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError(
                f"operator seed must be 32 bytes, got "
                f"{len(seed) if hasattr(seed, '__len__') else type(seed).__name__}"
            )
        self._signing_key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        self._pub_bytes = self._signing_key.public_key().public_bytes_raw()

    @classmethod
    def from_seed_bytes(cls, seed: bytes) -> "OperatorSigner":
        return cls(seed)

    @classmethod
    def from_hex(cls, seed_hex: str) -> "OperatorSigner":
        """Load from a 64-char hex string (the format
        ``generate-cluster-manifest.py`` emits)."""
        if not isinstance(seed_hex, str):
            raise ValueError("seed_hex must be a string")
        cleaned = seed_hex.strip()
        if len(cleaned) != 64:
            raise ValueError(f"seed_hex must be 64 hex chars, got {len(cleaned)}")
        try:
            seed = bytes.fromhex(cleaned)
        except ValueError as exc:
            raise ValueError(f"seed_hex is not valid hex: {exc}") from exc
        return cls(seed)

    def get_signing_public_key_bytes(self) -> bytes:
        return self._pub_bytes

    def sign_data(self, data: bytes) -> bytes:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes")
        return self._signing_key.sign(bytes(data))
