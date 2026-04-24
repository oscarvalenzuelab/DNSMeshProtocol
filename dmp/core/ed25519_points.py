"""Ed25519 low-order / small-subgroup public-key block list.

Holding any of these as an Ed25519 public key lets an attacker forge
a signature that the permissive RFC-8032 verify accepts:

  - Identity point (01 00..00) with sig = identity || 0^32 verifies
    on EVERY message — a complete signature-forgery bypass.
  - Other small-order points (orders 2, 4, 8) allow forgery on
    subsets of messages, which is still grindable.

Reference: https://pkg.go.dev/c2sp.org/CCTV/ed25519.

Every DMP wire-format consumer that does
``Ed25519PublicKey.from_public_bytes(spk).verify(sig, msg)`` must
first refuse ``spk`` in this set. Centralizing the list here means
a future addition (new non-canonical alias discovered, etc.) only
needs to update one file.
"""

from __future__ import annotations


LOW_ORDER_ED25519_PUBKEYS: frozenset = frozenset(
    bytes.fromhex(h)
    for h in (
        # Canonical encodings — small-order points (orders 1, 2, 4, 8),
        # each sign.
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        # Non-canonical aliases that `cryptography`'s Ed25519
        # still accepts as valid 32-byte pubkey encodings.
        "0100000000000000000000000000000000000000000000000000000000000080",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
)


def is_low_order(pubkey: bytes) -> bool:
    """Return True iff ``pubkey`` is a known low-order / small-subgroup
    Ed25519 public-key encoding that must be rejected before any verify.
    """
    if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
        return True  # wrong shape — fail closed
    return bytes(pubkey) in LOW_ORDER_ED25519_PUBKEYS
