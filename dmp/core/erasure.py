"""Cross-chunk erasure coding via Reed-Solomon (k-of-n).

The per-chunk RS layer in `chunking.py` repairs bit errors *within* a chunk
but does nothing against chunk loss. This layer sits above it: the plaintext
is split into k data blocks, `zfec` generates (n-k) parity blocks, and any
k of the n total blocks suffice to reconstruct. Chunk loss up to n-k is
fully recoverable.

k is chosen per-message based on plaintext size:
    k = ceil((len(plaintext) + 4) / DATA_PER_CHUNK)    # +4 for length prefix
    parity = max(1, ceil(k * REDUNDANCY))
    n = k + parity

REDUNDANCY = 0.3 gives ~30% redundancy, matching the original design intent.
Small k gets at least one parity so every message survives a single lost
chunk.

Wire format of each block: DATA_PER_CHUNK bytes, same size as the old
chunk payload, so a block fits the existing per-chunk RS wrapper
(MessageChunker.wrap_block) without layout changes.

The plaintext is length-prefixed (4 bytes, big-endian) before padding so
the recipient can strip trailing zeros unambiguously.
"""

from __future__ import annotations

from math import ceil
from typing import Dict, List, Optional, Tuple

import zfec

from dmp.core.chunking import MessageChunker


DEFAULT_REDUNDANCY = 0.3

# Internal: length of the original-message length prefix (big-endian u32).
_LEN_PREFIX = 4


def choose_kn(plaintext_size: int, redundancy: float = DEFAULT_REDUNDANCY) -> Tuple[int, int]:
    """Return (k, n) for a given plaintext size.

    Pure function; exposed so callers can compute n before they encode, e.g.
    to budget chunk publish calls or build the manifest.
    """
    block_size = MessageChunker.DATA_PER_CHUNK
    wrapped = plaintext_size + _LEN_PREFIX
    k = max(1, ceil(wrapped / block_size))
    parity = max(1, ceil(k * redundancy))
    n = k + parity
    return k, n


def encode(
    plaintext: bytes,
    redundancy: float = DEFAULT_REDUNDANCY,
) -> Tuple[List[bytes], int, int]:
    """Split plaintext into n equal-sized blocks where any k reconstruct.

    Returns (blocks, k, n). Each block is DATA_PER_CHUNK bytes long; the
    first k blocks are the data blocks (share IDs 0..k-1) and the rest are
    parity blocks (share IDs k..n-1).
    """
    if len(plaintext) > (1 << 32) - 1:
        raise ValueError("plaintext too large for 4-byte length prefix")
    block_size = MessageChunker.DATA_PER_CHUNK
    k, n = choose_kn(len(plaintext), redundancy)

    # Length-prefix and zero-pad to exactly k * block_size bytes.
    wrapped = len(plaintext).to_bytes(_LEN_PREFIX, "big") + plaintext
    padded = wrapped + b"\x00" * (k * block_size - len(wrapped))
    data_blocks = [
        padded[i * block_size : (i + 1) * block_size] for i in range(k)
    ]

    # k == n is not legal in zfec (requires at least one parity). choose_kn
    # always adds at least one parity, so we never hit that case here.
    encoder = zfec.Encoder(k, n)
    shares = encoder.encode(data_blocks)
    # zfec returns `n` shares in order — data blocks first, then parity.
    return list(shares), k, n


def decode(
    shares: Dict[int, bytes],
    k: int,
    n: int,
) -> Optional[bytes]:
    """Reconstruct plaintext from any k valid shares.

    `shares` maps share_id → block bytes. Returns the original plaintext or
    None if fewer than k shares are available or decode produces a
    malformed length-prefixed blob.
    """
    if k <= 0 or n < k:
        return None
    if len(shares) < k:
        return None

    ordered = sorted(shares.items())[:k]
    share_ids = [i for i, _ in ordered]
    blocks = [b for _, b in ordered]
    if any(len(b) != MessageChunker.DATA_PER_CHUNK for b in blocks):
        return None

    decoder = zfec.Decoder(k, n)
    try:
        data_blocks = decoder.decode(blocks, share_ids)
    except Exception:
        return None

    padded = b"".join(data_blocks)
    if len(padded) < _LEN_PREFIX:
        return None
    length = int.from_bytes(padded[:_LEN_PREFIX], "big")
    if length > len(padded) - _LEN_PREFIX:
        return None
    return padded[_LEN_PREFIX : _LEN_PREFIX + length]
