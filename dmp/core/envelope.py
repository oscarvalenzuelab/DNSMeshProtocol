"""DMPv2 plaintext envelope.

Wraps the AEAD plaintext with a versioned header that carries optional
sender metadata (today: ``from = user@host``). Lives INSIDE the AEAD
ciphertext, so the wrapper itself is not visible on the wire — DNS chunks
still expose only the existing ``DMPHeader`` JSON and the encrypted blob.

Wire format::

    DMPV2_PREFIX + canonical_json(header) + b"\\n" + body

- ``DMPV2_PREFIX`` (6 bytes) discriminates a v1 plaintext (no envelope,
  body bytes only) from a v2 plaintext (envelope present). Plain ASCII so
  a misrouted v2 plaintext arriving at a v1 receiver renders as readable
  garbage rather than binary noise. Misrouting should not happen once
  ``IdentityRecord.versions`` gates emission, but the readable-fallback
  property is cheap insurance.
- Header JSON is serialized with ``sort_keys=True, separators=(",", ":")``
  so encode is deterministic; receivers MUST parse generously (ignore
  unknown keys) so we can add fields later without breaking older
  receivers.
- ``\\n`` terminates the header. Empty body is legal.

Confidentiality: the entire envelope rides inside ChaCha20-Poly1305
ciphertext bound to ``DMPHeader`` as AAD. An attacker who scrapes the
erasure-coded DNS chunks sees only the AEAD blob; they cannot recover
``from`` without breaking the AEAD or the per-recipient X25519 ECDH.

Trust: the ``from`` claim by itself is unauthenticated metadata — the
sender chose to write whatever they wanted. The receiver MUST verify
``fetch_identity(from).ed25519_spk == manifest.sender_spk`` before
trusting the claim. See ``DMPClient._verify_envelope_address``. Until
verification succeeds, the receive path stores an empty
``sender_label``; the UI shows the SPK fingerprint.

Canonicalization: ``from`` is canonicalized both on encode (so the
sender publishes a stable form) and on decode (so the receiver looks up
and displays the stable form). Canonicalization rejects any non-ASCII
address — alpha addresses are ASCII-only. If we ever need IDNA / Unicode
local-parts we can extend the canonicalizer; pinning the rules now keeps
homograph attacks out of v1.
"""

from __future__ import annotations

import json
import re
from typing import Optional, Tuple

DMPV2_PREFIX = b"DMPV2:"
MAX_HEADER_BYTES = 256
"""Reject any envelope whose header JSON exceeds this many bytes.

Defensive cap — a malicious sender can already bloat the AEAD payload
by stuffing the body, so the cost of bloated metadata is linear, not
catastrophic. The cap nonetheless keeps the header at a sane size for
deterministic parsing and so future fields can't quietly grow the
envelope past chunk-reassembly cost expectations.
"""

_LOCALPART_MAX = 64
_HOST_LABEL_MAX = 63
_HOST_MAX = 253

_LOCALPART_RE = re.compile(r"^[a-z0-9][a-z0-9_\-.]{0,%d}$" % (_LOCALPART_MAX - 1))
_HOST_LABEL_RE = re.compile(
    r"^[a-z0-9]([a-z0-9\-]{0,%d}[a-z0-9])?$" % (_HOST_LABEL_MAX - 2)
)


def canonicalize_address(addr: str) -> Optional[str]:
    """Return the canonical ``user@host`` form, or ``None`` on reject.

    Rules (intentionally strict for alpha):

    - ASCII only. Non-ASCII codepoints reject. If you want IDNA, do it
      yourself and pass the punycoded form.
    - Lowercased.
    - Trailing dots on host stripped.
    - Local-part: starts alphanumeric, then ``a-z0-9_-.``, up to 64 chars.
    - Host: dot-separated labels, each ``a-z0-9-`` not starting/ending
      with ``-``, label ≤63 chars, total ≤253 chars.
    - Exactly one ``@``.
    - Empty local-part or host reject.

    Used on both encode (sender publishes the canonical form) and decode
    (receiver looks up and displays the canonical form). Receivers MUST
    canonicalize before any comparison or UI render — never display the
    raw bytes the sender wrote.
    """
    if not isinstance(addr, str):
        return None
    try:
        addr.encode("ascii")
    except UnicodeEncodeError:
        return None
    addr = addr.strip().lower()
    if addr.count("@") != 1:
        return None
    local, host = addr.split("@", 1)
    host = host.rstrip(".")
    if not local or not host:
        return None
    if len(host) > _HOST_MAX:
        return None
    if not _LOCALPART_RE.match(local):
        return None
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    labels = host.split(".")
    if any(not _HOST_LABEL_RE.match(lbl) for lbl in labels):
        return None
    return f"{local}@{host}"


def encode(body: bytes, *, sender_addr: Optional[str]) -> bytes:
    """Wrap ``body`` with a DMPv2 envelope, or return ``body`` unchanged.

    Returns the raw ``body`` (no wrapper) when ``sender_addr`` is None
    or fails canonicalization — that's the v1 wire form, which existing
    v1 receivers decrypt and display unchanged. Callers gate v2 emission
    on the recipient's published version capability (see
    ``IdentityRecord.versions``) so a wrapped plaintext never reaches a
    v1 receiver.
    """
    if sender_addr is None:
        return body
    canonical = canonicalize_address(sender_addr)
    if canonical is None:
        return body
    header = {"from": canonical}
    header_bytes = json.dumps(
        header, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(header_bytes) > MAX_HEADER_BYTES:
        # Should be unreachable for {"from": canonical} alone — the
        # canonicalizer already caps local+host length — but keep the
        # guard so future header fields can't sneak past it.
        return body
    return DMPV2_PREFIX + header_bytes + b"\n" + body


def decode(plaintext: bytes) -> Tuple[bytes, Optional[str]]:
    """Split a decrypted plaintext into ``(body, claimed_from_or_None)``.

    Decision matrix:

    - Prefix does not match → ``(plaintext, None)``. Treat as v1 wire
      form unchanged.
    - Prefix matches but no newline appears within ``MAX_HEADER_BYTES``
      → ``(plaintext, None)``. Safety valve for the implausible case
      where a v1 body happens to start with ``DMPV2:`` followed by
      256 bytes without a newline. The probability is ~256⁻⁶ but the
      safety valve keeps v1 fallback total.
    - Prefix matches and a newline is found → committed v2 envelope.
      Body is everything after the first newline. The header is
      then parsed best-effort; any failure downgrades to
      ``sender_label = None`` but the body is still returned cleanly.
      Failure modes that yield ``(body, None)``:

        * header bytes not valid ASCII / not valid JSON,
        * JSON is not a dict,
        * no ``from`` key,
        * ``from`` value not a string,
        * ``from`` fails canonicalization.

      Successful canonicalization yields ``(body, canonical_from)``.

    The returned ``claimed_from`` is canonicalized. It is NOT yet
    trust-verified — the caller MUST resolve ``from`` via DNS and
    compare ``ed25519_spk`` against the manifest's ``sender_spk``
    before populating any user-visible sender label.
    """
    if not plaintext.startswith(DMPV2_PREFIX):
        return plaintext, None
    rest = plaintext[len(DMPV2_PREFIX) :]
    nl = rest.find(b"\n", 0, MAX_HEADER_BYTES + 1)
    if nl < 0:
        return plaintext, None
    header_bytes = rest[:nl]
    body = rest[nl + 1 :]
    try:
        header = json.loads(header_bytes.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return body, None
    if not isinstance(header, dict):
        return body, None
    raw_from = header.get("from")
    if not isinstance(raw_from, str):
        return body, None
    canonical = canonicalize_address(raw_from)
    if canonical is None:
        return body, None
    return body, canonical
