"""Signed slot manifests and replay protection for DMP mailboxes.

A slot manifest is the TXT record a sender publishes at a mailbox slot to tell
the recipient "a message is waiting here." It names the message, how many
chunks to fetch, when it expires, and is signed by the sender's Ed25519
identity so it can't be forged or silently mutated.

Without this, anyone can publish to a mailbox slot and impersonate any sender.
With this, forged slots are detectable and the recipient-side replay cache can
reject re-publication of old valid manifests.

Wire format (compact binary to fit in one 255-byte DNS TXT string):

    v=dmp1;t=manifest;d=<b64(body || sig)>

body = msg_id(16) || sender_spk(32) || recipient_id(32) ||
       total_chunks(4) || data_chunks(4) || ts(8) || exp(8)        =  104 bytes
sig  = Ed25519 signature over `body`                                =   64 bytes
total                                                               =  168 bytes
base64                                                              =  224 chars
prefix `v=dmp1;t=manifest;d=`                                       =   20 chars
wire total                                                          =  244 chars  (fits)

`data_chunks` is the erasure threshold k: the recipient needs any k of the
total_chunks to reconstruct the message. When the sender disables erasure
(single-chunk legacy flow), data_chunks == total_chunks.
"""

from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from dmp.core.crypto import DMPCrypto


RECORD_PREFIX = "v=dmp1;t=manifest;d="
_BODY_LEN = 16 + 32 + 32 + 4 + 4 + 8 + 8   # 104 bytes (adds data_chunks)
_SIG_LEN = 64
_WIRE_LEN = _BODY_LEN + _SIG_LEN            # 168 bytes
DEFAULT_MANIFEST_TTL = 300


@dataclass
class SlotManifest:
    """Claim that a message is waiting at a mailbox slot.

    The Ed25519 signature covers `to_body_bytes()` so any mutation of any
    field breaks verification.
    """

    msg_id: bytes            # 16 bytes
    sender_spk: bytes        # 32-byte Ed25519 signing public key of the sender
    recipient_id: bytes      # 32-byte sha256 of recipient's X25519 pubkey
    total_chunks: int        # n — chunks actually published
    data_chunks: int         # k — chunks needed to reconstruct (erasure threshold)
    ts: int                  # unix seconds when the sender published
    exp: int                 # unix seconds after which recipient should drop

    def to_body_bytes(self) -> bytes:
        """Binary representation of the manifest fields, used as the signed payload."""
        if len(self.msg_id) != 16:
            raise ValueError("msg_id must be 16 bytes")
        if len(self.sender_spk) != 32:
            raise ValueError("sender_spk must be 32 bytes")
        if len(self.recipient_id) != 32:
            raise ValueError("recipient_id must be 32 bytes")
        if self.data_chunks <= 0 or self.data_chunks > self.total_chunks:
            raise ValueError("data_chunks must be in 1..total_chunks")
        return (
            self.msg_id
            + self.sender_spk
            + self.recipient_id
            + self.total_chunks.to_bytes(4, "big")
            + self.data_chunks.to_bytes(4, "big")
            + self.ts.to_bytes(8, "big")
            + self.exp.to_bytes(8, "big")
        )

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "SlotManifest":
        if len(body) != _BODY_LEN:
            raise ValueError(f"manifest body must be {_BODY_LEN} bytes, got {len(body)}")
        total_chunks = int.from_bytes(body[80:84], "big")
        data_chunks = int.from_bytes(body[84:88], "big")
        if data_chunks <= 0 or data_chunks > total_chunks:
            raise ValueError("data_chunks out of range")
        return cls(
            msg_id=body[0:16],
            sender_spk=body[16:48],
            recipient_id=body[48:80],
            total_chunks=total_chunks,
            data_chunks=data_chunks,
            ts=int.from_bytes(body[88:96], "big"),
            exp=int.from_bytes(body[96:104], "big"),
        )

    def sign(self, sender_crypto: DMPCrypto) -> str:
        """Return the wire-format TXT record string, signed by `sender_crypto`."""
        body = self.to_body_bytes()
        signature = sender_crypto.sign_data(body)
        wire = body + signature
        return f"{RECORD_PREFIX}{base64.b64encode(wire).decode('ascii')}"

    @classmethod
    def parse_and_verify(
        cls, record: str
    ) -> Optional[Tuple["SlotManifest", bytes]]:
        """Parse and verify a manifest TXT record.

        Returns (manifest, raw_signature) on success, or None if the record is
        malformed, truncated, or the signature fails verification against the
        sender_spk embedded in the body. Callers should still check `exp` and
        replay state.
        """
        if not record.startswith(RECORD_PREFIX):
            return None
        try:
            wire = base64.b64decode(record[len(RECORD_PREFIX):])
        except Exception:
            return None
        if len(wire) != _WIRE_LEN:
            return None

        body = wire[:_BODY_LEN]
        signature = wire[_BODY_LEN:]
        try:
            manifest = cls.from_body_bytes(body)
        except ValueError:
            return None
        if not DMPCrypto.verify_signature(body, signature, manifest.sender_spk):
            return None
        return manifest, signature

    def is_expired(self, now: Optional[int] = None) -> bool:
        now = int(time.time()) if now is None else now
        return now > self.exp


@dataclass
class ReplayCache:
    """Reject re-publication of already-seen (sender_spk, msg_id) pairs.

    Split API:
      has_seen(spk, msg_id)  — read-only check; safe to call before fetch.
      record(spk, msg_id, exp) — commit the pair to the seen set.

    The caller is responsible for only calling `record()` once a message has
    been successfully decoded, so a transient DNS miss during chunk fetch
    doesn't permanently blacklist a valid manifest.

    Optionally persists to disk at `persist_path`. Each `record()` rewrites
    the file atomically (write to `<path>.tmp`, rename into place) so a
    crash mid-write leaves either the old or the new state, never a torn
    file. If `persist_path` is None the cache is purely in-memory and
    resets on process restart.

    Format: JSON array of `[sender_spk_hex, msg_id_hex, expiry_unix]`.
    Expired entries are dropped on load, on every query, and on every record.
    """

    default_ttl: int = 3600
    persist_path: Optional[str] = None
    _seen: Dict[Tuple[bytes, bytes], int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.persist_path:
            self._load()

    # ---- persistence -------------------------------------------------------

    def _load(self) -> None:
        if not self.persist_path:
            return
        try:
            with open(self.persist_path, "r") as f:
                raw = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return
        if not isinstance(raw, list):
            return
        now = int(time.time())
        loaded: Dict[Tuple[bytes, bytes], int] = {}
        for entry in raw:
            try:
                spk_hex, mid_hex, exp = entry
                exp = int(exp)
                if exp <= now:
                    continue
                loaded[(bytes.fromhex(spk_hex), bytes.fromhex(mid_hex))] = exp
            except (ValueError, TypeError):
                continue
        self._seen = loaded

    def _save(self) -> None:
        if not self.persist_path:
            return
        data = [
            [spk.hex(), mid.hex(), exp]
            for (spk, mid), exp in self._seen.items()
        ]
        tmp = self.persist_path + ".tmp"
        parent = os.path.dirname(self.persist_path) or "."
        os.makedirs(parent, exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.persist_path)

    # ---- public API --------------------------------------------------------

    def has_seen(self, sender_spk: bytes, msg_id: bytes) -> bool:
        self._purge()
        return (bytes(sender_spk), bytes(msg_id)) in self._seen

    def record(
        self,
        sender_spk: bytes,
        msg_id: bytes,
        expiry: Optional[int] = None,
    ) -> None:
        self._purge()
        key = (bytes(sender_spk), bytes(msg_id))
        self._seen[key] = (
            expiry if expiry is not None else int(time.time()) + self.default_ttl
        )
        self._save()

    def check_and_record(
        self,
        sender_spk: bytes,
        msg_id: bytes,
        expiry: Optional[int] = None,
    ) -> bool:
        """Atomically check-then-record.

        Returns True if the pair is fresh (and records it); False on replay.
        Kept for callers that genuinely want the old single-step semantics.
        New code should prefer `has_seen` + `record` around the work that
        proves the message was actually delivered.
        """
        if self.has_seen(sender_spk, msg_id):
            return False
        self.record(sender_spk, msg_id, expiry)
        return True

    def _purge(self) -> None:
        now = int(time.time())
        expired = [k for k, exp in self._seen.items() if now > exp]
        if not expired:
            return
        for k in expired:
            self._seen.pop(k, None)
        self._save()

    def size(self) -> int:
        self._purge()
        return len(self._seen)
