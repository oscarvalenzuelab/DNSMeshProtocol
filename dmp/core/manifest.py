"""Signed slot manifests and replay protection for DMP mailboxes.

A slot manifest is the TXT record a sender publishes at a mailbox slot to tell
the recipient "a message is waiting here." It names the message, how many
chunks to fetch, when it expires, and is signed by the sender's Ed25519
identity so it can't be forged or silently mutated.

Without this, anyone can publish to a mailbox slot and impersonate any sender.
With this, forged slots are detectable and the recipient-side replay cache can
reject re-publication of old valid manifests.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, Tuple

from dmp.core.crypto import DMPCrypto


RECORD_PREFIX = "v=dmp1;t=manifest"
DEFAULT_MANIFEST_TTL = 300  # seconds the manifest claims validity for


@dataclass
class SlotManifest:
    """Claim that a message is waiting at a mailbox slot.

    Wire form: "v=dmp1;t=manifest;d=<b64(json)>;s=<b64(ed25519_sig)>"

    The signature covers the canonical JSON bytes of the manifest fields
    (`msg_id`, `sender_spk`, `recipient_id`, `total_chunks`, `ts`, `exp`) so
    any mutation flips verification.
    """

    msg_id: bytes            # 16 bytes
    sender_spk: bytes        # 32-byte Ed25519 signing public key of the sender
    recipient_id: bytes      # 32-byte sha256 of recipient's X25519 pubkey
    total_chunks: int
    ts: int                  # unix seconds when the sender published
    exp: int                 # unix seconds after which recipient should drop

    def to_canonical_bytes(self) -> bytes:
        """Canonical JSON bytes used both for the wire payload and AAD-style signing."""
        return json.dumps(
            {
                "msg_id": self.msg_id.hex(),
                "sender_spk": self.sender_spk.hex(),
                "recipient_id": self.recipient_id.hex(),
                "total_chunks": self.total_chunks,
                "ts": self.ts,
                "exp": self.exp,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_canonical_bytes(cls, data: bytes) -> "SlotManifest":
        obj = json.loads(data.decode("utf-8"))
        return cls(
            msg_id=bytes.fromhex(obj["msg_id"]),
            sender_spk=bytes.fromhex(obj["sender_spk"]),
            recipient_id=bytes.fromhex(obj["recipient_id"]),
            total_chunks=int(obj["total_chunks"]),
            ts=int(obj["ts"]),
            exp=int(obj["exp"]),
        )

    def sign(self, sender_crypto: DMPCrypto) -> str:
        """Return the wire-format TXT record string, signed by `sender_crypto`."""
        payload = self.to_canonical_bytes()
        signature = sender_crypto.sign_data(payload)
        return (
            f"{RECORD_PREFIX};"
            f"d={base64.b64encode(payload).decode('ascii')};"
            f"s={base64.b64encode(signature).decode('ascii')}"
        )

    @classmethod
    def parse_and_verify(
        cls, record: str
    ) -> Optional[Tuple["SlotManifest", bytes]]:
        """Parse and verify a manifest TXT record.

        Returns (manifest, raw_signature) on success, or None if the record
        is malformed or the signature is invalid against the sender_spk field.
        Callers should still check `exp` and replay state.
        """
        if not record.startswith(RECORD_PREFIX):
            return None
        parts: Dict[str, str] = {}
        for piece in record.split(";"):
            if "=" in piece:
                key, _, value = piece.partition("=")
                parts[key.strip()] = value.strip()

        raw_b64 = parts.get("d")
        sig_b64 = parts.get("s")
        if not raw_b64 or not sig_b64:
            return None

        try:
            payload = base64.b64decode(raw_b64)
            signature = base64.b64decode(sig_b64)
        except Exception:
            return None

        try:
            manifest = cls.from_canonical_bytes(payload)
        except (ValueError, KeyError, json.JSONDecodeError):
            return None

        if not DMPCrypto.verify_signature(payload, signature, manifest.sender_spk):
            return None
        return manifest, signature

    def is_expired(self, now: Optional[int] = None) -> bool:
        now = int(time.time()) if now is None else now
        return now > self.exp


@dataclass
class ReplayCache:
    """Reject re-publication of already-seen (sender_spk, msg_id) pairs.

    In-memory only. Entries are purged when their stored expiry passes, so the
    cache stays bounded under normal traffic. Persisting across restarts is
    future work — an attacker who catches a process restart can replay.
    """

    default_ttl: int = 3600
    _seen: Dict[Tuple[bytes, bytes], int] = field(default_factory=dict)

    def check_and_record(
        self,
        sender_spk: bytes,
        msg_id: bytes,
        expiry: Optional[int] = None,
    ) -> bool:
        """Return True if this is a fresh (sender, msg_id); False if replay.

        Fresh pairs are recorded so subsequent calls with the same pair return
        False. `expiry` controls when the entry can be forgotten; defaults to
        now + default_ttl.
        """
        self._purge()
        key = (bytes(sender_spk), bytes(msg_id))
        if key in self._seen:
            return False
        self._seen[key] = expiry if expiry is not None else int(time.time()) + self.default_ttl
        return True

    def _purge(self) -> None:
        now = int(time.time())
        expired = [k for k, exp in self._seen.items() if now > exp]
        for k in expired:
            self._seen.pop(k, None)

    def size(self) -> int:
        self._purge()
        return len(self._seen)
