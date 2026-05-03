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
       total_chunks(4) || data_chunks(4) || prekey_id(4) ||
       ts(8) || exp(8)                                              =  108 bytes
sig  = Ed25519 signature over `body`                                =   64 bytes
total                                                               =  172 bytes
base64                                                              =  232 chars
prefix `v=dmp1;t=manifest;d=`                                       =   20 chars
wire total                                                          =  252 chars  (fits)

`data_chunks` is the erasure threshold k: the recipient needs any k of the
total_chunks to reconstruct the message. When the sender disables erasure
(single-chunk legacy flow), data_chunks == total_chunks.

`prekey_id` tells the recipient which one-time X25519 prekey to use for
ECDH-based decryption. 0 (`NO_PREKEY`) means the sender fell back to the
recipient's long-term X25519 key — forward secrecy is NOT in effect for
that message, and the recipient should flag or surface that fact to the
user (current client: drops the "pinned signer required" check for
unpinned TOFU, but the long-term-key path is noted in the dataclass).
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

from dmp.core.crypto import DMPCrypto

RECORD_PREFIX = "v=dmp1;t=manifest;d="
_BODY_LEN = 16 + 32 + 32 + 4 + 4 + 4 + 8 + 8  # 108 bytes (adds prekey_id)
_SIG_LEN = 64
_WIRE_LEN = _BODY_LEN + _SIG_LEN  # 172 bytes
DEFAULT_MANIFEST_TTL = 300

# Upper bound on how far in the future a manifest's signed `exp`
# can be. Real messages live for minutes to hours; a 30-day ceiling
# leaves headroom for slow-delivery scenarios while bounding the
# replay-cache and intro-queue bloat a sender could otherwise
# induce by publishing year-3000-expiry records that every recipient
# must remember.
MAX_EXP_FUTURE_SECONDS = 30 * 86400

# Sentinel for "sender did not use a prekey; ECDH used recipient's
# long-term X25519 key — no forward secrecy for this message."
NO_PREKEY = 0

# Protocol-level cap on chunk count in a signed manifest. Without a cap,
# a signature-valid manifest can ask the receiver to fetch ~2^32 chunks
# and the DNS-query loop pins the process. 1024 chunks at DATA_PER_CHUNK
# bytes each = ~128 KiB of plaintext, which is well past anything the
# rest of the stack is sized for. Operators who need bigger messages
# should raise this knob uniformly across sender + receiver.
MAX_TOTAL_CHUNKS = 1024


@dataclass
class SlotManifest:
    """Claim that a message is waiting at a mailbox slot.

    The Ed25519 signature covers `to_body_bytes()` so any mutation of any
    field breaks verification.
    """

    msg_id: bytes  # 16 bytes
    sender_spk: bytes  # 32-byte Ed25519 signing public key of the sender
    recipient_id: bytes  # 32-byte sha256 of recipient's X25519 pubkey
    total_chunks: int  # n — chunks actually published
    data_chunks: int  # k — chunks needed to reconstruct (erasure threshold)
    prekey_id: int  # recipient prekey used for ECDH; 0 = long-term key
    ts: int  # unix seconds when the sender published
    exp: int  # unix seconds after which recipient should drop

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
        if self.total_chunks > MAX_TOTAL_CHUNKS:
            raise ValueError(
                f"total_chunks {self.total_chunks} exceeds protocol max "
                f"{MAX_TOTAL_CHUNKS}"
            )
        if not (0 <= self.prekey_id < (1 << 32)):
            raise ValueError("prekey_id out of range")
        return (
            self.msg_id
            + self.sender_spk
            + self.recipient_id
            + self.total_chunks.to_bytes(4, "big")
            + self.data_chunks.to_bytes(4, "big")
            + self.prekey_id.to_bytes(4, "big")
            + self.ts.to_bytes(8, "big")
            + self.exp.to_bytes(8, "big")
        )

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "SlotManifest":
        if len(body) != _BODY_LEN:
            raise ValueError(
                f"manifest body must be {_BODY_LEN} bytes, got {len(body)}"
            )
        total_chunks = int.from_bytes(body[80:84], "big")
        data_chunks = int.from_bytes(body[84:88], "big")
        prekey_id = int.from_bytes(body[88:92], "big")
        if data_chunks <= 0 or data_chunks > total_chunks:
            raise ValueError("data_chunks out of range")
        if total_chunks > MAX_TOTAL_CHUNKS:
            raise ValueError(
                f"total_chunks {total_chunks} exceeds protocol max "
                f"{MAX_TOTAL_CHUNKS}"
            )
        return cls(
            msg_id=body[0:16],
            sender_spk=body[16:48],
            recipient_id=body[48:80],
            total_chunks=total_chunks,
            data_chunks=data_chunks,
            prekey_id=prekey_id,
            ts=int.from_bytes(body[92:100], "big"),
            exp=int.from_bytes(body[100:108], "big"),
        )

    def sign(self, sender_crypto: DMPCrypto) -> str:
        """Return the wire-format TXT record string, signed by `sender_crypto`."""
        body = self.to_body_bytes()
        signature = sender_crypto.sign_data(body)
        wire = body + signature
        return f"{RECORD_PREFIX}{base64.b64encode(wire).decode('ascii')}"

    @classmethod
    def parse_and_verify(cls, record: str) -> Optional[Tuple["SlotManifest", bytes]]:
        """Parse and verify a manifest TXT record.

        Returns (manifest, raw_signature) on success, or None if the record is
        malformed, truncated, or the signature fails verification against the
        sender_spk embedded in the body. Callers should still check `exp` and
        replay state.
        """
        if not record.startswith(RECORD_PREFIX):
            return None
        try:
            wire = base64.b64decode(record[len(RECORD_PREFIX) :])
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
        # Refuse manifests whose expiry is too far in the future. A
        # legitimate sender publishes messages with TTLs of minutes to
        # hours; an `exp` that lands in year 3000 is either a clock
        # bug or a deliberate attempt to make every receiver remember
        # this message in their replay cache forever.
        if manifest.exp - int(time.time()) > MAX_EXP_FUTURE_SECONDS:
            return None
        return manifest, signature

    def is_expired(self, now: Optional[int] = None) -> bool:
        now = int(time.time()) if now is None else now
        return now > self.exp


@dataclass
class ReplayCache:
    """Reject re-publication of already-seen (sender_spk, msg_id) pairs.

    Atomic claim/finalize/release API for the receive path:
      claim_for_decode(spk, msg_id, exp) — returns True if the caller now
        owns the (spk, msg_id) slot; False if it is already in `seen` or
        another worker holds an in-flight claim within the TTL. On True the
        caller MUST follow up with either:
          finalize(spk, msg_id, exp) — promote the slot to `seen` after a
            successful decrypt+deliver.
          release(spk, msg_id) — free the slot after a transient decrypt
            failure (DNS miss, malformed ciphertext, etc.) so a later poll
            can retry.

    Why a separate in-flight set instead of just check-and-record on entry:
    a transient chunk-fetch miss must not permanently blacklist a still-valid
    manifest. The split lets the caller hold the slot only for the duration
    of the actual decrypt attempt.

    Why this matters: the previous split-API
      `if has_seen(): skip; decrypt(); record()` is non-atomic. Two
    concurrent workers (threads, async loops, or repeated calls to
    receive_messages) can both pass the has_seen gate, both decrypt the
    same message, and both deliver the same plaintext to the inbox.

    Legacy single-step `check_and_record(...)` is kept for callers that
    don't have a separate decrypt phase; they get the atomic seen-set
    update without using the in-flight set.

    Concurrency: a single `threading.RLock` covers seen, in_flight, and the
    persistence file write. Within-process workers are serialized; cross-
    process safety relies on the atomic `os.replace` (last writer wins).

    Crashed-worker recovery: in-flight claims older than
    `in_flight_ttl_seconds` are reclaimed on the next `claim_for_decode`,
    so a worker that crashed between claim and finalize/release does not
    permanently block the slot.

    Persistence: optional, at `persist_path`. Only `seen` is persisted —
    in-flight claims are intentionally in-memory only (process restart
    clears them). Each finalize/record rewrites the file atomically
    (`<path>.tmp` → rename). Format: JSON array of
    `[sender_spk_hex, msg_id_hex, expiry_unix]`. Expired entries are
    dropped on load, on every query, and on every write.
    """

    default_ttl: int = 3600
    persist_path: Optional[str] = None
    in_flight_ttl_seconds: int = 300
    _seen: Dict[Tuple[bytes, bytes], int] = field(default_factory=dict)
    _in_flight: Dict[Tuple[bytes, bytes], int] = field(
        default_factory=dict, init=False, repr=False
    )
    _lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

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
        # Caller holds _lock. Only `seen` persists; in-flight is in-memory.
        if not self.persist_path:
            return
        data = [[spk.hex(), mid.hex(), exp] for (spk, mid), exp in self._seen.items()]
        tmp = self.persist_path + ".tmp"
        parent = os.path.dirname(self.persist_path) or "."
        os.makedirs(parent, exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.persist_path)

    # ---- public API --------------------------------------------------------

    def has_seen(self, sender_spk: bytes, msg_id: bytes) -> bool:
        with self._lock:
            self._purge()
            return (bytes(sender_spk), bytes(msg_id)) in self._seen

    def record(
        self,
        sender_spk: bytes,
        msg_id: bytes,
        expiry: Optional[int] = None,
    ) -> None:
        with self._lock:
            self._purge()
            key = (bytes(sender_spk), bytes(msg_id))
            self._seen[key] = (
                expiry if expiry is not None else int(time.time()) + self.default_ttl
            )
            self._in_flight.pop(key, None)
            self._save()

    def check_and_record(
        self,
        sender_spk: bytes,
        msg_id: bytes,
        expiry: Optional[int] = None,
    ) -> bool:
        """Atomically check-then-record without using the in-flight set.

        Returns True if the pair is fresh (and records it); False on replay.
        For receive paths that have a distinct decrypt phase, prefer
        `claim_for_decode` + `finalize` / `release` so a transient decrypt
        failure does not permanently consume the slot.
        """
        with self._lock:
            if self.has_seen(sender_spk, msg_id):
                return False
            self.record(sender_spk, msg_id, expiry)
            return True

    def claim_for_decode(
        self,
        sender_spk: bytes,
        msg_id: bytes,
        expiry: Optional[int] = None,
    ) -> bool:
        """Atomically reserve a slot for a decrypt attempt.

        Returns True iff this caller now owns the (sender_spk, msg_id)
        slot — neither in the seen set nor held by another worker's still-
        fresh in-flight claim. Caller MUST follow with `finalize(...)` on
        successful decrypt or `release(...)` on failure.

        Stale in-flight claims older than `in_flight_ttl_seconds` are
        reclaimed here so a crashed worker does not permanently block the
        slot.
        """
        with self._lock:
            self._purge()
            self._purge_stale_in_flight()
            key = (bytes(sender_spk), bytes(msg_id))
            if key in self._seen or key in self._in_flight:
                return False
            self._in_flight[key] = int(time.time())
            return True

    def finalize(
        self,
        sender_spk: bytes,
        msg_id: bytes,
        expiry: Optional[int] = None,
    ) -> None:
        """Promote an in-flight claim to seen. Pairs with claim_for_decode."""
        self.record(sender_spk, msg_id, expiry)

    def release(self, sender_spk: bytes, msg_id: bytes) -> None:
        """Release an in-flight claim without recording it as seen.

        Used when decrypt fails so a later poll can retry the same slot.
        Idempotent: releasing an already-released or never-claimed slot
        is a no-op.
        """
        with self._lock:
            key = (bytes(sender_spk), bytes(msg_id))
            self._in_flight.pop(key, None)

    def _purge_stale_in_flight(self) -> None:
        # Caller holds _lock.
        cutoff = int(time.time()) - self.in_flight_ttl_seconds
        stale = [k for k, claimed_at in self._in_flight.items() if claimed_at < cutoff]
        for k in stale:
            self._in_flight.pop(k, None)

    def _purge(self) -> None:
        # Caller holds _lock.
        now = int(time.time())
        expired = [k for k, exp in self._seen.items() if now > exp]
        if not expired:
            return
        for k in expired:
            self._seen.pop(k, None)
        self._save()

    def size(self) -> int:
        with self._lock:
            self._purge()
            return len(self._seen)
