"""DMP client: encrypt, chunk, publish, poll, verify, decrypt."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from dmp.core import erasure
from dmp.core.chunking import MessageAssembler, MessageChunker
from dmp.core.crypto import DMPCrypto, EncryptedMessage, MessageEncryption
from dmp.core.dns import DMPDNSRecord
from dmp.core.manifest import ReplayCache, SlotManifest
from dmp.core.message import DMPHeader, DMPIdentity, DMPMessage, MessageType
from dmp.network.base import DNSRecordReader, DNSRecordStore, DNSRecordWriter
from dmp.network.memory import InMemoryDNSStore


SLOT_COUNT = 10
DEFAULT_TTL_SECONDS = 300


@dataclass
class Contact:
    """A pinned identity for send/receive.

    `public_key_bytes` is the 32-byte X25519 encryption pubkey; `signing_key_bytes`
    is the 32-byte Ed25519 signing pubkey. Pinning both lets the client (a)
    encrypt to the right recipient and (b) on receive, reject any manifest
    whose `sender_spk` doesn't match a contact the user has explicitly
    accepted. Older configs that predate the Ed25519 pin leave
    `signing_key_bytes` empty and fall back to TOFU on first delivery.
    """

    username: str
    public_key_bytes: bytes   # X25519 encryption pubkey (32 bytes)
    signing_key_bytes: bytes  # Ed25519 signing pubkey (32 bytes); may be b'' for legacy contacts
    domain: str


@dataclass
class InboxMessage:
    """One decrypted message returned by receive_messages."""

    sender_signing_pk: bytes  # 32-byte Ed25519 pubkey of the sender
    plaintext: bytes
    timestamp: int
    msg_id: bytes


class DMPClient:
    """Send and receive end-to-end encrypted messages over DNS TXT records.

    The client speaks to a DNSRecordWriter (to publish) and a DNSRecordReader
    (to poll). For local testing or single-process demos, pass a single
    DNSRecordStore via `store`; the client uses it for both sides. In
    production, pass a writer that talks to an authoritative DNS API and a
    reader that uses a recursive resolver.

    Addressing (all on a shared mesh `domain`):
      slot-{N}.mb-{recipient_hash12}.{domain}   -- signed manifest (10 slots)
      chunk-{NNNN}-{msg_key}.{domain}           -- chunks by per-message key

    msg_key = sha256(msg_id + recipient_id + sender_spk)[:12] so sender and
    recipient derive the same chunk path without the recipient needing to
    know the sender's X25519 public key in advance.
    """

    def __init__(
        self,
        username: str,
        passphrase: str,
        *,
        domain: str = "mesh.local",
        store: Optional[DNSRecordStore] = None,
        writer: Optional[DNSRecordWriter] = None,
        reader: Optional[DNSRecordReader] = None,
        replay_cache_path: Optional[str] = None,
        kdf_salt: Optional[bytes] = None,
    ):
        if store is not None:
            if writer is None:
                writer = store
            if reader is None:
                reader = store
        if writer is None or reader is None:
            # Default to an in-memory store for tests / demos
            default = InMemoryDNSStore()
            writer = writer or default
            reader = reader or default
        self.writer: DNSRecordWriter = writer
        self.reader: DNSRecordReader = reader

        self.username = username
        self.domain = domain
        self.crypto = DMPCrypto.from_passphrase(passphrase, salt=kdf_salt)
        self.user_id = hashlib.sha256(self.crypto.get_public_key_bytes()).digest()

        self.chunker = MessageChunker(enable_error_correction=True)
        self.assembler = MessageAssembler(enable_error_correction=True)
        self.encryption = MessageEncryption(self.crypto)
        self.replay_cache = ReplayCache(persist_path=replay_cache_path)

        self.contacts: Dict[str, Contact] = {}

        self.identity = DMPIdentity(
            username=username,
            public_key=self.crypto.get_public_key_bytes(),
            signature=self.crypto.sign_data(username.encode("utf-8")),
            metadata={
                "signing_pk": self.crypto.get_signing_public_key_bytes().hex(),
            },
        )

    # ---- addressing helpers ------------------------------------------------

    @staticmethod
    def _hash12(b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()[:12]

    def _slot_domain(self, recipient_id: bytes, slot: int) -> str:
        return f"slot-{slot}.mb-{self._hash12(recipient_id)}.{self.domain}"

    @staticmethod
    def _msg_key(msg_id: bytes, recipient_id: bytes, sender_spk: bytes) -> str:
        return hashlib.sha256(msg_id + recipient_id + sender_spk).hexdigest()[:12]

    def _chunk_domain(self, msg_key: str, chunk_num: int) -> str:
        return f"chunk-{chunk_num:04d}-{msg_key}.{self.domain}"

    # ---- contacts ----------------------------------------------------------

    def add_contact(
        self,
        username: str,
        public_key_hex: str,
        domain: Optional[str] = None,
        *,
        signing_key_hex: str = "",
    ) -> bool:
        """Pin a contact.

        `signing_key_hex` is optional for back-compat with configs that
        predate Ed25519 pinning. When empty, incoming manifests from any
        signer will be accepted on first delivery (TOFU); when present,
        only manifests whose `sender_spk` matches are delivered.
        """
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
        except ValueError:
            return False
        if len(public_key_bytes) != 32:
            return False

        if signing_key_hex:
            try:
                signing_key_bytes = bytes.fromhex(signing_key_hex)
            except ValueError:
                return False
            if len(signing_key_bytes) != 32:
                return False
        else:
            signing_key_bytes = b""

        self.contacts[username] = Contact(
            username=username,
            public_key_bytes=public_key_bytes,
            signing_key_bytes=signing_key_bytes,
            domain=domain or self.domain,
        )
        return True

    def _known_signing_keys(self) -> set[bytes]:
        """Signing keys we've pinned; used to filter incoming manifests."""
        return {c.signing_key_bytes for c in self.contacts.values() if c.signing_key_bytes}

    # ---- identity ----------------------------------------------------------

    def get_public_key_hex(self) -> str:
        return self.crypto.get_public_key_bytes().hex()

    def get_signing_public_key_hex(self) -> str:
        return self.crypto.get_signing_public_key_bytes().hex()

    def get_user_info(self) -> dict:
        return {
            "username": self.username,
            "domain": self.domain,
            "public_key": self.get_public_key_hex(),
            "signing_public_key": self.get_signing_public_key_hex(),
            "user_id": self.user_id.hex(),
        }

    # ---- send --------------------------------------------------------------

    def send_message(
        self,
        recipient_username: str,
        message: str,
        *,
        ttl: int = DEFAULT_TTL_SECONDS,
    ) -> bool:
        contact = self.contacts.get(recipient_username)
        if contact is None:
            return False

        recipient_id = hashlib.sha256(contact.public_key_bytes).digest()
        msg_id = uuid.uuid4().bytes
        now = int(time.time())

        header = DMPHeader(
            version=1,
            message_type=MessageType.DATA,
            message_id=msg_id,
            sender_id=self.user_id,
            recipient_id=recipient_id,
            total_chunks=1,  # placeholder; chunker updates this
            chunk_number=0,
            timestamp=now,
            ttl=ttl,
        )

        try:
            recipient_pubkey = X25519PublicKey.from_public_bytes(
                contact.public_key_bytes
            )
        except Exception:
            return False

        # Encrypt once, with AAD bound to a canonical header subset that excludes
        # total_chunks (unknown until after chunking). Everything else that
        # matters — sender_id, recipient_id, msg_id, timestamp, ttl — is bound.
        aad_header = DMPHeader(
            version=header.version,
            message_type=header.message_type,
            message_id=header.message_id,
            sender_id=header.sender_id,
            recipient_id=header.recipient_id,
            total_chunks=0,  # sentinel so AAD is stable regardless of chunk count
            chunk_number=0,
            timestamp=header.timestamp,
            ttl=header.ttl,
        )
        aad_bytes = aad_header.to_bytes()
        encrypted = self.encryption.encrypt_with_header(
            message.encode("utf-8"),
            recipient_pubkey,
            aad_bytes,
        )

        outer = DMPMessage(header=header, payload=encrypted.to_bytes())
        outer_bytes = outer.to_bytes()

        # Cross-chunk erasure coding: split into k data blocks + parity.
        # Any k of n received chunks reconstructs. erasure.encode also
        # length-prefixes and pads to a whole number of DATA_PER_CHUNK
        # blocks so the receiver can strip padding unambiguously.
        shares, k, n = erasure.encode(outer_bytes)
        total_chunks = n
        data_chunks = k

        sender_spk = self.crypto.get_signing_public_key_bytes()
        msg_key = self._msg_key(msg_id, recipient_id, sender_spk)

        # Each share gets wrapped with the existing per-chunk RS + checksum
        # so bit errors inside a received chunk are repaired BEFORE the
        # erasure layer runs. Drop the metadata dict from the wire record
        # — chunk_num and msg_key are already in the domain name and
        # encoding them again would push us over the 255-byte TXT limit.
        for chunk_num, share in enumerate(shares):
            wire_chunk = self.chunker.wrap_block(share)
            record = DMPDNSRecord(
                version=1,
                record_type="chunk",
                data=wire_chunk,
                metadata={},
            )
            ok = self.writer.publish_txt_record(
                self._chunk_domain(msg_key, chunk_num),
                record.to_txt_record(),
                ttl=ttl,
            )
            if not ok:
                return False

        manifest = SlotManifest(
            msg_id=msg_id,
            sender_spk=sender_spk,
            recipient_id=recipient_id,
            total_chunks=total_chunks,
            data_chunks=data_chunks,
            ts=now,
            exp=now + ttl,
        )
        slot_record = manifest.sign(self.crypto)
        # Append semantics in the store make slot choice effectively cosmetic:
        # we can't overwrite someone else's manifest even if we land in the
        # same slot. Spread load across slots deterministically based on the
        # msg_id so recipients see a roughly-even RRset distribution instead
        # of a single crowded slot.
        slot = int.from_bytes(msg_id[:4], "big") % SLOT_COUNT
        return self.writer.publish_txt_record(
            self._slot_domain(recipient_id, slot),
            slot_record,
            ttl=ttl,
        )

    # ---- receive -----------------------------------------------------------

    def receive_messages(self) -> List[InboxMessage]:
        """Poll all mailbox slots; verify and decrypt any fresh messages.

        Returns the list of newly-delivered messages. Replay-cache rejections,
        signature failures, and manifests from un-pinned senders are silently
        skipped. If the client has no pinned Ed25519 contacts at all, receive
        falls back to TOFU and delivers any signature-valid manifest — useful
        for fresh onboarding, but users should pin contacts before treating
        delivered messages as authenticated.
        """
        results: List[InboxMessage] = []
        known_spks = self._known_signing_keys()
        for slot in range(SLOT_COUNT):
            slot_domain = self._slot_domain(self.user_id, slot)
            records = self.reader.query_txt_record(slot_domain)
            if not records:
                continue
            for record in records:
                parsed = SlotManifest.parse_and_verify(record)
                if parsed is None:
                    continue
                manifest, _ = parsed
                if manifest.recipient_id != self.user_id:
                    continue
                if manifest.is_expired():
                    continue
                # If the user has pinned any signing keys, only accept
                # manifests from those senders. Unknown signers are dropped.
                if known_spks and manifest.sender_spk not in known_spks:
                    continue
                # Check-only here; we record in the replay cache *after* we
                # actually decode the message. Otherwise a transient DNS miss
                # during chunk fetch would permanently suppress a still-valid
                # manifest on later polls.
                if self.replay_cache.has_seen(
                    manifest.sender_spk, manifest.msg_id
                ):
                    continue
                decoded = self._fetch_and_decrypt(manifest)
                if decoded is None:
                    continue
                plaintext, ts, msg_id = decoded
                self.replay_cache.record(
                    manifest.sender_spk, manifest.msg_id, manifest.exp
                )
                results.append(InboxMessage(
                    sender_signing_pk=manifest.sender_spk,
                    plaintext=plaintext,
                    timestamp=ts,
                    msg_id=msg_id,
                ))
        return results

    def _fetch_and_decrypt(
        self,
        manifest: SlotManifest,
    ) -> Optional[Tuple[bytes, int, bytes]]:
        """Return (plaintext, timestamp, msg_id) or None if assembly/decrypt fails."""
        msg_key = self._msg_key(
            manifest.msg_id, manifest.recipient_id, manifest.sender_spk
        )

        # Walk every chunk position up to total_chunks, collecting valid
        # shares into a dict keyed by share_id. Stop early once we have k
        # shares — erasure.decode only needs k of n.
        shares: Dict[int, bytes] = {}
        for chunk_num in range(manifest.total_chunks):
            if len(shares) >= manifest.data_chunks:
                break
            records = self.reader.query_txt_record(
                self._chunk_domain(msg_key, chunk_num)
            )
            if not records:
                continue
            dmp_record: Optional[DMPDNSRecord] = None
            for txt in records:
                if txt.startswith("v=dmp"):
                    try:
                        dmp_record = DMPDNSRecord.from_txt_record(txt)
                        break
                    except Exception:
                        continue
            if dmp_record is None or dmp_record.record_type != "chunk":
                continue
            block = self.chunker.unwrap_block(dmp_record.data)
            if block is None:
                continue
            shares[chunk_num] = block

        if len(shares) < manifest.data_chunks:
            return None

        assembled = erasure.decode(
            shares, manifest.data_chunks, manifest.total_chunks
        )
        if assembled is None:
            return None

        try:
            outer = DMPMessage.from_bytes(assembled)
        except ValueError:
            return None

        try:
            encrypted = EncryptedMessage.from_bytes(outer.payload)
        except ValueError:
            return None

        # Cross-check the inner header against the signed manifest. The AEAD
        # proves the ciphertext+header came from someone holding the
        # recipient's pubkey, and the manifest signature proves a specific
        # sender put a claim at the slot — but without this check a
        # legitimate sender could put a different msg_id / recipient_id
        # inside the ciphertext than in the manifest and the client would
        # happily surface the lie.
        if outer.header.message_id != manifest.msg_id:
            return None
        if outer.header.recipient_id != manifest.recipient_id:
            return None
        # Freshness: drop messages whose inner header's ts+ttl has passed.
        if outer.header.is_expired():
            return None

        # Rebuild the same AAD the sender bound at encrypt time.
        aad_header = DMPHeader(
            version=outer.header.version,
            message_type=outer.header.message_type,
            message_id=outer.header.message_id,
            sender_id=outer.header.sender_id,
            recipient_id=outer.header.recipient_id,
            total_chunks=0,
            chunk_number=0,
            timestamp=outer.header.timestamp,
            ttl=outer.header.ttl,
        )
        try:
            plaintext = self.encryption.decrypt_with_header(
                encrypted, aad_header.to_bytes()
            )
        except Exception:
            return None
        return plaintext, outer.header.timestamp, outer.header.message_id
