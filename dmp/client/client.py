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
from dmp.core.manifest import NO_PREKEY, ReplayCache, SlotManifest
from dmp.core.message import DMPHeader, DMPIdentity, DMPMessage, MessageType
from dmp.core.prekeys import Prekey, PrekeyStore, prekey_rrset_name
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
    public_key_bytes: bytes  # X25519 encryption pubkey (32 bytes)
    signing_key_bytes: (
        bytes  # Ed25519 signing pubkey (32 bytes); may be b'' for legacy contacts
    )
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
        prekey_store_path: Optional[str] = None,
        rotation_chain_enabled: bool = False,
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

        # Prekey store: holds one-time X25519 prekey *private* halves so the
        # receive path can look them up by prekey_id and consume after decrypt.
        # If no path is provided we get an ephemeral in-memory store via
        # sqlite's :memory: — useful for tests but it drops on process exit,
        # so a CLI deployment should always pass a path.
        self.prekey_store = PrekeyStore(prekey_store_path or ":memory:")

        self.contacts: Dict[str, Contact] = {}

        # EXPERIMENTAL (M5.4): rotation-chain walking on verify failure.
        # Default False preserves byte-identical legacy behavior. Wire
        # format is subject to post-audit revision in v0.3.0.
        self.rotation_chain_enabled = rotation_chain_enabled
        self._rotation_chain = None
        if rotation_chain_enabled:
            # Import lazily so the default (off) path never imports the
            # experimental module.
            from dmp.client.rotation_chain import RotationChain

            self._rotation_chain = RotationChain(self.reader)

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
        return {
            c.signing_key_bytes for c in self.contacts.values() if c.signing_key_bytes
        }

    def _rotation_manifest_revoked(self, sender_spk: bytes) -> bool:
        """EXPERIMENTAL (M5.4): return True iff ``sender_spk`` matches a
        pinned contact whose current rotate RRset publishes a
        verifying revocation for that spk.

        Called on the receive path AFTER the `known_spks` pin-list
        accepts a manifest, to catch the case where a pinned key has
        been explicitly revoked by its sender. Only compromise and
        lost_key rotations publish a RevocationRecord; routine rotations
        do not (the chain walker follows them forward instead — see
        ``cmd_identity_rotate``). Without this check, a holder of the
        revoked key can keep delivering messages to every pinned contact
        indefinitely.

        Only fires when ``rotation_chain_enabled=True``; legacy
        clients return False and skip the check entirely.
        """
        if not self.rotation_chain_enabled or self._rotation_chain is None:
            return False
        from dmp.core.rotation import SUBJECT_TYPE_USER_IDENTITY

        for contact in self.contacts.values():
            if not contact.signing_key_bytes or contact.signing_key_bytes != sender_spk:
                continue
            subject = f"{contact.username}@{contact.domain}"
            try:
                if self._rotation_chain.is_spk_revoked(
                    sender_spk, subject, SUBJECT_TYPE_USER_IDENTITY
                ):
                    return True
            except Exception:
                # Defense-in-depth: a revocation check that somehow
                # raises must not crash the receive path.
                continue
        return False

    def _rotation_manifest_accepted(self, sender_spk: bytes) -> bool:
        """EXPERIMENTAL (M5.4): check a rotation chain for sender_spk.

        Walks each pinned contact's rotation chain; if any chain's
        current head is ``sender_spk``, accept the manifest. A rotation
        chain is ONLY consulted when ``rotation_chain_enabled=True``;
        otherwise this returns False and legacy behavior is preserved.

        Wire format subject to post-audit revision in v0.3.0 — see
        ``docs/protocol/rotation.md``.
        """
        if not self.rotation_chain_enabled or self._rotation_chain is None:
            return False
        # Import lazily to avoid the cold-path import on every receive.
        from dmp.core.rotation import SUBJECT_TYPE_USER_IDENTITY

        for contact in self.contacts.values():
            if not contact.signing_key_bytes:
                continue
            subject = f"{contact.username}@{contact.domain}"
            try:
                current = self._rotation_chain.resolve_current_spk(
                    contact.signing_key_bytes,
                    subject,
                    SUBJECT_TYPE_USER_IDENTITY,
                )
            except Exception:
                # Defense-in-depth: a chain walker that somehow raises
                # must not crash the receive path.
                continue
            if current is not None and current == sender_spk:
                return True
        return False

    def _pick_recipient_prekey(self, contact: "Contact") -> Tuple[int, Optional[bytes]]:
        """Fetch a fresh prekey from DNS and return (prekey_id, x25519_pub).

        Returns (0, None) when:
          - contact has no pinned Ed25519 key (can't verify prekey signatures)
          - no valid, unexpired prekey records are published
          - the pool DNS fetch fails for any other reason

        In those cases the caller falls back to the recipient's long-term
        X25519 key (no forward secrecy for this message). A pinned contact
        with a live prekey pool gets real FS: the recipient consumes the
        prekey_sk after decrypt, so a later leak of their long-term X25519
        key does not recover that message's session key.
        """
        if not contact.signing_key_bytes:
            return (0, None)
        name = prekey_rrset_name(contact.username, contact.domain)
        try:
            records = self.reader.query_txt_record(name)
        except Exception:
            return (0, None)
        if not records:
            return (0, None)
        verified: List[Prekey] = []
        for txt in records:
            pk = Prekey.parse_and_verify(txt, contact.signing_key_bytes)
            if pk is None:
                continue
            if pk.is_expired():
                continue
            verified.append(pk)
        if not verified:
            return (0, None)
        chosen = random.choice(verified)
        return (chosen.prekey_id, chosen.public_key)

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

    # ---- prekeys -----------------------------------------------------------

    def refresh_prekeys(self, count: int = 50, ttl_seconds: int = 86_400) -> int:
        """Generate `count` new one-time prekeys, sign them, publish as an RRset.

        Call this periodically so senders always find a live pool. Previous
        prekey *records* in DNS stay until they expire; previous prekey
        *private keys* in the local store stay until cleanup_expired runs.
        Returns the number successfully published.

        Records the exact wire bytes of each published prekey in the local
        PrekeyStore so `consume_prekey` can DELETE the matching published
        record from DNS — otherwise the consumed (now undecryptable)
        prekey_pub would keep attracting senders until its TTL expired.
        """
        pool = self.prekey_store.generate_pool(count=count, ttl_seconds=ttl_seconds)
        name = prekey_rrset_name(self.username, self.domain)
        published = 0
        for prekey, _sk in pool:
            wire = prekey.sign(self.crypto)
            if self.writer.publish_txt_record(name, wire, ttl=ttl_seconds):
                self.prekey_store.record_wire(prekey.prekey_id, wire)
                published += 1
        return published

    def _consume_prekey(self, prekey_id: int) -> None:
        """Delete a prekey both locally and in DNS.

        The local sqlite row carries the sk (FS secret) and the wire-record
        string we published. We DELETE the wire record from the node so
        later senders won't pick a prekey whose sk is already gone, then
        drop the sqlite row. Best-effort on the DNS side — if the DELETE
        fails we log nothing and still wipe the local sk; the published
        prekey will just rot until its TTL elapses (old behavior).
        """
        wire = self.prekey_store.get_wire(prekey_id)
        if wire:
            try:
                self.writer.delete_txt_record(
                    prekey_rrset_name(self.username, self.domain),
                    value=wire,
                )
            except Exception:
                pass
        self.prekey_store.consume(prekey_id)

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

        # Pick a recipient prekey for forward-secrecy if one is available;
        # fall back to the long-term X25519 key if none is reachable. The
        # recipient signs prekeys with their Ed25519 identity, so we need
        # the pinned signing key to verify — unpinned contacts get
        # long-term ECDH only (no FS).
        prekey_id, prekey_pub = self._pick_recipient_prekey(contact)
        if prekey_pub is not None:
            try:
                recipient_pubkey = X25519PublicKey.from_public_bytes(prekey_pub)
            except Exception:
                return False
        else:
            try:
                recipient_pubkey = X25519PublicKey.from_public_bytes(
                    contact.public_key_bytes
                )
            except Exception:
                return False

        # Encrypt once, with AAD bound to a canonical header subset that excludes
        # total_chunks (unknown until after chunking). Everything else that
        # matters — sender_id, recipient_id, msg_id, timestamp, ttl, and the
        # chosen prekey_id — is bound. Including prekey_id here is
        # defense-in-depth: the ECDH key mismatch already breaks decryption
        # if the sender lies about which prekey they used, but binding it
        # into AAD makes the mismatch surface cleanly as an AEAD tag
        # failure rather than as an opaque "shared secret disagreed".
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
        aad_bytes = aad_header.to_bytes() + prekey_id.to_bytes(4, "big")
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
            prekey_id=prekey_id,
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
                    # EXPERIMENTAL (M5.4): if rotation-chain walking is
                    # enabled, try walking each pinned contact's chain
                    # forward to see if the manifest's sender_spk is the
                    # current head of a rotation. A valid walk means the
                    # contact rotated their identity key; we extend the
                    # accepted set for this receive pass. If the walk
                    # fails or aborts (revocation, ambiguity, max_hops),
                    # the manifest stays dropped. Never modifies
                    # self.contacts — a rotation-chain walk is a
                    # per-receive trust decision, not a permanent re-pin.
                    if not self._rotation_manifest_accepted(manifest.sender_spk):
                        continue
                # EXPERIMENTAL (M5.4): cross-check that a PINNED
                # signing key hasn't itself been revoked. Without this,
                # a sender who published (rotation A→B) + (revocation of
                # A) would still have manifests signed by A accepted by
                # every contact that pinned A — defeating the whole
                # point of revocation. Only fires when rotation chain
                # walking is enabled; legacy clients keep their byte-
                # identical behavior.
                elif self._rotation_manifest_revoked(manifest.sender_spk):
                    continue
                # Check-only here; we record in the replay cache *after* we
                # actually decode the message. Otherwise a transient DNS miss
                # during chunk fetch would permanently suppress a still-valid
                # manifest on later polls.
                if self.replay_cache.has_seen(manifest.sender_spk, manifest.msg_id):
                    continue
                decoded = self._fetch_and_decrypt(manifest)
                if decoded is None:
                    continue
                plaintext, ts, msg_id = decoded
                self.replay_cache.record(
                    manifest.sender_spk, manifest.msg_id, manifest.exp
                )
                results.append(
                    InboxMessage(
                        sender_signing_pk=manifest.sender_spk,
                        plaintext=plaintext,
                        timestamp=ts,
                        msg_id=msg_id,
                    )
                )
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

        assembled = erasure.decode(shares, manifest.data_chunks, manifest.total_chunks)
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

        # Rebuild the same AAD the sender bound at encrypt time. Includes
        # manifest.prekey_id so a sender who encrypts with one prekey but
        # claims another in the manifest fails AEAD verification.
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
        aad_bytes = aad_header.to_bytes() + manifest.prekey_id.to_bytes(4, "big")
        # Prekey-based ECDH path for forward secrecy. When manifest.prekey_id
        # is nonzero, look up the matching one-time X25519 private key in the
        # local store and use it for decrypt instead of our long-term key.
        # On successful decrypt we consume the prekey_sk so a later long-term
        # key leak cannot recover this message's session.
        prekey_private = None
        if manifest.prekey_id != NO_PREKEY:
            prekey_private = self.prekey_store.get_private_key(manifest.prekey_id)
            if prekey_private is None:
                # Prekey was deleted or expired — we can't decrypt this
                # message. That's a delivery failure, not a security failure.
                return None
        try:
            plaintext = self.encryption.decrypt_with_header(
                encrypted, aad_bytes, private_key=prekey_private
            )
        except Exception:
            return None
        if manifest.prekey_id != NO_PREKEY:
            # One-time use: delete the sk locally AND the matching public
            # record from DNS so future senders don't pick a prekey whose
            # sk is gone. Best effort — a crash between decrypt and consume
            # leaves the sk on disk; a DELETE failure leaves the prekey_pub
            # rotting until its TTL.
            self._consume_prekey(manifest.prekey_id)
        return plaintext, outer.header.timestamp, outer.header.message_id
