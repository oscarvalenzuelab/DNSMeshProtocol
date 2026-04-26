"""DMP client: encrypt, chunk, publish, poll, verify, decrypt."""

from __future__ import annotations

import hashlib
import random
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

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

# M9.2.6 — claim-publish DNS UPDATE helpers.
#
# Default DNS port for cross-zone UPDATE writes. Real deployments run
# the DMP DNS server on 53. Dev environments override via the
# ``DMP_PROVIDER_DNS_PORT`` env to match a custom port (the e2e harness
# uses 5353).
import os as _os
from urllib.parse import urlsplit as _urlsplit


def _provider_dns_target(
    provider_endpoint: str, provider_zone: str
) -> Optional[Tuple[str, int]]:
    """Resolve the (host, port) we should send a claim UPDATE to.

    Order (codex round-15 P1):
      1. ``provider_endpoint`` URL host. The endpoint is the operator's
         own advertisement of WHERE their server lives, while
         ``provider_zone`` is just the zone the records are HOSTED
         under. In split-host deployments (``api.example.com``
         serving the ``example.com`` zone), the zone apex doesn't
         run the DNS server. Without proper NS/target discovery for
         the zone, we route to the advertised host.
      2. ``provider_zone`` as a fallback when no endpoint is given —
         covers single-host deployments where zone apex == host.

    Port is ``DMP_PROVIDER_DNS_PORT`` when set (dev override), else 53.
    """
    raw_port = _os.environ.get("DMP_PROVIDER_DNS_PORT", "").strip()
    try:
        port = int(raw_port) if raw_port else 53
    except ValueError:
        port = 53

    endpoint_host = ""
    if provider_endpoint:
        try:
            parts = _urlsplit(
                provider_endpoint
                if "://" in provider_endpoint
                else "https://" + provider_endpoint
            )
            endpoint_host = (parts.hostname or "").strip().lower()
        except ValueError:
            endpoint_host = ""

    if endpoint_host:
        return (endpoint_host, port)
    zone_host = (provider_zone or "").strip().lower().rstrip(".")
    if zone_host:
        return (zone_host, port)
    return None


def _publish_claim_via_dns_update(
    *,
    zone: str,
    target: Tuple[str, int],
    name: str,
    wire: str,
    ttl: int,
    resolver_pool=None,
) -> bool:
    """Build + send an un-TSIG'd DNS UPDATE for one claim record.

    The provider's DNS server accepts un-TSIG'd UPDATE iff EVERY op is
    a claim-record ADD whose wire verifies as a signed ClaimRecord
    (see ``dmp.server.dns_server._is_signed_claim_wire``). The Ed25519
    signature in the wire IS the on-zone authentication; TSIG on top
    would gate only the network path, which the senders generally
    can't be authenticated on.

    ``resolver_pool`` is the caller's configured :class:`ResolverPool`
    (typically the CLI's ``DMP_HEARTBEAT_DNS_RESOLVERS``). When given,
    UDP-destination resolution goes through it; otherwise we fall back
    to the host's system resolver. Routing both reads AND writes
    through the same pinned recursors avoids the NXDOMAIN-cache stall
    that breaks a federation-wide zone migration.
    """
    try:
        import dns.exception
        import dns.flags
        import dns.message  # noqa: F401  (forces submodule registration)
        import dns.name
        import dns.query
        import dns.rcode
        import dns.update
    except Exception:
        return False
    host, port = target
    # dnspython's UDP/TCP destination must be an IP literal. The
    # provider host comes from a heartbeat-advertised endpoint URL or
    # a CLI override — both routinely hostnames. Resolve here so the
    # caller doesn't have to pre-resolve.
    from dmp.network.dns_update_writer import _resolve_to_ip

    host = _resolve_to_ip(host, resolver_pool=resolver_pool)
    if host is None:
        return False
    upd = dns.update.UpdateMessage(zone)
    try:
        upd.add(
            dns.name.from_text(name.rstrip(".") + "."),
            int(ttl),
            "TXT",
            '"' + wire.replace("\\", "\\\\").replace('"', r"\"") + '"',
        )
    except Exception:
        return False
    try:
        response = dns.query.udp(
            upd, host, port=port, timeout=5.0, raise_on_truncation=True
        )
    except dns.message.Truncated:
        try:
            response = dns.query.tcp(upd, host, port=port, timeout=5.0)
        except Exception:
            return False
    except Exception:
        return False
    if response.flags & dns.flags.TC:
        try:
            response = dns.query.tcp(upd, host, port=port, timeout=5.0)
        except Exception:
            return False
    return response.rcode() == dns.rcode.NOERROR


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


@dataclass
class ClaimDeliveryResult:
    """Outcome of a single claim-poll pass on `receive_claims`.

    `delivered` are messages that landed in the inbox (sender was
    pinned). `quarantined_intro_ids` are intro_queue ids the user
    can review with `dnsmesh intro list`. `dropped` is a count of
    claims that were dropped silently — denylisted senders, expired
    claims, or sigverify failures. The detail breakdown is in
    `dropped_reasons` for diagnostics.
    """

    delivered: List["InboxMessage"]
    quarantined_intro_ids: List[int]
    dropped: int
    dropped_reasons: Dict[str, int]


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
        intro_queue_path: Optional[str] = None,
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

        # M8.3 — pending-intro queue for claim-discovered messages from
        # un-pinned senders. Lazy-imported so legacy code paths that
        # never invoke claim send/recv don't pay the import cost.
        from dmp.client.intro_queue import IntroQueue

        self.intro_queue = IntroQueue(intro_queue_path or ":memory:")

    # ---- addressing helpers ------------------------------------------------

    @staticmethod
    def _hash12(b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()[:12]

    def _slot_domain(
        self, recipient_id: bytes, slot: int, *, zone: Optional[str] = None
    ) -> str:
        return f"slot-{slot}.mb-{self._hash12(recipient_id)}.{zone or self.domain}"

    @staticmethod
    def _msg_key(msg_id: bytes, recipient_id: bytes, sender_spk: bytes) -> str:
        return hashlib.sha256(msg_id + recipient_id + sender_spk).hexdigest()[:12]

    def _chunk_domain(
        self, msg_key: str, chunk_num: int, *, zone: Optional[str] = None
    ) -> str:
        return f"chunk-{chunk_num:04d}-{msg_key}.{zone or self.domain}"

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

        `public_key_hex` is the X25519 encryption key (32 bytes hex).
        Empty string is permitted ONLY when `signing_key_hex` is set —
        the M8.3 ``dnsmesh intro trust`` flow pins a sender's Ed25519
        identity from an intro queue entry without yet knowing their
        X25519 pubkey; the user fills it in later via
        ``dnsmesh identity fetch user@host --add``. With pub empty,
        the contact is "spk-pin only": receive accepts manifests
        signed by `signing_key_bytes` (so cross-zone walks pull from
        their zone), but ``send_message`` refuses (no ECDH target).

        `signing_key_hex` is optional for back-compat with configs that
        predate Ed25519 pinning. When empty, incoming manifests from any
        signer will be accepted on first delivery (TOFU); when present,
        only manifests whose `sender_spk` matches are delivered.
        """
        # Allow an empty `public_key_hex` only when the caller has at
        # least pinned a signing key — otherwise this is just a name
        # with no cryptographic content and we have nothing useful
        # to do with it.
        if not public_key_hex and not signing_key_hex:
            return False
        if public_key_hex:
            try:
                public_key_bytes = bytes.fromhex(public_key_hex)
            except ValueError:
                return False
            if len(public_key_bytes) != 32:
                return False
        else:
            public_key_bytes = b""

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
        claim_providers: Sequence[Tuple[str, str]] = (),
        claim_outcomes: Optional[List[bool]] = None,
        claim_writer: Optional[DNSRecordWriter] = None,
    ) -> bool:
        """Send an encrypted message to a pinned contact.

        ``claim_providers`` is the ranked list of ``(provider_zone,
        provider_endpoint)`` tuples — typically built by the CLI from
        the recipient's perspective via
        ``dmp.client.claim_routing.select_providers``. When non-empty,
        we publish a claim record at each provider so an unpinned
        recipient can still discover the mail. Always-on (codex
        P1 round 2 dropped the same-zone optimization).

        ``claim_outcomes`` is an optional out-parameter: when supplied
        as a list, each provider's publish result is appended (True
        on success, False otherwise). The CLI uses this to surface
        partial-failure cases — codex P2 round 5 caught the bug where
        send_message silently returned True even when every claim
        attempt failed, so first-contact reach silently broke for
        recipients who hadn't pinned the sender.

        Claim publish failures do NOT block the underlying message
        delivery: best-effort first-contact reach, not a delivery
        guarantee.
        """
        contact = self.contacts.get(recipient_username)
        if contact is None:
            return False
        if not contact.public_key_bytes:
            # M8.3 — a contact pinned via `dnsmesh intro trust` may
            # carry only the Ed25519 spk (recv-pin) until the user
            # runs `identity fetch` to populate the X25519 pubkey.
            # Refuse to send rather than silently encrypting to a
            # zero key.
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
        ok = self.writer.publish_txt_record(
            self._slot_domain(recipient_id, slot),
            slot_record,
            ttl=ttl,
        )
        if not ok:
            return False

        # M8.3 — first-contact reach. Always publish a claim when the
        # caller configured providers, regardless of zone/pin state.
        # Codex P1 (round 2): a "skip if same-zone and we have their
        # signing key pinned" optimization breaks first-contact for
        # any same-zone recipient who has ANY pinned contact, because
        # their pin fence at receive_messages() drops un-pinned
        # senders globally. We can't know whether the recipient has
        # us pinned, so the safe default is always-publish. Cost is
        # M extra DNS records per send (M = number of providers) —
        # acceptable for first-contact correctness.
        if claim_providers:
            for provider_zone, provider_endpoint in claim_providers:
                outcome = self.publish_claim(
                    recipient_id=recipient_id,
                    msg_id=msg_id,
                    slot=slot,
                    sender_mailbox_domain=self.domain,
                    ttl=ttl,
                    provider_zone=provider_zone,
                    provider_endpoint=provider_endpoint or "",
                    provider_writer=claim_writer,
                )
                if claim_outcomes is not None:
                    claim_outcomes.append(bool(outcome))
        return True

    # ---- receive -----------------------------------------------------------

    def _zones_to_poll(self) -> List[str]:
        """Zones we walk on receive: each pinned contact's zone plus our own.

        The original DMP spec (`docs/design-intent/protocol.md`) puts the
        sender's records under the sender's zone — Alice publishes to
        `slot-N.mb-{hash(bob)}.{alice-zone}`, and Bob fetches from the same
        name via the recursive DNS chain. M8.1 restores that property by
        walking each pinned contact's zone in addition to `self.domain`.

        `Contact.domain` is populated when a contact is added via
        `dnsmesh identity fetch user@host --add` (cli.py:854). Legacy
        contacts that predate the field fall back to `self.domain` in
        `add_contact`, so same-mesh deployments keep working: their pinned
        contacts' domain equals `self.domain` and we collapse to a single
        zone walk.

        `self.domain` is always included even when we have no contacts —
        that's the legacy same-mesh path and keeps the TOFU bootstrap
        flow ("publish identity, exchange keys, pin") working before any
        contact is added.
        """
        zones: List[str] = []
        seen: set = set()
        for contact in self.contacts.values():
            z = contact.domain or self.domain
            if z and z not in seen:
                zones.append(z)
                seen.add(z)
        if self.domain and self.domain not in seen:
            zones.append(self.domain)
        return zones

    def receive_messages(
        self,
        *,
        claim_providers: Sequence[Tuple[str, str]] = (),
    ) -> List[InboxMessage]:
        """Poll all mailbox slots; verify and decrypt any fresh messages.

        Walks each zone in `_zones_to_poll()` — pinned contacts' zones plus
        our own — and queries the 10 slot RRsets under each. The chunk
        zone for any accepted manifest is the SAME zone the manifest was
        fetched from; we never re-derive it from `sender_spk`, because a
        manifest signed by Alice but published in a zone Alice doesn't
        control would otherwise be allowed to redirect chunk fetches to
        that zone. Manifest-zone integrity is the load-bearing security
        property here.

        Returns the list of newly-delivered messages. Replay-cache rejections,
        signature failures, and manifests from un-pinned senders are silently
        skipped. If the client has no pinned Ed25519 contacts at all, receive
        falls back to TOFU and delivers any signature-valid manifest — useful
        for fresh onboarding, but users should pin contacts before treating
        delivered messages as authenticated.
        """
        results: List[InboxMessage] = []
        known_spks = self._known_signing_keys()
        for zone in self._zones_to_poll():
            for slot in range(SLOT_COUNT):
                slot_domain = self._slot_domain(self.user_id, slot, zone=zone)
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
                    # Check-only here; we record in the replay cache *after*
                    # we actually decode the message. Otherwise a transient
                    # DNS miss during chunk fetch would permanently suppress
                    # a still-valid manifest on later polls.
                    if self.replay_cache.has_seen(manifest.sender_spk, manifest.msg_id):
                        continue
                    decoded = self._fetch_and_decrypt(manifest, source_zone=zone)
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
        # M8.3 — poll claim providers for first-contact pointers in
        # the same pass. Pinned-sender claims roll into `results`;
        # un-pinned ones land in the intro queue (visible via
        # `dnsmesh intro list`). Caller-provided empty providers list
        # skips claim polling entirely — preserves the legacy
        # behavior for callers that haven't migrated.
        if claim_providers:
            claim_result = self.receive_claims(provider_zones=claim_providers)
            results.extend(claim_result.delivered)
        return results

    # ---- claims (M8.3) -----------------------------------------------------

    def publish_claim(
        self,
        *,
        recipient_id: bytes,
        msg_id: bytes,
        slot: int,
        sender_mailbox_domain: str,
        ttl: int,
        provider_zone: str,
        provider_endpoint: str = "",
        provider_writer: Optional[DNSRecordWriter] = None,
    ) -> bool:
        """Publish one signed claim record at a single provider.

        The claim is a tiny pointer: it tells whoever polls that
        ``sender_spk`` has mail for the recipient (identified by the
        hash12 in the RRset name) at slot ``slot`` of zone
        ``sender_mailbox_domain``. The recipient verifies the signature,
        then fetches the manifest+chunks from ``sender_mailbox_domain``
        via the normal cross-zone receive path (M8.1).

        Delivery (M9.2.6 — DNS-only):

          - ``provider_writer`` set → write via that writer. Tests use
            this to point the sender + provider at a shared in-memory
            store; production deployments use it for cross-zone DNS
            UPDATE wiring.
          - Otherwise build a one-shot un-TSIG'd DNS UPDATE to the
            provider's DNS port (derived from ``provider_endpoint``
            host or ``provider_zone``). The provider's DNS server
            accepts the un-TSIG'd UPDATE only when the wire parses as
            a verifiable ``ClaimRecord``; the on-zone authentication
            IS that Ed25519 signature, so requiring TSIG would only
            block first-contact reach.

        ``provider_endpoint`` is now used purely as a hostname source
        for the DNS UPDATE target — the legacy HTTP ``/v1/claim/publish``
        path is gone (the user authorized breaking that, M9 cleanup).

        Returns True on successful publish. Failures (oversize,
        signing mismatch, write rejection, network error) return
        False without raising — first-message reach is best-effort,
        not a delivery guarantee.
        """
        from dmp.core.claim import (
            MAX_MAILBOX_DOMAIN_LEN,
            ClaimRecord,
            claim_rrset_name,
        )

        if len(sender_mailbox_domain) > MAX_MAILBOX_DOMAIN_LEN:
            return False
        now = int(time.time())
        try:
            record = ClaimRecord(
                msg_id=bytes(msg_id),
                sender_spk=self.crypto.get_signing_public_key_bytes(),
                sender_mailbox_domain=sender_mailbox_domain,
                slot=int(slot),
                ts=now,
                exp=now + int(ttl),
            )
            wire = record.sign(self.crypto)
        except (ValueError, Exception):
            return False

        try:
            name = claim_rrset_name(recipient_id, int(slot), provider_zone)
        except ValueError:
            return False

        if provider_writer is not None:
            try:
                return bool(
                    provider_writer.publish_txt_record(name, wire, ttl=int(ttl))
                )
            except Exception:
                return False

        # No explicit writer override.
        #
        # Cross-zone path (production): the provider zone is different
        # from this client's own zone, OR the caller passed a
        # ``provider_endpoint``. Build a one-shot un-TSIG'd DNS UPDATE
        # against the provider's authoritative DNS server — the claim
        # wire's Ed25519 signature is the on-zone authentication, so
        # TSIG is not required for this surface (M9.2.6 server-side
        # gate enforces this).
        provider_z = (provider_zone or "").strip().lower().rstrip(".")
        own_zone = (self.domain or "").strip().lower().rstrip(".")
        if provider_endpoint or (provider_z and provider_z != own_zone):
            target = _provider_dns_target(provider_endpoint, provider_zone)
            if not target:
                return False
            return _publish_claim_via_dns_update(
                zone=provider_zone,
                target=target,
                name=name,
                wire=wire,
                ttl=int(ttl),
                resolver_pool=self.reader,
            )

        # Same-zone / colocated path: sender IS the provider (test
        # fixtures, single-node setups). Use the local writer.
        try:
            return bool(self.writer.publish_txt_record(name, wire, ttl=int(ttl)))
        except Exception:
            return False

    def receive_claims(
        self,
        *,
        provider_zones: Sequence[Tuple[str, str]] = (),
    ) -> ClaimDeliveryResult:
        """Poll claim providers for first-contact pointers, deliver / quarantine.

        `provider_zones` is the ranked list `[(provider_zone,
        provider_endpoint), ...]` from `claim_routing.select_providers`.
        Only the `provider_zone` is used here (the DNS query name);
        the endpoint is informational, surfaced for logging.

        For each verified, unexpired claim:

          1. Fetch the manifest at
             `slot-{N}.mb-{hash(self)}.{claim.sender_mailbox_domain}`.
          2. Verify signature, recipient_id, freshness.
          3. Fetch chunks from the SAME zone (M8.1 manifest-zone
             integrity).
          4. Decrypt.
          5. If `claim.sender_spk` is pinned → deliver to inbox.
             Else → land in `intro_queue` with the decrypted plaintext.

        Claims from denylisted senders are dropped at `intro_queue.add_intro`
        time. Replay protection uses the existing `ReplayCache` once a
        claim leads to a successful decrypt — the replay cache is keyed
        on (sender_spk, msg_id), so a re-poll that re-discovers the same
        claim is naturally deduplicated.

        Returns a `ClaimDeliveryResult` with the delivered messages,
        the quarantined intro ids (for `dnsmesh intro list`), and a
        small drop-reasons counter for diagnostics.
        """
        from dmp.core.claim import ClaimRecord, claim_rrset_name
        from dmp.core.manifest import SlotManifest

        delivered: List[InboxMessage] = []
        quarantined_ids: List[int] = []
        drop_reasons: Dict[str, int] = {}
        dropped = 0

        def _drop(reason: str) -> None:
            nonlocal dropped
            dropped += 1
            drop_reasons[reason] = drop_reasons.get(reason, 0) + 1

        known_spks = self._known_signing_keys()

        for provider_zone, _provider_endpoint in provider_zones:
            for slot in range(SLOT_COUNT):
                try:
                    name = claim_rrset_name(self.user_id, slot, provider_zone)
                except ValueError:
                    _drop("bad-provider-zone")
                    continue
                try:
                    records = self.reader.query_txt_record(name)
                except Exception:
                    _drop("dns-query-failed")
                    continue
                if not records:
                    continue
                for record in records:
                    claim = ClaimRecord.parse_and_verify(record)
                    if claim is None:
                        _drop("invalid-claim")
                        continue
                    # Already delivered or seen-once — skip without
                    # paying the manifest+chunk fetch cost.
                    if self.replay_cache.has_seen(claim.sender_spk, claim.msg_id):
                        _drop("replay")
                        continue
                    # Denylist short-circuit.
                    if self.intro_queue.is_blocked(claim.sender_spk):
                        _drop("denylisted")
                        continue
                    # Same-spk + same-msg already pending in intro
                    # queue: don't try to fetch+decrypt again.
                    if self.intro_queue.has_intro(claim.sender_spk, claim.msg_id):
                        _drop("already-pending")
                        continue

                    # Fetch the manifest from the sender's zone.
                    manifest = self._fetch_claim_manifest(
                        claim.sender_mailbox_domain, claim
                    )
                    if manifest is None:
                        _drop("manifest-not-found")
                        continue
                    # Cross-bind: the manifest's sender_spk must match
                    # the claim's. Otherwise a malicious provider can
                    # claim "alice@zoneX has mail at zoneY" but zoneY's
                    # manifest is signed by bob — refuse the mismatch.
                    if manifest.sender_spk != claim.sender_spk:
                        _drop("manifest-spk-mismatch")
                        continue
                    if manifest.recipient_id != self.user_id:
                        _drop("manifest-recipient-mismatch")
                        continue
                    if manifest.is_expired():
                        _drop("manifest-expired")
                        continue
                    # M5.4: revocation check, same as receive_messages.
                    if self._rotation_manifest_revoked(manifest.sender_spk):
                        _drop("revoked")
                        continue
                    decoded = self._fetch_and_decrypt(
                        manifest, source_zone=claim.sender_mailbox_domain
                    )
                    if decoded is None:
                        _drop("decrypt-failed")
                        continue
                    plaintext, ts, msg_id = decoded
                    # Record in replay cache only after successful
                    # decrypt — a transient chunk fetch miss must not
                    # permanently suppress this claim.
                    self.replay_cache.record(
                        manifest.sender_spk, manifest.msg_id, manifest.exp
                    )

                    # Codex P2 final-review fix: a contact who rotated
                    # their Ed25519 key has manifest.sender_spk that
                    # isn't literally in known_spks, but the
                    # rotation-chain walk (M5.4) accepts it on the
                    # mailbox path. Without this branch, a rotated
                    # contact's claim-discovered message gets
                    # quarantined as an intro even though the same
                    # contact's same-zone message would be delivered
                    # straight to the inbox. Mirror the receive_messages
                    # logic: pinned ∪ rotated → inbox; everyone else →
                    # intro queue.
                    is_pinned_or_rotated = bool(known_spks) and (
                        manifest.sender_spk in known_spks
                        or self._rotation_manifest_accepted(manifest.sender_spk)
                    )
                    if is_pinned_or_rotated:
                        # Pinned (possibly via rotation chain) sender →
                        # straight to the inbox, same semantics as
                        # receive_messages.
                        delivered.append(
                            InboxMessage(
                                sender_signing_pk=manifest.sender_spk,
                                plaintext=plaintext,
                                timestamp=ts,
                                msg_id=msg_id,
                            )
                        )
                    else:
                        # Un-pinned sender → quarantine in intro queue.
                        intro_id = self.intro_queue.add_intro(
                            sender_spk=manifest.sender_spk,
                            msg_id=manifest.msg_id,
                            plaintext=plaintext,
                            sender_mailbox_domain=claim.sender_mailbox_domain,
                            msg_exp=manifest.exp,
                        )
                        if intro_id is not None:
                            quarantined_ids.append(intro_id)
                        else:
                            # Either denylisted (raced) or duplicate.
                            _drop("intro-add-failed")

        return ClaimDeliveryResult(
            delivered=delivered,
            quarantined_intro_ids=quarantined_ids,
            dropped=dropped,
            dropped_reasons=drop_reasons,
        )

    def _fetch_claim_manifest(
        self,
        sender_mailbox_domain: str,
        claim: "ClaimRecord",  # forward ref; ClaimRecord imported in caller
    ):
        """Fetch the slot manifest a claim points at, verify it.

        Returns the verified `SlotManifest` or None. The slot field
        in the claim is informational — we walk all slots in the
        sender's zone keyed by hash(self.user_id), because the sender
        chooses a deterministic-by-msg_id slot at publish time and
        the claim's slot may have drifted (or been published as a
        sentinel). Robust against minor sender bugs.
        """
        from dmp.core.manifest import SlotManifest

        for slot in range(SLOT_COUNT):
            try:
                slot_name = self._slot_domain(
                    self.user_id, slot, zone=sender_mailbox_domain
                )
            except ValueError:
                continue
            try:
                records = self.reader.query_txt_record(slot_name)
            except Exception:
                continue
            if not records:
                continue
            for record in records:
                parsed = SlotManifest.parse_and_verify(record)
                if parsed is None:
                    continue
                manifest, _ = parsed
                if manifest.msg_id == claim.msg_id:
                    return manifest
        return None

    # ---- intro queue actions (M8.3) ----------------------------------------

    def accept_intro(self, intro_id: int) -> Optional[InboxMessage]:
        """Promote a pending intro into a delivered message; do NOT pin.

        Returns the InboxMessage equivalent on success, None if the
        intro_id doesn't exist. The intro row is removed after promotion
        so the same id can't be replayed.
        """
        intro = self.intro_queue.get_intro(intro_id)
        if intro is None:
            return None
        msg = InboxMessage(
            sender_signing_pk=intro.sender_spk,
            plaintext=intro.plaintext,
            timestamp=intro.received_at,
            msg_id=intro.msg_id,
        )
        self.intro_queue.remove_intro(intro_id)
        return msg

    def trust_intro(
        self,
        intro_id: int,
        *,
        label: str = "",
        remote_username: str = "",
    ) -> Optional[InboxMessage]:
        """Promote + pin the sender as a trusted contact.

        ``label`` is the local nickname for the new pinned contact
        (the dict key in ``self.contacts``); defaults to
        ``intro-{spk-prefix}`` if empty.

        ``remote_username`` is the sender's actual identity name on
        their home node — used by ``Contact.username`` for protocol
        lookups (prekey RRsets, rotation-chain subjects). When
        empty, ``Contact.username`` is left empty too; downstream
        protocol lookups skip gracefully (prekey fetch falls back
        to long-term ECDH; rotation walks return None). The user
        fills this in by running
        ``dnsmesh identity fetch user@host --add`` after the trust
        action; that flow knows the real name from the identity
        record it just verified.

        We deliberately do NOT use ``label`` as ``Contact.username``
        — codex P2 round 2 caught the bug where the local label
        leaks into protocol queries (prekey_rrset_name builds
        ``_prekey.<label>.<domain>`` which doesn't exist). Empty
        username + the existing protocol-skip logic is the safe
        default.
        """
        intro = self.intro_queue.get_intro(intro_id)
        if intro is None:
            return None
        spk_hex = bytes(intro.sender_spk).hex()
        contact_label = label or f"intro-{spk_hex[:12]}"
        self.contacts[contact_label] = Contact(
            username=remote_username,  # empty unless caller knows the real name
            public_key_bytes=b"",  # filled by `dnsmesh identity fetch`
            signing_key_bytes=intro.sender_spk,
            domain=intro.sender_mailbox_domain,
        )
        return self.accept_intro(intro_id)

    def block_intro(self, intro_id: int, *, note: str = "") -> bool:
        """Drop the intro and add the sender_spk to the denylist."""
        intro = self.intro_queue.get_intro(intro_id)
        if intro is None:
            return False
        self.intro_queue.block_sender(intro.sender_spk, note=note)
        self.intro_queue.remove_intro(intro_id)
        return True

    def _fetch_and_decrypt(
        self,
        manifest: SlotManifest,
        *,
        source_zone: Optional[str] = None,
    ) -> Optional[Tuple[bytes, int, bytes]]:
        """Return (plaintext, timestamp, msg_id) or None if assembly/decrypt fails.

        `source_zone` MUST be the zone the manifest itself was fetched from.
        The chunk RRsets for this message live in the same zone the manifest
        does — the sender publishes both at once under their own zone — so
        we hard-bind the chunk query to that zone. We do NOT look up the
        chunk zone via `sender_spk` → contact lookup, because a manifest
        signed by a pinned sender but published in a zone the sender
        doesn't control would otherwise redirect chunk fetches to that
        zone. The contract: a manifest fetched at zone X may only point
        at chunks at zone X.

        Defaults to `self.domain` only as a safety net for legacy callers
        that don't yet thread the source zone through.
        """
        msg_key = self._msg_key(
            manifest.msg_id, manifest.recipient_id, manifest.sender_spk
        )
        zone = source_zone or self.domain

        # Walk every chunk position up to total_chunks, collecting valid
        # shares into a dict keyed by share_id. Stop early once we have k
        # shares — erasure.decode only needs k of n.
        shares: Dict[int, bytes] = {}
        for chunk_num in range(manifest.total_chunks):
            if len(shares) >= manifest.data_chunks:
                break
            records = self.reader.query_txt_record(
                self._chunk_domain(msg_key, chunk_num, zone=zone)
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
