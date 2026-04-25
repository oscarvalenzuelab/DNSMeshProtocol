"""End-to-end client tests over an InMemoryDNSStore."""

import time

import pytest

from dmp.client.client import DMPClient, InboxMessage
from dmp.network.memory import InMemoryDNSStore


def _pair(store: InMemoryDNSStore, domain: str = "mesh.test"):
    alice = DMPClient("alice", "alice-pass", domain=domain, store=store)
    bob = DMPClient("bob", "bob-pass", domain=domain, store=store)
    alice.add_contact("bob", bob.get_public_key_hex())
    bob.add_contact("alice", alice.get_public_key_hex())
    return alice, bob


class TestSendReceive:
    def test_roundtrip_small_message(self):
        store = InMemoryDNSStore()
        alice, bob = _pair(store)

        assert alice.send_message("bob", "hello bob")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        msg = inbox[0]
        assert isinstance(msg, InboxMessage)
        assert msg.plaintext == b"hello bob"
        assert msg.sender_signing_pk == alice.crypto.get_signing_public_key_bytes()

    def test_roundtrip_multi_chunk(self):
        store = InMemoryDNSStore()
        alice, bob = _pair(store)

        payload = "A" * 2000  # forces several chunks
        assert alice.send_message("bob", payload)
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == payload.encode("utf-8")

    def test_receive_twice_replay_cache_suppresses(self):
        store = InMemoryDNSStore()
        alice, bob = _pair(store)

        assert alice.send_message("bob", "once")
        first = bob.receive_messages()
        assert len(first) == 1

        # The manifest still sits in the slot; a second poll must not
        # re-deliver the same message because the replay cache remembers it.
        second = bob.receive_messages()
        assert second == []

    def test_other_user_cannot_decrypt(self):
        store = InMemoryDNSStore()
        alice, bob = _pair(store)
        eve = DMPClient("eve", "eve-pass", domain="mesh.test", store=store)

        alice.send_message("bob", "secret")

        # Eve polls her own slots — she shouldn't see anything (manifest is
        # addressed to bob's recipient_id, so eve's slot polling returns
        # nothing matching her own user_id).
        eve_inbox = eve.receive_messages()
        assert eve_inbox == []

    def test_unknown_recipient_returns_false(self):
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "p", domain="mesh.test", store=store)
        assert alice.send_message("nobody", "hi") is False

    def test_invalid_contact_key_rejected(self):
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "p", domain="mesh.test", store=store)
        assert alice.add_contact("badhex", "zz") is False
        assert alice.add_contact("shortkey", "aabb") is False

    def test_txt_records_fit_in_single_dns_string(self):
        """Every published TXT value must be <= 255 bytes to fit a single DNS string.

        Real DNS backends (BIND UPDATE, Route53, dnsmasq) publish one string
        per record by default. A record that exceeds 255 bytes either gets
        truncated, rejected, or silently splits in backend-specific ways.
        """
        store = InMemoryDNSStore()
        alice, bob = _pair(store)

        # A multi-chunk message exercises both chunk records and the manifest.
        assert alice.send_message("bob", "X" * 600)

        for name in store.list_names():
            for value in store.query_txt_record(name) or []:
                assert (
                    len(value.encode("utf-8")) <= 255
                ), f"TXT record at {name} is {len(value)} bytes — exceeds DNS per-string limit"

    def test_transient_chunk_miss_does_not_blacklist(self):
        """Replay cache must not record a manifest until decrypt succeeds.

        If chunks are not yet visible when the recipient first sees the
        manifest, a naive cache would lock the message out forever. The fixed
        client records only post-decrypt, so a later poll still delivers.
        """
        import hashlib

        store = InMemoryDNSStore()
        alice, bob = _pair(store)
        assert alice.send_message("bob", "deferred")

        # Find the chunk records and remove them so the first poll can't fetch.
        bob_user_id = hashlib.sha256(bytes.fromhex(bob.get_public_key_hex())).digest()
        chunk_names = [n for n in store.list_names() if n.startswith("chunk-")]
        assert chunk_names  # sanity check

        saved = {n: store.query_txt_record(n) for n in chunk_names}
        for n in chunk_names:
            store.delete_txt_record(n)

        # First poll: manifest visible, chunks missing → decrypt fails silently.
        assert bob.receive_messages() == []
        # Make chunks available again (simulates DNS propagation).
        for n, values in saved.items():
            store.publish_txt_record(n, values[0])
        # Second poll: manifest still in slot, chunks now present → delivered.
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"deferred"

    def test_concurrent_sends_do_not_silently_clobber(self):
        """Back-to-back sends prefer empty slots so neither message is lost."""
        store = InMemoryDNSStore()
        alice, bob = _pair(store)
        eve = DMPClient("eve", "eve-pass", domain="mesh.test", store=store)
        eve.add_contact("bob", bob.get_public_key_hex())

        # Two different senders, two back-to-back messages to bob. With 10
        # empty slots available, the first-empty scan should deposit them in
        # distinct slots.
        assert alice.send_message("bob", "from-alice")
        assert eve.send_message("bob", "from-eve")
        inbox = bob.receive_messages()
        assert len(inbox) == 2
        payloads = sorted(m.plaintext for m in inbox)
        assert payloads == [b"from-alice", b"from-eve"]

    def test_unknown_signer_dropped_when_contacts_pinned(self):
        """Once alice has pinned bob's signing key, a manifest from a random
        third party (eve) is dropped even if she correctly signs it and
        addresses it to alice.

        This closes the 'sender_spk is any Ed25519 key' gap flagged in the
        codex audit — without pinning, the client accepts any valid signer
        as "some sender"; with pinning, only the expected key is accepted.
        """
        import hashlib

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)
        eve = DMPClient("eve", "eve-pass", domain="mesh.test", store=store)

        # alice pins bob (both keys). No pin for eve.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        # eve sends a message to alice. eve has alice's pubkey (she
        # queried DNS) but alice has NOT pinned eve, so on receive the
        # manifest's sender_spk won't match any known contact.
        eve.add_contact("alice", alice.get_public_key_hex())
        assert eve.send_message("alice", "eve is not a contact")

        # bob also sends. Alice should accept this one.
        bob.add_contact("alice", alice.get_public_key_hex())
        assert bob.send_message("alice", "bob is pinned")

        inbox = alice.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"bob is pinned"
        assert inbox[0].sender_signing_pk == bob.crypto.get_signing_public_key_bytes()

    def test_tofu_delivery_when_no_contacts_pinned(self):
        """Without any pinned signing keys, receive falls back to TOFU —
        any signature-valid manifest for us is delivered. This keeps the
        initial 'publish your identity, exchange keys, pin' workflow
        working at all."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)
        # alice has no contacts at all — no pins yet.
        bob.add_contact("alice", alice.get_public_key_hex())
        assert bob.send_message("alice", "first contact")

        inbox = alice.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"first contact"

    def test_prekey_forward_secrecy_roundtrip(self):
        """When bob publishes prekeys and alice has pinned his signing key,
        the message uses a one-time prekey for ECDH and bob's store consumes
        the sk after decrypt. A later leak of bob's long-term X25519 key
        cannot recover that session's plaintext.
        """
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)

        # Pin both directions with signing keys so prekey verification works.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        # Bob refreshes prekeys → a pool of one-time X25519 keys lands in DNS.
        published = bob.refresh_prekeys(count=5, ttl_seconds=3600)
        assert published == 5
        assert bob.prekey_store.count_live() == 5

        assert alice.send_message("bob", "FS-protected payload")

        # Find the manifest → prekey_id should be nonzero (FS path taken).
        from dmp.core.manifest import NO_PREKEY, SlotManifest

        manifest = None
        for name in store.list_names():
            if not name.startswith("slot-"):
                continue
            for value in store.query_txt_record(name) or []:
                parsed = SlotManifest.parse_and_verify(value)
                if parsed and parsed[0].recipient_id == bob.user_id:
                    manifest = parsed[0]
                    break
            if manifest:
                break
        assert manifest is not None
        assert manifest.prekey_id != NO_PREKEY
        used_id = manifest.prekey_id
        assert bob.prekey_store.get_private_key(used_id) is not None

        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"FS-protected payload"

        # Consumed after decrypt — FS property: even if bob's long-term X25519
        # private key leaks now, this message's session key can't be recovered
        # because the prekey sk is gone.
        assert bob.prekey_store.get_private_key(used_id) is None
        assert bob.prekey_store.count_live() == 4

    def test_fallback_to_long_term_when_no_prekeys(self):
        """Without a pinned signing key for bob, alice falls back to his
        long-term X25519 key (no FS) rather than failing to send."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)
        # NOTE: no signing_key_hex — alice can't verify any prekey signature.
        alice.add_contact("bob", bob.get_public_key_hex())

        # Bob publishes prekeys, but alice won't verify them without the pin.
        bob.refresh_prekeys(count=3, ttl_seconds=3600)

        assert alice.send_message("bob", "long-term path")

        from dmp.core.manifest import NO_PREKEY, SlotManifest

        manifest = None
        for name in store.list_names():
            if not name.startswith("slot-"):
                continue
            for value in store.query_txt_record(name) or []:
                parsed = SlotManifest.parse_and_verify(value)
                if parsed and parsed[0].recipient_id == bob.user_id:
                    manifest = parsed[0]
                    break
            if manifest:
                break
        assert manifest is not None
        assert manifest.prekey_id == NO_PREKEY

        # Bob still decrypts fine via the long-term key path.
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"long-term path"

    def test_consumed_prekey_is_removed_from_published_pool(self):
        """The prekey_pub stays in DNS until consumed by the recipient.

        Without the DELETE-on-consume path, senders keep picking from the
        same RRset even after its sks have been eaten locally — so
        increasing fractions of messages become undeliverable over time.
        This test pins the invariant: after decrypt, the published pool
        has one fewer entry.
        """
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        bob.refresh_prekeys(count=3, ttl_seconds=3600)

        from dmp.core.prekeys import prekey_rrset_name

        pool_name = prekey_rrset_name("bob", "mesh.test")
        assert len(store.query_txt_record(pool_name) or []) == 3

        assert alice.send_message("bob", "consume me")
        inbox = bob.receive_messages()
        assert len(inbox) == 1

        # One prekey consumed both locally AND in DNS.
        assert bob.prekey_store.count_live() == 2
        assert len(store.query_txt_record(pool_name) or []) == 2

    def test_prekey_deleted_before_decrypt_drops_message(self):
        """If bob's prekey_sk is wiped (e.g. refresh rotated it out) before
        he polls, the ciphertext is undeliverable — the FS property working
        in the other direction."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        bob.refresh_prekeys(count=2, ttl_seconds=3600)
        assert alice.send_message("bob", "undecodable after wipe")

        # Wipe bob's prekey store before he polls.
        for pid in bob.prekey_store.list_live_ids():
            bob.prekey_store.consume(pid)
        assert bob.receive_messages() == []

    def test_lost_chunks_recover_via_erasure(self):
        """Dropping up to (n-k) chunks before bob polls still delivers.

        This is the promise erasure coding is supposed to deliver. Each
        message is split into k data blocks + parity blocks; any k of n
        chunks reconstruct. Here we delete all *parity* chunks and show
        the k remaining data chunks deliver. Then a separate message
        where we delete some data chunks and rely on parity to fill in.
        """
        import hashlib

        store = InMemoryDNSStore()
        alice, bob = _pair(store)

        # Send a message big enough to get multiple chunks (k >= 4).
        payload = b"A" * 800  # k≈7, n≈10 with 30% redundancy
        assert alice.send_message("bob", payload.decode())

        # Find the manifest, extract msg_key and chunk count.
        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        from dmp.core.manifest import SlotManifest

        manifest = None
        for name in store.list_names():
            if not name.startswith("slot-"):
                continue
            for value in store.query_txt_record(name) or []:
                parsed = SlotManifest.parse_and_verify(value)
                if parsed and parsed[0].recipient_id == bob_recipient_id:
                    manifest = parsed[0]
                    break
            if manifest:
                break
        assert manifest is not None
        assert manifest.total_chunks > manifest.data_chunks  # parity exists

        # Delete the parity chunks. Bob should still be able to reconstruct.
        msg_key = alice._msg_key(
            manifest.msg_id, manifest.recipient_id, manifest.sender_spk
        )
        for chunk_num in range(manifest.data_chunks, manifest.total_chunks):
            store.delete_txt_record(alice._chunk_domain(msg_key, chunk_num))

        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == payload

    def test_lost_data_chunks_recover_via_parity(self):
        """Dropping data chunks but keeping parity still delivers."""
        import hashlib

        store = InMemoryDNSStore()
        alice, bob = _pair(store)
        payload = b"B" * 800
        assert alice.send_message("bob", payload.decode())

        # Find the manifest.
        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        from dmp.core.manifest import SlotManifest

        manifest = None
        for name in store.list_names():
            if not name.startswith("slot-"):
                continue
            for value in store.query_txt_record(name) or []:
                parsed = SlotManifest.parse_and_verify(value)
                if parsed and parsed[0].recipient_id == bob_recipient_id:
                    manifest = parsed[0]
                    break
            if manifest:
                break
        assert manifest is not None

        # Delete enough data chunks that we need parity to reconstruct.
        # Keep (total - data) = parity chunks, plus (data - parity) data.
        parity = manifest.total_chunks - manifest.data_chunks
        msg_key = alice._msg_key(
            manifest.msg_id, manifest.recipient_id, manifest.sender_spk
        )
        for chunk_num in range(parity):  # delete the first `parity` data chunks
            store.delete_txt_record(alice._chunk_domain(msg_key, chunk_num))

        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == payload

    def test_forged_manifest_msg_id_rejected(self):
        """A sender who puts one msg_id in the manifest and a different one
        in the inner header is caught by the cross-check on receive.

        Without that check, a legitimate sender could lie about which
        message the manifest describes and the client would surface the
        lie as fact.
        """
        import hashlib
        import uuid

        from dmp.core.manifest import SlotManifest

        store = InMemoryDNSStore()
        alice, bob = _pair(store)
        bob.add_contact("alice", alice.get_public_key_hex())

        # alice sends normally so the chunks land with the *real* msg_id
        # embedded in the inner header.
        assert alice.send_message("bob", "real payload")

        # Find alice's just-published manifest, rewrite it so the manifest's
        # msg_id disagrees with the chunks' msg_id, then re-sign and
        # republish at the same slot so bob sees the forged manifest too.
        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        mb_hash = hashlib.sha256(bob_recipient_id).hexdigest()[:12]

        forged_slot = None
        real_manifest = None
        for slot in range(10):
            name = f"slot-{slot}.mb-{mb_hash}.mesh.test"
            for value in store.query_txt_record(name) or []:
                parsed = SlotManifest.parse_and_verify(value)
                if parsed is None:
                    continue
                real_manifest = parsed[0]
                forged_slot = name
                break
            if real_manifest is not None:
                break
        assert real_manifest is not None

        forged = SlotManifest(
            msg_id=uuid.uuid4().bytes,  # different msg_id
            sender_spk=real_manifest.sender_spk,
            recipient_id=real_manifest.recipient_id,
            total_chunks=real_manifest.total_chunks,
            data_chunks=real_manifest.data_chunks,
            prekey_id=0,
            ts=real_manifest.ts,
            exp=real_manifest.exp,
        )
        store.publish_txt_record(forged_slot, forged.sign(alice.crypto))

        # bob polls. The real manifest still delivers "real payload". The
        # forged one points at chunks that don't exist (wrong msg_key) or
        # at chunks whose inner header.message_id doesn't match the
        # forged msg_id. Either way, the forged delivery fails. In both
        # cases bob should NOT see two deliveries of the same plaintext.
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"real payload"

    def test_expired_inner_header_dropped(self):
        """A message whose inner-header ts+ttl is in the past is dropped.

        Belt-and-suspenders with the manifest's own `exp` field: the
        replay cache may not kick in if the entry was purged, and a
        stale manifest could survive if TTL wasn't enforced on the inner
        header too.
        """
        import hashlib
        import time as _time

        store = InMemoryDNSStore()
        alice, bob = _pair(store)

        # Push the wall clock forward so a 1-second TTL message goes stale
        # before bob polls. Monkeypatch time.time used by is_expired().
        _real = _time.time
        sent_at = int(_real())
        _time.time = lambda: sent_at  # freeze at send time

        try:
            assert alice.send_message("bob", "expires fast", ttl=1)
        finally:
            _time.time = _real

        # Wait past the TTL. Sleep needs to push int(time.time()) strictly
        # past exp; since exp = sent_at + 1 and int() truncates, 2.2 s is the
        # smallest safe wait.
        import time

        time.sleep(2.2)
        inbox = bob.receive_messages()
        # Either the manifest expired (dropped by manifest.is_expired) or
        # the inner header expired (dropped by the new cross-check) — both
        # reach the same outcome: no delivery.
        assert inbox == []

    def test_slot_squatting_attacker_cannot_evict_real_messages(self):
        """An attacker who blasts junk into every slot cannot block delivery.

        Under the old replace-the-RRset semantics, a single publish at each
        of the 10 slot names wiped out any legitimate manifest waiting there.
        With append semantics a real manifest survives alongside the junk,
        and the receive loop filters on signature + replay-cache — so bob
        still gets alice's message even after eve sprays all 10 slots.
        """
        import hashlib
        import uuid
        from dmp.core.manifest import SlotManifest

        store = InMemoryDNSStore()
        alice, bob = _pair(store)
        eve = DMPClient("eve", "eve-pass", domain="mesh.test", store=store)

        # Alice legitimately sends, chunks and manifest land in the store.
        assert alice.send_message("bob", "survive the squat")

        # Eve publishes a valid (but irrelevant) manifest into every one of
        # bob's mailbox slots. She can sign with her own key and her
        # manifests pass verification, but they address a different msg_id
        # so bob's fetch-and-decrypt fails and nothing is delivered from them.
        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        mb_hash = hashlib.sha256(bob_recipient_id).hexdigest()[:12]
        for slot in range(10):
            junk = SlotManifest(
                msg_id=uuid.uuid4().bytes,
                sender_spk=eve.crypto.get_signing_public_key_bytes(),
                recipient_id=bob_recipient_id,
                total_chunks=99,  # points to chunks that don't exist
                data_chunks=99,
                prekey_id=0,
                ts=int(time.time()),
                exp=int(time.time()) + 300,
            ).sign(eve.crypto)
            store.publish_txt_record(f"slot-{slot}.mb-{mb_hash}.mesh.test", junk)

        # Bob polls — he sees both alice's real manifest and eve's junk at
        # each slot. Alice's message still comes through.
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"survive the squat"

    def test_signed_manifest_rejects_impersonation(self):
        """An attacker forging a manifest in a victim's slot is caught."""
        import hashlib
        import uuid
        from dmp.core.manifest import SlotManifest

        store = InMemoryDNSStore()
        alice, bob = _pair(store)
        eve = DMPClient("eve", "eve-pass", domain="mesh.test", store=store)

        # Eve overwrites every one of Bob's slots with a manifest that claims
        # to be from Alice. Since Eve can't sign with Alice's Ed25519 key, the
        # manifest signature won't verify and Bob's poll drops it.
        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        forged = SlotManifest(
            msg_id=uuid.uuid4().bytes,
            sender_spk=alice.crypto.get_signing_public_key_bytes(),  # claims alice
            recipient_id=bob_recipient_id,
            total_chunks=1,
            data_chunks=1,
            prekey_id=0,
            ts=int(time.time()),
            exp=int(time.time()) + 300,
        )
        # Eve signs with HER key; spk in manifest still says alice.
        fake_record = forged.sign(eve.crypto)
        mb_hash = hashlib.sha256(bob_recipient_id).hexdigest()[:12]
        for slot in range(10):
            store.publish_txt_record(
                f"slot-{slot}.mb-{mb_hash}.mesh.test",
                fake_record,
            )

        # Bob polls — the forged manifest fails signature verification.
        assert bob.receive_messages() == []


class TestSpkOnlyContact:
    """Codex M8.3 P1 fix: a contact pinned via intro_trust may have spk
    but no X25519 pub yet. add_contact must accept it; send_message
    must refuse it; receive walks its zone."""

    def test_add_contact_accepts_spk_only(self):
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        ok = alice.add_contact(
            "spk-only-friend",
            public_key_hex="",
            domain="friend.mesh",
            signing_key_hex="bb" * 32,
        )
        assert ok
        contact = alice.contacts["spk-only-friend"]
        assert contact.public_key_bytes == b""
        assert contact.signing_key_bytes == bytes.fromhex("bb" * 32)
        assert contact.domain == "friend.mesh"

    def test_add_contact_rejects_no_keys_at_all(self):
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        # Empty pub AND empty spk — nothing useful to pin.
        assert alice.add_contact("ghost", public_key_hex="", domain="g.mesh") is False

    def test_recv_walks_spk_only_contact_zone(self):
        """An spk-only pinned contact still gets their zone polled."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)

        # Bob pins alice with full keys.
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        # Now bob ALSO has an spk-only contact at a different zone —
        # this would happen after `intro trust` before `identity fetch`.
        bob.add_contact(
            "future-friend",
            public_key_hex="",
            domain="future.mesh",
            signing_key_hex="cc" * 32,
        )

        # Alice sends; bob receives. Bob's _zones_to_poll now includes
        # alice.mesh, future.mesh, and bob.mesh (own). Test that recv
        # still works on the alice path despite the spk-only entry.
        alice.send_message("bob", "still works")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"still works"


class TestCrossZoneReceive:
    """M8.1 — receive walks pinned contacts' zones, not just self.domain.

    Original spec: sender publishes records under sender's own zone;
    recipient polls sender's zone via the recursive DNS chain. Before
    M8.1 the recv path queried `self.domain`, silently restricting
    delivery to same-mesh pairs (or same-cluster federated peers).
    These tests guard the fix.
    """

    def test_cross_zone_delivery_with_pinned_contact(self):
        """Alice on `alice.mesh`, Bob on `bob.mesh`, single shared store.

        Alice publishes manifests + chunks under `alice.mesh`. Bob walks
        `alice.mesh` because alice is pinned with that domain. Without
        M8.1, Bob would query `slot-N.mb-{hash(bob)}.bob.mesh` and find
        nothing.
        """
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)

        # Bob pins alice and explicitly records her zone — this is what
        # `dnsmesh identity fetch alice@alice.mesh --add` writes today.
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        # Alice pins bob symmetrically so the prekey/forward-secrecy path
        # has somewhere to look (not load-bearing for this test, but
        # mirrors a realistic deployment).
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        assert alice.send_message("bob", "from another zone")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"from another zone"
        assert inbox[0].sender_signing_pk == alice.crypto.get_signing_public_key_bytes()

    def test_chunks_fetched_from_manifest_source_zone(self):
        """Chunk fetch is hard-bound to the manifest's source zone.

        If Mallory squats Bob's zone with a manifest that claims Alice
        as sender (via her pinned spk somehow leaked or — more
        realistically — via a rotation or anti-entropy relay), the
        chunk fetch must NOT fall back to Alice's zone via sender_spk
        lookup. Bob expects chunks where the manifest lives.

        This test verifies that when chunks for Alice's message live
        ONLY in alice.mesh, a Bob who incorrectly queried bob.mesh
        for chunks would get nothing — but the fixed Bob queries
        alice.mesh and decodes successfully.
        """
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        # Multi-chunk forces the chunk fetch path to run.
        payload = "B" * 2000
        assert alice.send_message("bob", payload)

        # Sanity: the slot RRset lives at alice.mesh, not bob.mesh.
        import hashlib

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        bob_hash = hashlib.sha256(bob_recipient_id).hexdigest()[:12]
        bob_zone_names = [n for n in store.list_names() if n.endswith(".bob.mesh")]
        assert bob_zone_names == [], "manifest+chunks must not land in recipient's zone"
        alice_zone_names = [
            n for n in store.list_names() if f".mb-{bob_hash}.alice.mesh" in n
        ]
        assert (
            alice_zone_names
        ), "manifest must land in sender's zone keyed by recipient hash"

        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == payload.encode("utf-8")

    def test_legacy_same_mesh_still_works(self):
        """Pre-M8.1 same-mesh deployments must keep working.

        When alice and bob share a `mesh_domain` and contacts are added
        without an explicit `domain=` (the legacy `dnsmesh contacts add`
        path), `Contact.domain` falls back to `self.domain` — both
        zones collapse and `_zones_to_poll()` returns a single entry.
        """
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)
        # Legacy add — no domain= passed, no signing key (TOFU mode).
        alice.add_contact("bob", bob.get_public_key_hex())
        bob.add_contact("alice", alice.get_public_key_hex())

        assert alice.send_message("bob", "same mesh")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"same mesh"

    def test_unrelated_zone_not_polled(self):
        """Recv only walks zones we've explicitly pinned (or our own).

        Mallory publishes a malformed-but-recipient-targeted manifest in
        her own zone. Bob has not pinned mallory's zone. Mallory's
        manifest must not be discovered.
        """
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        mallory = DMPClient(
            "mallory", "mallory-pass", domain="mallory.mesh", store=store
        )

        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # Mallory pretends Bob is hers and publishes addressed to him.
        # Her records land at slot-N.mb-{hash(bob)}.mallory.mesh.
        mallory.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        assert mallory.send_message("bob", "you don't know me")
        # And alice sends a real message.
        assert alice.send_message("bob", "from alice")

        inbox = bob.receive_messages()
        # Bob's `_zones_to_poll` is {alice.mesh, bob.mesh}; mallory's
        # zone is not walked, so her manifest is invisible. Even if it
        # were walked, the pin fence would drop it (mallory's spk isn't
        # pinned) — but the M8.1 promise is that we don't even look.
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"from alice"
