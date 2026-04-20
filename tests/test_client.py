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
                assert len(value.encode("utf-8")) <= 255, (
                    f"TXT record at {name} is {len(value)} bytes — exceeds DNS per-string limit"
                )

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
                ts=int(time.time()),
                exp=int(time.time()) + 300,
            ).sign(eve.crypto)
            store.publish_txt_record(
                f"slot-{slot}.mb-{mb_hash}.mesh.test", junk
            )

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
        bob_recipient_id = hashlib.sha256(bytes.fromhex(bob.get_public_key_hex())).digest()
        forged = SlotManifest(
            msg_id=uuid.uuid4().bytes,
            sender_spk=alice.crypto.get_signing_public_key_bytes(),  # claims alice
            recipient_id=bob_recipient_id,
            total_chunks=1,
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
