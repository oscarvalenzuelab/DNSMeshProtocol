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
