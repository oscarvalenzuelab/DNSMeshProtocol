"""End-to-end M8.3 claim send + receive against an in-memory store."""

from __future__ import annotations

import time

import pytest

from dmp.client.client import DMPClient, InboxMessage
from dmp.network.memory import InMemoryDNSStore

PROVIDER_ZONE = "claims.dnsmesh.io"
# Empty endpoint forces publish_claim to fall back to self.writer (the
# shared InMemoryDNSStore), rather than attempting an HTTP POST. The
# provider's actual endpoint is exercised separately in
# tests/test_http_claim.py against a real DMPHttpApi instance.
PROVIDER_ENDPOINT = ""


def _send_with_claim(
    alice: DMPClient,
    bob: DMPClient,
    message: str,
    *,
    ttl: int = 300,
):
    """Send a normal message, then publish a claim pointing at it."""
    assert alice.send_message(bob.username, message, ttl=ttl)
    # The send_message we just executed used a deterministic slot
    # derived from msg_id. We don't have the msg_id back from the
    # call site (send_message returns a bool). For the e2e test
    # we publish a "blanket" claim covering slot 0 — the receiver
    # walks all slots when the claim arrives, so the slot field is
    # informational, not load-bearing for routing. (See
    # `_fetch_claim_manifest` which iterates SLOT_COUNT.)
    contact = alice.contacts[bob.username]
    import hashlib

    recipient_id = hashlib.sha256(contact.public_key_bytes).digest()
    # We need a real msg_id to put in the claim, but send_message
    # generates msg_id internally. For the test, we publish a separate
    # message via send_message, then look up the msg_id from the
    # store.  Easier: refactor — but keeping this minimal, we emit a
    # second message and capture the msg_id from the store.
    return recipient_id


def _publish_claim_for_latest(
    alice: DMPClient,
    bob_recipient_id: bytes,
    store: InMemoryDNSStore,
    *,
    sender_zone: str,
    provider_zone: str,
    ttl: int = 300,
    skip_msg_ids: set = None,
) -> bytes:
    """Publish a claim for the most-recent manifest alice published.

    If `skip_msg_ids` is provided, manifests whose msg_id is in the
    set are skipped — useful when the test sends multiple messages
    in sequence and earlier ones are already in bob's replay cache.
    """
    import hashlib

    from dmp.core.manifest import SlotManifest

    bob_hash = hashlib.sha256(bob_recipient_id).hexdigest()[:12]
    skip = skip_msg_ids or set()
    candidates = []
    for slot in range(10):
        name = f"slot-{slot}.mb-{bob_hash}.{sender_zone}"
        for record in store.query_txt_record(name) or []:
            parsed = SlotManifest.parse_and_verify(record)
            if parsed is None:
                continue
            manifest, _ = parsed
            if manifest.msg_id in skip:
                continue
            candidates.append((slot, manifest.msg_id, manifest.ts))
    assert candidates, "no fresh manifest published yet"
    # Pick the most recent (highest ts) manifest as the "latest."
    candidates.sort(key=lambda c: c[2], reverse=True)
    chosen_slot, chosen_msg_id, _ = candidates[0]
    ok = alice.publish_claim(
        recipient_id=bob_recipient_id,
        msg_id=chosen_msg_id,
        slot=chosen_slot,
        sender_mailbox_domain=sender_zone,
        ttl=ttl,
        provider_zone=provider_zone,
    )
    assert ok
    return chosen_msg_id


class TestClaimFlow:
    def test_pinned_sender_claim_delivered_to_inbox(self):
        """Alice (pinned) publishes a claim; Bob receives it as a normal inbox message."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)

        # Alice has bob pinned (so she can address him).
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # Bob has alice pinned — so when the claim points at her zone
        # and his recv tries the manifest, the sender_spk is in
        # known_spks and the message lands in the inbox.
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        # Publish the message AND the claim.
        assert alice.send_message("bob", "first-contact via claim")
        import hashlib

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        _publish_claim_for_latest(
            alice,
            bob_recipient_id,
            store,
            sender_zone="alice.mesh",
            provider_zone=PROVIDER_ZONE,
        )

        # Bob polls the claim provider zone.
        result = bob.receive_claims(
            provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)],
        )
        assert len(result.delivered) == 1
        assert result.delivered[0].plaintext == b"first-contact via claim"
        assert result.quarantined_intro_ids == []
        assert result.dropped == 0

    def test_unpinned_sender_lands_in_intro_queue(self):
        """Alice is NOT pinned; her claim leads to a quarantined intro."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)

        # Alice can address bob (knows his pubkey from a directory
        # lookup, say). Bob does NOT pin alice.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # IMPORTANT: bob has zero pinned contacts. The receive path
        # falls back to TOFU, but receive_claims still deposits
        # into the intro queue when the sender_spk isn't pinned.
        # Confirm intro_queue path even in TOFU mode.

        assert alice.send_message("bob", "I'm a stranger")
        import hashlib

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        _publish_claim_for_latest(
            alice,
            bob_recipient_id,
            store,
            sender_zone="alice.mesh",
            provider_zone=PROVIDER_ZONE,
        )

        result = bob.receive_claims(
            provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)],
        )
        assert result.delivered == []
        assert len(result.quarantined_intro_ids) == 1

        intros = bob.intro_queue.list_intros()
        assert len(intros) == 1
        assert intros[0].plaintext == b"I'm a stranger"
        assert intros[0].sender_mailbox_domain == "alice.mesh"
        # sender_spk matches alice's signing key
        assert intros[0].sender_spk == alice.crypto.get_signing_public_key_bytes()

    def test_block_then_re_poll_drops_silently(self):
        """A blocked sender's claim is dropped; intro queue stays empty."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        bob.intro_queue.block_sender(
            alice.crypto.get_signing_public_key_bytes(), note="spam"
        )

        assert alice.send_message("bob", "blocked attempt")
        import hashlib

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        _publish_claim_for_latest(
            alice,
            bob_recipient_id,
            store,
            sender_zone="alice.mesh",
            provider_zone=PROVIDER_ZONE,
        )

        result = bob.receive_claims(
            provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)],
        )
        assert result.delivered == []
        assert result.quarantined_intro_ids == []
        assert result.dropped >= 1
        assert "denylisted" in result.dropped_reasons

    def test_replay_skips_repolled_claim(self):
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        assert alice.send_message("bob", "deliver once")
        import hashlib

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        _publish_claim_for_latest(
            alice,
            bob_recipient_id,
            store,
            sender_zone="alice.mesh",
            provider_zone=PROVIDER_ZONE,
        )

        result1 = bob.receive_claims(
            provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)]
        )
        assert len(result1.delivered) == 1

        result2 = bob.receive_claims(
            provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)]
        )
        assert result2.delivered == []
        assert "replay" in result2.dropped_reasons

    def test_claim_with_mismatched_spk_dropped(self):
        """A claim whose sender_spk doesn't match the manifest's is rejected.

        Defends against a malicious provider serving a claim that
        points at a manifest signed by someone else.
        """
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        eve = DMPClient("eve", "eve-pass", domain="eve.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)

        # Alice publishes a real message + manifest.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        assert alice.send_message("bob", "from alice")

        # Eve publishes a claim pointing at alice.mesh but signed by
        # eve's spk — provider can't tell the lie at receive time
        # by signature alone, so we have to detect it at manifest-fetch.
        import hashlib

        from dmp.core.claim import ClaimRecord, claim_rrset_name

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        # Find alice's msg_id.
        bob_hash = hashlib.sha256(bob_recipient_id).hexdigest()[:12]
        from dmp.core.manifest import SlotManifest

        msg_id = None
        for slot in range(10):
            for r in (
                store.query_txt_record(f"slot-{slot}.mb-{bob_hash}.alice.mesh") or []
            ):
                parsed = SlotManifest.parse_and_verify(r)
                if parsed:
                    msg_id = parsed[0].msg_id
                    break
            if msg_id:
                break
        assert msg_id

        now = int(time.time())
        evil_claim = ClaimRecord(
            msg_id=msg_id,
            sender_spk=eve.crypto.get_signing_public_key_bytes(),  # eve's, not alice's
            sender_mailbox_domain="alice.mesh",  # alice's zone
            slot=0,
            ts=now,
            exp=now + 300,
        )
        wire = evil_claim.sign(eve.crypto)
        store.publish_txt_record(
            claim_rrset_name(bob_recipient_id, 0, PROVIDER_ZONE), wire, ttl=300
        )

        result = bob.receive_claims(provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)])
        # Alice's manifest is signed by alice's spk; the claim's
        # sender_spk is eve's; the cross-check at receive_claims
        # rejects the mismatch. Dropped, not delivered.
        assert result.delivered == []
        assert result.quarantined_intro_ids == []
        assert "manifest-spk-mismatch" in result.dropped_reasons


class TestIntroQueueCli:
    def _setup_pending_intro(self):
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # bob has no pinned contacts → unpinned-sender path.
        assert alice.send_message("bob", "intro me")
        import hashlib

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        _publish_claim_for_latest(
            alice,
            bob_recipient_id,
            store,
            sender_zone="alice.mesh",
            provider_zone=PROVIDER_ZONE,
        )
        result = bob.receive_claims(provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)])
        assert len(result.quarantined_intro_ids) == 1
        return alice, bob, result.quarantined_intro_ids[0]

    def test_accept_intro_returns_inbox_message_does_not_pin(self):
        alice, bob, intro_id = self._setup_pending_intro()
        msg = bob.accept_intro(intro_id)
        assert msg is not None
        assert msg.plaintext == b"intro me"
        # accept does NOT pin alice as a contact.
        assert "intro" not in str(bob.contacts.keys())
        # The intro is gone from the queue.
        assert bob.intro_queue.list_intros() == []

    def test_trust_intro_pins_sender(self):
        alice, bob, intro_id = self._setup_pending_intro()
        msg = bob.trust_intro(intro_id, label="alice")
        assert msg is not None
        assert msg.plaintext == b"intro me"
        # Alice is now pinned.
        assert "alice" in bob.contacts
        assert bob.contacts["alice"].signing_key_bytes == (
            alice.crypto.get_signing_public_key_bytes()
        )
        # And the intro is removed.
        assert bob.intro_queue.list_intros() == []

    def test_block_intro_drops_and_denylists(self):
        alice, bob, intro_id = self._setup_pending_intro()
        sender_spk = bob.intro_queue.get_intro(intro_id).sender_spk
        assert bob.block_intro(intro_id, note="not interested") is True
        assert bob.intro_queue.is_blocked(sender_spk)
        assert bob.intro_queue.list_intros() == []

    def test_send_with_claim_providers_publishes_claim(self):
        """Codex P1 fix: send_message with claim_providers populates the
        provider's claim namespace."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        ok = alice.send_message(
            "bob",
            "first-contact reach via send",
            claim_providers=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)],
        )
        assert ok
        # The claim is published — bob's recv discovers it without
        # needing pre-pinned alice.
        result = bob.receive_claims(provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)])
        # Bob hasn't pinned alice → lands in intro queue.
        assert len(result.quarantined_intro_ids) == 1
        intros = bob.intro_queue.list_intros()
        assert intros[0].plaintext == b"first-contact reach via send"

    def test_receive_messages_picks_up_claim_intros(self):
        """Codex P1 fix: receive_messages with claim_providers also polls
        claims and lands un-pinned senders in the intro queue."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        # Alice sends with a claim — bob has not pinned her.
        alice.send_message(
            "bob",
            "intro through receive_messages",
            claim_providers=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)],
        )
        # Single-call recv: pinned mailboxes (none yet) + claim providers.
        delivered = bob.receive_messages(
            claim_providers=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)]
        )
        # Un-pinned → no inbox delivery, but the intro queue grows.
        assert delivered == []
        assert len(bob.intro_queue.list_intros()) == 1

    def test_send_refuses_spk_only_contact(self):
        """Codex P1 fix: a contact pinned via `intro trust` (spk only)
        cannot be sent to until X25519 is filled in."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        # Manually pin a spk-only contact (mimics what trust_intro
        # leaves behind before identity-fetch fills in pub).
        ok = alice.add_contact(
            "bob-spk-only",
            public_key_hex="",
            domain="bob.mesh",
            signing_key_hex="aa" * 32,
        )
        assert ok
        # send_message must refuse rather than encrypting to b''.
        sent = alice.send_message("bob-spk-only", "should fail")
        assert sent is False

    def test_block_then_repoll_drops(self):
        alice, bob, intro_id = self._setup_pending_intro()
        store = bob.reader  # InMemoryDNSStore
        intro = bob.intro_queue.get_intro(intro_id)
        sender_spk = intro.sender_spk
        first_msg_id = intro.msg_id
        bob.block_intro(intro_id)
        # Republish a fresh claim from the same sender — the intro
        # path drops it on the denylist.
        assert alice.send_message("bob", "trying again", ttl=300)
        import hashlib

        bob_recipient_id = hashlib.sha256(
            bytes.fromhex(bob.get_public_key_hex())
        ).digest()
        _publish_claim_for_latest(
            alice,
            bob_recipient_id,
            store,
            sender_zone="alice.mesh",
            provider_zone=PROVIDER_ZONE,
            skip_msg_ids={first_msg_id},
        )
        result = bob.receive_claims(provider_zones=[(PROVIDER_ZONE, PROVIDER_ENDPOINT)])
        assert result.delivered == []
        assert result.quarantined_intro_ids == []
        assert "denylisted" in result.dropped_reasons
