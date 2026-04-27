"""M10 — receiver-zone claim notification tests.

Covers the 12 scenarios from docs/protocol/notifications.md "Implementation
scope". Two surface areas:

  1. Server-side: un-TSIG'd UPDATE accept path under
     ``DMP_RECEIVER_CLAIM_NOTIFICATIONS=1``, signature/wire validation,
     per-recipient-hash rate limiting, opt-out default.
  2. Client-side: phase-1 own-zone claim poll, phase-2 slot-walk
     fallback, dedup across phases, intro-queue routing for non-pinned
     senders, ``primary_only`` / ``skip_primary`` diagnostic toggles.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import time

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.update
import pytest

from dmp.client.client import DMPClient
from dmp.core.claim import ClaimRecord, claim_rrset_name
from dmp.core.crypto import DMPCrypto
from dmp.network.memory import InMemoryDNSStore
from dmp.server.dns_server import DMPDnsServer
from dmp.server.rate_limit import RateLimit

# ---------------------------------------------------------------------------
# Client-side fixtures
# ---------------------------------------------------------------------------


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _alice_bob_pinned(store: InMemoryDNSStore):
    """Build an alice→bob pair where each pins the other's signing key.

    Both contacts carry an explicit ``domain``, so M10 phase-1 publishes
    land on the recipient's zone and bob's phase-1 poll finds them on
    his own zone.
    """
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
    return alice, bob


# ---------------------------------------------------------------------------
# Phase-1 client-side scenarios
# ---------------------------------------------------------------------------


class TestM10Client:
    def test_happy_path_primary_delivery(self):
        """Phase 1 picks up the M10 claim from bob's own zone and delivers
        the message to bob's inbox in a single round-trip."""
        store = InMemoryDNSStore()
        alice, bob = _alice_bob_pinned(store)

        ok = alice.send_message("bob", "primary-path delivery", claim_writer=store)
        assert ok

        # The M10 claim should be sitting under bob's zone now.
        bob_recipient = hashlib.sha256(bytes.fromhex(bob.get_public_key_hex())).digest()
        h12 = hashlib.sha256(bob_recipient).hexdigest()[:12]
        any_claim = False
        for slot in range(10):
            if store.query_txt_record(f"claim-{slot}.mb-{h12}.bob.mesh"):
                any_claim = True
                break
        assert any_claim, "alice's M10 publish did not land on bob's zone"

        # Phase 1 only — confirm the claim path delivers without phase 2.
        delivered = bob.receive_messages(primary_only=True)
        assert len(delivered) == 1
        assert delivered[0].plaintext == b"primary-path delivery"
        assert delivered[0].sender_signing_pk == (
            alice.crypto.get_signing_public_key_bytes()
        )

    def test_fallback_to_secondary_when_claim_drops(self):
        """If alice's M10 claim never lands at bob's zone (split-store
        simulating a recipient whose home node refused the publish),
        phase 2 still delivers via the slot walk on alice's zone."""
        sender_store = InMemoryDNSStore()
        # A separate "recipient zone" backing means alice's M10 publish
        # has nowhere to land — publish_claim's same-zone path uses
        # ``self.writer``, which IS sender_store; alice's perspective on
        # bob's zone is just the same store, so we have to actively
        # refuse the M10 publish to simulate a recipient drop. We do
        # that by making bob's contact carry a domain alice doesn't
        # share AND short-circuiting publish_claim with a writer that
        # rejects the recipient-zone path.
        alice = DMPClient(
            "alice", "alice-pass", domain="alice.mesh", store=sender_store
        )
        bob = DMPClient("bob", "bob-pass", domain="alice.mesh", store=sender_store)
        # Both clients see the same shared store at "alice.mesh"; bob's
        # contact for alice carries a *different* domain (bob.mesh), so
        # alice's M10 publish targets a zone that doesn't exist in the
        # shared store. publish_claim will best-effort fail.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",  # zone alice can't reach
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        # Refuse the M10 claim publish by pointing publish_claim at a
        # writer that rejects bob.mesh. Easier: drop the claim_writer
        # for the M10 path by passing a no-op writer that returns False.
        class _NoopWriter:
            def publish_txt_record(self, *_a, **_kw):
                return False

            def delete_txt_record(self, *_a, **_kw):
                return False

        outcome: list = []
        ok = alice.send_message(
            "bob",
            "secondary-fallback delivery",
            claim_writer=_NoopWriter(),
            recipient_claim_outcome=outcome,
        )
        assert ok
        # M10 claim publish failed (no-op writer returned False).
        assert outcome == [False]

        # bob's domain == "alice.mesh" so phase 2 walks the slot at
        # alice.mesh and finds the manifest. Use skip_primary to make
        # the test outcome unambiguous.
        delivered = bob.receive_messages(skip_primary=True)
        assert len(delivered) == 1
        assert delivered[0].plaintext == b"secondary-fallback delivery"

    def test_dedup_across_primary_and_secondary(self):
        """Phase 1 and phase 2 each see a path to the same message;
        the replay cache ensures only one delivery."""
        store = InMemoryDNSStore()
        alice, bob = _alice_bob_pinned(store)

        # Bob's contact for alice already carries domain="alice.mesh".
        # So phase 2 walks alice.mesh slots; phase 1 walks bob.mesh
        # claims. Both find the message.
        ok = alice.send_message("bob", "dedup test", claim_writer=store)
        assert ok

        delivered = bob.receive_messages()
        assert len(delivered) == 1
        assert delivered[0].plaintext == b"dedup test"

        # Re-poll: replay cache suppresses everything.
        again = bob.receive_messages()
        assert again == []

    def test_recipient_zone_unreachable(self):
        """Same as the secondary-fallback test but framed from the
        sender's perspective: the recipient's home node is dead, so
        the M10 publish silently fails and the recipient's pinned
        slot-walk recovers."""
        sender_store = InMemoryDNSStore()
        alice = DMPClient(
            "alice", "alice-pass", domain="alice.mesh", store=sender_store
        )
        bob = DMPClient("bob", "bob-pass", domain="alice.mesh", store=sender_store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="dead.mesh",  # unreachable zone
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        class _DeadZoneWriter:
            def publish_txt_record(self, name, *_a, **_kw):
                # Anything addressed to dead.mesh fails.
                if name.endswith(".dead.mesh"):
                    return False
                return sender_store.publish_txt_record(name, *_a, **_kw)

            def delete_txt_record(self, *_a, **_kw):
                return sender_store.delete_txt_record(*_a, **_kw)

        outcome: list = []
        ok = alice.send_message(
            "bob",
            "claim publish bounced",
            claim_writer=_DeadZoneWriter(),
            recipient_claim_outcome=outcome,
        )
        assert ok
        assert outcome == [False]

        delivered = bob.receive_messages(skip_primary=True)
        assert len(delivered) == 1

    def test_sender_zone_unreachable(self):
        """The recipient sees a claim on their own zone but the manifest
        fetch from the sender's zone fails — no inbox delivery, no crash."""
        recipient_store = InMemoryDNSStore()
        # bob's own zone has the claim but no manifest is reachable at
        # alice's claimed sender_mailbox_domain.
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=recipient_store)
        alice_signer = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        bob.add_contact(
            "alice",
            "11" * 32,  # any X25519 hex; not used on the recv path
            domain="ghost.mesh",
            signing_key_hex=alice_signer.get_signing_public_key_bytes().hex(),
        )

        # Forge a claim at bob's zone pointing at a sender zone whose
        # manifest doesn't exist in recipient_store.
        bob_recipient = hashlib.sha256(bytes.fromhex(bob.get_public_key_hex())).digest()
        now = int(time.time())
        claim = ClaimRecord(
            msg_id=b"\x42" * 16,
            sender_spk=alice_signer.get_signing_public_key_bytes(),
            sender_mailbox_domain="ghost.mesh",
            slot=0,
            ts=now,
            exp=now + 300,
        )
        wire = claim.sign(alice_signer)
        recipient_store.publish_txt_record(
            claim_rrset_name(bob_recipient, 0, "bob.mesh"), wire, ttl=300
        )

        delivered = bob.receive_messages(primary_only=True)
        # Pending message — no manifest → drop.  The receive call
        # returns cleanly; the claim is dropped (manifest-not-found)
        # rather than crashing.
        assert delivered == []

    def test_cross_recipient_replay(self):
        """A captured claim re-published under a different recipient's
        hash12 is invisible: recipients only query names keyed on their
        OWN hash12."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        carol = DMPClient("carol", "carol-pass", domain="bob.mesh", store=store)

        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        carol.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        # Alice sends to bob — claim lands at bob's hash12 RRset.
        ok = alice.send_message("bob", "for bob only", claim_writer=store)
        assert ok

        # Re-publish that claim under carol's hash12 by manually crafting
        # the RRset name. Carol queries her own hash12 — different name —
        # so the replayed claim never surfaces in her recv.
        bob_h12 = hashlib.sha256(
            hashlib.sha256(bytes.fromhex(bob.get_public_key_hex())).digest()
        ).hexdigest()[:12]
        carol_h12 = hashlib.sha256(
            hashlib.sha256(bytes.fromhex(carol.get_public_key_hex())).digest()
        ).hexdigest()[:12]
        # Find any claim record sitting under bob's hash12.
        captured = None
        for slot in range(10):
            recs = store.query_txt_record(f"claim-{slot}.mb-{bob_h12}.bob.mesh")
            if recs:
                captured = recs[0]
                break
        assert captured
        store.publish_txt_record(f"claim-0.mb-{carol_h12}.bob.mesh", captured, ttl=300)

        delivered = carol.receive_messages(primary_only=True)
        # Carol's claim wire (parsed) has recipient hash baked in via
        # the RRset name only; the wire itself doesn't carry the full
        # recipient_id. But the manifest at alice.mesh has bob's
        # recipient_id — which doesn't match carol's user_id. Cross-
        # recipient replay → manifest-recipient-mismatch drop.
        assert delivered == []

    def test_signature_passing_claim_from_non_pinned_lands_in_intro(self):
        """A claim with a valid signature but from a sender bob hasn't
        pinned ends up in the intro queue, not the inbox. Bob must have
        at least one OTHER pin so phase 1 isn't skipped under the pure-
        TOFU rule."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        eve = DMPClient("eve", "eve-pass", domain="eve.mesh", store=store)

        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        eve.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # Bob pins ALICE (some pin so he's not in pure TOFU mode), but
        # NOT eve. Eve's claim is the one we'll exercise.
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        ok = eve.send_message("bob", "stranger says hi", claim_writer=store)
        assert ok

        result = bob.receive_claims_from_own_zone()
        # Eve isn't pinned; the M10 claim path quarantines it as an
        # intro, mirroring M8.2 first-contact semantics.
        assert result.delivered == []
        assert len(result.quarantined_intro_ids) == 1
        intros = bob.intro_queue.list_intros()
        assert intros[0].plaintext == b"stranger says hi"
        assert intros[0].sender_spk == eve.crypto.get_signing_public_key_bytes()

    def test_primary_only_flag_runs_phase1_only(self):
        """``primary_only=True`` exercises phase 1 in isolation. Sending
        a message via the slot-walk-only path (no claim) yields zero
        deliveries under ``primary_only``."""
        store = InMemoryDNSStore()
        alice, bob = _alice_bob_pinned(store)

        # Send the message but BLOCK the M10 claim publish at the writer
        # so only the slot-walk record exists.
        class _NoClaimWriter:
            def publish_txt_record(self, name, *_a, **_kw):
                # M10 publish targets bob's zone; route those to /dev/null.
                if "bob.mesh" in name and name.startswith("claim-"):
                    return False
                return store.publish_txt_record(name, *_a, **_kw)

            def delete_txt_record(self, *_a, **_kw):
                return store.delete_txt_record(*_a, **_kw)

        ok = alice.send_message("bob", "phase-1-only", claim_writer=_NoClaimWriter())
        assert ok
        # No claim landed; phase 1 finds nothing.
        primary_delivered = bob.receive_messages(primary_only=True)
        assert primary_delivered == []
        # Phase 2 finds the message via the slot walk.
        secondary_delivered = bob.receive_messages(skip_primary=True)
        assert len(secondary_delivered) == 1
        assert secondary_delivered[0].plaintext == b"phase-1-only"

    def test_skip_primary_flag_runs_phase2_only(self):
        """``skip_primary=True`` skips phase 1 even when a claim is
        available, exercising the legacy slot-walk path in isolation."""
        store = InMemoryDNSStore()
        alice, bob = _alice_bob_pinned(store)

        ok = alice.send_message("bob", "skip-primary", claim_writer=store)
        assert ok
        # Even though the M10 claim is in bob's zone, skip_primary
        # avoids the claim poll entirely. Phase 2 still delivers
        # because bob has alice.mesh in _zones_to_poll.
        delivered = bob.receive_messages(skip_primary=True)
        assert len(delivered) == 1
        assert delivered[0].plaintext == b"skip-primary"

    def test_primary_only_and_skip_primary_are_mutually_exclusive(self):
        store = InMemoryDNSStore()
        alice, bob = _alice_bob_pinned(store)
        with pytest.raises(ValueError):
            bob.receive_messages(primary_only=True, skip_primary=True)


# ---------------------------------------------------------------------------
# Codex round-1 regression coverage
# ---------------------------------------------------------------------------


class TestCodexRound1Regressions:
    """Locks in the three findings from the post-M10-implementation
    codex review:

      P1: ``--primary-only`` / ``--skip-primary`` MUST NOT silently
          turn off the M8.3 first-contact ``claim_providers`` channel.
      P1: ``recv_secondary_disable=true`` in pure TOFU MUST preserve
          the M9 'phase 2 delivers any signature-valid manifest'
          contract (cmd_recv-level gate).
      P2: M10 ``send_message`` MUST always exercise the recipient
          home-node opt-in gate, even same-zone — the un-TSIG'd
          UPDATE accept path is the gate, so the publish must go
          through it (not via the sender's authorized writer).
    """

    PROVIDER_ZONE = "claims.dnsmesh.io"

    def test_claim_providers_polled_under_primary_only(self):
        """Codex P1 #1: ``primary_only=True`` MUST still poll
        ``claim_providers``. Phase 2 (slot walk) is the only thing
        the diagnostic flag turns off — the M8.3 first-contact
        provider channel is orthogonal."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        eve = DMPClient("eve", "eve-pass", domain="eve.mesh", store=store)

        # Bob pins alice (so phase 1's TOFU skip rule doesn't fire),
        # but NOT eve. Eve is the unpinned stranger whose claim has
        # to land in the intro queue via the M8.3 provider channel.
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        eve.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        # Eve sends with M8.3 claim_providers ONLY (no recipient-zone
        # publish — drop bob's domain to skip the M10 path).
        eve.contacts["bob"].domain = ""  # type: ignore[attr-defined]
        ok = eve.send_message(
            "bob",
            "stranger first-contact",
            claim_providers=[(self.PROVIDER_ZONE, "")],
            claim_writer=store,
        )
        assert ok

        # Run with primary_only=True. The claim_providers polling
        # MUST still run, depositing eve's intro into the queue.
        delivered = bob.receive_messages(
            primary_only=True,
            claim_providers=[(self.PROVIDER_ZONE, "")],
        )
        assert delivered == []  # eve isn't pinned → not delivered to inbox
        intros = bob.intro_queue.list_intros()
        assert len(intros) == 1, (
            "claim_providers polling was silently turned off by "
            "primary_only — eve's first-contact intro is missing"
        )
        assert intros[0].plaintext == b"stranger first-contact"

    def test_claim_providers_polled_under_skip_primary(self):
        """Same regression flagged in the same finding: ``skip_primary``
        MUST also leave the claim_providers channel intact."""
        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        eve = DMPClient("eve", "eve-pass", domain="eve.mesh", store=store)

        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.mesh",
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        eve.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        eve.contacts["bob"].domain = ""  # type: ignore[attr-defined]
        ok = eve.send_message(
            "bob",
            "stranger via skip_primary",
            claim_providers=[(self.PROVIDER_ZONE, "")],
            claim_writer=store,
        )
        assert ok

        delivered = bob.receive_messages(
            skip_primary=True,
            claim_providers=[(self.PROVIDER_ZONE, "")],
        )
        assert delivered == []
        intros = bob.intro_queue.list_intros()
        assert len(intros) == 1
        assert intros[0].plaintext == b"stranger via skip_primary"

    def test_tofu_primary_only_override_engages_phase1(self):
        """Codex P1 #2 (lower-half check): the ``primary_only`` diagnostic
        flag DOES override the TOFU skip rule — an operator who explicitly
        asks for phase 1 gets it, regardless of pin state. This
        complements the cmd_recv-level fix that prevents the persisted
        ``recv_secondary_disable`` knob from triggering the same
        override on a fresh install."""
        store = InMemoryDNSStore()
        # No pinned contacts → pure TOFU.
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        ok = alice.send_message("bob", "tofu primary-only", claim_writer=store)
        assert ok

        # Default path (no primary_only) → phase 1 SKIPPED in pure
        # TOFU; phase 2 slot walk delivers (bob has no contact zones
        # except own, but the M10 claim isn't queried). Result: zero.
        # Phase 2 won't find anything because alice published to
        # alice.mesh, which bob's _zones_to_poll doesn't cover (no
        # pinned contact for alice). So: zero deliveries — which is
        # the legitimate pre-M10 behavior for a TOFU receiver who
        # doesn't even know alice exists.
        delivered_default = bob.receive_messages()
        assert delivered_default == []

        # Explicit primary_only=True overrides TOFU skip → phase 1
        # runs → finds the M10 claim → quarantines into intro queue
        # because the sender_spk isn't pinned.
        delivered_forced = bob.receive_messages(primary_only=True)
        assert delivered_forced == []
        # The intro should be there from the forced phase 1 pass.
        assert len(bob.intro_queue.list_intros()) == 1


class TestCodexRound1ServerSameZone:
    """Codex P2 #3 server-side coverage: a same-zone M10 publish from
    ``send_message`` MUST be REFUSED when the recipient's home node
    has ``DMP_RECEIVER_CLAIM_NOTIFICATIONS=0``. Previously the
    same-zone branch fell through to ``self.writer`` (the sender's
    authorized writer), bypassing the opt-in entirely."""

    def test_same_zone_send_message_un_tsig_d_path_invoked(self):
        """Whitebox: confirm send_message routes the M10 publish
        through ``_publish_claim_via_dns_update``, not the
        TSIG'd writer, even when ``contact.domain == self.domain``."""
        from dmp.client import client as _client

        store = InMemoryDNSStore()
        # Same-zone deployment: alice + bob both on dmp.example.com.
        alice = DMPClient("alice", "alice-pass", domain="dmp.example.com", store=store)
        bob = DMPClient("bob", "bob-pass", domain="dmp.example.com", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="dmp.example.com",  # SAME zone as alice's
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        captured: list = []
        original = _client._publish_claim_via_dns_update

        def _capture_un_tsig_d(*, zone, target, name, wire, ttl, **kw):
            captured.append({"zone": zone, "target": target, "name": name})
            # Pretend the un-TSIG'd UPDATE succeeded so send_message
            # returns True.
            return True

        # Also stub the target resolver so we don't need real DNS.
        _client._provider_dns_target = lambda *_a, **_k: ("127.0.0.1", 5353)
        _client._publish_claim_via_dns_update = _capture_un_tsig_d
        try:
            ok = alice.send_message("bob", "same-zone but un-TSIG'd")
        finally:
            _client._publish_claim_via_dns_update = original

        assert ok, "send_message should still succeed"
        assert len(captured) == 1, (
            "M10 publish did NOT route through "
            "_publish_claim_via_dns_update — same-zone bypass regressed"
        )
        assert captured[0]["zone"] == "dmp.example.com"
        assert captured[0]["name"].endswith(".dmp.example.com")

    def test_same_zone_publish_refused_when_server_flag_off(self):
        """Server-level: a real DMPDnsServer with both flags off MUST
        REFUSE the M10 publish even when the un-TSIG'd UPDATE is sent
        from a host that would otherwise be inside the served zone.
        Confirms the operator opt-out actually keeps the surface closed."""
        store = InMemoryDNSStore()
        port = _free_port()
        # Both un-TSIG'd accept flags OFF — the operator hasn't opted
        # into either M8.3 or M10. TSIG is configured (some other
        # users on this node are publishing their own records via
        # TSIG'd UPDATE), but the un-TSIG'd surface stays closed.
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring={},
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=False,
        )
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        wire = _claim_wire(sender, recipient_id, sender_zone="dmp.example.com")
        owner = f"claim-0.mb-{h12}.dmp.example.com."

        with server:
            upd = dns.update.UpdateMessage("dmp.example.com")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED, (
            f"same-zone un-TSIG'd UPDATE should be REFUSED with "
            f"both flags off, got {dns.rcode.to_text(response.rcode())}"
        )
        assert store.query_txt_record(owner.rstrip(".")) is None


# ---------------------------------------------------------------------------
# Server-side scenarios — real DNS server + UDP
# ---------------------------------------------------------------------------


def _send_update(update: dns.update.UpdateMessage, port: int):
    return dns.query.udp(update, "127.0.0.1", port=port, timeout=2.0)


def _claim_wire(
    sender_crypto: DMPCrypto,
    recipient_id: bytes,
    *,
    sender_zone: str = "alice.example.com",
    slot: int = 0,
    ttl: int = 300,
):
    """Build + sign a ClaimRecord wire for tests."""
    now = int(time.time())
    claim = ClaimRecord(
        msg_id=b"\x42" * 16,
        sender_spk=sender_crypto.get_signing_public_key_bytes(),
        sender_mailbox_domain=sender_zone,
        slot=slot,
        ts=now,
        exp=now + ttl,
    )
    return claim.sign(sender_crypto)


class TestM10Server:
    def test_default_refuses_m10_writes_when_flag_off(self):
        """Both DMP_CLAIM_PROVIDER and DMP_RECEIVER_CLAIM_NOTIFICATIONS
        default to off. An un-TSIG'd UPDATE for a valid claim wire under
        the served zone must be REFUSED."""
        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring={},  # any keyring; we don't use it
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=False,  # opt-out
        )
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        wire = _claim_wire(sender, recipient_id)
        owner = f"claim-0.mb-{h12}.dmp.example.com."

        with server:
            upd = dns.update.UpdateMessage("dmp.example.com")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED
        assert store.query_txt_record(owner.rstrip(".")) is None

    def test_m10_flag_enables_un_tsig_d_publish(self):
        """With DMP_RECEIVER_CLAIM_NOTIFICATIONS=1, a verified claim wire
        publishes successfully even though DMP_CLAIM_PROVIDER stays off."""
        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring={},
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=True,
        )
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        wire = _claim_wire(sender, recipient_id)
        owner = f"claim-0.mb-{h12}.dmp.example.com."

        with server:
            upd = dns.update.UpdateMessage("dmp.example.com")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.NOERROR
        assert store.query_txt_record(owner.rstrip(".")) == [wire]

    def test_bad_signature_refused(self):
        """A claim wire whose signature is corrupted fails verification at
        the server and the UPDATE is REFUSED — no record lands."""
        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring={},
            allowed_zones=("dmp.example.com",),
            receiver_claim_publish_enabled=True,
        )
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        wire = _claim_wire(sender, recipient_id)
        # Flip a few bits inside the base64 body so the signature no
        # longer verifies under sender_spk.
        prefix, body = wire.split(";", 2)[:2], wire.split(";", 2)[2]
        decoded = bytearray(base64.b64decode(body))
        decoded[-1] ^= 0xFF  # corrupt the trailing signature byte
        forged = ";".join(prefix) + ";" + base64.b64encode(bytes(decoded)).decode()
        owner = f"claim-0.mb-{h12}.dmp.example.com."

        with server:
            upd = dns.update.UpdateMessage("dmp.example.com")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + forged.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED
        assert store.query_txt_record(owner.rstrip(".")) is None

    def test_rate_limit_exhaustion_returns_servfail(self):
        """Per-recipient-hash bucket: once burst is exhausted, further
        UPDATEs for the SAME hash12 are answered SERVFAIL until the
        bucket refills. Distinct from REFUSED for shape violations:
        SERVFAIL signals a transient backoff to the legitimate sender."""
        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring={},
            allowed_zones=("dmp.example.com",),
            receiver_claim_publish_enabled=True,
            # Tight bucket so the test exhausts in two writes without
            # waiting for refill.
            claim_rate_limit=RateLimit(rate_per_second=0.01, burst=2),
        )
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        owner = f"claim-0.mb-{h12}.dmp.example.com."

        with server:
            # Generate fresh wires so duplicate-RR collapsing in the
            # store doesn't mask the count.
            for i in range(2):
                wire = _claim_wire(
                    sender, recipient_id, sender_zone=f"a{i}.example.com"
                )
                upd = dns.update.UpdateMessage("dmp.example.com")
                upd.add(
                    dns.name.from_text(owner),
                    300,
                    "TXT",
                    '"' + wire.replace('"', r"\"") + '"',
                )
                response = _send_update(upd, port)
                assert response.rcode() == dns.rcode.NOERROR

            # Third write within burst window → bucket empty → SERVFAIL.
            wire = _claim_wire(sender, recipient_id, sender_zone="overflow.example.com")
            upd = dns.update.UpdateMessage("dmp.example.com")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
            assert response.rcode() == dns.rcode.SERVFAIL
