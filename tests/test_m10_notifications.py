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


@pytest.fixture
def m10_un_tsig_d_to_store():
    """Redirect ``_publish_claim_via_dns_update`` to the test store.

    The M10 send path uses ``force_un_tsig_d=True`` so the recipient
    home node's ``DMP_RECEIVER_CLAIM_NOTIFICATIONS`` gate fires (codex
    round-2 P1: a writer override would defeat the gate). For unit
    tests that don't run a real DNS server, this fixture monkey-patches
    the un-TSIG'd UPDATE function to write directly into a shared
    in-memory store, simulating "the recipient's node accepted the
    publish." Tests yield ``(restore, redirector)`` where
    ``redirector(store)`` installs the patch against a specific store
    and ``restore()`` rolls it back.
    """
    from dmp.client import client as _client

    original = _client._publish_claim_via_dns_update

    def _redirect(store: InMemoryDNSStore):
        def _to_store(*, zone, target, name, wire, ttl, resolver_pool=None):
            return bool(store.publish_txt_record(name, wire, ttl=int(ttl)))

        _client._publish_claim_via_dns_update = _to_store

    yield _redirect
    _client._publish_claim_via_dns_update = original


# ---------------------------------------------------------------------------
# Phase-1 client-side scenarios
# ---------------------------------------------------------------------------


class TestM10Client:
    def test_happy_path_primary_delivery(self, m10_un_tsig_d_to_store):
        """Phase 1 picks up the M10 claim from bob's own zone and delivers
        the message to bob's inbox in a single round-trip."""
        store = InMemoryDNSStore()
        m10_un_tsig_d_to_store(store)
        alice, bob = _alice_bob_pinned(store)

        ok = alice.send_message("bob", "primary-path delivery")
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

    def test_dedup_across_primary_and_secondary(self, m10_un_tsig_d_to_store):
        """Phase 1 and phase 2 each see a path to the same message;
        the replay cache ensures only one delivery."""
        store = InMemoryDNSStore()
        m10_un_tsig_d_to_store(store)
        alice, bob = _alice_bob_pinned(store)

        # Bob's contact for alice already carries domain="alice.mesh".
        # So phase 2 walks alice.mesh slots; phase 1 walks bob.mesh
        # claims. Both find the message.
        ok = alice.send_message("bob", "dedup test")
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

    def test_cross_recipient_replay(self, m10_un_tsig_d_to_store):
        """A captured claim re-published under a different recipient's
        hash12 is invisible: recipients only query names keyed on their
        OWN hash12."""
        store = InMemoryDNSStore()
        m10_un_tsig_d_to_store(store)
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
        ok = alice.send_message("bob", "for bob only")
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

    def test_signature_passing_claim_from_non_pinned_lands_in_intro(
        self, m10_un_tsig_d_to_store
    ):
        """A claim with a valid signature but from a sender bob hasn't
        pinned ends up in the intro queue, not the inbox. Bob must have
        at least one OTHER pin so phase 1 isn't skipped under the pure-
        TOFU rule."""
        store = InMemoryDNSStore()
        m10_un_tsig_d_to_store(store)
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

        ok = eve.send_message("bob", "stranger says hi")
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

    def test_tofu_primary_only_override_engages_phase1(self, m10_un_tsig_d_to_store):
        """Codex P1 #2 (lower-half check): the ``primary_only`` diagnostic
        flag DOES override the TOFU skip rule — an operator who explicitly
        asks for phase 1 gets it, regardless of pin state. This
        complements the cmd_recv-level fix that prevents the persisted
        ``recv_secondary_disable`` knob from triggering the same
        override on a fresh install."""
        store = InMemoryDNSStore()
        m10_un_tsig_d_to_store(store)
        # No pinned contacts → pure TOFU.
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        ok = alice.send_message("bob", "tofu primary-only")
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


class TestCodexRound6LocalDnsFallback:
    """Codex round-6 P2: ``_make_client`` MUST seed
    ``client.local_dns_server`` / ``local_dns_port`` even on HTTP-mode
    configs that haven't run ``dnsmesh tsig register``. Otherwise
    same-zone M10 publishes silently fall through to
    ``_provider_dns_target()`` and try ``<contact.domain>:53``, which
    fails on dev / split-host deployments where the auth DNS server
    is only reachable via ``cfg.dns_host`` / ``cfg.dns_port``."""

    def _build_client(self, tmp_path, monkeypatch, **cfg_overrides):
        """Run cli._make_client with a minimal config override and
        return the resulting DMPClient. Skips the network path via
        ``requires_network=False``."""
        from dmp import cli as _cli
        from dmp.cli import CLIConfig

        monkeypatch.setenv("DMP_CONFIG_HOME", str(tmp_path))
        cfg = CLIConfig(
            username="alice",
            domain="alice.mesh",
            kdf_salt="aa" * 32,
            **cfg_overrides,
        )
        return _cli._make_client(cfg, "passphrase", requires_network=False)

    def test_tsig_block_populates_local_dns(self, tmp_path, monkeypatch):
        """Post-tsig-register: TSIG fields are the canonical source."""
        client = self._build_client(
            tmp_path,
            monkeypatch,
            tsig_dns_server="alice-node.example",
            tsig_dns_port=5353,
            endpoint="http://alice-node.example:8053",
        )
        assert client.local_dns_server == "alice-node.example"
        assert client.local_dns_port == 5353

    def test_endpoint_host_used_when_tsig_unset(self, tmp_path, monkeypatch):
        """HTTP-mode pre-TSIG (codex round-12 P2): the local target
        comes from ``cfg.endpoint`` (the DMP HTTP API host = the
        auth node), NOT from ``cfg.dns_host`` (which is a read-side
        resolver). Sending un-TSIG'd UPDATE to a recursive resolver
        like 1.1.1.1 would be refused; the auth node is at the
        endpoint URL."""
        client = self._build_client(
            tmp_path,
            monkeypatch,
            dns_host="1.1.1.1",  # recursive resolver — must NOT be used
            dns_port=5353,
            endpoint="http://node.example:8053",
        )
        assert client.local_dns_server == "node.example"
        assert client.local_dns_port == 5353

    def test_dns_host_not_used_as_local_target(self, tmp_path, monkeypatch):
        """Codex round-12 P2 (negative): no endpoint, no TSIG —
        dns_host MUST NOT be used as the local target either. The
        client falls through to ``_provider_dns_target`` (zone:53)
        for same-zone publishes, which works in production zone-apex
        deployments and silently fails in dev — but never sends
        un-TSIG'd UPDATE to a recursive resolver."""
        client = self._build_client(
            tmp_path,
            monkeypatch,
            dns_host="1.1.1.1",
            dns_port=5353,
        )
        assert client.local_dns_server is None
        assert client.local_dns_port is None


class TestCodexRound5DomainExplicitPersistence:
    """Codex round-5 P2 #1: ``domain_explicit`` MUST survive contact
    rebuild paths in the CLI (intro-trust → identity-fetch upgrade).
    Without this, an upgraded contact silently loses its M10 explicit-
    domain marker on the next CLI restart and same-zone phase-1
    delivery breaks."""

    def test_contact_rebuild_preserves_domain_explicit(self):
        """Whitebox: simulate the cli ``_make_client`` rebuild path
        (used by intro-trust → identity-fetch upgrades) and confirm
        ``domain_explicit`` is preserved across the Contact swap."""
        from dmp.client.client import Contact

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        # Add a contact with an explicit domain — what
        # ``identity fetch user@host --add`` does.
        alice.add_contact(
            "intro-abc",
            "11" * 32,
            domain="bob.mesh",
            signing_key_hex="22" * 32,
        )
        existing = alice.contacts["intro-abc"]
        assert existing.domain_explicit is True, "precondition"

        # Simulate the cli rebuild: replace the Contact with a fresh
        # one carrying remote_username, the way the intro-trust
        # upgrade path does.
        alice.contacts["intro-abc"] = Contact(
            username="bob@bob.mesh",
            public_key_bytes=existing.public_key_bytes,
            signing_key_bytes=existing.signing_key_bytes,
            domain=existing.domain,
            domain_explicit=existing.domain_explicit,
        )
        rebuilt = alice.contacts["intro-abc"]
        assert rebuilt.domain_explicit is True, (
            "domain_explicit lost on rebuild — M10 publish will skip "
            "this contact on next CLI invocation"
        )
        assert rebuilt.username == "bob@bob.mesh"
        assert rebuilt.domain == "bob.mesh"


class TestCodexRound1ServerSameZone:
    """Codex P2 #3 server-side coverage: a same-zone M10 publish from
    ``send_message`` MUST be REFUSED when the recipient's home node
    has ``DMP_RECEIVER_CLAIM_NOTIFICATIONS=0``. Previously the
    same-zone branch fell through to ``self.writer`` (the sender's
    authorized writer), bypassing the opt-in entirely."""

    def test_legacy_backfilled_contact_skips_m10_publish(self):
        """Codex round-3 P1 #2: a contact with no persisted domain
        (legacy ``contacts add`` without ``identity fetch``) is
        backfilled to ``self.domain`` for prekey/rotation back-compat.
        That contact's ``domain_explicit`` stays False, so the M10
        publish is SKIPPED — those records would otherwise land in
        the SENDER's own zone where nobody queries them."""
        from dmp.client import client as _client

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="dmp.example.com", store=store)
        bob = DMPClient("bob", "bob-pass", domain="dmp.example.com", store=store)
        # Legacy add: no domain passed → backfill to self.domain,
        # domain_explicit=False.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        assert alice.contacts["bob"].domain == "dmp.example.com"
        assert alice.contacts["bob"].domain_explicit is False

        captured: list = []
        original = _client._publish_claim_via_dns_update

        def _capture(*, zone, target, name, wire, ttl, **kw):
            captured.append({"zone": zone, "name": name})
            return True

        _client._publish_claim_via_dns_update = _capture
        try:
            ok = alice.send_message("bob", "legacy backfill — no M10")
        finally:
            _client._publish_claim_via_dns_update = original

        assert ok, "send_message should still succeed (chunks landed)"
        assert captured == [], (
            f"legacy backfilled contact should NOT trigger M10 "
            f"publish, but got {len(captured)} call(s)"
        )

    def test_explicit_same_zone_send_message_publishes_m10(self):
        """Codex round-3 P1 #2 (positive): a contact whose domain
        was explicitly set (e.g. via ``dnsmesh identity fetch
        user@host --add``), even if it matches ``self.domain``, MUST
        still trigger the M10 publish so ``recv --primary-only`` and
        ``recv_secondary_disable=true`` work in same-zone deployments
        where phase 2 is the only fallback."""
        from dmp.client import client as _client

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="dmp.example.com", store=store)
        bob = DMPClient("bob", "bob-pass", domain="dmp.example.com", store=store)
        # Explicit same-zone: caller passed the zone name even though
        # it matches alice's own.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="dmp.example.com",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        assert alice.contacts["bob"].domain_explicit is True

        captured: list = []
        original = _client._publish_claim_via_dns_update
        original_target = _client._provider_dns_target

        def _capture(*, zone, target, name, wire, ttl, **kw):
            captured.append({"zone": zone, "name": name})
            return True

        _client._provider_dns_target = lambda *_a, **_k: ("127.0.0.1", 5353)
        _client._publish_claim_via_dns_update = _capture
        try:
            ok = alice.send_message("bob", "same-zone but explicit")
        finally:
            _client._publish_claim_via_dns_update = original
            _client._provider_dns_target = original_target

        assert ok
        assert len(captured) == 1, (
            "explicit same-zone contact should trigger M10 publish "
            "(needed for --primary-only / recv_secondary_disable)"
        )
        assert captured[0]["zone"] == "dmp.example.com"
        assert captured[0]["name"].endswith(".dmp.example.com")

    def test_cross_zone_send_message_routes_through_un_tsig_d(self):
        """Codex round-2 P1: cross-zone M10 publish MUST always go
        through the un-TSIG'd UPDATE path, never the writer override.
        The recipient's home node enforces the opt-in gate AND
        per-recipient rate limit, both of which only fire on the
        un-TSIG'd accept path."""
        from dmp.client import client as _client

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",  # cross-zone
            signing_key_hex=bob.get_signing_public_key_hex(),
        )

        captured: list = []
        original = _client._publish_claim_via_dns_update
        original_target = _client._provider_dns_target

        def _capture_un_tsig_d(*, zone, target, name, wire, ttl, **kw):
            captured.append({"zone": zone, "target": target, "name": name})
            return True

        _client._provider_dns_target = lambda *_a, **_k: ("127.0.0.1", 5353)
        _client._publish_claim_via_dns_update = _capture_un_tsig_d
        try:
            # Pass an explicit ``claim_writer`` to confirm force_un_tsig_d
            # wins over the writer override. Pre-fix this would have
            # silently bypassed the un-TSIG'd path and written into the
            # store directly.
            ok = alice.send_message(
                "bob", "cross-zone goes through gate", claim_writer=store
            )
        finally:
            _client._publish_claim_via_dns_update = original
            _client._provider_dns_target = original_target

        assert ok
        assert len(captured) == 1, (
            "M10 publish did NOT route through _publish_claim_via_dns_update "
            "— claim_writer override silently bypassed the gate"
        )
        assert captured[0]["zone"] == "bob.mesh"
        assert captured[0]["name"].endswith(".bob.mesh")

    def test_same_zone_publish_uses_local_dns_endpoint(self):
        """Codex round-5 P2 #2: a same-zone explicit M10 publish MUST
        target the client's pinned ``local_dns_server`` /
        ``local_dns_port`` (the local node's DNS endpoint), NOT
        whatever ``_provider_dns_target`` would derive from the zone.
        This keeps cross-zone publishes routed through the standard
        DNS chain on the operator's configured port (default 53)
        even when the local node listens on a non-standard port —
        without exporting a process-wide ``DMP_PROVIDER_DNS_PORT``
        that would also misroute the cross-zone publishes."""
        from dmp.client import client as _client

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="dmp.example.com", store=store)
        bob = DMPClient("bob", "bob-pass", domain="dmp.example.com", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="dmp.example.com",
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # Pin the local DNS endpoint — what the CLI sets from
        # ``cfg.tsig_dns_server`` / ``cfg.tsig_dns_port``.
        alice.local_dns_server = "127.0.0.1"
        alice.local_dns_port = 5353

        captured: list = []
        original = _client._publish_claim_via_dns_update
        original_target = _client._provider_dns_target

        def _capture(*, zone, target, name, wire, ttl, **kw):
            captured.append({"zone": zone, "target": target, "name": name})
            return True

        # Sentinel: if _provider_dns_target gets called, the test
        # caught a regression — the local override wasn't used.
        called_target_resolver: list = []

        def _sentinel_target(*_a, **_kw):
            called_target_resolver.append(True)
            return ("WRONG", 53)

        _client._provider_dns_target = _sentinel_target
        _client._publish_claim_via_dns_update = _capture
        try:
            ok = alice.send_message("bob", "same-zone explicit")
        finally:
            _client._publish_claim_via_dns_update = original
            _client._provider_dns_target = original_target

        assert ok
        assert len(captured) == 1
        assert captured[0]["target"] == ("127.0.0.1", 5353), (
            "M10 same-zone publish did not honor local_dns_server / " "local_dns_port"
        )
        assert called_target_resolver == [], (
            "_provider_dns_target was called for same-zone publish — "
            "the local override should win"
        )

    def test_cross_zone_publish_uses_dns_target_resolver(self):
        """Codex round-5 P2 #2 (negative): cross-zone publishes MUST
        NOT use the local DNS override. The local port pinning is
        scoped to same-zone only; cross-zone publishes resolve via
        the standard ``_provider_dns_target`` path so a dev operator
        running their own node on 5353 can still send to remote
        zones on the standard port 53."""
        from dmp.client import client as _client

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="alice.mesh", store=store)
        bob = DMPClient("bob", "bob-pass", domain="bob.mesh", store=store)
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            domain="bob.mesh",  # cross-zone
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # Pin a different local DNS endpoint — must NOT be used.
        alice.local_dns_server = "127.0.0.1"
        alice.local_dns_port = 5353

        captured: list = []
        original = _client._publish_claim_via_dns_update
        original_target = _client._provider_dns_target

        def _capture(*, zone, target, name, wire, ttl, **kw):
            captured.append({"zone": zone, "target": target, "name": name})
            return True

        _client._provider_dns_target = lambda *_a, **_k: ("203.0.113.5", 53)
        _client._publish_claim_via_dns_update = _capture
        try:
            ok = alice.send_message("bob", "cross-zone")
        finally:
            _client._publish_claim_via_dns_update = original
            _client._provider_dns_target = original_target

        assert ok
        assert len(captured) == 1
        assert captured[0]["target"] == ("203.0.113.5", 53), (
            "cross-zone publish should resolve via _provider_dns_target, "
            "not the local override"
        )

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


def _keystore_with_recipient(zone: str, recipient_hash12: str, tmp_path):
    """Build an on-disk TSIGKeyStore that has one user registered with
    a scope containing ``mb-{recipient_hash12}.{zone}``.

    M10-only mode (codex round-3 P1) gates the un-TSIG'd accept path
    on registered recipient hashes; tests exercising that mode need a
    real keystore rather than the empty ``tsig_keyring={}`` shortcut.
    """
    from dmp.server.tsig_keystore import TSIGKeyStore

    db_path = str(tmp_path / "tsig.db")
    store = TSIGKeyStore(db_path)
    store.put(
        name=f"user-{recipient_hash12}.",
        secret=b"\x33" * 32,
        allowed_suffixes=[
            f"mb-{recipient_hash12}.{zone}",
            f"slot-*.mb-{recipient_hash12}.{zone}",
        ],
    )
    return store


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

    def test_m10_flag_enables_un_tsig_d_publish(self, tmp_path):
        """With DMP_RECEIVER_CLAIM_NOTIFICATIONS=1, a verified claim
        wire for a REGISTERED recipient publishes successfully even
        though DMP_CLAIM_PROVIDER stays off. Codex round-3 P1: the
        accept path requires the recipient hash to belong to one of
        the node's registered users, so this test ships a keystore
        with the hash registered."""
        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        keystore = _keystore_with_recipient("dmp.example.com", h12, tmp_path)
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=True,
        )
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

    def test_m10_only_refuses_unregistered_recipient_hash(self, tmp_path):
        """Codex round-3 P1: M10-only mode (DMP_RECEIVER_CLAIM_NOTIFICATIONS=1
        + DMP_CLAIM_PROVIDER=0) MUST refuse claim writes whose hash12
        doesn't correspond to a registered user on the served zone.
        Otherwise the operator's M8.3 opt-out (closed first-contact
        provider role) is silently re-opened by M10."""
        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        # Register ONE recipient on the keystore.
        registered_id = hashlib.sha256(b"registered").digest()
        registered_h12 = hashlib.sha256(registered_id).hexdigest()[:12]
        keystore = _keystore_with_recipient("dmp.example.com", registered_h12, tmp_path)
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=True,
        )

        # Stranger sends a claim for a DIFFERENT hash that's NOT
        # registered on this node — server must REFUSE.
        stranger_id = hashlib.sha256(b"stranger").digest()
        stranger_h12 = hashlib.sha256(stranger_id).hexdigest()[:12]
        wire = _claim_wire(sender, stranger_id)
        owner = f"claim-0.mb-{stranger_h12}.dmp.example.com."

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
            "M10-only mode must reject claims for un-registered "
            "recipient hashes; got "
            f"{dns.rcode.to_text(response.rcode())}"
        )
        assert store.query_txt_record(owner.rstrip(".")) is None

    def test_m8_3_provider_role_accepts_any_recipient_hash(self, tmp_path):
        """When DMP_CLAIM_PROVIDER=1 (open first-contact provider tier),
        the registered-hash gate does NOT apply — the whole point of
        the M8.3 role is to accept claims for arbitrary recipients
        the operator does not know about. Codex round-3 P1: confirm
        the gate fires only in M10-only mode."""
        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        # Stranger recipient — NOT registered on this node.
        stranger_id = hashlib.sha256(b"stranger").digest()
        stranger_h12 = hashlib.sha256(stranger_id).hexdigest()[:12]
        # Empty keystore (no users registered) but provider role on.
        keystore = _keystore_with_recipient("dmp.example.com", "ffffffffffff", tmp_path)
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=True,  # M8.3 open provider tier
            receiver_claim_publish_enabled=True,
        )
        wire = _claim_wire(sender, stranger_id)
        owner = f"claim-0.mb-{stranger_h12}.dmp.example.com."

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

    def test_loose_scope_user_accepted_via_x25519_pub(self, tmp_path):
        """Codex round-4 P2 #1: a user registered under
        ``DMP_TSIG_LOOSE_SCOPE=1`` has only the bare zone in their TSIG
        scope (no ``mb-{hash}.{zone}`` entry). The M10 registered-hash
        gate MUST still admit them by recomputing the canonical hash
        from the persisted X25519 pub. Without this, an M10-only
        operator running loose-scope mode (typical for a dev / single-
        user node) would have phase-1 silently fail for everyone."""
        from dmp.server.tsig_keystore import TSIGKeyStore

        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        # Recipient: derive their X25519 pub deterministically.
        recipient_crypto = DMPCrypto.from_passphrase("loose-bob", salt=b"L" * 32)
        x_pub = recipient_crypto.get_public_key_bytes()
        recipient_id = hashlib.sha256(x_pub).digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]

        # Loose-scope registration: only the bare zone, no
        # ``mb-{hash}.{zone}`` entry — but the X25519 pub IS persisted.
        db_path = str(tmp_path / "tsig.db")
        keystore = TSIGKeyStore(db_path)
        keystore.put(
            name="loose-bob.",
            secret=b"\x55" * 32,
            allowed_suffixes=["dmp.example.com"],  # bare zone only
            registered_x25519_pub=x_pub.hex(),
        )

        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=True,
        )
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
        assert response.rcode() == dns.rcode.NOERROR, (
            "loose-scope user with persisted x25519_pub should pass "
            "the M10 gate via hash recompute; got "
            f"{dns.rcode.to_text(response.rcode())}"
        )
        assert store.query_txt_record(owner.rstrip(".")) == [wire]

    def test_x25519_pub_hash_requires_mailbox_scope_not_just_zone_suffix(
        self, tmp_path
    ):
        """Codex round-7 P1: a row whose ``allowed_suffixes`` only
        contains identity-style entries under ``{zone}`` (e.g.
        ``id-XXX.{zone}``) MUST NOT qualify the user's x25519 hash
        for M10 admission. The round-6 fix was too permissive: it
        treated any suffix ending in ``.{zone}`` as proof the row
        belonged to that zone, even if the actual scope didn't
        authorize mailbox writes there."""
        from dmp.server.tsig_keystore import TSIGKeyStore

        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_crypto = DMPCrypto.from_passphrase("identity-only", salt=b"I" * 32)
        x_pub = recipient_crypto.get_public_key_bytes()
        recipient_id = hashlib.sha256(x_pub).digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]

        db_path = str(tmp_path / "tsig.db")
        keystore = TSIGKeyStore(db_path)
        # Identity-only key: scope authorizes id-XXX.{zone} owners
        # but NOT mailbox writes. Storing x_pub anyway (registration
        # always persists it). Pre-fix, registered_recipient_hashes
        # would happily admit this user as an M10 recipient.
        keystore.put(
            name="identity-only.",
            secret=b"\x99" * 32,
            allowed_suffixes=["id-deadbeef0011.dmp.example.com"],
            registered_x25519_pub=x_pub.hex(),
        )

        admitted = keystore.registered_recipient_hashes("dmp.example.com")
        assert h12 not in admitted, (
            "round-6 zone-suffix check is too loose — id-XXX.{zone} "
            "should not qualify as mailbox scope"
        )

        # Server-level: M10-only mode REFUSES the claim because the
        # hash isn't in the registered set.
        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=True,
        )
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

    def test_x25519_pub_hash_admitted_for_explicit_mailbox_scope(self, tmp_path):
        """Round-7 P1 (positive): a row with an actual mailbox-
        authorizing entry — ``mb-{hash}.{zone}``, ``mb-*.{zone}``,
        ``slot-*.mb-*.{zone}``, ``claim-*.mb-*.{zone}``, or the bare
        zone — DOES qualify for M10 admission."""
        from dmp.server.tsig_keystore import TSIGKeyStore

        recipient_crypto = DMPCrypto.from_passphrase("mb-user", salt=b"M" * 32)
        x_pub = recipient_crypto.get_public_key_bytes()
        recipient_id = hashlib.sha256(x_pub).digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]

        for ok_suffix in (
            "dmp.example.com",  # bare zone (loose-scope)
            f"mb-{h12}.dmp.example.com",  # explicit mailbox anchor
            "mb-*.dmp.example.com",  # wildcard mailbox
            "slot-*.mb-*.dmp.example.com",  # wildcard slots
            "claim-*.mb-*.dmp.example.com",  # wildcard claims
        ):
            db_path = str(tmp_path / f"tsig-{abs(hash(ok_suffix)):x}.db")
            keystore = TSIGKeyStore(db_path)
            keystore.put(
                name=f"user-{abs(hash(ok_suffix)):x}.",
                secret=b"\xaa" * 32,
                allowed_suffixes=[ok_suffix],
                registered_x25519_pub=x_pub.hex(),
            )
            admitted = keystore.registered_recipient_hashes("dmp.example.com")
            assert h12 in admitted, (
                f"mailbox-authorizing suffix {ok_suffix!r} should qualify "
                "the user's hash for M10 admission"
            )

    def test_x25519_pub_hash_filtered_by_zone_scope(self, tmp_path):
        """Codex round-6 P1: ``registered_recipient_hashes`` MUST NOT
        admit an x25519-derived hash unless the registering key's
        scope actually covers the queried zone. Otherwise a multi-zone
        keystore (or stale rows) would let a user registered under
        one zone be admitted as a recipient under another, silently
        re-opening the surface that ``DMP_CLAIM_PROVIDER=0`` was
        supposed to close."""
        from dmp.server.tsig_keystore import TSIGKeyStore

        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        # Bob is registered under ``alpha.example`` only.
        recipient_crypto = DMPCrypto.from_passphrase("bob", salt=b"B" * 32)
        x_pub = recipient_crypto.get_public_key_bytes()
        recipient_id = hashlib.sha256(x_pub).digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]

        db_path = str(tmp_path / "tsig.db")
        keystore = TSIGKeyStore(db_path)
        keystore.put(
            name="bob-alpha.",
            secret=b"\x77" * 32,
            allowed_suffixes=["alpha.example"],  # only this zone
            registered_x25519_pub=x_pub.hex(),
        )

        # Different zone: registered_recipient_hashes("beta.example")
        # MUST NOT include bob's hash.
        beta_hashes = keystore.registered_recipient_hashes("beta.example")
        assert h12 not in beta_hashes, (
            "x_pub-derived hash leaked into the wrong zone — "
            "round-6 P1 zone-filter regressed"
        )
        # Same zone: included.
        alpha_hashes = keystore.registered_recipient_hashes("alpha.example")
        assert h12 in alpha_hashes

        # End-to-end: a server gating on beta.example with bob's
        # claim-publish attempt → REFUSED (cross-zone leak shut).
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("beta.example",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=True,
        )
        wire = _claim_wire(sender, recipient_id)
        owner = f"claim-0.mb-{h12}.beta.example."
        with server:
            upd = dns.update.UpdateMessage("beta.example")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED, (
            "server admitted a claim under beta.example for a hash "
            "registered only on alpha.example"
        )

    def test_legacy_keystore_with_old_hash_format_falls_back_to_suffix(self, tmp_path):
        """Codex round-4 P1: a keystore upgraded from a pre-M10 build
        has rows whose ``allowed_suffixes`` carry the old single-round
        ``mb-{sha256(x_pub)[:12]}.{zone}`` (which never matched any
        real owner) AND no ``registered_x25519_pub``. Such users are
        effectively un-registered for M10 — the gate's suffix-scan
        fallback returns the wrong hash, no claim writes succeed.
        Operators upgrading must re-register users to mint the
        canonical mailbox-hash scope (and persist x_pub).

        This test locks the migration story in: a legacy row WITHOUT
        x_pub does NOT admit the canonical hash. Once x_pub is
        backfilled, the gate works."""
        from dmp.server.tsig_keystore import TSIGKeyStore

        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_crypto = DMPCrypto.from_passphrase("legacy-bob", salt=b"M" * 32)
        x_pub = recipient_crypto.get_public_key_bytes()
        canonical_recipient_id = hashlib.sha256(x_pub).digest()
        canonical_h12 = hashlib.sha256(canonical_recipient_id).hexdigest()[:12]
        # OLD suffix: single-round hash of x_pub. Doesn't match any
        # real owner.
        old_h12 = hashlib.sha256(x_pub).hexdigest()[:12]

        db_path = str(tmp_path / "tsig.db")
        keystore = TSIGKeyStore(db_path)
        # Legacy row: OLD suffix, no x_pub persisted.
        keystore.put(
            name="legacy-bob.",
            secret=b"\x66" * 32,
            allowed_suffixes=[f"mb-{old_h12}.dmp.example.com"],
        )

        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            claim_publish_enabled=False,
            receiver_claim_publish_enabled=True,
        )
        wire = _claim_wire(sender, canonical_recipient_id)
        owner = f"claim-0.mb-{canonical_h12}.dmp.example.com."

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
            "legacy keystore row without x25519_pub must NOT admit "
            "the canonical hash — operator must re-register"
        )

        # Backfill x_pub on the same row → gate now passes.
        keystore.put(
            name="legacy-bob.",
            secret=b"\x66" * 32,
            allowed_suffixes=[f"mb-{old_h12}.dmp.example.com"],
            registered_x25519_pub=x_pub.hex(),
        )
        with server:
            upd2 = dns.update.UpdateMessage("dmp.example.com")
            upd2.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response2 = _send_update(upd2, port)
        assert response2.rcode() == dns.rcode.NOERROR

    def test_bad_signature_refused(self, tmp_path):
        """A claim wire whose signature is corrupted fails verification at
        the server and the UPDATE is REFUSED — no record lands."""
        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        keystore = _keystore_with_recipient("dmp.example.com", h12, tmp_path)
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            receiver_claim_publish_enabled=True,
        )
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

    def test_rate_limit_exhaustion_returns_servfail(self, tmp_path):
        """Per-recipient-hash bucket: once burst is exhausted, further
        UPDATEs for the SAME hash12 are answered SERVFAIL until the
        bucket refills. Distinct from REFUSED for shape violations:
        SERVFAIL signals a transient backoff to the legitimate sender."""
        store = InMemoryDNSStore()
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        keystore = _keystore_with_recipient("dmp.example.com", h12, tmp_path)
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keystore=keystore,
            allowed_zones=("dmp.example.com",),
            receiver_claim_publish_enabled=True,
            # Tight bucket so the test exhausts in two writes without
            # waiting for refill.
            claim_rate_limit=RateLimit(rate_per_second=0.01, burst=2),
        )
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
