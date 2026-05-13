"""End-to-end tests for the DMPv2 envelope flow.

Exercises send → publish → receive across DMPClient instances with
identity records published to an in-memory store, so the envelope
codec, the identity-record versions field, the recipient-versions
cache, and the receive-side address verifier are all on the hot
path together.

These are the regression guarantees for the wire-format change.
"""

from __future__ import annotations

from typing import Tuple

import pytest

from dmp.client.client import DMPClient
from dmp.core.envelope import DMPV2_PREFIX
from dmp.core.identity import (
    SUPPORTED_VERSIONS,
    IdentityRecord,
    make_record,
    zone_anchored_identity_name,
)
from dmp.network.memory import InMemoryDNSStore


def _publish_identity(
    client: DMPClient,
    host: str,
    *,
    versions: Tuple[int, ...] = SUPPORTED_VERSIONS,
) -> None:
    """Publish the client's identity record at ``dmp.<host>``."""
    rec = make_record(client.crypto, client.username, versions=versions)
    wire = rec.sign(client.crypto)
    name = zone_anchored_identity_name(host)
    ok = client.writer.publish_txt_record(name, wire, ttl=300)
    assert ok, f"failed to publish identity record at {name}"


def _make_pair(
    store: InMemoryDNSStore,
    *,
    alice_versions: Tuple[int, ...] = SUPPORTED_VERSIONS,
    bob_versions: Tuple[int, ...] = SUPPORTED_VERSIONS,
) -> Tuple[DMPClient, DMPClient]:
    """Create alice@alice.test and bob@bob.test with mutual pinning.

    Each client lives in its own zone so the zone-anchored identity
    record name is unambiguous. Both clients share the same in-memory
    DNS store so cross-zone publish/poll just works.
    """
    alice = DMPClient(
        "alice",
        "alice-pass",
        domain="alice.test",
        store=store,
        intro_queue_path=":memory:",
        prekey_store_path=":memory:",
    )
    bob = DMPClient(
        "bob",
        "bob-pass",
        domain="bob.test",
        store=store,
        intro_queue_path=":memory:",
        prekey_store_path=":memory:",
    )
    _publish_identity(alice, "alice.test", versions=alice_versions)
    _publish_identity(bob, "bob.test", versions=bob_versions)
    # Cross-zone pin: domain_explicit=True so M10 phase-1 publishes
    # land in the other party's zone, mirroring real cross-zone use.
    alice.add_contact(
        "bob",
        bob.get_public_key_hex(),
        signing_key_hex=bob.get_signing_public_key_hex(),
        domain="bob.test",
    )
    bob.add_contact(
        "alice",
        alice.get_public_key_hex(),
        signing_key_hex=alice.get_signing_public_key_hex(),
        domain="alice.test",
    )
    return alice, bob


class TestEnvelopeRoundtrip:
    def test_v2_to_v2_populates_sender_label(self):
        store = InMemoryDNSStore()
        alice, bob = _make_pair(store)
        assert alice.send_message("bob", "hello bob")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        msg = inbox[0]
        assert msg.plaintext == b"hello bob"
        assert msg.sender_label == "alice@alice.test"
        # body stripped — no prefix leaks into the message payload
        assert DMPV2_PREFIX not in msg.plaintext

    def test_v2_to_v1_recipient_skips_envelope(self):
        """A v1-only recipient (versions=(1,) in identity record) must
        never receive the DMPV2: prefix in the message body — the
        sender's versions-gate must hold."""
        store = InMemoryDNSStore()
        alice, bob = _make_pair(store, bob_versions=(1,))
        assert alice.send_message("bob", "hello bob")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        msg = inbox[0]
        # Body is the raw v1 plaintext, no envelope wrapper.
        assert msg.plaintext == b"hello bob"
        assert not msg.plaintext.startswith(DMPV2_PREFIX)
        # No verified label since no envelope was sent.
        assert msg.sender_label == ""

    def test_sender_versions_does_not_gate_emission(self):
        """The version-gate is on the RECIPIENT's advertised support,
        not the sender's. Alice's identity record can say versions=(1,)
        — that's a statement about what she can RECEIVE — and she
        still emits v2 envelopes when sending to a v2-capable peer.
        This is the codex-validated design: senders never need to
        consult their own identity record to decide what to emit."""
        store = InMemoryDNSStore()
        alice, bob = _make_pair(store, alice_versions=(1,))
        assert alice.send_message("bob", "hello bob")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"hello bob"
        assert inbox[0].sender_label == "alice@alice.test"

    def test_missing_identity_record_defaults_to_v1(self):
        """When the recipient has no identity record published yet,
        the send path defaults to v1 — the safe assumption is "peer
        capability unknown, don't risk emitting a wrapper they can't
        strip."""
        store = InMemoryDNSStore()
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="alice.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # NOTE: no identity records published; only alice published.
        _publish_identity(alice, "alice.test")
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
            domain="bob.test",
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
            domain="alice.test",
        )
        assert alice.send_message("bob", "hi")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        # No wrapper emitted (bob unknown → defaults to v1).
        assert inbox[0].plaintext == b"hi"
        assert inbox[0].sender_label == ""


def _publish_alice_claim_for_latest_message(
    alice: DMPClient,
    bob: DMPClient,
    store: InMemoryDNSStore,
    *,
    provider_zone: str,
) -> bytes:
    """Find alice's most-recently-published manifest and publish a
    matching claim record so bob can discover the message via
    receive_claims. Mirrors tests/test_claim_flow.py's helper —
    the in-memory store doesn't run DNS UPDATE, so the test fixture
    writes the claim record directly via ``publish_claim`` with
    ``provider_writer=store``.
    """
    import hashlib

    from dmp.core.manifest import SlotManifest

    contact = alice.contacts[bob.username]
    recipient_id = hashlib.sha256(contact.public_key_bytes).digest()
    bob_hash = hashlib.sha256(recipient_id).hexdigest()[:12]
    candidates = []
    for slot in range(10):
        name = f"slot-{slot}.mb-{bob_hash}.{alice.domain}"
        for record in store.query_txt_record(name) or []:
            parsed = SlotManifest.parse_and_verify(record)
            if parsed is None:
                continue
            manifest, _ = parsed
            candidates.append((slot, manifest.msg_id, manifest.ts))
    assert candidates, "no manifest published yet"
    candidates.sort(key=lambda c: c[2], reverse=True)
    chosen_slot, chosen_msg_id, _ = candidates[0]
    assert alice.publish_claim(
        recipient_id=recipient_id,
        msg_id=chosen_msg_id,
        slot=chosen_slot,
        sender_mailbox_domain=alice.domain,
        ttl=300,
        provider_zone=provider_zone,
        provider_writer=store,
    )
    return chosen_msg_id


class TestEnvelopeFirstContact:
    """Intro-queue path: first-contact from an unpinned sender carries
    the envelope from-claim into the intro row's sender_label."""

    def test_unpinned_sender_intro_gets_verified_label(self):
        store = InMemoryDNSStore()
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="alice.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        _publish_identity(alice, "alice.test")
        _publish_identity(bob, "bob.test")
        # Alice pins bob so she can send.
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
            domain="bob.test",
        )
        # Bob does NOT pin alice — she's an unpinned sender.

        # Send the message (no claim publish via UPDATE since this
        # is an in-memory store).
        assert alice.send_message("bob", "hello bob, this is alice")
        # Test fixture writes the claim directly to the shared store.
        _publish_alice_claim_for_latest_message(
            alice, bob, store, provider_zone="bob.test"
        )

        result = bob.receive_claims(provider_zones=[("bob.test", "")])
        assert result.delivered == []
        assert len(result.quarantined_intro_ids) == 1
        intros = bob.intro_queue.list_intros()
        assert len(intros) == 1
        intro = intros[0]
        assert intro.plaintext == b"hello bob, this is alice"
        assert intro.sender_label == "alice@alice.test"

    def test_unpinned_sender_label_empty_when_spk_mismatch(self):
        """If the identity record at alice's claimed address advertises
        a DIFFERENT signing key than the manifest's sender_spk, the
        verifier MUST refuse to populate sender_label — squat
        resistance. We simulate this by overwriting alice's identity
        record with one signed by an impostor (different SPK) AFTER
        alice publishes hers."""
        from dmp.core.crypto import DMPCrypto

        store = InMemoryDNSStore()
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="alice.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        _publish_identity(alice, "alice.test")
        _publish_identity(bob, "bob.test")
        # Append an impostor record at the same name. Now there are
        # TWO records, both valid signatures but bound to different
        # SPKs. The verifier walks them; the impostor's username
        # matches "alice" so its SPK is compared to the manifest spk
        # — mismatch → keep walking. The real one then matches.
        # To force the FAILURE path: replace alice's record with
        # only the impostor's, so the lookup finds only mismatching
        # records.
        store._records.pop(zone_anchored_identity_name("alice.test"), None)  # type: ignore[attr-defined]
        impostor = DMPCrypto.from_passphrase("impostor", salt=b"x" * 16)
        rec = IdentityRecord(
            username="alice",
            x25519_pk=impostor.get_public_key_bytes(),
            ed25519_spk=impostor.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=SUPPORTED_VERSIONS,
        )
        bob.writer.publish_txt_record(
            zone_anchored_identity_name("alice.test"), rec.sign(impostor), ttl=300
        )

        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
            domain="bob.test",
        )
        # Alice's send-path checks bob's versions OK (bob's record
        # still verifies). But alice's own send still emits the
        # envelope because she's v2-capable and bob is too. Good.
        assert alice.send_message("bob", "hi from real alice")
        _publish_alice_claim_for_latest_message(
            alice, bob, store, provider_zone="bob.test"
        )
        bob.receive_claims(provider_zones=[("bob.test", "")])
        intros = bob.intro_queue.list_intros()
        assert len(intros) == 1
        intro = intros[0]
        # The verifier looks up alice.test → finds the impostor's
        # record → SPK doesn't match the manifest's sender_spk
        # (alice's real key) → returns "". The body still delivers.
        assert intro.sender_label == ""
        assert intro.plaintext == b"hi from real alice"


class TestEnvelopeCaches:
    """The receive-side label cache must survive transient DNS misses
    and the send-side versions cache must not be a positive cache for
    failures."""

    def test_resolve_envelope_label_caches_positive(self):
        store = InMemoryDNSStore()
        _, bob = _make_pair(store)
        # Look up an envelope that should verify.
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="alice.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        addr = "alice@alice.test"
        spk = alice.crypto.get_signing_public_key_bytes()
        # First call hits DNS.
        label = bob._resolve_envelope_label(addr, spk)
        assert label == addr
        # Cached.
        assert (addr, spk) in bob._envelope_label_cache
        # Mutate the store to break the lookup — the cache must not
        # forget the previously-verified binding (codex consult
        # 2026-05-13: a transient NXDOMAIN must not evict).
        store._records.clear()  # type: ignore[attr-defined]
        cached = bob._resolve_envelope_label(addr, spk)
        assert cached == addr

    def test_resolve_envelope_label_does_not_cache_negative(self):
        """A negative result must NOT poison the cache — a later
        legitimate publish must be able to verify."""
        store = InMemoryDNSStore()
        _, bob = _make_pair(store)
        unknown_addr = "noone@unknown.test"
        spk = b"\x01" * 32  # nonsense spk
        # Returns "" (no identity record at unknown.test).
        assert bob._resolve_envelope_label(unknown_addr, spk) == ""
        # The negative result is not cached.
        assert (unknown_addr, spk) not in bob._envelope_label_cache
