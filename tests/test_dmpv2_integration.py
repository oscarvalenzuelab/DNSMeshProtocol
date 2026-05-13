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
        This is the designed behavior: senders never need to
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


class TestRRSetDisambiguation:
    """The receive verifier MUST prefer a record whose ed25519_spk
    matches the expected key even when an older sibling record
    appears first in the RRset.

    Append-semantics DNS publishers can leave a previous version of
    a user's identity record alongside the live one (e.g. after key
    rotation or a republish). If the lookup returns the first
    signature-valid record by RRset order without filtering by SPK,
    a stale tombstone would silently shadow the live record:

    - ``_recipient_versions`` would read the old record's
      ``versions`` and downgrade the send path to v1 even though the
      live record advertises v2.
    - ``_resolve_envelope_label`` would see the old record's SPK,
      fail to match the manifest's ``sender_spk``, and refuse to
      populate the verified label.
    """

    def test_resolve_envelope_label_picks_record_matching_sender_spk(self):
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
        # Publish alice's REAL identity first.
        _publish_identity(alice, "alice.test")
        # Then publish a SECOND record at the same name signed by a
        # different identity (call it "stale"). Both records are
        # signature-valid; the lookup should still match the
        # caller-supplied expected_spk against alice's real SPK.
        stale = DMPCrypto.from_passphrase("stale", salt=b"x" * 16)
        stale_rec = IdentityRecord(
            username="alice",
            x25519_pk=stale.get_public_key_bytes(),
            ed25519_spk=stale.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=SUPPORTED_VERSIONS,
        )
        alice.writer.publish_txt_record(
            zone_anchored_identity_name("alice.test"),
            stale_rec.sign(stale),
            ttl=300,
        )

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        alice_spk = alice.crypto.get_signing_public_key_bytes()
        # The verifier MUST find alice's real record even if the stale
        # one is iterated first.
        label = bob._resolve_envelope_label("alice@alice.test", alice_spk)
        assert label == "alice@alice.test"

    def test_recipient_versions_picks_record_matching_pinned_spk(self):
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
        # Publish a STALE v1-only record FIRST, then alice's real
        # record with versions=(1,2). RRset append semantics keeps both.
        stale = DMPCrypto.from_passphrase("stale", salt=b"x" * 16)
        stale_rec = IdentityRecord(
            username="alice",
            x25519_pk=stale.get_public_key_bytes(),
            ed25519_spk=stale.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=(1,),
        )
        store.publish_txt_record(
            zone_anchored_identity_name("alice.test"),
            stale_rec.sign(stale),
            ttl=300,
        )
        _publish_identity(alice, "alice.test")

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
            domain="alice.test",
        )
        # _recipient_versions has bob's pinned SPK for alice, so the
        # lookup MUST prefer alice's real record (advertising v2) over
        # the stale v1 one.
        versions = bob._recipient_versions(bob.contacts["alice"])
        assert versions == SUPPORTED_VERSIONS


class TestFallbackNameSearch:
    """When the zone-anchored name has only a stale record but the
    TOFU-hash name has the live record, the lookup MUST keep searching.
    A premature early-return at the first username-matching record
    would silently break v2 emission and label verification in any
    deployment that's gone through a republish/migration.
    """

    def test_recipient_versions_falls_through_to_hash_named_record(self):
        from dmp.core.crypto import DMPCrypto
        from dmp.core.identity import identity_domain

        store = InMemoryDNSStore()
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="alice.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # Stale record at the zone-anchored name (wrong SPK, but a
        # valid signature so it can't just be discarded).
        stale = DMPCrypto.from_passphrase("stale", salt=b"x" * 16)
        stale_rec = IdentityRecord(
            username="alice",
            x25519_pk=stale.get_public_key_bytes(),
            ed25519_spk=stale.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=(1,),
        )
        store.publish_txt_record(
            zone_anchored_identity_name("alice.test"),
            stale_rec.sign(stale),
            ttl=300,
        )
        # Live record at the TOFU-hash name (alice's real key,
        # advertising v2). Publish via _publish_identity but at the
        # hashed name — go around the helper because the helper
        # writes to the zone-anchored name.
        live_rec = IdentityRecord(
            username="alice",
            x25519_pk=alice.crypto.get_public_key_bytes(),
            ed25519_spk=alice.crypto.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=SUPPORTED_VERSIONS,
        )
        store.publish_txt_record(
            identity_domain("alice", "alice.test"),
            live_rec.sign(alice.crypto),
            ttl=300,
        )

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
            domain="alice.test",
        )
        # The verifier must look past the stale zone-anchored record
        # and find alice's real key at the hash-named fallback.
        versions = bob._recipient_versions(bob.contacts["alice"])
        assert versions == SUPPORTED_VERSIONS

    def test_resolve_envelope_label_falls_through_to_hash_named_record(self):
        from dmp.core.crypto import DMPCrypto
        from dmp.core.identity import identity_domain

        store = InMemoryDNSStore()
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="alice.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # Stale at zone-anchored name.
        stale = DMPCrypto.from_passphrase("stale", salt=b"x" * 16)
        stale_rec = IdentityRecord(
            username="alice",
            x25519_pk=stale.get_public_key_bytes(),
            ed25519_spk=stale.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=SUPPORTED_VERSIONS,
        )
        store.publish_txt_record(
            zone_anchored_identity_name("alice.test"),
            stale_rec.sign(stale),
            ttl=300,
        )
        # Live at hash-name.
        live_rec = IdentityRecord(
            username="alice",
            x25519_pk=alice.crypto.get_public_key_bytes(),
            ed25519_spk=alice.crypto.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=SUPPORTED_VERSIONS,
        )
        store.publish_txt_record(
            identity_domain("alice", "alice.test"),
            live_rec.sign(alice.crypto),
            ttl=300,
        )

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        alice_spk = alice.crypto.get_signing_public_key_bytes()
        label = bob._resolve_envelope_label("alice@alice.test", alice_spk)
        assert label == "alice@alice.test"


class TestIdentityDomainOverride:
    """When the CLI configures `identity_domain` separately from the
    mailbox domain, the envelope's `from` must point at the identity
    domain (where the identity record is actually published), not at
    the mailbox domain. Otherwise receivers look up the wrong address
    and never produce a verified sender_label.
    """

    def test_envelope_uses_identity_domain_when_configured(self):
        store = InMemoryDNSStore()
        # Alice runs with mailbox under cluster.test but publishes
        # her identity at her own domain alice.example.
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="cluster.test",
            identity_domain="alice.example",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        _publish_identity(alice, "alice.example")
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="cluster.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        _publish_identity(bob, "cluster.test")
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
            domain="cluster.test",
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
            domain="cluster.test",
        )

        assert alice.send_message("bob", "hello bob")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        # `from` MUST resolve to alice's identity domain, not her
        # mailbox domain. The receiver finds the record at
        # dmp.alice.example, matches SPK, and surfaces the label.
        assert inbox[0].plaintext == b"hello bob"
        assert inbox[0].sender_label == "alice@alice.example"


class TestVersionsCacheRespectsPinChange:
    """The recipient-versions cache MUST be keyed by the pinned key
    material, not just the address. Otherwise a contact re-pinned to
    a different key at the same address inherits the previous pin's
    cached v2-OK verdict — and the send path emits a wrapper to a
    recipient that the new pin says is v1-only or unrelated.
    """

    def test_repinning_invalidates_versions_cache(self):
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
        _publish_identity(alice, "alice.test")
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # First pin: alice's real keys.
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
            domain="alice.test",
        )
        versions1 = bob._recipient_versions(bob.contacts["alice"])
        assert versions1 == SUPPORTED_VERSIONS

        # Now re-pin "alice" to a different identity at the same
        # address — simulates rotation or a manual re-trust step.
        new_alice = DMPCrypto.from_passphrase("new-alice", salt=b"x" * 16)
        bob.contacts["alice"] = type(bob.contacts["alice"])(
            username="alice",
            public_key_bytes=new_alice.get_public_key_bytes(),
            signing_key_bytes=new_alice.get_signing_public_key_bytes(),
            domain="alice.test",
        )
        # The identity record at alice.test still belongs to the OLD
        # alice (advertising v2). With the cache properly keyed by
        # pin material, the new pin is a cache miss → fresh lookup →
        # SPK mismatch (new pin != record's old SPK) → downgrade
        # to v1.
        versions2 = bob._recipient_versions(bob.contacts["alice"])
        assert versions2 == (1,)


class TestFullAddressContact:
    """The CLI's `identity fetch user@host --add` saves the full
    address as the contact's username when no `remote_username` is
    resolved. `_recipient_versions` must normalize this — build
    `user@host` from the localpart, not from the already-full
    string — or canonicalization fails and v2 emission silently
    downgrades.
    """

    def test_full_address_username_still_emits_v2(self):
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
        # Simulate the CLI's full-address contact shape: username is
        # the full address.
        alice.add_contact(
            "bob@bob.test",  # full address as username
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

        # Even though the contact's username is "bob@bob.test",
        # _recipient_versions strips the @host suffix before
        # canonicalizing — so v2 emission survives.
        versions = alice._recipient_versions(alice.contacts["bob@bob.test"])
        assert versions == SUPPORTED_VERSIONS

        # End-to-end send + receive still works, and bob gets
        # the verified label.
        assert alice.send_message("bob@bob.test", "hello")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"hello"
        assert inbox[0].sender_label == "alice@alice.test"


class TestMixedCaseUsername:
    """A legacy identity published with mixed-case username
    (e.g. `dnsmesh init Alice`) MUST still match envelope lookups
    even though the envelope canonicalizer lowercases addresses. The
    record's stored username preserves the original case for display
    + DNS, but the lookup compares case-insensitively to find the
    matching record.
    """

    def test_mixed_case_record_username_matches_lowercase_envelope_lookup(self):
        from dmp.core.identity import make_record, zone_anchored_identity_name

        store = InMemoryDNSStore()
        # Publish "Alice" (capitalized) at alice.test.
        alice = DMPClient(
            "Alice",
            "alice-pass",
            domain="alice.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        record = make_record(alice.crypto, "Alice", versions=SUPPORTED_VERSIONS)
        store.publish_txt_record(
            zone_anchored_identity_name("alice.test"),
            record.sign(alice.crypto),
            ttl=300,
        )

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # bob looks up alice via the canonicalized lowercase form
        # because that's what the envelope decoder returns.
        label = bob._resolve_envelope_label(
            "alice@alice.test",  # lowercase, as canonicalize emits
            alice.crypto.get_signing_public_key_bytes(),
        )
        assert label == "alice@alice.test"


class TestMixedCaseHashName:
    """A contact whose identity was published under the TOFU-hash form
    with a mixed-case username (`dnsmesh init Alice` without
    `identity_domain`) has its record at `identity_domain("Alice",
    host)` — a different hash than `identity_domain("alice", host)`.
    The send path must look up under the ORIGINAL case to find the
    record.
    """

    def test_recipient_versions_finds_mixed_case_hash_named_record(self):
        from dmp.core.identity import identity_domain, make_record

        store = InMemoryDNSStore()
        alice = DMPClient(
            "Alice",
            "alice-pass",
            domain="mesh.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # Publish under the TOFU-hash name computed from "Alice" (the
        # mixed-case publish path), with v2 advertised.
        record = make_record(alice.crypto, "Alice", versions=SUPPORTED_VERSIONS)
        store.publish_txt_record(
            identity_domain("Alice", "mesh.test"),
            record.sign(alice.crypto),
            ttl=300,
        )

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="mesh.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # bob pins alice with the original case (as it would be after
        # a successful identity fetch).
        bob.add_contact(
            "Alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
            domain="mesh.test",
        )
        # _recipient_versions must hash against "Alice" (original case)
        # so it hits the record at `id-<hash("Alice")[:16]>.mesh.test`.
        versions = bob._recipient_versions(bob.contacts["Alice"])
        assert versions == SUPPORTED_VERSIONS


class TestLegacyPinX25519Disambiguation:
    """A legacy X25519-only pin must get the same RRset-shadow
    protection a modern Ed25519 pin gets. The lookup must keep
    searching past a stale record whose X25519 key doesn't match the
    pinned encryption key.
    """

    def test_legacy_pin_finds_matching_record_past_stale(self):
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
        # Stale record published FIRST under alice's address —
        # different X25519 key, different SPK, advertising v1.
        stale = DMPCrypto.from_passphrase("stale", salt=b"x" * 16)
        stale_rec = IdentityRecord(
            username="alice",
            x25519_pk=stale.get_public_key_bytes(),
            ed25519_spk=stale.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=(1,),
        )
        store.publish_txt_record(
            zone_anchored_identity_name("alice.test"),
            stale_rec.sign(stale),
            ttl=300,
        )
        # Live record published SECOND — alice's real keys + v2.
        _publish_identity(alice, "alice.test")

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # Legacy pin: only X25519, no signing key.
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            domain="alice.test",
        )
        # With the X25519 disambiguator, the lookup walks past the
        # stale record (mismatched x25519_pk) to alice's real
        # record (matching x25519_pk, advertising v2).
        versions = bob._recipient_versions(bob.contacts["alice"])
        assert versions == SUPPORTED_VERSIONS


class TestLegacyContactDoesNotTrustSquattedVersions:
    """A legacy contact pinned only via X25519 (signing_key_bytes empty)
    must NOT have `versions` trusted unless the fetched identity
    record's ``x25519_pk`` matches the pinned encryption key. Without
    this gate, a squatter who publishes any identity record at the
    address (advertising v2) would trick the send path into wrapping
    plaintext destined for a v1-only legacy contact, leaking the
    `DMPV2:` prefix into their message body.
    """

    def test_squatted_v2_record_does_not_upgrade_legacy_contact(self):
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
        # Publish a SQUAT record at alice's address signed by a
        # different identity, advertising v2.
        squat = DMPCrypto.from_passphrase("squat", salt=b"x" * 16)
        squat_rec = IdentityRecord(
            username="alice",
            x25519_pk=squat.get_public_key_bytes(),
            ed25519_spk=squat.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=SUPPORTED_VERSIONS,
        )
        store.publish_txt_record(
            zone_anchored_identity_name("alice.test"),
            squat_rec.sign(squat),
            ttl=300,
        )

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="bob.test",
            store=store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        # Legacy pin: bob has alice's X25519 pubkey but NOT her
        # Ed25519 signing key (the pre-Ed25519-pin contact shape).
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            # signing_key_hex omitted → contact.signing_key_bytes = b""
            domain="alice.test",
        )
        # With only an X25519 pin available, the squatted v2 record
        # must NOT cause v2 emission. The X25519 pubkey in the squat
        # record doesn't match alice's real pubkey, so the
        # _recipient_versions defense rejects it.
        versions = bob._recipient_versions(bob.contacts["alice"])
        assert versions == (1,)


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
        # forget the previously-verified binding (transient NXDOMAIN
        # must not evict).
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
