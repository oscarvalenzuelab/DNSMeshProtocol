"""Tests for RotationChain — client-side rotation-chain walker (M5.4).

EXPERIMENTAL. See ``dmp/client/rotation_chain.py`` and
``docs/protocol/rotation.md``.

Covers:
- No chain → None (caller falls back to pinned).
- Single-hop rotation A→B.
- Multi-hop rotation A→B→C.
- Revocation terminates walk mid-chain and on the pinned key.
- ``max_hops`` bound refuses longer chains.
- Seq regression / repeat rejected.
- Ambiguous fork (two rotations from same head to different new keys)
  rejected.
- Broken chain (orphan pair from an unrelated key) ignored.
- Corrupt record in the RRset does not break a valid walk alongside it.
"""

from __future__ import annotations

import time
from typing import List, Optional

from dmp.client.rotation_chain import RotationChain
from dmp.core.crypto import DMPCrypto
from dmp.core.rotation import (
    REASON_COMPROMISE,
    RECORD_PREFIX_ROTATION,
    RevocationRecord,
    RotationRecord,
    SUBJECT_TYPE_USER_IDENTITY,
    rotation_rrset_name_user_identity,
)
from dmp.network.base import DNSRecordReader

SUBJECT = "alice@example.com"


class _StubReader(DNSRecordReader):
    """Minimal DNSRecordReader backed by a dict."""

    def __init__(self, records: Optional[dict[str, List[str]]] = None) -> None:
        self._records = records or {}

    def query_txt_record(self, name: str):
        return list(self._records.get(name, [])) or None


def _sign_rotation(
    *,
    old: DMPCrypto,
    new: DMPCrypto,
    seq: int,
    subject: str = SUBJECT,
    exp_delta: int = 3600,
) -> str:
    now = int(time.time())
    rec = RotationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject=subject,
        old_spk=old.get_signing_public_key_bytes(),
        new_spk=new.get_signing_public_key_bytes(),
        seq=seq,
        ts=now,
        exp=now + exp_delta,
    )
    return rec.sign(old, new)


def _sign_revocation(
    *, revoked: DMPCrypto, subject: str = SUBJECT, ts: Optional[int] = None
) -> str:
    rec = RevocationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject=subject,
        revoked_spk=revoked.get_signing_public_key_bytes(),
        reason_code=REASON_COMPROMISE,
        ts=int(time.time()) if ts is None else ts,
    )
    return rec.sign(revoked)


def _rrset() -> str:
    user, _, host = SUBJECT.partition("@")
    return rotation_rrset_name_user_identity(user, host)


# ---- no-chain / single-hop / multi-hop ------------------------------------


def test_no_chain_returns_none():
    """No rotation records published → returns None (caller uses pinned_spk)."""
    reader = _StubReader()
    chain = RotationChain(reader)
    a = DMPCrypto()
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result is None


def test_no_chain_from_pinned_returns_none_even_with_unrelated_records():
    """Pinned key has no outgoing rotation → None (caller falls back)."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    # Published chain is b→c; pinned is a. The walk from a finds no
    # rotation whose old_spk = a, so we return None.
    reader = _StubReader({_rrset(): [_sign_rotation(old=b, new=c, seq=1)]})
    chain = RotationChain(reader)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_single_hop_rotation():
    """Pinned A, chain A→B, returns B."""
    a = DMPCrypto()
    b = DMPCrypto()
    reader = _StubReader({_rrset(): [_sign_rotation(old=a, new=b, seq=1)]})
    chain = RotationChain(reader)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == b.get_signing_public_key_bytes()


def test_multi_hop_rotation():
    """Pinned A, chain A→B→C, returns C."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_rotation(old=b, new=c, seq=2),
            ]
        }
    )
    chain = RotationChain(reader)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == c.get_signing_public_key_bytes()


# ---- revocation -----------------------------------------------------------


def test_revocation_terminates_walk():
    """A→B published, B revoked, walk from A returns None (trust aborted)."""
    a = DMPCrypto()
    b = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_revocation(revoked=b),
            ]
        }
    )
    chain = RotationChain(reader)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_revocation_on_pinned_terminates_walk():
    """A pinned, A itself revoked, returns None."""
    a = DMPCrypto()
    b = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_revocation(revoked=a),
            ]
        }
    )
    chain = RotationChain(reader)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_revocation_mid_chain_aborts_even_if_later_hops_exist():
    """A→B→C, B revoked. Walk from A must abort, not silently skip B."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_rotation(old=b, new=c, seq=2),
                _sign_revocation(revoked=b),
            ]
        }
    )
    chain = RotationChain(reader)
    # B is on the walk path (pinned A -> B -> C). Revoking B aborts the
    # walk regardless of whether the chain continues past B.
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


# ---- bounds / robustness --------------------------------------------------


def test_max_hops_bound():
    """A→B→C→D→E, max_hops=3, returns None (refuse to walk blindly)."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    d = DMPCrypto()
    e = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_rotation(old=b, new=c, seq=2),
                _sign_rotation(old=c, new=d, seq=3),
                _sign_rotation(old=d, new=e, seq=4),
            ]
        }
    )
    chain = RotationChain(reader, max_hops=3)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_seq_regression_rejected():
    """A→B (seq 5), B→C (seq 3). Walk finds regression and aborts."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=5),
                _sign_rotation(old=b, new=c, seq=3),
            ]
        }
    )
    chain = RotationChain(reader)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_seq_repeat_rejected():
    """A→B (seq 5), B→C (seq 5). Seq must STRICTLY increase."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=5),
                _sign_rotation(old=b, new=c, seq=5),
            ]
        }
    )
    chain = RotationChain(reader)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_ambiguous_fork_rejected():
    """A→B AND A→C both published. Ambiguous — abort."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_rotation(old=a, new=c, seq=2),
            ]
        }
    )
    chain = RotationChain(reader)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_broken_chain_rejected_orphan_ignored():
    """A→B valid plus an orphan D→E pair. Walk from A returns B, orphan ignored."""
    a = DMPCrypto()
    b = DMPCrypto()
    d = DMPCrypto()
    e = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_rotation(old=d, new=e, seq=10),
            ]
        }
    )
    chain = RotationChain(reader)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == b.get_signing_public_key_bytes()


def test_signature_failure_skips_record():
    """Corrupt RotationRecord in the RRset, valid one present; walk picks valid."""
    a = DMPCrypto()
    b = DMPCrypto()
    valid = _sign_rotation(old=a, new=b, seq=1)
    # Corrupt = prefix OK but body garbled.
    corrupt = RECORD_PREFIX_ROTATION + "!!!"
    reader = _StubReader({_rrset(): [corrupt, valid]})
    chain = RotationChain(reader)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == b.get_signing_public_key_bytes()


def test_subject_mismatch_record_skipped():
    """Valid rotation record but for a DIFFERENT subject → ignored."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    # Rotation for eve, not alice — should not affect alice's walk.
    stray = _sign_rotation(old=a, new=c, seq=1, subject="eve@example.com")
    valid = _sign_rotation(old=a, new=b, seq=2)
    reader = _StubReader({_rrset(): [stray, valid]})
    chain = RotationChain(reader)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == b.get_signing_public_key_bytes()


def test_expired_rotation_skipped():
    """Expired rotation record is dropped; walk ignores it."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    expired = _sign_rotation(old=a, new=c, seq=1, exp_delta=-10)
    valid = _sign_rotation(old=a, new=b, seq=2)
    reader = _StubReader({_rrset(): [expired, valid]})
    chain = RotationChain(reader)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == b.get_signing_public_key_bytes()


def test_reader_exception_returns_none():
    """Reader raises → returns None (never propagates)."""

    class ExplodingReader(DNSRecordReader):
        def query_txt_record(self, name):
            raise RuntimeError("simulated DNS failure")

    chain = RotationChain(ExplodingReader())
    a = DMPCrypto()
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_invalid_pinned_spk_returns_none():
    """Non-32-byte pinned key → None, not an exception."""
    reader = _StubReader()
    chain = RotationChain(reader)
    assert (
        chain.resolve_current_spk(b"short", SUBJECT, SUBJECT_TYPE_USER_IDENTITY) is None
    )


def test_max_hops_enforced_at_one():
    """max_hops=1 allows exactly one hop, refuses two."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_rotation(old=b, new=c, seq=2),
            ]
        }
    )
    chain = RotationChain(reader, max_hops=1)
    assert (
        chain.resolve_current_spk(
            a.get_signing_public_key_bytes(),
            SUBJECT,
            SUBJECT_TYPE_USER_IDENTITY,
        )
        is None
    )


def test_max_hops_exact_boundary_returns_tail():
    """max_hops=2 with exactly A→B→C returns C (tail reached inside the budget)."""
    a = DMPCrypto()
    b = DMPCrypto()
    c = DMPCrypto()
    reader = _StubReader(
        {
            _rrset(): [
                _sign_rotation(old=a, new=b, seq=1),
                _sign_rotation(old=b, new=c, seq=2),
            ]
        }
    )
    chain = RotationChain(reader, max_hops=2)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == c.get_signing_public_key_bytes()


def test_duplicate_same_record_accepted():
    """Publisher may re-publish a record; same old→new at same seq is fine."""
    a = DMPCrypto()
    b = DMPCrypto()
    wire = _sign_rotation(old=a, new=b, seq=1)
    reader = _StubReader({_rrset(): [wire, wire]})
    chain = RotationChain(reader)
    result = chain.resolve_current_spk(
        a.get_signing_public_key_bytes(),
        SUBJECT,
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert result == b.get_signing_public_key_bytes()


# ---- DMPClient integration (EXPERIMENTAL feature flag) --------------------


class TestDMPClientRotationChainIntegration:
    """Verify DMPClient(rotation_chain_enabled=...) plumbing.

    Default (False) MUST preserve byte-identical legacy behavior: a
    manifest from a non-pinned signer is dropped, period.

    Opt-in (True) adds the experimental trust: if a rotation chain
    published under a pinned contact's RRset resolves to the manifest's
    sender_spk, the manifest is accepted for this receive pass.
    """

    def test_default_behavior_byte_identical_without_flag(self):
        """rotation_chain_enabled=False: unknown signer manifest dropped."""
        from dmp.client.client import DMPClient
        from dmp.network.memory import InMemoryDNSStore

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        bob = DMPClient("bob", "bob-pass", domain="mesh.test", store=store)
        # Bob pins alice, then alice rotates to a new passphrase/key.
        # The rotated-alice sends from the new key; without the flag,
        # bob's receive drops it (pinned key doesn't match).
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        alice2 = DMPClient("alice", "alice-new-pass", domain="mesh.test", store=store)
        alice2.add_contact("bob", bob.get_public_key_hex())
        alice2.send_message("bob", "hello from rotated alice")
        assert bob.receive_messages() == []
        # Internal flag state.
        assert bob.rotation_chain_enabled is False
        assert bob._rotation_chain is None

    def test_opt_in_accepts_rotated_sender(self):
        """rotation_chain_enabled=True: rotation published → manifest accepted."""
        from dmp.client.client import DMPClient
        from dmp.core.rotation import rotation_rrset_name_user_identity
        from dmp.network.memory import InMemoryDNSStore

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        alice2 = DMPClient("alice", "alice-new-pass", domain="mesh.test", store=store)

        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="mesh.test",
            store=store,
            rotation_chain_enabled=True,
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        alice2.add_contact("bob", bob.get_public_key_hex())

        # Publish the A→A2 rotation at rotate.dmp.<hash>.mesh.test.
        # Alice's contact was added with domain="mesh.test", so the
        # subject is "alice@mesh.test".
        wire = _sign_rotation(
            old=alice.crypto,
            new=alice2.crypto,
            seq=1,
            subject="alice@mesh.test",
        )
        rrset = rotation_rrset_name_user_identity("alice", "mesh.test")
        store.publish_txt_record(rrset, wire)

        alice2.send_message("bob", "hello from rotated alice")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"hello from rotated alice"
        # Crucially, the pinning is NOT permanently mutated; bob's
        # contact entry still has the original (old) signing key.
        assert bob.contacts["alice"].signing_key_bytes == bytes.fromhex(
            alice.get_signing_public_key_hex()
        )

    def test_opt_in_rejects_when_revoked(self):
        """Rotation + revocation → manifest still dropped."""
        from dmp.client.client import DMPClient
        from dmp.core.rotation import rotation_rrset_name_user_identity
        from dmp.network.memory import InMemoryDNSStore

        store = InMemoryDNSStore()
        alice = DMPClient("alice", "alice-pass", domain="mesh.test", store=store)
        alice2 = DMPClient("alice", "alice-new-pass", domain="mesh.test", store=store)
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="mesh.test",
            store=store,
            rotation_chain_enabled=True,
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
        )
        alice2.add_contact("bob", bob.get_public_key_hex())

        rrset = rotation_rrset_name_user_identity("alice", "mesh.test")
        store.publish_txt_record(
            rrset,
            _sign_rotation(
                old=alice.crypto,
                new=alice2.crypto,
                seq=1,
                subject="alice@mesh.test",
            ),
        )
        # But the new key was ALSO revoked.
        store.publish_txt_record(
            rrset, _sign_revocation(revoked=alice2.crypto, subject="alice@mesh.test")
        )

        alice2.send_message("bob", "attempt after revoke")
        assert bob.receive_messages() == []
