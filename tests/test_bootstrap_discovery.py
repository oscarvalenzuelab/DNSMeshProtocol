"""Tests for the M3.2-wire bootstrap discovery helper.

Mirrors ``tests/test_cluster_bootstrap.py`` for
:func:`fetch_bootstrap_record`: read-side happy path, signer mismatch,
user-domain binding, multi-record seq selection, reader failure.
"""

from __future__ import annotations

import time
from typing import List, Optional

from dmp.client.bootstrap_discovery import fetch_bootstrap_record
from dmp.core.bootstrap import (
    BootstrapEntry,
    BootstrapRecord,
    bootstrap_rrset_name,
)
from dmp.core.crypto import DMPCrypto
from dmp.network.base import DNSRecordReader
from dmp.network.memory import InMemoryDNSStore

# --------------------------------------------------------------------------- helpers


def _entry(
    priority: int = 10,
    cluster_base_domain: str = "mesh.example.com",
    operator_spk: Optional[bytes] = None,
) -> BootstrapEntry:
    if operator_spk is None:
        # Use a deterministic stand-in for tests that don't care about
        # cluster-operator identity (bootstrap verification only checks
        # the zone operator's signature; the entry's operator_spk is
        # opaque bytes at this layer).
        operator_spk = bytes(range(32))
    return BootstrapEntry(
        priority=priority,
        cluster_base_domain=cluster_base_domain,
        operator_spk=operator_spk,
    )


def _build_record(
    signer: DMPCrypto,
    *,
    user_domain: str = "example.com",
    seq: int = 1,
    exp_delta: int = 3600,
    entries: Optional[List[BootstrapEntry]] = None,
) -> BootstrapRecord:
    return BootstrapRecord(
        user_domain=user_domain,
        signer_spk=signer.get_signing_public_key_bytes(),
        entries=entries if entries is not None else [_entry()],
        seq=seq,
        exp=int(time.time()) + exp_delta,
    )


class _FailingReader(DNSRecordReader):
    """Reader whose query always raises — simulates DNS outage."""

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        raise RuntimeError("bootstrap reader down")


# --------------------------------------------------------------------------- tests


class TestFetchBootstrapRecord:
    def test_happy_path(self):
        signer = DMPCrypto()
        record = _build_record(signer)
        wire = record.sign(signer)

        store = InMemoryDNSStore()
        store.publish_txt_record(bootstrap_rrset_name("example.com"), wire)

        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is not None
        assert got.user_domain == "example.com"
        assert got.seq == 1
        assert got.entries[0].cluster_base_domain == "mesh.example.com"

    def test_wrong_signer_spk_returns_none(self):
        signer = DMPCrypto()
        record = _build_record(signer)
        wire = record.sign(signer)

        store = InMemoryDNSStore()
        store.publish_txt_record(bootstrap_rrset_name("example.com"), wire)

        imposter = DMPCrypto()
        got = fetch_bootstrap_record(
            "example.com",
            imposter.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_mismatched_user_domain_returns_none(self):
        """A correctly-signed record published at user_domain A should not
        be accepted for user_domain B — binding is enforced internally.
        """
        signer = DMPCrypto()
        # Record's signed user_domain is 'other.com' — but we publish
        # it under example.com's RRset. parse_and_verify binds to the
        # expected user domain we pass in and rejects the mismatch.
        record = _build_record(signer, user_domain="other.com")
        wire = record.sign(signer)

        store = InMemoryDNSStore()
        store.publish_txt_record(bootstrap_rrset_name("example.com"), wire)

        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_picks_highest_seq_when_multiple_valid(self):
        """During a zone-operator rollout the RRset may carry both old
        and new signed records. Return the highest seq."""
        signer = DMPCrypto()
        old = _build_record(signer, seq=1)
        new = _build_record(signer, seq=7)

        store = InMemoryDNSStore()
        name = bootstrap_rrset_name("example.com")
        # Insertion order: old first — proves we don't just take the
        # first verifying record.
        store.publish_txt_record(name, old.sign(signer))
        store.publish_txt_record(name, new.sign(signer))

        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is not None
        assert got.seq == 7

    def test_picks_valid_out_of_multiple_records(self):
        """RRset has garbage + one valid record → return the valid one."""
        signer = DMPCrypto()
        record = _build_record(signer)
        wire = record.sign(signer)

        store = InMemoryDNSStore()
        name = bootstrap_rrset_name("example.com")
        store.publish_txt_record(name, "not-a-record")
        store.publish_txt_record(name, "v=dmp1;t=other;garbage")
        store.publish_txt_record(name, wire)
        store.publish_txt_record(name, "random garbage")

        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is not None
        assert got.seq == 1

    def test_no_records_returns_none(self):
        signer = DMPCrypto()
        store = InMemoryDNSStore()  # empty
        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_all_garbage_returns_none(self):
        signer = DMPCrypto()
        store = InMemoryDNSStore()
        name = bootstrap_rrset_name("example.com")
        store.publish_txt_record(name, "v=dmp1;t=cluster;not-a-bootstrap")
        store.publish_txt_record(name, "random garbage")

        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_expired_record_returns_none(self):
        """A record whose exp has passed → rejected by parse_and_verify."""
        signer = DMPCrypto()
        record = BootstrapRecord(
            user_domain="example.com",
            signer_spk=signer.get_signing_public_key_bytes(),
            entries=[_entry()],
            seq=1,
            exp=int(time.time()) - 60,  # already expired
        )
        # Sign while still "fresh enough" in the protocol sense — the
        # expiry check runs in parse_and_verify, not at sign.
        wire = record.sign(signer)

        store = InMemoryDNSStore()
        store.publish_txt_record(bootstrap_rrset_name("example.com"), wire)

        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_bootstrap_reader_exception_returns_none(self):
        """A reader that raises is treated as a failed fetch (None)."""
        signer = DMPCrypto()
        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            _FailingReader(),
        )
        assert got is None

    def test_user_domain_case_insensitive_binding(self):
        """Binding uses casefold — EXAMPLE.com should verify against
        a record signed for example.com."""
        signer = DMPCrypto()
        record = _build_record(signer, user_domain="example.com")
        wire = record.sign(signer)

        store = InMemoryDNSStore()
        # Publish at the canonical name; ask under different casing.
        store.publish_txt_record(bootstrap_rrset_name("example.com"), wire)

        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
        )
        assert got is not None

    def test_now_override_applies_to_expiry(self):
        """Passing `now` well before the record's exp keeps an otherwise-
        fresh record valid; passing it well after triggers expiry.
        """
        signer = DMPCrypto()
        # Exp = now + 100s at sign time. Pass now = exp + 1 → expired.
        record = BootstrapRecord(
            user_domain="example.com",
            signer_spk=signer.get_signing_public_key_bytes(),
            entries=[_entry()],
            seq=1,
            exp=int(time.time()) + 100,
        )
        wire = record.sign(signer)

        store = InMemoryDNSStore()
        store.publish_txt_record(bootstrap_rrset_name("example.com"), wire)

        # Before exp → OK.
        got_ok = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
            now=int(time.time()),
        )
        assert got_ok is not None

        # After exp → None.
        got_stale = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            store,
            now=int(time.time()) + 1_000_000,
        )
        assert got_stale is None

    def test_empty_records_list_returns_none(self):
        """A reader returning an empty list (vs None) → still None."""

        class _EmptyListReader(DNSRecordReader):
            def query_txt_record(self, name: str) -> Optional[List[str]]:
                return []

        signer = DMPCrypto()
        got = fetch_bootstrap_record(
            "example.com",
            signer.get_signing_public_key_bytes(),
            _EmptyListReader(),
        )
        assert got is None
