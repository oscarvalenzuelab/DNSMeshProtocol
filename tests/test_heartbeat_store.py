"""Tests for dmp.server.heartbeat_store — M5.8 phase 2 seen-store."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import HeartbeatRecord
from dmp.server.heartbeat_store import (
    DEFAULT_MAX_ROWS,
    DEFAULT_RETENTION_SECONDS,
    SeenRow,
    SeenStore,
)


def _signer(passphrase: str = "alice-pass", salt: bytes = b"A" * 32) -> DMPCrypto:
    return DMPCrypto.from_passphrase(passphrase, salt=salt)


def _build_and_sign(
    signer: DMPCrypto,
    endpoint: str = "https://dmp.example.com",
    *,
    version: str = "0.1.0",
    ts: int,
    exp_delta: int = 86400,
) -> tuple:
    hb = HeartbeatRecord(
        endpoint=endpoint,
        operator_spk=signer.get_signing_public_key_bytes(),
        version=version,
        ts=ts,
        exp=ts + exp_delta,
    )
    return hb, hb.sign(signer)


@pytest.fixture
def now() -> int:
    return 1_750_000_000


@pytest.fixture
def store(tmp_path: Path) -> SeenStore:
    s = SeenStore(str(tmp_path / "heartbeats.db"))
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Writes + reads
# ---------------------------------------------------------------------------


class TestAcceptAndList:
    def test_round_trip(self, store: SeenStore, now: int) -> None:
        signer = _signer()
        hb, wire = _build_and_sign(signer, ts=now)
        store.accept(hb, wire, remote_addr="10.0.0.1", now=now)

        rows = store.list_recent(now=now)
        assert len(rows) == 1
        assert rows[0].wire == wire
        assert rows[0].endpoint == hb.endpoint
        assert rows[0].ts == now
        assert rows[0].remote_addr == "10.0.0.1"

    def test_upsert_on_repeat_pair(self, store: SeenStore, now: int) -> None:
        """Same (operator_spk, endpoint) pair → overwrite the older row
        rather than accumulate duplicates."""
        signer = _signer()
        _, wire_a = _build_and_sign(signer, ts=now)
        _, wire_b = _build_and_sign(signer, ts=now + 60)
        hb_a = HeartbeatRecord.parse_and_verify(wire_a, now=now)
        hb_b = HeartbeatRecord.parse_and_verify(wire_b, now=now + 60)
        store.accept(hb_a, wire_a, now=now)
        store.accept(hb_b, wire_b, now=now + 60)

        rows = store.list_recent(now=now + 60)
        assert len(rows) == 1
        # Newer ts wins.
        assert rows[0].ts == now + 60
        assert rows[0].wire == wire_b

    def test_older_ts_does_not_clobber_newer(
        self, store: SeenStore, now: int
    ) -> None:
        """Race: if an out-of-order older heartbeat arrives after a
        newer one, it must NOT overwrite the newer row.

        ON CONFLICT ... WHERE excluded.ts >= stored.ts handles this
        at the sqlite level.
        """
        signer = _signer()
        _, wire_new = _build_and_sign(signer, ts=now + 120)
        _, wire_old = _build_and_sign(signer, ts=now)
        hb_new = HeartbeatRecord.parse_and_verify(wire_new, now=now + 120)
        hb_old = HeartbeatRecord.parse_and_verify(wire_old, now=now)
        store.accept(hb_new, wire_new, now=now + 120)
        store.accept(hb_old, wire_old, now=now + 120)

        rows = store.list_recent(now=now + 120)
        assert len(rows) == 1
        assert rows[0].ts == now + 120
        assert rows[0].wire == wire_new

    def test_distinct_nodes_both_stored(
        self, store: SeenStore, now: int
    ) -> None:
        s1 = _signer("a", b"A" * 32)
        s2 = _signer("b", b"B" * 32)
        hb1, w1 = _build_and_sign(s1, ts=now)
        hb2, w2 = _build_and_sign(s2, "https://other.example.com", ts=now)
        store.accept(hb1, w1, now=now)
        store.accept(hb2, w2, now=now)

        rows = store.list_recent(now=now)
        assert len(rows) == 2

    def test_same_operator_different_endpoint_both_stored(
        self, store: SeenStore, now: int
    ) -> None:
        signer = _signer()
        hb1, w1 = _build_and_sign(signer, "https://a.example.com", ts=now)
        hb2, w2 = _build_and_sign(signer, "https://b.example.com", ts=now)
        store.accept(hb1, w1, now=now)
        store.accept(hb2, w2, now=now)

        rows = store.list_recent(now=now)
        assert len(rows) == 2


class TestListRecentFilters:
    def test_expired_excluded(self, store: SeenStore, now: int) -> None:
        """A row whose `exp` is <= now should NOT appear in list_recent
        even if sweep_expired hasn't run yet."""
        signer = _signer()
        hb, wire = _build_and_sign(signer, ts=now - 86400 - 1, exp_delta=1)
        # Write the row directly (bypassing the freshness check we
        # normally rely on upstream).
        store.accept(hb, wire, now=now - 86400 - 1)

        rows = store.list_recent(now=now)
        assert rows == []

    def test_list_respects_limit(self, store: SeenStore, now: int) -> None:
        for i in range(5):
            signer = _signer(str(i), bytes([i]) * 32)
            hb, wire = _build_and_sign(
                signer, f"https://n{i}.example.com", ts=now + i
            )
            store.accept(hb, wire, now=now + i)

        rows = store.list_recent(now=now + 5, limit=2)
        assert len(rows) == 2
        # Newest first by ts.
        assert rows[0].ts == now + 4
        assert rows[1].ts == now + 3


# ---------------------------------------------------------------------------
# Retention sweep + row-count cap
# ---------------------------------------------------------------------------


class TestRetention:
    def test_sweep_drops_well_past_exp(
        self, tmp_path: Path, now: int
    ) -> None:
        # Short retention so we don't need a 72h jump.
        store = SeenStore(str(tmp_path / "hb.db"), retention_seconds=60)
        try:
            signer = _signer()
            hb, wire = _build_and_sign(signer, ts=now - 1000, exp_delta=60)
            store.accept(hb, wire, now=now - 1000)
            # At `now`, exp = now - 940; retention = 60s; so exp < now - 60.
            deleted = store.sweep_expired(now=now)
            assert deleted == 1
            assert store.count() == 0
        finally:
            store.close()

    def test_sweep_keeps_rows_within_retention(
        self, tmp_path: Path, now: int
    ) -> None:
        store = SeenStore(str(tmp_path / "hb.db"), retention_seconds=3600)
        try:
            signer = _signer()
            hb, wire = _build_and_sign(signer, ts=now, exp_delta=86400)
            store.accept(hb, wire, now=now)
            # exp is in the future — sweep must not drop it.
            deleted = store.sweep_expired(now=now + 60)
            assert deleted == 0
            assert store.count() == 1
        finally:
            store.close()


class TestRowCountCap:
    def test_insert_past_cap_evicts_oldest(
        self, tmp_path: Path, now: int
    ) -> None:
        store = SeenStore(str(tmp_path / "hb.db"), max_rows=3)
        try:
            # Insert 5 distinct rows with increasing received_at
            # order (via the `now` parameter).
            for i in range(5):
                signer = _signer(str(i), bytes([i + 1]) * 32)
                hb, wire = _build_and_sign(
                    signer, f"https://n{i}.example.com", ts=now + i
                )
                store.accept(hb, wire, now=now + i)

            # At most 3 rows remain, and the two oldest (i=0,1) are gone.
            assert store.count() == 3
            rows = store.list_recent(now=now + 10)
            endpoints = sorted(r.endpoint for r in rows)
            assert endpoints == [
                "https://n2.example.com",
                "https://n3.example.com",
                "https://n4.example.com",
            ]
        finally:
            store.close()


# ---------------------------------------------------------------------------
# Ping-list exposure
# ---------------------------------------------------------------------------


class TestPingList:
    def test_returns_unique_endpoints_newest_first(
        self, store: SeenStore, now: int
    ) -> None:
        for i in range(3):
            signer = _signer(str(i), bytes([i + 1]) * 32)
            hb, wire = _build_and_sign(
                signer, f"https://n{i}.example.com", ts=now + i
            )
            store.accept(hb, wire, now=now + i)
        urls = store.list_for_ping(limit=2, now=now + 5)
        assert urls == ["https://n2.example.com", "https://n1.example.com"]

    def test_empty_store(self, store: SeenStore, now: int) -> None:
        assert store.list_for_ping(limit=10, now=now) == []


# ---------------------------------------------------------------------------
# forget — operator escape hatch
# ---------------------------------------------------------------------------


class TestForget:
    def test_forget_removes_row(self, store: SeenStore, now: int) -> None:
        signer = _signer()
        hb, wire = _build_and_sign(signer, ts=now)
        store.accept(hb, wire, now=now)
        spk_hex = signer.get_signing_public_key_bytes().hex()

        assert store.forget(spk_hex, hb.endpoint) is True
        assert store.list_recent(now=now) == []

    def test_forget_idempotent(self, store: SeenStore, now: int) -> None:
        signer = _signer()
        hb, wire = _build_and_sign(signer, ts=now)
        store.accept(hb, wire, now=now)
        spk_hex = signer.get_signing_public_key_bytes().hex()
        store.forget(spk_hex, hb.endpoint)
        # Second call returns False; store is unchanged.
        assert store.forget(spk_hex, hb.endpoint) is False
