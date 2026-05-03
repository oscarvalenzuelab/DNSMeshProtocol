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
) -> str:
    """Returns the wire string. Tests that need both the record and
    the wire can parse_and_verify the wire themselves — keeps the
    store's API as the single point of trust."""
    hb = HeartbeatRecord(
        endpoint=endpoint,
        operator_spk=signer.get_signing_public_key_bytes(),
        version=version,
        ts=ts,
        exp=ts + exp_delta,
    )
    return hb.sign(signer)


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
        wire = _build_and_sign(signer, ts=now)
        assert store.accept(wire, remote_addr="10.0.0.1", now=now) is not None

        rows = store.list_recent(now=now)
        assert len(rows) == 1
        assert rows[0].wire == wire
        assert rows[0].endpoint == "https://dmp.example.com"
        assert rows[0].ts == now
        assert rows[0].remote_addr == "10.0.0.1"

    def test_accept_rejects_unverified_wire(self, store: SeenStore, now: int) -> None:
        """Codex phase-2 P3: accept verifies internally. Garbage
        wire must short-circuit to None and NOT touch the DB."""
        result = store.accept("not-a-valid-wire", now=now)
        assert result is None
        assert store.count() == 0

    def test_accept_rejects_tampered_wire(self, store: SeenStore, now: int) -> None:
        """A wire whose body has been mutated must fail the embedded
        signature verification and be refused."""
        signer = _signer()
        wire = _build_and_sign(signer, ts=now)
        # Flip one middle byte of the base64 payload to corrupt body.
        prefix, payload = wire.split(";", 2)[:2], wire.split(";", 2)[2]
        # Any-one-byte flip; keep it within the base64 alphabet.
        mutated = wire[:-4] + ("A" if wire[-4] != "A" else "B") + wire[-3:]
        assert store.accept(mutated, now=now) is None
        assert store.count() == 0

    def test_upsert_on_repeat_pair(self, store: SeenStore, now: int) -> None:
        """Same (operator_spk, endpoint) pair → overwrite the older row."""
        signer = _signer()
        wire_a = _build_and_sign(signer, ts=now)
        wire_b = _build_and_sign(signer, ts=now + 60)
        store.accept(wire_a, now=now)
        store.accept(wire_b, now=now + 60)

        rows = store.list_recent(now=now + 60)
        assert len(rows) == 1
        assert rows[0].ts == now + 60
        assert rows[0].wire == wire_b

    def test_older_ts_does_not_clobber_newer(self, store: SeenStore, now: int) -> None:
        """Race: if an out-of-order older heartbeat arrives after a
        newer one, it must NOT overwrite the newer row."""
        signer = _signer()
        wire_new = _build_and_sign(signer, ts=now + 120)
        wire_old = _build_and_sign(signer, ts=now)
        store.accept(wire_new, now=now + 120)
        store.accept(wire_old, now=now + 120)

        rows = store.list_recent(now=now + 120)
        assert len(rows) == 1
        assert rows[0].ts == now + 120
        assert rows[0].wire == wire_new

    def test_distinct_nodes_both_stored(self, store: SeenStore, now: int) -> None:
        s1 = _signer("a", b"A" * 32)
        s2 = _signer("b", b"B" * 32)
        w1 = _build_and_sign(s1, ts=now)
        w2 = _build_and_sign(s2, "https://other.example.com", ts=now)
        store.accept(w1, now=now)
        store.accept(w2, now=now)

        rows = store.list_recent(now=now)
        assert len(rows) == 2

    def test_same_operator_different_endpoint_both_stored(
        self, store: SeenStore, now: int
    ) -> None:
        signer = _signer()
        w1 = _build_and_sign(signer, "https://a.example.com", ts=now)
        w2 = _build_and_sign(signer, "https://b.example.com", ts=now)
        store.accept(w1, now=now)
        store.accept(w2, now=now)

        rows = store.list_recent(now=now)
        assert len(rows) == 2


class TestListRecentFilters:
    def test_expired_excluded(self, store: SeenStore, now: int) -> None:
        """A row whose `exp` is <= now should NOT appear in list_recent
        even if sweep_expired hasn't run yet."""
        signer = _signer()
        # Accept at the original time (when the wire is fresh); then
        # query at a later time after exp has passed.
        wire = _build_and_sign(signer, ts=now - 86400 - 1, exp_delta=60)
        store.accept(wire, now=now - 86400 - 1)

        rows = store.list_recent(now=now)
        assert rows == []

    def test_list_respects_limit(self, store: SeenStore, now: int) -> None:
        for i in range(5):
            signer = _signer(str(i), bytes([i + 1]) * 32)
            wire = _build_and_sign(signer, f"https://n{i}.example.com", ts=now + i)
            store.accept(wire, now=now + i)

        rows = store.list_recent(now=now + 5, limit=2)
        assert len(rows) == 2
        # Newest first by ts.
        assert rows[0].ts == now + 4
        assert rows[1].ts == now + 3


# ---------------------------------------------------------------------------
# Retention sweep + row-count cap
# ---------------------------------------------------------------------------


class TestRetention:
    def test_sweep_drops_well_past_exp(self, tmp_path: Path, now: int) -> None:
        # Short retention so we don't need a 72h jump.
        store = SeenStore(str(tmp_path / "hb.db"), retention_seconds=60)
        try:
            signer = _signer()
            wire = _build_and_sign(signer, ts=now - 1000, exp_delta=60)
            store.accept(wire, now=now - 1000)
            # At `now`, exp = now - 940; retention = 60s; so exp < now - 60.
            deleted = store.sweep_expired(now=now)
            assert deleted == 1
            assert store.count() == 0
        finally:
            store.close()

    def test_sweep_keeps_rows_within_retention(self, tmp_path: Path, now: int) -> None:
        store = SeenStore(str(tmp_path / "hb.db"), retention_seconds=3600)
        try:
            signer = _signer()
            wire = _build_and_sign(signer, ts=now, exp_delta=86400)
            store.accept(wire, now=now)
            # exp is in the future — sweep must not drop it.
            deleted = store.sweep_expired(now=now + 60)
            assert deleted == 0
            assert store.count() == 1
        finally:
            store.close()


class TestRowCountCap:
    def test_insert_past_cap_evicts_oldest(self, tmp_path: Path, now: int) -> None:
        store = SeenStore(str(tmp_path / "hb.db"), max_rows=3)
        try:
            # Insert 5 distinct rows with increasing received_at order.
            for i in range(5):
                signer = _signer(str(i), bytes([i + 1]) * 32)
                wire = _build_and_sign(signer, f"https://n{i}.example.com", ts=now + i)
                store.accept(wire, now=now + i)

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

    def test_cap_does_not_evict_live_because_of_stale(
        self, tmp_path: Path, now: int
    ) -> None:
        """Codex phase-2 P2: cap must be enforced against LIVE rows
        only. If the DB holds a mix of stale + live, a fresh accept
        that hits the cap should evict stale rows before ever
        considering a live row.
        """
        store = SeenStore(
            str(tmp_path / "hb.db"),
            max_rows=2,
            retention_seconds=100 * 86400,
        )
        try:
            # Seed with a stale row (exp well in the past at list time).
            stale_signer = _signer("stale", b"S" * 32)
            stale_wire = _build_and_sign(
                stale_signer,
                "https://stale.example.com",
                ts=now - 86400,
                exp_delta=60,
            )
            store.accept(stale_wire, now=now - 86400)

            # Two live rows fill the cap.
            for i in range(2):
                signer = _signer(f"live{i}", bytes([i + 1]) * 32)
                wire = _build_and_sign(
                    signer, f"https://live{i}.example.com", ts=now + i
                )
                store.accept(wire, now=now + i)

            # Accept one more live row — this is over cap IF stale
            # counts. Pre-fix: stale stays, one of live0/live1 evicted.
            # Post-fix: stale pruned first, all 3 live rows kept + cap
            # still over-by-one-live so oldest-live evicted.
            new_signer = _signer("live-new", b"N" * 32)
            new_wire = _build_and_sign(
                new_signer, "https://live-new.example.com", ts=now + 10
            )
            store.accept(new_wire, now=now + 10)

            # The stale row must be gone. The live rows must fill
            # exactly the cap (2).
            live_rows = store.list_recent(now=now + 10)
            endpoints = sorted(r.endpoint for r in live_rows)
            assert "https://stale.example.com" not in endpoints
            # With cap=2 and 3 live rows inserted, oldest-live evicted.
            assert len(live_rows) == 2
            assert "https://live-new.example.com" in endpoints
        finally:
            store.close()


class TestCrossProcessSharedDb:
    def test_two_store_instances_same_db_newer_ts_wins(
        self, tmp_path: Path, now: int
    ) -> None:
        """Codex phase-2 P3: two SeenStore instances over the same
        SQLite file must still respect the "newer ts wins" invariant
        under the ON CONFLICT clause.

        This simulates two node processes each with its own SeenStore
        pointing at a shared DB (unusual but possible deploy). The
        in-process lock doesn't cross processes; the SQLite-level
        constraint does.
        """
        db = str(tmp_path / "shared.db")
        store_a = SeenStore(db)
        store_b = SeenStore(db)
        try:
            signer = _signer()
            wire_old = _build_and_sign(signer, ts=now)
            wire_new = _build_and_sign(signer, ts=now + 120)

            # Instance A accepts the NEWER wire first.
            store_a.accept(wire_new, now=now + 120)
            # Instance B accepts the older wire.
            store_b.accept(wire_old, now=now + 120)

            # Either instance, reading, must see the newer wire.
            rows_a = store_a.list_recent(now=now + 120)
            rows_b = store_b.list_recent(now=now + 120)
            assert len(rows_a) == 1
            assert len(rows_b) == 1
            assert rows_a[0].ts == now + 120
            assert rows_b[0].ts == now + 120
            assert rows_a[0].wire == wire_new
            assert rows_b[0].wire == wire_new
        finally:
            store_a.close()
            store_b.close()


# ---------------------------------------------------------------------------
# Ping-list exposure
# ---------------------------------------------------------------------------


class TestPingList:
    def test_returns_unique_endpoints_newest_first(
        self, store: SeenStore, now: int
    ) -> None:
        for i in range(3):
            signer = _signer(str(i), bytes([i + 1]) * 32)
            wire = _build_and_sign(signer, f"https://n{i}.example.com", ts=now + i)
            store.accept(wire, now=now + i)
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
        wire = _build_and_sign(signer, ts=now)
        store.accept(wire, now=now)
        spk_hex = signer.get_signing_public_key_bytes().hex()

        assert store.forget(spk_hex, "https://dmp.example.com") is True
        assert store.list_recent(now=now) == []

    def test_forget_idempotent(self, store: SeenStore, now: int) -> None:
        signer = _signer()
        wire = _build_and_sign(signer, ts=now)
        store.accept(wire, now=now)
        spk_hex = signer.get_signing_public_key_bytes().hex()
        store.forget(spk_hex, "https://dmp.example.com")
        assert store.forget(spk_hex, "https://dmp.example.com") is False


class TestSchemaVersioning:
    """``PRAGMA user_version`` migration ladder for SeenStore.

    Per-node singleton with a single schema version so far; the ladder
    is in place for future bumps and to refuse newer-on-older opens.
    """

    def test_fresh_db_is_stamped_at_current_version(self, tmp_path):
        from dmp.server.heartbeat_store import _SCHEMA_VERSION, SeenStore

        store = SeenStore(str(tmp_path / "fresh.db"))
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == _SCHEMA_VERSION
        finally:
            store.close()

    def test_legacy_unversioned_db_is_migrated(self, tmp_path):
        """A pre-versioning database (current schema, user_version=0)
        opens cleanly, gets the current version stamped, and existing
        rows survive — the migration is no-op data-wise."""
        import sqlite3

        from dmp.server.heartbeat_store import SeenStore, _SCHEMA_V1

        path = str(tmp_path / "legacy.db")
        legacy = sqlite3.connect(path)
        legacy.executescript(_SCHEMA_V1)
        legacy.execute(
            "INSERT INTO heartbeats_seen("
            "operator_spk_hex, endpoint, wire, ts, exp, version,"
            "received_at, remote_addr"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                "aa" * 32,
                "https://x.test",
                "v=dmp1;t=hb;d=AAAA",
                1000,
                9_999_999_999,
                "0.0.1",
                1500,
                "127.0.0.1",
            ),
        )
        legacy.commit()
        legacy.close()

        store = SeenStore(path)
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == 1
            row = store._conn.execute(
                "SELECT operator_spk_hex FROM heartbeats_seen"
            ).fetchone()
            assert row[0] == "aa" * 32
        finally:
            store.close()

    def test_future_version_db_refuses_to_open(self, tmp_path):
        """A db stamped HIGHER than this binary understands raises —
        running an older binary against newer data risks dropping
        fields silently."""
        import sqlite3

        from dmp.server.heartbeat_store import SeenStore, _SCHEMA_V1, _SCHEMA_VERSION

        path = str(tmp_path / "future.db")
        future = sqlite3.connect(path)
        future.executescript(_SCHEMA_V1)
        future.execute(f"PRAGMA user_version = {_SCHEMA_VERSION + 5}")
        future.commit()
        future.close()

        with pytest.raises(RuntimeError, match="schema version"):
            SeenStore(path)
