"""Tests for dmp.server.heartbeat_worker — M5.8 phase 4."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import HeartbeatRecord
from dmp.server.heartbeat_store import SeenStore
from dmp.server.heartbeat_worker import (
    HeartbeatWorker,
    HeartbeatWorkerConfig,
)


def _signer(passphrase: str = "op", salt: bytes = b"A" * 32) -> DMPCrypto:
    return DMPCrypto.from_passphrase(passphrase, salt=salt)


@pytest.fixture
def store(tmp_path: Path) -> SeenStore:
    s = SeenStore(str(tmp_path / "hb.db"))
    yield s
    s.close()


@pytest.fixture
def now() -> int:
    return 1_750_000_000


def _heartbeat(
    signer: DMPCrypto,
    endpoint: str = "https://peer.example.com",
    *,
    ts: int,
    version: str = "0.1.0",
) -> str:
    hb = HeartbeatRecord(
        endpoint=endpoint,
        operator_spk=signer.get_signing_public_key_bytes(),
        version=version,
        ts=ts,
        exp=ts + 86400,
    )
    return hb.sign(signer)


class _StubPoster:
    """Capture POSTs; optionally return canned responses keyed by URL."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, url: str, body: dict, timeout: float):
        self.calls.append((url, body, timeout))
        return self.responses.get(url)


# ---------------------------------------------------------------------------
# Tick mechanics
# ---------------------------------------------------------------------------


class TestTickBasics:
    def test_solo_node_no_seeds_no_calls(
        self, store: SeenStore, now: int
    ) -> None:
        """A freshly-started node with no seeds and no cluster peers
        has nothing to ping. tick_once returns 0 and does not raise."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(),
        )
        poster = _StubPoster()
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        assert worker.tick_once(now=now) == 0
        assert poster.calls == []

    def test_seeds_are_pinged(self, store: SeenStore, now: int) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=("https://seed1.example.com", "https://seed2.example.com"),
        )
        poster = _StubPoster(
            responses={
                "https://seed1.example.com/v1/heartbeat": {"ok": True, "seen": []},
                "https://seed2.example.com/v1/heartbeat": {"ok": True, "seen": []},
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        assert worker.tick_once(now=now) == 2
        urls = [c[0] for c in poster.calls]
        assert urls == [
            "https://seed1.example.com/v1/heartbeat",
            "https://seed2.example.com/v1/heartbeat",
        ]

    def test_gossip_response_written_to_store(
        self, store: SeenStore, now: int
    ) -> None:
        """A seed responds with {"seen": [wire1, wire2]} — those
        wires get verified and stored."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=("https://seed.example.com",),
        )
        # Build two independent peer heartbeats the seed would gossip.
        peer_a = _signer("a", b"A" * 32)
        peer_b = _signer("b", b"B" * 32)
        wire_a = _heartbeat(peer_a, "https://a.example.com", ts=now)
        wire_b = _heartbeat(peer_b, "https://b.example.com", ts=now)

        poster = _StubPoster(
            responses={
                "https://seed.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": [wire_a, wire_b],
                }
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)

        rows = store.list_recent(now=now)
        endpoints = sorted(r.endpoint for r in rows)
        assert endpoints == ["https://a.example.com", "https://b.example.com"]

    def test_gossip_with_tampered_wire_is_dropped(
        self, store: SeenStore, now: int
    ) -> None:
        """A hostile seed returns a junk wire — accept() verifies
        internally and discards it. The store stays empty."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=("https://hostile.example.com",),
        )
        poster = _StubPoster(
            responses={
                "https://hostile.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": ["not-a-valid-wire", "v=dmp1;t=heartbeat;garbage"],
                }
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        assert store.count() == 0


class TestPeerList:
    def test_self_is_filtered(self, store: SeenStore, now: int) -> None:
        """If the seed list includes our own endpoint, we must not
        ping ourselves (infinite-loop guard)."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(
                "https://self.example.com",
                "https://self.example.com/",  # trailing slash variant
                "https://real-seed.example.com",
            ),
        )
        poster = _StubPoster(
            responses={
                "https://real-seed.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": [],
                }
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        urls = [c[0] for c in poster.calls]
        assert urls == ["https://real-seed.example.com/v1/heartbeat"]

    def test_gossip_learned_peers_expand_set(
        self, store: SeenStore, now: int
    ) -> None:
        """Seeding the store with known peers should cause them to
        appear in the ping list on the next tick."""
        # Pre-seed the store with two known peers.
        for name in ("a", "b"):
            s = _signer(name, name.encode() * 32)
            store.accept(
                _heartbeat(s, f"https://{name}.example.com", ts=now),
                now=now,
            )

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(),  # no explicit seeds — rely on gossip
        )
        poster = _StubPoster(
            responses={
                "https://a.example.com/v1/heartbeat": {"ok": True, "seen": []},
                "https://b.example.com/v1/heartbeat": {"ok": True, "seen": []},
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        urls = sorted(c[0] for c in poster.calls)
        assert urls == [
            "https://a.example.com/v1/heartbeat",
            "https://b.example.com/v1/heartbeat",
        ]

    def test_max_peers_cap_applies(
        self, store: SeenStore, now: int
    ) -> None:
        """max_peers caps the outbound fan-out per tick."""
        seeds = tuple(f"https://s{i}.example.com" for i in range(10))
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=seeds,
            max_peers=3,
        )
        poster = _StubPoster()
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        assert len(poster.calls) == 3

    def test_cluster_peers_included(self, store: SeenStore, now: int) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(),
        )
        poster = _StubPoster(
            responses={
                "https://cluster-b.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": [],
                }
            }
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            cluster_peers_provider=lambda: [
                "https://cluster-b.example.com",
            ],
            http_poster=poster,
        )
        worker.tick_once(now=now)
        urls = [c[0] for c in poster.calls]
        assert urls == ["https://cluster-b.example.com/v1/heartbeat"]


class TestCooldown:
    def test_failing_peer_cools_down(self, store: SeenStore, now: int) -> None:
        """A peer that returns None (network / non-200) gets skipped
        on the next tick, not hammered."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=("https://broken.example.com",),
            failure_cooldown_ticks=2,
        )
        poster = _StubPoster(
            responses={"https://broken.example.com/v1/heartbeat": None}
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        # Tick 1: try broken, fail, cooldown=2.
        worker.tick_once(now=now)
        assert len(poster.calls) == 1
        # Tick 2: cooldown skips.
        worker.tick_once(now=now + 60)
        assert len(poster.calls) == 1  # unchanged
        # Tick 3: cooldown still running (2-1-1=0 but we decrement
        # each tick, so tick 2 sets cd=2 -> 1; tick 3 sets 1 -> 0;
        # skip happens when cd>0 BEFORE decrement).
        worker.tick_once(now=now + 120)
        assert len(poster.calls) == 1  # still skipped
        # Tick 4: cooldown elapsed; try again.
        worker.tick_once(now=now + 180)
        assert len(poster.calls) == 2  # retried

    def test_successful_peer_clears_cooldown(
        self, store: SeenStore, now: int
    ) -> None:
        """A peer transitions from failing to working — cooldown clears."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=("https://flaky.example.com",),
            failure_cooldown_ticks=1,
        )
        poster = _StubPoster()
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)

        # Tick 1: fail.
        poster.responses = {"https://flaky.example.com/v1/heartbeat": None}
        worker.tick_once(now=now)
        # Tick 2: cooldown skip.
        worker.tick_once(now=now + 60)
        assert len(poster.calls) == 1
        # Tick 3: retry succeeds.
        poster.responses = {
            "https://flaky.example.com/v1/heartbeat": {"ok": True, "seen": []}
        }
        worker.tick_once(now=now + 120)
        assert len(poster.calls) == 2
        # Tick 4: no cooldown now (cleared on success), pings again.
        worker.tick_once(now=now + 180)
        assert len(poster.calls) == 3


class TestOwnHeartbeatShape:
    def test_own_wire_is_valid_heartbeat(
        self, store: SeenStore, now: int
    ) -> None:
        """The wire the worker posts to peers must parse + verify
        cleanly on the receiving side."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=("https://seed.example.com",),
        )
        signer = _signer()
        poster = _StubPoster(
            responses={
                "https://seed.example.com/v1/heartbeat": {"ok": True, "seen": []}
            }
        )
        worker = HeartbeatWorker(cfg, signer, store, http_poster=poster)
        worker.tick_once(now=now)
        (url, body, _) = poster.calls[0]
        wire = body["wire"]
        parsed = HeartbeatRecord.parse_and_verify(wire, now=now)
        assert parsed is not None
        assert parsed.endpoint == "https://self.example.com"
        assert parsed.version == "0.1.0"
        assert parsed.operator_spk == signer.get_signing_public_key_bytes()


class TestFreshnessPerPeer:
    """Codex phase-4 P2: frozen-clock regression.

    The old worker signed ``own_wire`` ONCE at tick start and used
    the same ``now`` across every POST. With max_peers=25 ×
    http_timeout=10s the tail peer could receive a 250s-old wire,
    eating into the receiver's 5-min ts-skew budget. Now each POST
    refreshes ``now`` + re-signs.
    """

    def test_clock_refreshed_per_peer(
        self, store: SeenStore, now: int
    ) -> None:
        """Inject a poster that captures the `ts` field in each
        posted wire; assert ts increases across consecutive peers."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(
                "https://a.example.com",
                "https://b.example.com",
                "https://c.example.com",
            ),
        )

        captured_ts = []
        call_count = [0]

        def _stub(url, body, timeout):
            # Advance the virtual clock by 60 seconds per call so a
            # second-resolution per-peer ts MUST differ.
            parsed = HeartbeatRecord.parse_and_verify(
                body["wire"], now=now + call_count[0] * 60 + 1
            )
            assert parsed is not None
            captured_ts.append(parsed.ts)
            call_count[0] += 1
            return {"ok": True, "seen": []}

        class _ClockingWorker(HeartbeatWorker):
            """Subclass that advances clock 60s per POST to simulate
            a slow network where each peer takes a minute to respond."""

            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self._fake_now = now

            def _current_time(self) -> int:
                t = self._fake_now
                self._fake_now += 60
                return t

        # Instead of a subclass we override time.time indirectly by
        # passing explicit `now` to tick_once — but tick_once's
        # per-peer refresh only fires when `now is None`. So the
        # simpler test: don't pass `now`, and monkeypatch time.time
        # to a counter.
        import dmp.server.heartbeat_worker as hb_mod

        orig_time = hb_mod.time.time
        counter = [now]

        def _fake_time():
            counter[0] += 60
            return counter[0]

        hb_mod.time.time = _fake_time
        try:
            worker = HeartbeatWorker(cfg, _signer(), store, http_poster=_stub)
            worker.tick_once()  # no `now`, so each peer uses live time
            assert len(captured_ts) == 3
            # ts values strictly increase per POST (60s apart).
            assert captured_ts[0] < captured_ts[1] < captured_ts[2]
        finally:
            hb_mod.time.time = orig_time


class TestGossipIngestBounded:
    """Codex phase-4 P2: cap on per-response gossip ingest."""

    def test_oversized_gossip_is_truncated(
        self, store: SeenStore, now: int
    ) -> None:
        """A hostile seed returns `seen` with far more wires than
        the configured cap. The worker must only process up to
        max_gossip_per_response of them.
        """
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=("https://hostile.example.com",),
            max_gossip_per_response=3,
        )
        # Build 10 valid heartbeats from distinct signers.
        many = []
        for i in range(10):
            s = _signer(f"peer{i}", bytes([i + 10]) * 32)
            many.append(_heartbeat(s, f"https://p{i}.example.com", ts=now))

        poster = _StubPoster(
            responses={
                "https://hostile.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": many,
                }
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        # Only the first 3 of the 10 wires should have been accepted.
        assert store.count() == 3


class TestSelfFilterCanonicalization:
    """Codex phase-4 P2: self-filter must canonicalize URLs."""

    def test_uppercase_host_filtered(self, store: SeenStore, now: int) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(
                "https://SELF.example.com",
                "https://other.example.com",
            ),
        )
        poster = _StubPoster(
            responses={
                "https://other.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": [],
                }
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        urls = [c[0] for c in poster.calls]
        assert urls == ["https://other.example.com/v1/heartbeat"]

    def test_uppercase_scheme_filtered(
        self, store: SeenStore, now: int
    ) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(
                "HTTPS://self.example.com",
                "https://other.example.com",
            ),
        )
        poster = _StubPoster(
            responses={
                "https://other.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": [],
                }
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        urls = [c[0] for c in poster.calls]
        assert urls == ["https://other.example.com/v1/heartbeat"]

    def test_default_port_filtered(
        self, store: SeenStore, now: int
    ) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            seed_peers=(
                "https://self.example.com:443",  # default-port variant
                "https://other.example.com",
            ),
        )
        poster = _StubPoster(
            responses={
                "https://other.example.com/v1/heartbeat": {
                    "ok": True,
                    "seen": [],
                }
            }
        )
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.tick_once(now=now)
        urls = [c[0] for c in poster.calls]
        assert urls == ["https://other.example.com/v1/heartbeat"]


class TestLifecycle:
    def test_start_stop(self, store: SeenStore) -> None:
        """Daemon thread lifecycle: start -> stop returns cleanly even
        if no tick has fired yet."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            interval_seconds=10,  # never actually fires during the test
        )
        poster = _StubPoster()
        worker = HeartbeatWorker(cfg, _signer(), store, http_poster=poster)
        worker.start()
        # Give the thread a brief moment to hit its wait().
        time.sleep(0.05)
        worker.stop(timeout=2.0)
