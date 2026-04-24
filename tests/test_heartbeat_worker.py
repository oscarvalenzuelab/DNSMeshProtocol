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
