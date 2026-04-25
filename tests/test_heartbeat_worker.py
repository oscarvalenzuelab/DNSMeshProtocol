"""Tests for dmp.server.heartbeat_worker — M9.1.2 DNS-native model.

The worker no longer POSTs to peers' /v1/heartbeat. Each tick:

  - Publishes its own signed heartbeat at
    ``_dnsmesh-heartbeat.<dns_zone>`` through the local record store.
  - Queries each configured seed zone's
    ``_dnsmesh-heartbeat.<seed_zone>`` through the supplied DNS
    reader, verifies, and feeds the wire into the SeenStore.

Tests use ``InMemoryDNSStore`` for both the writer and the reader —
in production they're separate (sqlite-backed authoritative store +
recursive resolver pool), but the abstract interface is the same.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import HeartbeatRecord
from dmp.network.memory import InMemoryDNSStore
from dmp.server.heartbeat_store import SeenStore
from dmp.server.heartbeat_worker import (
    HeartbeatWorker,
    HeartbeatWorkerConfig,
    heartbeat_rrset_name,
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


@pytest.fixture
def transport() -> InMemoryDNSStore:
    """Shared DNS reader/writer used by both the worker-under-test and
    test fixtures populating peer zones."""
    return InMemoryDNSStore()


def _publish_peer_heartbeat(
    transport: InMemoryDNSStore,
    signer: DMPCrypto,
    zone: str,
    *,
    endpoint: str,
    ts: int,
    version: str = "0.1.0",
) -> str:
    """Helper: a peer at `zone` has its heartbeat record live at
    `_dnsmesh-heartbeat.<zone>`. Returns the wire."""
    hb = HeartbeatRecord(
        endpoint=endpoint,
        operator_spk=signer.get_signing_public_key_bytes(),
        version=version,
        ts=ts,
        exp=ts + 86400,
    )
    wire = hb.sign(signer)
    transport.publish_txt_record(heartbeat_rrset_name(zone), wire)
    return wire


# ---------------------------------------------------------------------------
# Tick mechanics — publish + harvest
# ---------------------------------------------------------------------------


class TestPublishOwn:
    def test_solo_node_publishes_into_zone(
        self, store, transport, now
    ) -> None:
        """A node with a configured zone publishes its own heartbeat
        regardless of whether it has seeds — peers will discover it
        by querying the zone."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        records = transport.query_txt_record(
            heartbeat_rrset_name("self.example")
        )
        assert records and len(records) == 1
        parsed = HeartbeatRecord.parse_and_verify(records[0], now=now)
        assert parsed is not None
        assert parsed.endpoint == "https://self.example.com"
        assert parsed.version == "0.1.0"

    def test_no_zone_no_publish(self, store, transport, now) -> None:
        """Without a configured zone the worker still ticks but
        publishes nothing — useful for read-only / disposable nodes."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="",  # no zone configured
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        # Nothing was published anywhere.
        assert transport.list_names() == []

    def test_no_writer_no_publish(self, store, transport, now) -> None:
        """A worker built without a record_writer still ticks but
        publishes nothing (test-fixture mode)."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=None,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        assert transport.list_names() == []


class TestHarvestPeers:
    def test_seed_zone_heartbeat_ingested(
        self, store, transport, now
    ) -> None:
        """A configured seed zone's heartbeat is queried, verified,
        and stored in the seen-store."""
        peer = _signer("peer-a", b"A" * 32)
        _publish_peer_heartbeat(
            transport, peer, "peer.example",
            endpoint="https://peer.example.com", ts=now,
        )
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=("peer.example",),
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        assert worker.tick_once(now=now) == 1
        rows = store.list_recent(now=now)
        endpoints = [r.endpoint for r in rows]
        assert endpoints == ["https://peer.example.com"]

    def test_garbage_at_zone_silently_dropped(
        self, store, transport, now
    ) -> None:
        """A zone serving a malformed record at the heartbeat name —
        SeenStore.accept verifies and rejects, store stays empty."""
        transport.publish_txt_record(
            heartbeat_rrset_name("hostile.example"),
            "v=dmp1;t=heartbeat;not-real-base64",
        )
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=("hostile.example",),
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        assert store.count() == 0

    def test_self_zone_filtered_from_harvest(
        self, store, transport, now
    ) -> None:
        """If the worker's own zone appears in the seed list, the
        worker doesn't query itself (would re-ingest its own
        heartbeat with the wrong remote-addr provenance)."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=("self.example", "peer.example"),
        )
        peer = _signer("peer-b", b"B" * 32)
        _publish_peer_heartbeat(
            transport, peer, "peer.example",
            endpoint="https://peer.example.com", ts=now,
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        # Self-publish lands at our own _dnsmesh-heartbeat name. The
        # worker's filter prevents the harvest pass from re-ingesting
        # it. Only the peer's heartbeat ends up in the seen store.
        rows = store.list_recent(now=now)
        assert [r.endpoint for r in rows] == ["https://peer.example.com"]

    def test_oversized_gossip_truncated(
        self, store, transport, now
    ) -> None:
        """A zone serving more heartbeats than max_gossip_per_response
        only contributes that many to the seen-store. Defends against
        a hostile zone forcing unbounded crypto work."""
        # Multi-record TXT at one name with 10 distinct heartbeats.
        for i in range(10):
            s = _signer(f"peer{i}", bytes([i + 10]) * 32)
            wire = HeartbeatRecord(
                endpoint=f"https://p{i}.example.com",
                operator_spk=s.get_signing_public_key_bytes(),
                version="0.1.0",
                ts=now,
                exp=now + 86400,
            ).sign(s)
            transport.publish_txt_record(
                heartbeat_rrset_name("hostile.example"), wire
            )
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=("hostile.example",),
            max_gossip_per_response=3,
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        assert store.count() == 3


class TestSeedZoneList:
    def test_max_peers_caps_harvest_set(
        self, store, transport, now
    ) -> None:
        """max_peers caps the per-tick harvest fan-out."""
        seeds = tuple(f"s{i}.example" for i in range(10))
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=seeds,
            max_peers=3,
        )
        # Track which zones got queried.
        queried = []
        original = transport.query_txt_record

        def tracking_query(name):
            queried.append(name)
            return original(name)

        transport.query_txt_record = tracking_query
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        # 3 seed zones queried for heartbeats (max_peers cap).
        heartbeat_queries = [
            q for q in queried if q.startswith("_dnsmesh-heartbeat.")
        ]
        assert len(heartbeat_queries) == 3

    def test_legacy_url_seed_normalized_to_zone(
        self, store, transport, now
    ) -> None:
        """A 0.4.x operator's DMP_HEARTBEAT_SEEDS entry was a URL
        like `https://dnsmesh.io`. node.py's _zone_from_seed strips
        the scheme; verify the worker accepts a zone-formatted seed
        without further translation."""
        peer = _signer("peer-c", b"C" * 32)
        _publish_peer_heartbeat(
            transport, peer, "dnsmesh.io",
            endpoint="https://dnsmesh.io", ts=now,
        )
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=("dnsmesh.io",),
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        assert worker.tick_once(now=now) == 1


class TestCooldown:
    def test_failing_zone_cools_down(
        self, store, transport, now
    ) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=("broken.example",),
            failure_cooldown_ticks=2,
        )
        # broken.example has no _dnsmesh-heartbeat record published.
        # Track query attempts to assert cooldown skips them.
        original = transport.query_txt_record
        attempts = {"broken": 0}

        def tracking(name):
            if name == heartbeat_rrset_name("broken.example"):
                attempts["broken"] += 1
            return original(name)

        transport.query_txt_record = tracking
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        # Tick 1: query broken, fail, cooldown=2.
        worker.tick_once(now=now)
        assert attempts["broken"] == 1
        # Tick 2 + 3: cooldown skips.
        worker.tick_once(now=now + 60)
        assert attempts["broken"] == 1
        worker.tick_once(now=now + 120)
        assert attempts["broken"] == 1
        # Tick 4: cooldown elapsed; retry.
        worker.tick_once(now=now + 180)
        assert attempts["broken"] == 2

    def test_recovering_zone_clears_cooldown(
        self, store, transport, now
    ) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
            seed_zones=("flaky.example",),
            failure_cooldown_ticks=1,
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        # Tick 1: nothing published at flaky.example yet — fail.
        worker.tick_once(now=now)
        # Tick 2: cooldown skip.
        worker.tick_once(now=now + 60)
        # Now publish a real heartbeat at flaky.example.
        peer = _signer("flake", b"F" * 32)
        _publish_peer_heartbeat(
            transport, peer, "flaky.example",
            endpoint="https://flaky.example.com", ts=now + 119,
        )
        # Tick 3: cooldown elapsed, retry, succeeds.
        result = worker.tick_once(now=now + 120)
        assert result == 1
        # Tick 4: still queryable, succeeds again.
        result2 = worker.tick_once(now=now + 180)
        assert result2 == 1


class TestOwnHeartbeatShape:
    def test_published_wire_round_trips(
        self, store, transport, now
    ) -> None:
        """The wire we publish at _dnsmesh-heartbeat.<zone> is a
        verifiable HeartbeatRecord."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.4.4",
            dns_zone="self.example",
            capabilities=1,  # CAP_CLAIM_PROVIDER
            claim_provider_zone="self.example",
        )
        signer = _signer()
        worker = HeartbeatWorker(
            cfg,
            signer,
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        records = transport.query_txt_record(
            heartbeat_rrset_name("self.example")
        )
        assert records
        parsed = HeartbeatRecord.parse_and_verify(records[0], now=now)
        assert parsed is not None
        assert parsed.endpoint == "https://self.example.com"
        assert parsed.version == "0.4.4"
        assert parsed.capabilities == 1
        assert parsed.claim_provider_zone == "self.example"
        assert parsed.operator_spk == signer.get_signing_public_key_bytes()


class TestLifecycle:
    def test_start_stop(self, store, transport) -> None:
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            interval_seconds=10,
            dns_zone="self.example",
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.start()
        time.sleep(0.05)
        worker.stop(timeout=2.0)
