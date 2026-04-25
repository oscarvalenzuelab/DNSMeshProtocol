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
    seen_rrset_name,
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


class TestTransitiveDiscovery:
    """M9.1.3 P2 regression: a node seeded with B must also harvest
    B's seen-graph at ``_dnsmesh-seen.<B>``, not just B's own
    heartbeat. Otherwise C is invisible to A unless A directly
    seeds C."""

    def test_a_learns_about_c_through_b(self, store, transport, now) -> None:
        # B has its own heartbeat published.
        b_signer = _signer("peer-b", salt=b"B" * 32)
        b_wire = _publish_peer_heartbeat(
            transport,
            b_signer,
            "peer-b.example",
            endpoint="https://peer-b.example.com",
            ts=now,
        )
        # B has ALSO observed C and republished C's heartbeat in
        # its seen-graph RRset. C's wire is signed by C's own key.
        c_signer = _signer("peer-c", salt=b"C" * 32)
        c_hb = HeartbeatRecord(
            endpoint="https://peer-c.example.com",
            operator_spk=c_signer.get_signing_public_key_bytes(),
            version="0.5.0",
            ts=now,
            exp=now + 86400,
        )
        c_wire = c_hb.sign(c_signer)
        transport.publish_txt_record(seen_rrset_name("peer-b.example"), c_wire)

        # A is seeded with B only. A ticks once and should pick up
        # both B (from heartbeat) AND C (from B's seen-graph).
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://a.example.com",
            version="0.5.0",
            dns_zone="a.example",
            seed_zones=("peer-b.example",),
        )
        worker = HeartbeatWorker(
            cfg, _signer(), store, record_writer=transport, dns_reader=transport
        )
        worker.tick_once(now=now)
        # Both peers landed in A's local SeenStore. Pass ``now=now``
        # so list_recent uses the same clock the test stamps records
        # with — the default uses real time and would filter our
        # past-stamped fixtures as expired.
        endpoints = {row.endpoint for row in store.list_recent(now=now)}
        assert "https://peer-b.example.com" in endpoints
        assert "https://peer-c.example.com" in endpoints


class TestSeenGraphPublish:
    """M9.1.3 — node republishes recently-verified peer wires under
    ``_dnsmesh-seen.<own-zone>`` as a multi-value TXT RRset so other
    nodes can crawl the mesh through pure DNS reads.
    """

    def test_publishes_each_seen_peer_as_separate_txt_value(
        self, store, transport, now
    ) -> None:
        """Two distinct peers in the SeenStore → two TXT values in
        the published RRset, each independently verifiable."""
        # Pre-populate two peer zones; harvest will ingest into store.
        peer_a = _publish_peer_heartbeat(
            transport,
            _signer("peer-a", salt=b"A" * 32),
            "peer-a.example",
            endpoint="https://peer-a.example.com",
            ts=now,
        )
        peer_b = _publish_peer_heartbeat(
            transport,
            _signer("peer-b", salt=b"B" * 32),
            "peer-b.example",
            endpoint="https://peer-b.example.com",
            ts=now,
        )

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.0",
            dns_zone="self.example",
            seed_zones=("peer-a.example", "peer-b.example"),
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)

        published = transport.query_txt_record(seen_rrset_name("self.example"))
        assert published is not None
        assert peer_a in published
        assert peer_b in published
        # Multi-value RRset, one entry per peer.
        assert len(published) == 2

    def test_seen_graph_is_empty_when_store_is_empty(
        self, store, transport, now
    ) -> None:
        """A node that has heard from no one publishes nothing under
        _dnsmesh-seen.<zone> — the absence is meaningful (no peers
        discovered yet)."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.0",
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
        assert transport.query_txt_record(seen_rrset_name("self.example")) is None

    def test_seen_graph_skipped_without_zone_or_writer(
        self, store, transport, now
    ) -> None:
        """No dns_zone OR no record_writer → no seen-graph publish.
        Read-only nodes don't expose a directory."""
        # Inject a row directly so the SeenStore has content. We use
        # the worker's own signer + endpoint so accept() verifies.
        signer = _signer()
        hb = HeartbeatRecord(
            endpoint="https://x.example.com",
            operator_spk=signer.get_signing_public_key_bytes(),
            version="0.1.0",
            ts=now,
            exp=now + 3600,
        )
        wire = hb.sign(signer)
        store.accept(wire, now=now)

        # No zone configured → publish skipped.
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="",
        )
        worker = HeartbeatWorker(
            cfg, _signer(), store, record_writer=transport, dns_reader=transport
        )
        worker.tick_once(now=now)
        assert transport.list_names() == []  # nothing published anywhere

        # Zone configured but no writer → publish skipped.
        cfg2 = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="self.example",
        )
        worker2 = HeartbeatWorker(
            cfg2, _signer(), store, record_writer=None, dns_reader=transport
        )
        worker2.tick_once(now=now)
        assert transport.list_names() == []  # still nothing published

    def test_seen_graph_capped_at_max_seen_publish(
        self, store, transport, now
    ) -> None:
        """A flood of seen peers must not produce an unbounded RRset —
        the worker caps at max_seen_publish."""
        # Publish 5 peers; cap to 3.
        for i in range(5):
            _publish_peer_heartbeat(
                transport,
                _signer(f"peer-{i}", salt=bytes([0x10 + i]) * 32),
                f"peer-{i}.example",
                endpoint=f"https://peer-{i}.example.com",
                ts=now,
            )

        seeds = tuple(f"peer-{i}.example" for i in range(5))
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.0",
            dns_zone="self.example",
            seed_zones=seeds,
            max_seen_publish=3,
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)

        published = transport.query_txt_record(seen_rrset_name("self.example"))
        assert published is not None
        assert len(published) == 3

    def test_seen_graph_replaces_rrset_each_tick(
        self, store, transport, now
    ) -> None:
        """Codex P1 regression: seen-graph publish must REPLACE the
        existing RRset, not APPEND to it. publish_txt_record's append
        semantics meant stale wires lingered for ttl_seconds and
        consumers saw newly-departed peers indefinitely."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.0",
            dns_zone="self.example",
            seed_zones=("peer-a.example",),
        )
        signer = _signer()
        worker = HeartbeatWorker(
            cfg, signer, store, record_writer=transport, dns_reader=transport
        )

        # Tick 1: peer-a is alive.
        _publish_peer_heartbeat(
            transport,
            _signer("peer-a", salt=b"A" * 32),
            "peer-a.example",
            endpoint="https://peer-a.example.com",
            ts=now,
        )
        worker.tick_once(now=now)
        first = transport.query_txt_record(seen_rrset_name("self.example")) or []
        assert len(first) == 1

        # Tick 2: peer-a's wire in the local SeenStore expires; peer-b
        # arrives. The published RRset must reflect ONLY peer-b.
        # Force expiry by jumping past peer-a's exp window.
        future = now + 86400 * 2  # past the default 24h heartbeat window
        _publish_peer_heartbeat(
            transport,
            _signer("peer-b", salt=b"B" * 32),
            "peer-b.example",
            endpoint="https://peer-b.example.com",
            ts=future,
        )
        worker = HeartbeatWorker(
            HeartbeatWorkerConfig(
                self_endpoint="https://self.example.com",
                version="0.5.0",
                dns_zone="self.example",
                seed_zones=("peer-b.example",),
            ),
            signer,
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=future)
        second = transport.query_txt_record(seen_rrset_name("self.example")) or []
        # Only the live peer (peer-b) should appear; peer-a's stale
        # wire from tick 1 must be evicted.
        assert len(second) == 1
        parsed = HeartbeatRecord.parse_and_verify(second[0], now=future)
        assert parsed is not None
        assert parsed.endpoint == "https://peer-b.example.com"

    def test_seen_graph_values_are_independently_verifiable(
        self, store, transport, now
    ) -> None:
        """A consumer querying _dnsmesh-seen.<zone> can re-verify
        every wire on its own — no trust in the publishing node
        beyond DNS chain integrity."""
        signers = [
            _signer(f"peer-{i}", salt=bytes([0x20 + i]) * 32) for i in range(2)
        ]
        for i, signer in enumerate(signers):
            _publish_peer_heartbeat(
                transport,
                signer,
                f"peer-{i}.example",
                endpoint=f"https://peer-{i}.example.com",
                ts=now,
            )
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.0",
            dns_zone="self.example",
            seed_zones=("peer-0.example", "peer-1.example"),
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)

        published = transport.query_txt_record(seen_rrset_name("self.example"))
        assert published and len(published) == 2
        spk_seen = set()
        for wire in published:
            parsed = HeartbeatRecord.parse_and_verify(wire, now=now)
            assert parsed is not None  # signature checks out
            spk_seen.add(bytes(parsed.operator_spk).hex())
        assert spk_seen == {
            signers[0].get_signing_public_key_bytes().hex(),
            signers[1].get_signing_public_key_bytes().hex(),
        }


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
