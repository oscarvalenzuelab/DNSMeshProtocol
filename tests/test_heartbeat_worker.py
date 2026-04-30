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
    def test_solo_node_publishes_into_zone(self, store, transport, now) -> None:
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
        records = transport.query_txt_record(heartbeat_rrset_name("self.example"))
        assert records and len(records) == 1
        parsed = HeartbeatRecord.parse_and_verify(records[0], now=now)
        assert parsed is not None
        assert parsed.endpoint == "https://self.example.com"
        assert parsed.version == "0.1.0"

    def test_shared_zone_does_not_clobber_peers(self, store, transport, now) -> None:
        """Codex round-18 P1: when multiple nodes publish heartbeats
        under the SAME zone (cluster mode where all peers share
        ``DMP_CLUSTER_BASE_DOMAIN``), each node's tick must NOT wipe
        the others' wires from ``_dnsmesh-heartbeat.<shared-zone>``.

        Pre-fix: the worker did ``delete_txt_record(name, value=None)``
        before publishing its own wire, which erased every peer's
        record on a shared RRset. Cluster discovery collapsed to
        whichever node ticked last.

        Post-fix: only the node's OWN previous self-wire is evicted
        (via the tracked ``_last_self_wire``). Peers stay untouched.
        """
        # Pre-publish a peer's wire under the shared zone — simulates
        # another cluster node having already heartbeated into the
        # same RRset.
        peer_signer = _signer("peer-a", salt=b"A" * 32)
        peer_wire = _publish_peer_heartbeat(
            transport,
            peer_signer,
            "shared.example",
            endpoint="https://peer-a.example.com",
            ts=now,
        )
        # Now run the worker against the SAME shared zone.
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.1.0",
            dns_zone="shared.example",
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        # Tick once more to exercise the eviction path on the
        # second tick.
        worker.tick_once(now=now + 1)

        records = (
            transport.query_txt_record(heartbeat_rrset_name("shared.example")) or []
        )
        # Peer's wire is still present (NOT clobbered by self-publish).
        assert (
            peer_wire in records
        ), "self-publish wiped a peer's wire from the shared RRset"
        # And exactly ONE self-wire is present (latest tick), not two
        # leftover ones from each tick — the eviction path is working.
        own_spk = _signer().get_signing_public_key_bytes()
        own_wires = []
        for w in records:
            parsed = HeartbeatRecord.parse_and_verify(w, now=now + 1)
            if parsed and parsed.operator_spk == own_spk:
                own_wires.append(w)
        assert (
            len(own_wires) == 1
        ), f"expected 1 self-wire after eviction, got {len(own_wires)}"

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


class TestOrphanSweep:
    """Codex round-22 P1 — restart leaves orphan self-wires at
    ``_dnsmesh-heartbeat.<own-zone>`` because ``_last_self_wire``
    lives in process memory only. The worker MUST evict them on
    first tick of each lifetime, otherwise the RRset grows
    unbounded across restarts and inflates UDP responses past the
    512-byte cap."""

    def test_first_tick_sweeps_prior_process_self_wires(
        self, store, transport, now
    ) -> None:
        """Pre-seed the RRset with three self-wires from earlier
        process lifetimes (same operator key, different ts). The
        first tick should leave exactly ONE wire — the freshly-
        published current one."""
        signer = _signer("operator-A", salt=b"A" * 32)
        zone = "self.example"
        # Simulate prior-lifetime publishes: 3 wires at the RRset,
        # all signed by the same operator, all at older timestamps.
        for offset in (-300, -120, -30):
            old = HeartbeatRecord(
                endpoint="https://self.example.com",
                operator_spk=signer.get_signing_public_key_bytes(),
                version="0.4.9",
                ts=now + offset,
                exp=now + offset + 86400,
            )
            transport.publish_txt_record(heartbeat_rrset_name(zone), old.sign(signer))
        assert (
            len(transport.query_txt_record(heartbeat_rrset_name(zone))) == 3
        ), "fixture sanity"

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.2",
            dns_zone=zone,
        )
        worker = HeartbeatWorker(
            cfg,
            signer,
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)

        records = transport.query_txt_record(heartbeat_rrset_name(zone))
        assert (
            len(records) == 1
        ), f"expected exactly 1 self-wire after sweep, got {len(records)}"
        # And the surviving one is the FRESH publish, not a stale
        # carry-over: it MUST verify under `now` with the strict
        # ±300s freshness gate.
        rec = HeartbeatRecord.parse_and_verify(records[0], now=now)
        assert rec is not None
        assert rec.version == "0.5.2"
        assert rec.ts == now

    def test_sweep_does_not_touch_other_operators(self, store, transport, now) -> None:
        """A shared zone (cluster-mode siblings) carries multiple
        operators' self-wires at the same RRset. The sweep MUST
        only delete wires signed by THIS operator's key."""
        zone = "shared.example"
        peer_signer = _signer("peer-B", salt=b"B" * 32)
        peer_wire = _publish_peer_heartbeat(
            transport,
            peer_signer,
            zone,
            endpoint="https://peer-b.example.com",
            ts=now - 60,
        )
        # Plant an orphan self-wire as if from a previous lifetime.
        own_signer = _signer("operator-A", salt=b"A" * 32)
        old = HeartbeatRecord(
            endpoint="https://self.example.com",
            operator_spk=own_signer.get_signing_public_key_bytes(),
            version="0.4.9",
            ts=now - 200,
            exp=now - 200 + 86400,
        )
        transport.publish_txt_record(heartbeat_rrset_name(zone), old.sign(own_signer))
        assert len(transport.query_txt_record(heartbeat_rrset_name(zone))) == 2

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.2",
            dns_zone=zone,
        )
        worker = HeartbeatWorker(
            cfg,
            own_signer,
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)

        records = transport.query_txt_record(heartbeat_rrset_name(zone))
        # Peer's wire still there + exactly one fresh self-wire.
        assert peer_wire in records, "peer's wire must survive the sweep"
        assert len(records) == 2

    def test_sweep_only_runs_once(self, store, transport, now) -> None:
        """Subsequent ticks shouldn't re-sweep — the in-process
        ``_last_self_wire`` tracking handles eviction from then on,
        and re-querying the RRset every tick is wasted I/O."""
        signer = _signer("operator-A", salt=b"A" * 32)
        zone = "self.example"
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.2",
            dns_zone=zone,
        )
        worker = HeartbeatWorker(
            cfg,
            signer,
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        # Tick 1 — sweep flag flips.
        worker.tick_once(now=now)
        assert worker._orphan_sweep_done is True
        # Plant a fake orphan AFTER tick 1. Tick 2 must NOT delete
        # it (sweep already done; this proves the flag gates the
        # one-time behavior).
        rogue = HeartbeatRecord(
            endpoint="https://self.example.com",
            operator_spk=signer.get_signing_public_key_bytes(),
            version="0.4.9",
            ts=now - 60,
            exp=now - 60 + 86400,
        )
        rogue_wire = rogue.sign(signer)
        transport.publish_txt_record(heartbeat_rrset_name(zone), rogue_wire)

        worker.tick_once(now=now + 60)
        records = transport.query_txt_record(heartbeat_rrset_name(zone))
        assert rogue_wire in records, "post-sweep planted wire must NOT be cleaned"

    def test_no_record_writer_skips_sweep_silently(self, store, transport, now) -> None:
        """A worker constructed without a record_writer can't read
        OR write — sweep should no-op cleanly, not crash."""
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.2",
            dns_zone="self.example",
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=None,
            dns_reader=transport,
        )
        # No exception — _publish_own returns False and sweep is
        # never reached because record_writer is None.
        worker.tick_once(now=now)


class TestHarvestPeers:
    def test_seed_zone_heartbeat_ingested(self, store, transport, now) -> None:
        """A configured seed zone's heartbeat is queried, verified,
        and stored in the seen-store."""
        peer = _signer("peer-a", b"A" * 32)
        _publish_peer_heartbeat(
            transport,
            peer,
            "peer.example",
            endpoint="https://peer.example.com",
            ts=now,
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

    def test_garbage_at_zone_silently_dropped(self, store, transport, now) -> None:
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

    def test_self_zone_filtered_from_harvest(self, store, transport, now) -> None:
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
            transport,
            peer,
            "peer.example",
            endpoint="https://peer.example.com",
            ts=now,
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

    def test_oversized_gossip_truncated(self, store, transport, now) -> None:
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
            transport.publish_txt_record(heartbeat_rrset_name("hostile.example"), wire)
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
    def test_max_peers_caps_harvest_set(self, store, transport, now) -> None:
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
        # 3 seed zones queried for heartbeats (max_peers cap). The
        # own-zone read from the codex round-22 orphan-sweep is on
        # the local store and isn't a peer harvest, so exclude it
        # from the count.
        peer_heartbeat_queries = [
            q
            for q in queried
            if q.startswith("_dnsmesh-heartbeat.")
            and q != "_dnsmesh-heartbeat.self.example"
        ]
        assert len(peer_heartbeat_queries) == 3

    def test_legacy_url_seed_normalized_to_zone(self, store, transport, now) -> None:
        """A 0.4.x operator's DMP_HEARTBEAT_SEEDS entry was a URL
        like `https://dnsmesh.io`. node.py's _zone_from_seed strips
        the scheme; verify the worker accepts a zone-formatted seed
        without further translation."""
        peer = _signer("peer-c", b"C" * 32)
        _publish_peer_heartbeat(
            transport,
            peer,
            "dnsmesh.io",
            endpoint="https://dnsmesh.io",
            ts=now,
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
    def test_failing_zone_cools_down(self, store, transport, now) -> None:
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

    def test_recovering_zone_clears_cooldown(self, store, transport, now) -> None:
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
            transport,
            peer,
            "flaky.example",
            endpoint="https://flaky.example.com",
            ts=now + 119,
        )
        # Tick 3: cooldown elapsed, retry, succeeds.
        result = worker.tick_once(now=now + 120)
        assert result == 1
        # Tick 4: still queryable, succeeds again.
        result2 = worker.tick_once(now=now + 180)
        assert result2 == 1


class TestOwnHeartbeatShape:
    def test_published_wire_round_trips(self, store, transport, now) -> None:
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
        records = transport.query_txt_record(heartbeat_rrset_name("self.example"))
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

    def test_seen_graph_capped_at_max_seen_publish(self, store, transport, now) -> None:
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

    def test_seen_graph_replaces_rrset_each_tick(self, store, transport, now) -> None:
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

        # Tick 2 on the SAME worker instance: peer-a's wire in the
        # local SeenStore expires; peer-b arrives. The published
        # RRset must reflect ONLY peer-b. The worker tracks
        # ``_last_seen_wires`` across ticks and evicts the wires
        # it published last that have dropped out of the snapshot
        # — peer-a's stale wire is among them.
        future = now + 86400 * 2  # past the default 24h heartbeat window
        # Reset cooldown so the failing peer-a seed doesn't block
        # the new peer-b harvest.
        worker._cooldown.clear()
        # Reconfigure the seed list at runtime so the existing worker
        # harvests peer-b on tick 2.
        worker._cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.0",
            dns_zone="self.example",
            seed_zones=("peer-b.example",),
        )
        _publish_peer_heartbeat(
            transport,
            _signer("peer-b", salt=b"B" * 32),
            "peer-b.example",
            endpoint="https://peer-b.example.com",
            ts=future,
        )
        worker.tick_once(now=future)
        second = transport.query_txt_record(seen_rrset_name("self.example")) or []
        # Only the live peer (peer-b) should appear; peer-a's stale
        # wire from tick 1 was evicted via per-wire tracking.
        assert len(second) == 1
        parsed = HeartbeatRecord.parse_and_verify(second[0], now=future)
        assert parsed is not None
        assert parsed.endpoint == "https://peer-b.example.com"

    def test_shared_zone_seen_graph_does_not_clobber_peers(
        self, store, transport, now
    ) -> None:
        """Codex round-19 P1: when multiple cluster nodes publish
        their seen-graph under the SAME shared zone, each node's
        tick must NOT wipe the others' contributions from
        ``_dnsmesh-seen.<shared-zone>``."""
        # A peer cluster node already published a wire into the
        # shared seen RRset (simulated by direct write).
        peer_signer = _signer("peer-a", salt=b"A" * 32)
        sibling_wire = _publish_peer_heartbeat(
            transport,
            peer_signer,
            "peer-a.example",
            endpoint="https://peer-a.example.com",
            ts=now,
        )
        transport.publish_txt_record(seen_rrset_name("shared.example"), sibling_wire)
        # Now run our own worker against the same shared zone with
        # its own different peer in its SeenStore.
        own_peer = _signer("peer-c", salt=b"C" * 32)
        own_wire = _publish_peer_heartbeat(
            transport,
            own_peer,
            "peer-c.example",
            endpoint="https://peer-c.example.com",
            ts=now,
        )
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.5.0",
            dns_zone="shared.example",
            seed_zones=("peer-c.example",),
        )
        worker = HeartbeatWorker(
            cfg,
            _signer(),
            store,
            record_writer=transport,
            dns_reader=transport,
        )
        worker.tick_once(now=now)
        worker.tick_once(now=now + 1)

        records = transport.query_txt_record(seen_rrset_name("shared.example")) or []
        # Sibling cluster node's wire is still present (NOT
        # clobbered by the seen-graph publish).
        assert (
            sibling_wire in records
        ), "seen-graph publish wiped a sibling cluster node's wire"

    def test_seen_graph_values_are_independently_verifiable(
        self, store, transport, now
    ) -> None:
        """A consumer querying _dnsmesh-seen.<zone> can re-verify
        every wire on its own — no trust in the publishing node
        beyond DNS chain integrity."""
        signers = [_signer(f"peer-{i}", salt=bytes([0x20 + i]) * 32) for i in range(2)]
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


class TestSeenGraphSelfFilterAndOrphanSweep:
    """Self never belongs in a node's own ``_dnsmesh-seen.<zone>``
    RRset. Seen is "OTHER nodes I have heard from" — listing self
    creates a discovery-graph self-loop and inflates the RRset toward
    the recursive-resolver UDP buffer cap.

    Two layers of protection:
      1. Drop self-wires at ingest in ``_fetch_and_ingest`` so they
         never land in the local SeenStore.
      2. Filter self when building ``next_wires`` in
         ``_publish_seen_graph`` — defense-in-depth if a future
         bootstrap path leaks self into the store via some other
         route.

    Plus a one-shot orphan sweep on first tick to clean up
    accumulated wires from prior process lifetimes (mirrors the
    round-22 sweep added for the heartbeat RRset).
    """

    def test_self_wire_in_store_not_republished_in_seen(
        self, store, transport, now
    ) -> None:
        """If self somehow lands in the local SeenStore, the publish
        path must filter it out — a node never lists itself in its
        own seen RRset."""
        own = _signer("operator-A", salt=b"A" * 32)
        # Inject self directly into the store, simulating a stale
        # bootstrap path that put it there (e.g. older builds that
        # didn't filter at ingest).
        own_hb = HeartbeatRecord(
            endpoint="https://self.example.com",
            operator_spk=own.get_signing_public_key_bytes(),
            version="0.5.0",
            ts=now - 10,
            exp=now + 86400,
        )
        store.accept(own_hb.sign(own), now=now)
        # Plus a real peer so the test exercises the "publish only
        # the non-self entry" path, not the empty-set branch.
        _publish_peer_heartbeat(
            transport,
            _signer("peer-a", salt=b"P" * 32),
            "peer-a.example",
            endpoint="https://peer-a.example.com",
            ts=now,
        )

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.6.2",
            dns_zone="self.example",
            seed_zones=("peer-a.example",),
        )
        worker = HeartbeatWorker(
            cfg, own, store, record_writer=transport, dns_reader=transport
        )
        worker.tick_once(now=now)

        published = transport.query_txt_record(seen_rrset_name("self.example")) or []
        own_spk_hex = own.get_signing_public_key_bytes().hex()
        for wire in published:
            rec = HeartbeatRecord.parse_and_verify(wire, now=now)
            assert rec is not None
            assert (
                bytes(rec.operator_spk).hex() != own_spk_hex
            ), "self-wire leaked into our own _dnsmesh-seen RRset"
        # And the legitimate peer IS there.
        assert len(published) == 1

    def test_peer_gossiping_us_back_does_not_seed_self(
        self, store, transport, now
    ) -> None:
        """Root-cause check: when a peer's ``_dnsmesh-seen.<peer-zone>``
        RRset includes our own wire (a peer that has heard from us
        and republishes), ``_fetch_and_ingest`` must drop it before
        ``SeenStore.accept`` so self never enters the local store.
        Otherwise step 2 (publish filter) is the only thing keeping
        self out of DNS, and any future bug there leaks immediately.
        """
        own = _signer("operator-A", salt=b"A" * 32)
        peer = _signer("peer-B", salt=b"B" * 32)

        # Peer's heartbeat zone — normal, peer's own wire.
        _publish_peer_heartbeat(
            transport,
            peer,
            "peer.example",
            endpoint="https://peer.example.com",
            ts=now,
        )
        # Peer's seen-graph zone — peer is gossiping our wire back.
        own_hb = HeartbeatRecord(
            endpoint="https://self.example.com",
            operator_spk=own.get_signing_public_key_bytes(),
            version="0.6.0",
            ts=now - 5,
            exp=now + 86400,
        )
        transport.publish_txt_record(seen_rrset_name("peer.example"), own_hb.sign(own))

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.6.2",
            dns_zone="self.example",
            seed_zones=("peer.example",),
        )
        worker = HeartbeatWorker(
            cfg, own, store, record_writer=transport, dns_reader=transport
        )
        worker.tick_once(now=now)

        # The local store should hold the peer's wire but NOT our
        # own — even though the peer's gossip path served it.
        own_spk_hex = own.get_signing_public_key_bytes().hex()
        for row in store.list_recent(now=now):
            assert (
                row.operator_spk_hex != own_spk_hex
            ), "self-wire ingested into local SeenStore via peer gossip"
        # Peer's wire IS there.
        assert any(
            row.operator_spk_hex == peer.get_signing_public_key_bytes().hex()
            for row in store.list_recent(now=now)
        )

    def test_first_tick_sweeps_prior_process_seen_orphans(
        self, store, transport, now
    ) -> None:
        """Pre-seed ``_dnsmesh-seen.<own-zone>`` with stale self-
        wires from earlier process lifetimes (a real-world failure
        mode caused by self-leak + process-memory eviction tracking).
        The first tick must clean them up so the published RRset
        shrinks back to a single entry per peer.
        """
        own = _signer("operator-A", salt=b"A" * 32)
        zone = "self.example"
        # Three orphan self-wires at the seen RRset, simulating
        # multiple prior lifetimes that all leaked self.
        for offset in (-300, -120, -30):
            old = HeartbeatRecord(
                endpoint="https://self.example.com",
                operator_spk=own.get_signing_public_key_bytes(),
                version="0.6.0",
                ts=now + offset,
                exp=now + offset + 86400,
            )
            transport.publish_txt_record(seen_rrset_name(zone), old.sign(own))
        # And one legitimate peer wire we want to keep.
        peer = _signer("peer-B", salt=b"B" * 32)
        peer_wire = _publish_peer_heartbeat(
            transport,
            peer,
            "peer.example",
            endpoint="https://peer.example.com",
            ts=now,
        )
        # Peer is in our store via the harvest below; pre-publish
        # it directly into the seen RRset so the sweep has a real
        # peer to keep.
        transport.publish_txt_record(seen_rrset_name(zone), peer_wire)
        assert len(transport.query_txt_record(seen_rrset_name(zone))) == 4

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.6.2",
            dns_zone=zone,
            seed_zones=("peer.example",),
        )
        worker = HeartbeatWorker(
            cfg, own, store, record_writer=transport, dns_reader=transport
        )
        worker.tick_once(now=now)

        records = transport.query_txt_record(seen_rrset_name(zone)) or []
        own_spk_hex = own.get_signing_public_key_bytes().hex()
        # No self left.
        for w in records:
            rec = HeartbeatRecord.parse_and_verify(w, now=now)
            assert rec is not None
            assert bytes(rec.operator_spk).hex() != own_spk_hex
        # Peer wire still there (untouched by the sweep — we never
        # delete other operators' wires).
        assert peer_wire in records

    def test_seen_sweep_does_not_touch_other_operators(
        self, store, transport, now
    ) -> None:
        """A shared zone (cluster siblings publishing into the same
        ``_dnsmesh-seen.<shared-zone>``) must keep peers' wires
        intact through the sweep. Only THIS operator's self-leakage
        + our own prior stale copies of currently-seen peers are
        targets. Codex round-19 P1 carry-over behavior.
        """
        own = _signer("operator-A", salt=b"A" * 32)
        zone = "shared.example"

        # A sibling node has published a wire at the shared zone.
        sibling_signer = _signer("sibling", salt=b"S" * 32)
        sibling_peer_wire = _publish_peer_heartbeat(
            transport,
            sibling_signer,
            "sib-peer.example",
            endpoint="https://sib-peer.example.com",
            ts=now - 30,
        )
        # Sibling published the sib-peer wire into the shared seen
        # RRset directly (simulating cluster co-publish).
        transport.publish_txt_record(seen_rrset_name(zone), sibling_peer_wire)

        # Plant a self-orphan from an earlier process lifetime.
        own_old = HeartbeatRecord(
            endpoint="https://self.example.com",
            operator_spk=own.get_signing_public_key_bytes(),
            version="0.6.0",
            ts=now - 200,
            exp=now - 200 + 86400,
        )
        transport.publish_txt_record(seen_rrset_name(zone), own_old.sign(own))
        assert len(transport.query_txt_record(seen_rrset_name(zone))) == 2

        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.6.2",
            dns_zone=zone,
        )
        worker = HeartbeatWorker(
            cfg, own, store, record_writer=transport, dns_reader=transport
        )
        worker.tick_once(now=now)

        records = transport.query_txt_record(seen_rrset_name(zone)) or []
        # Sibling's wire SURVIVED.
        assert sibling_peer_wire in records
        # Self-orphan deleted.
        own_spk_hex = own.get_signing_public_key_bytes().hex()
        for w in records:
            rec = HeartbeatRecord.parse_and_verify(w, now=now)
            assert rec is not None
            assert bytes(rec.operator_spk).hex() != own_spk_hex

    def test_seen_sweep_only_runs_once(self, store, transport, now) -> None:
        """Subsequent ticks shouldn't re-sweep — the in-process
        ``_last_seen_wires`` tracking handles eviction from there
        forward. Re-querying the RRset every tick is wasted I/O and
        could mask a legitimate operator-side write that should be
        treated as authoritative."""
        own = _signer("operator-A", salt=b"A" * 32)
        zone = "self.example"
        cfg = HeartbeatWorkerConfig(
            self_endpoint="https://self.example.com",
            version="0.6.2",
            dns_zone=zone,
        )
        worker = HeartbeatWorker(
            cfg, own, store, record_writer=transport, dns_reader=transport
        )
        worker.tick_once(now=now)
        assert worker._seen_orphan_sweep_done is True

        # Plant a fake self-orphan AFTER tick 1. Subsequent ticks
        # must NOT touch it (the flag gates the one-time behavior).
        rogue = HeartbeatRecord(
            endpoint="https://self.example.com",
            operator_spk=own.get_signing_public_key_bytes(),
            version="0.6.0",
            ts=now - 60,
            exp=now - 60 + 86400,
        )
        rogue_wire = rogue.sign(own)
        transport.publish_txt_record(seen_rrset_name(zone), rogue_wire)

        worker.tick_once(now=now + 60)
        records = transport.query_txt_record(seen_rrset_name(zone)) or []
        assert rogue_wire in records, "post-sweep planted wire must NOT be re-cleaned"


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
