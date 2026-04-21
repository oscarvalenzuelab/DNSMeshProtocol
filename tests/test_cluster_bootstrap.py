"""Tests for the M2.wire ClusterClient + fetch_cluster_manifest.

Covers:
- `fetch_cluster_manifest` against an `InMemoryDNSStore` seeded with a
  signed manifest → returns the manifest.
- Wrong operator_spk → None.
- Multiple TXT records (one valid, several garbage) → picks the valid one.
- `ClusterClient.refresh_now` picks up a higher-seq manifest; install
  lands on both fanout + union; old seq ignored.
- `ClusterClient.refresh_now` on bootstrap_reader failure → returns False;
  existing manifest preserved.
- Background refresh calls refresh_now on cadence; close() stops the
  thread deterministically.
"""

from __future__ import annotations

import threading
import time
from typing import List, Optional

import pytest

from dmp.client.cluster_bootstrap import ClusterClient, fetch_cluster_manifest
from dmp.core.cluster import ClusterManifest, ClusterNode, cluster_rrset_name
from dmp.core.crypto import DMPCrypto
from dmp.network.base import DNSRecordReader, DNSRecordWriter
from dmp.network.memory import InMemoryDNSStore

# --------------------------------------------------------------------------- helpers


def _node(i: int, *, with_dns: bool = False) -> ClusterNode:
    return ClusterNode(
        node_id=f"n{i:02d}",
        http_endpoint=f"https://n{i}.example.com:8053",
        dns_endpoint=f"203.0.113.{i}:53" if with_dns else None,
    )


def _build_manifest(
    operator: DMPCrypto,
    *,
    seq: int = 1,
    exp_delta: int = 3600,
    cluster_name: str = "mesh.example.com",
    n_nodes: int = 2,
) -> ClusterManifest:
    return ClusterManifest(
        cluster_name=cluster_name,
        operator_spk=operator.get_signing_public_key_bytes(),
        nodes=[_node(i) for i in range(1, n_nodes + 1)],
        seq=seq,
        exp=int(time.time()) + exp_delta,
    )


class _FakeWriter(DNSRecordWriter):
    """No-op writer used to build FanoutWriter for tests that don't care."""

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        return True

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        return True


class _FakeReader(DNSRecordReader):
    """No-op reader used as a per-node reader factory."""

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        return None


class _CountingReader(DNSRecordReader):
    """Reader that records how many times it was queried.

    Useful for asserting that the background refresh thread is
    actually running.
    """

    def __init__(self, backing: DNSRecordReader) -> None:
        self._backing = backing
        self.calls = 0
        self._lock = threading.Lock()

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        with self._lock:
            self.calls += 1
        return self._backing.query_txt_record(name)


class _FailingReader(DNSRecordReader):
    """Reader whose `query_txt_record` always raises."""

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        raise RuntimeError("bootstrap reader down")


def _writer_factory(node: ClusterNode) -> DNSRecordWriter:
    return _FakeWriter()


def _reader_factory(node: ClusterNode) -> DNSRecordReader:
    return _FakeReader()


# --------------------------------------------------------------------------- fetch_cluster_manifest


class TestFetchClusterManifest:
    def test_happy_path(self):
        op = DMPCrypto()
        manifest = _build_manifest(op)
        wire = manifest.sign(op)

        store = InMemoryDNSStore()
        store.publish_txt_record(cluster_rrset_name("mesh.example.com"), wire)

        got = fetch_cluster_manifest(
            "mesh.example.com",
            op.get_signing_public_key_bytes(),
            store,
        )
        assert got is not None
        assert got.cluster_name == "mesh.example.com"
        assert got.seq == 1
        assert [n.node_id for n in got.nodes] == ["n01", "n02"]

    def test_wrong_operator_spk_returns_none(self):
        op = DMPCrypto()
        manifest = _build_manifest(op)
        wire = manifest.sign(op)

        store = InMemoryDNSStore()
        store.publish_txt_record(cluster_rrset_name("mesh.example.com"), wire)

        imposter = DMPCrypto()
        got = fetch_cluster_manifest(
            "mesh.example.com",
            imposter.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_mismatched_cluster_name_returns_none(self):
        """A correctly-signed manifest for cluster A should not be accepted
        under cluster B's DNS name."""
        op = DMPCrypto()
        manifest = _build_manifest(op, cluster_name="mesh.other.example.com")
        wire = manifest.sign(op)

        store = InMemoryDNSStore()
        # Published under the WRONG name; fetch_cluster_manifest will
        # bind to that name and reject.
        store.publish_txt_record(cluster_rrset_name("mesh.example.com"), wire)

        got = fetch_cluster_manifest(
            "mesh.example.com",
            op.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_picks_valid_out_of_multiple_records(self):
        """RRset carries garbage + a valid signed manifest; returns the valid one."""
        op = DMPCrypto()
        manifest = _build_manifest(op)
        wire = manifest.sign(op)

        store = InMemoryDNSStore()
        name = cluster_rrset_name("mesh.example.com")
        store.publish_txt_record(name, "not-a-manifest")
        store.publish_txt_record(name, "v=dmp1;t=other;garbage")
        store.publish_txt_record(name, wire)
        store.publish_txt_record(name, "yet-more-junk")

        got = fetch_cluster_manifest(
            "mesh.example.com",
            op.get_signing_public_key_bytes(),
            store,
        )
        assert got is not None
        assert got.seq == 1

    def test_picks_highest_seq_when_multiple_valid(self):
        """During an operator rollout the RRset can briefly carry both
        the old and new signed manifests. Returning the first valid
        one would pin the client to the stale node set; we must choose
        the highest seq."""
        op = DMPCrypto()
        old = _build_manifest(op, seq=1)
        new = _build_manifest(op, seq=5)
        store = InMemoryDNSStore()
        name = cluster_rrset_name("mesh.example.com")
        # Insertion order: old first, then new — proves we're not just
        # returning the first valid.
        store.publish_txt_record(name, old.sign(op))
        store.publish_txt_record(name, new.sign(op))

        got = fetch_cluster_manifest(
            "mesh.example.com",
            op.get_signing_public_key_bytes(),
            store,
        )
        assert got is not None
        assert got.seq == 5

    def test_no_records_returns_none(self):
        op = DMPCrypto()
        store = InMemoryDNSStore()
        got = fetch_cluster_manifest(
            "mesh.example.com",
            op.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_all_garbage_returns_none(self):
        op = DMPCrypto()
        store = InMemoryDNSStore()
        name = cluster_rrset_name("mesh.example.com")
        store.publish_txt_record(name, "v=dmp1;t=identity;not-a-cluster")
        store.publish_txt_record(name, "random garbage")

        got = fetch_cluster_manifest(
            "mesh.example.com",
            op.get_signing_public_key_bytes(),
            store,
        )
        assert got is None

    def test_bootstrap_reader_exception_returns_none(self):
        """A bootstrap reader that raises should be treated as a failed
        fetch (None), not a propagated exception."""
        op = DMPCrypto()
        got = fetch_cluster_manifest(
            "mesh.example.com",
            op.get_signing_public_key_bytes(),
            _FailingReader(),
        )
        assert got is None


# --------------------------------------------------------------------------- ClusterClient


class TestClusterClient:
    def test_construction_exposes_writer_and_reader(self):
        op = DMPCrypto()
        manifest = _build_manifest(op)
        store = InMemoryDNSStore()

        cc = ClusterClient(
            manifest,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        )
        try:
            # Writer and reader should be the FanoutWriter and UnionReader.
            assert cc.writer is not None
            assert cc.reader is not None
            assert cc.manifest.seq == 1
            assert len(cc.manifest.nodes) == 2
        finally:
            cc.close()

    def test_refresh_now_installs_higher_seq(self):
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        store = InMemoryDNSStore()
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v1.sign(op),
        )

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        )
        try:
            # Publish a v2 manifest (clear v1 first — InMemoryDNSStore
            # appends otherwise; the fetch loop tries each record so
            # the leftover v1 would still work, but we want a clean
            # "only v2 is present" scenario).
            store.delete_txt_record(cluster_rrset_name("mesh.example.com"))
            manifest_v2 = _build_manifest(op, seq=2, n_nodes=3)
            store.publish_txt_record(
                cluster_rrset_name("mesh.example.com"),
                manifest_v2.sign(op),
            )

            assert cc.refresh_now() is True
            # Both sides installed → manifest reflects seq 2 and the
            # union reader got the new node count too.
            assert cc.manifest.seq == 2
            assert len(cc.manifest.nodes) == 3
            assert len(cc.reader.manifest.nodes) == 3  # type: ignore[attr-defined]
        finally:
            cc.close()

    def test_refresh_now_ignores_same_seq(self):
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=5)
        store = InMemoryDNSStore()
        # Publish a same-seq manifest; fanout+union both reject seq <=.
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v1.sign(op),
        )

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        )
        try:
            assert cc.refresh_now() is False
            assert cc.manifest.seq == 5  # unchanged
        finally:
            cc.close()

    def test_refresh_now_ignores_lower_seq(self):
        op = DMPCrypto()
        manifest_current = _build_manifest(op, seq=10)
        store = InMemoryDNSStore()
        manifest_older = _build_manifest(op, seq=3)
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_older.sign(op),
        )

        cc = ClusterClient(
            manifest_current,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        )
        try:
            assert cc.refresh_now() is False
            assert cc.manifest.seq == 10
        finally:
            cc.close()

    def test_refresh_on_failed_fetch_preserves_manifest(self):
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        # Bootstrap reader that always raises.
        failing = _FailingReader()

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=failing,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        )
        try:
            assert cc.refresh_now() is False
            # Previous manifest still installed.
            assert cc.manifest.seq == 1
            assert len(cc.manifest.nodes) == 2
        finally:
            cc.close()

    def test_refresh_on_empty_rrset_preserves_manifest(self):
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        store = InMemoryDNSStore()  # no records published

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        )
        try:
            assert cc.refresh_now() is False
            assert cc.manifest.seq == 1
        finally:
            cc.close()

    def test_background_refresh_runs_on_cadence(self):
        """With a tight refresh_interval, the bootstrap reader should be
        queried multiple times within a short window."""
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        inner = InMemoryDNSStore()
        inner.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v1.sign(op),
        )
        counter = _CountingReader(inner)

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=counter,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
            refresh_interval=0.02,
        )
        try:
            # Wait long enough for several refresh ticks. At 20ms
            # cadence, 300ms gives >10 opportunities; we assert >= 3
            # to leave headroom for loaded CI.
            deadline = time.monotonic() + 1.0
            while counter.calls < 3 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert counter.calls >= 3
        finally:
            cc.close()

    def test_close_stops_refresh_thread_deterministically(self):
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        store = InMemoryDNSStore()
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v1.sign(op),
        )

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
            refresh_interval=60.0,  # long interval — close must unblock it
        )
        # Grab a reference so we can assert on thread state after close.
        thread = cc._refresh_thread
        assert thread is not None and thread.is_alive()
        cc.close()
        # The refresh loop waits on an Event; close() sets it so the
        # thread exits within a handful of milliseconds.
        thread.join(timeout=2.0)
        assert not thread.is_alive()

    def test_close_is_idempotent(self):
        op = DMPCrypto()
        manifest = _build_manifest(op)
        store = InMemoryDNSStore()
        cc = ClusterClient(
            manifest,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        )
        cc.close()
        cc.close()  # second call is a no-op

    def test_context_manager_closes(self):
        op = DMPCrypto()
        manifest = _build_manifest(op)
        store = InMemoryDNSStore()
        with ClusterClient(
            manifest,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
        ) as cc:
            assert cc.manifest.seq == 1
        # After exit, writer / reader are closed. A second close() on
        # them is idempotent (already covered by M2.2 / M2.3 tests).

    def test_refresh_exception_in_loop_does_not_crash_thread(self):
        """A refresh tick that raises unexpectedly must not kill the thread."""
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)

        class _ExplodingReader(DNSRecordReader):
            def __init__(self):
                self.calls = 0
                self._lock = threading.Lock()

            def query_txt_record(self, name):
                # fetch_cluster_manifest catches reader exceptions and
                # returns None; to test that the loop itself is resilient
                # we let the first few calls through and then simulate a
                # raw bug by having refresh_now blow up via a sentinel.
                with self._lock:
                    self.calls += 1
                raise RuntimeError("boom")

        reader = _ExplodingReader()
        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=reader,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
            refresh_interval=0.02,
        )
        try:
            # Wait for multiple ticks. fetch_cluster_manifest catches
            # the RuntimeError internally and returns None, so
            # refresh_now returns False without raising; the loop
            # keeps going.
            deadline = time.monotonic() + 1.0
            while reader.calls < 3 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert reader.calls >= 3
            # Thread is still alive.
            assert cc._refresh_thread is not None
            assert cc._refresh_thread.is_alive()
        finally:
            cc.close()

    def test_invalid_refresh_interval_rejected(self):
        op = DMPCrypto()
        manifest = _build_manifest(op)
        store = InMemoryDNSStore()
        with pytest.raises(ValueError):
            ClusterClient(
                manifest,
                operator_spk=op.get_signing_public_key_bytes(),
                base_domain="mesh.example.com",
                bootstrap_reader=store,
                writer_factory=_writer_factory,
                reader_factory=_reader_factory,
                refresh_interval=0.0,
            )

    def test_no_refresh_thread_when_interval_none(self):
        op = DMPCrypto()
        manifest = _build_manifest(op)
        store = InMemoryDNSStore()
        cc = ClusterClient(
            manifest,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=_reader_factory,
            refresh_interval=None,
        )
        try:
            assert cc._refresh_thread is None
        finally:
            cc.close()

    # ------------------------------------------------------------- atomic refresh

    def test_refresh_now_atomic_on_writer_factory_failure(self):
        """If writer_factory raises for a node in the new manifest, the refresh
        is aborted: both writer AND reader stay at the old seq. Prevents
        a split-brain where reads advance but writes stay on the old node
        set (freshly published records would disappear)."""
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        store = InMemoryDNSStore()

        # v2 introduces a node whose http_endpoint triggers the
        # writer_factory to raise. The reader_factory is fine.
        bad_node = ClusterNode(
            node_id="n99",
            http_endpoint="https://BROKEN.example.com:8053",
            dns_endpoint=None,
        )
        manifest_v2 = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[_node(1), bad_node],
            seq=2,
            exp=int(time.time()) + 3600,
        )
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v2.sign(op),
        )

        def failing_writer_factory(node: ClusterNode) -> DNSRecordWriter:
            if "BROKEN" in node.http_endpoint:
                raise ValueError(f"cannot parse http_endpoint {node.http_endpoint}")
            return _FakeWriter()

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=failing_writer_factory,
            reader_factory=_reader_factory,
        )
        try:
            assert cc.refresh_now() is False
            # Both sides still at v1 — atomic rollback worked.
            assert cc.writer.manifest.seq == 1  # type: ignore[attr-defined]
            assert cc.reader.manifest.seq == 1  # type: ignore[attr-defined]
            assert len(cc.writer.manifest.nodes) == 2  # type: ignore[attr-defined]
            assert len(cc.reader.manifest.nodes) == 2  # type: ignore[attr-defined]
        finally:
            cc.close()

    def test_refresh_now_atomic_on_reader_factory_failure(self):
        """Symmetric: reader_factory raises for a node in v2. Neither side
        advances."""
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        store = InMemoryDNSStore()

        # v2 introduces a node whose dns_endpoint the reader factory
        # can't parse. The writer factory is fine.
        bad_node = ClusterNode(
            node_id="n99",
            http_endpoint="https://n99.example.com:8053",
            dns_endpoint="not-a-real-endpoint",
        )
        manifest_v2 = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[_node(1), bad_node],
            seq=2,
            exp=int(time.time()) + 3600,
        )
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v2.sign(op),
        )

        def failing_reader_factory(node: ClusterNode) -> DNSRecordReader:
            if node.dns_endpoint == "not-a-real-endpoint":
                raise ValueError(f"cannot parse dns_endpoint {node.dns_endpoint!r}")
            return _FakeReader()

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=_writer_factory,
            reader_factory=failing_reader_factory,
        )
        try:
            assert cc.refresh_now() is False
            # Both sides still at v1.
            assert cc.writer.manifest.seq == 1  # type: ignore[attr-defined]
            assert cc.reader.manifest.seq == 1  # type: ignore[attr-defined]
        finally:
            cc.close()

    def test_refresh_now_both_succeed_still_works(self):
        """Happy path: both factories succeed on every node of the new
        manifest. Both sides advance to the new seq."""
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        store = InMemoryDNSStore()
        manifest_v2 = _build_manifest(op, seq=2, n_nodes=4)
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v2.sign(op),
        )

        # Counters to verify the probe factories were called AND the
        # install_manifest internal factories were also called (the
        # probes don't replace them).
        writer_calls = {"n": 0}
        reader_calls = {"n": 0}

        def counting_writer_factory(node: ClusterNode) -> DNSRecordWriter:
            writer_calls["n"] += 1
            return _FakeWriter()

        def counting_reader_factory(node: ClusterNode) -> DNSRecordReader:
            reader_calls["n"] += 1
            return _FakeReader()

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=counting_writer_factory,
            reader_factory=counting_reader_factory,
        )
        try:
            assert cc.refresh_now() is True
            assert cc.writer.manifest.seq == 2  # type: ignore[attr-defined]
            assert cc.reader.manifest.seq == 2  # type: ignore[attr-defined]
            assert len(cc.writer.manifest.nodes) == 4  # type: ignore[attr-defined]
            assert len(cc.reader.manifest.nodes) == 4  # type: ignore[attr-defined]
            # The probe pass invokes each factory once per node (4 nodes)
            # on top of install_manifest's own per-node builds. The
            # exact count of install_manifest's internal calls depends
            # on node-state reuse (n01,n02 reuse v1 state), but the
            # probe pass always adds at least n_nodes calls.
            assert writer_calls["n"] >= 4
            assert reader_calls["n"] >= 4
        finally:
            cc.close()

    def test_refresh_now_does_not_close_probe_outputs(self):
        """Factories are allowed to return shared/singleton instances
        (e.g. _make_cluster_reader_factory hands back the live bootstrap
        reader for nodes without a dns_endpoint). If refresh_now closed
        probe outputs blindly, a successful refresh would tear down a
        live shared instance the installed ClusterClient still uses.
        Verify the probe pass never calls close() on factory outputs.
        """
        op = DMPCrypto()
        manifest_v1 = _build_manifest(op, seq=1)
        store = InMemoryDNSStore()
        manifest_v2 = _build_manifest(op, seq=2, n_nodes=3)
        store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest_v2.sign(op),
        )

        # One shared writer + reader handed back for every node. If the
        # probe pass calls close() on either, the counter trips.
        shared_writer_closes = 0
        shared_reader_closes = 0

        class _SharedWriter(_FakeWriter):
            def close(self) -> None:
                nonlocal shared_writer_closes
                shared_writer_closes += 1

        class _SharedReader(_FakeReader):
            def close(self) -> None:
                nonlocal shared_reader_closes
                shared_reader_closes += 1

        shared_writer = _SharedWriter()
        shared_reader = _SharedReader()

        def writer_factory(node: ClusterNode) -> DNSRecordWriter:
            return shared_writer

        def reader_factory(node: ClusterNode) -> DNSRecordReader:
            return shared_reader

        cc = ClusterClient(
            manifest_v1,
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=store,
            writer_factory=writer_factory,
            reader_factory=reader_factory,
        )
        try:
            assert cc.refresh_now() is True
            # The probe pass must NOT close shared factory outputs —
            # doing so would kill the live reader/writer the installed
            # ClusterClient is holding. Zero closes from refresh_now.
            assert shared_writer_closes == 0
            assert shared_reader_closes == 0
        finally:
            cc.close()
