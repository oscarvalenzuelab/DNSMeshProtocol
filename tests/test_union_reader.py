"""Tests for UnionReader (M2.3) — concurrent read union across cluster nodes.

Covers:
- Union semantics (disjoint / overlapping / empty / all-empty / all-error).
- Partial-error and timeout handling.
- Per-node health tracking (failures vs None returns).
- Manifest refresh (seq monotonicity, expiry, node add/remove/retain).
- Stable ordering via first-completed-first.
- Empty manifest / single-node edge cases.
"""

from __future__ import annotations

import threading
import time
from typing import List, Optional

import pytest

from dmp.core.cluster import ClusterManifest, ClusterNode
from dmp.core.crypto import DMPCrypto
from dmp.network.base import DNSRecordReader
from dmp.network.union_reader import UnionReader

# ---------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------


class FakeReader(DNSRecordReader):
    """Deterministic DNSRecordReader used by tests.

    - `records` → list returned on each call (copied).
    - `raise_exc` → if set, raise it instead of returning.
    - `latency_ms` → sleep before acting; lets tests order future completion.
    - `return_none` → return None instead of a list.
    - `release_event` → if set, block on the event before returning
      (for explicit completion ordering in stable-order tests).
    """

    def __init__(
        self,
        records: Optional[List[str]] = None,
        *,
        raise_exc: Optional[BaseException] = None,
        latency_ms: int = 0,
        return_none: bool = False,
        release_event: Optional[threading.Event] = None,
    ) -> None:
        self.records = records
        self.raise_exc = raise_exc
        self.latency_ms = latency_ms
        self.return_none = return_none
        self.release_event = release_event
        self.query_calls: List[str] = []

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        if self.release_event is not None:
            self.release_event.wait(timeout=10.0)
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000.0)
        self.query_calls.append(name)
        if self.raise_exc is not None:
            raise self.raise_exc
        if self.return_none:
            return None
        return list(self.records) if self.records else []


# ---------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------


def _node(i: int) -> ClusterNode:
    return ClusterNode(
        node_id=f"n{i:02d}",
        http_endpoint=f"https://node{i}.example.com:8053",
    )


def _manifest(
    nodes: List[ClusterNode],
    *,
    seq: int = 1,
    exp_delta: int = 3600,
    cluster_name: str = "mesh.example.com",
) -> ClusterManifest:
    operator = DMPCrypto()
    return ClusterManifest(
        cluster_name=cluster_name,
        operator_spk=operator.get_signing_public_key_bytes(),
        nodes=nodes,
        seq=seq,
        exp=int(time.time()) + exp_delta,
    )


def _factory(mapping):
    """Build a reader_factory from a {node_id: FakeReader} mapping."""

    def factory(node: ClusterNode) -> DNSRecordReader:
        reader = mapping.get(node.node_id)
        if reader is None:
            raise AssertionError(f"no fake reader for node {node.node_id}")
        return reader

    return factory


# ---------------------------------------------------------------------
# Union semantics
# ---------------------------------------------------------------------


class TestUnionSemantics:
    def test_implements_dns_record_reader(self):
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            assert isinstance(reader, DNSRecordReader)
        finally:
            reader.close()

    def test_disjoint_union(self):
        nodes = [_node(1), _node(2), _node(3)]
        fakes = {
            "n01": FakeReader(["a"]),
            "n02": FakeReader(["b"]),
            "n03": FakeReader(["c"]),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            result = reader.query_txt_record("mbox.example.com")
            assert result is not None
            assert set(result) == {"a", "b", "c"}
        finally:
            reader.close()

    def test_overlapping_union_deduplicates(self):
        nodes = [_node(1), _node(2), _node(3)]
        fakes = {
            "n01": FakeReader(["a", "b"]),
            "n02": FakeReader(["b", "c"]),
            "n03": FakeReader(["c", "a"]),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            result = reader.query_txt_record("mbox.example.com")
            assert result is not None
            assert sorted(result) == ["a", "b", "c"]
            # Each string must appear exactly once.
            assert len(result) == len(set(result))
        finally:
            reader.close()

    def test_one_node_returns_none(self):
        nodes = [_node(1), _node(2), _node(3)]
        fakes = {
            "n01": FakeReader(["a"]),
            "n02": FakeReader(return_none=True),
            "n03": FakeReader(["c"]),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            result = reader.query_txt_record("mbox.example.com")
            assert result is not None
            assert set(result) == {"a", "c"}
        finally:
            reader.close()

    def test_all_nodes_return_none(self):
        nodes = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader(return_none=True),
            "n02": FakeReader(return_none=True),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            assert reader.query_txt_record("mbox.example.com") is None
        finally:
            reader.close()

    def test_all_nodes_return_empty(self):
        nodes = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader([]),
            "n02": FakeReader([]),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            assert reader.query_txt_record("mbox.example.com") is None
        finally:
            reader.close()

    def test_empty_manifest_returns_none(self):
        reader = UnionReader(_manifest([]), _factory({}))
        try:
            assert reader.query_txt_record("mbox.example.com") is None
        finally:
            reader.close()


# ---------------------------------------------------------------------
# Errors and partial errors
# ---------------------------------------------------------------------


class TestErrorHandling:
    def test_all_nodes_raise(self):
        nodes = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader(raise_exc=RuntimeError("net down")),
            "n02": FakeReader(raise_exc=RuntimeError("net down")),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            assert reader.query_txt_record("mbox.example.com") is None
            snap = reader.snapshot()
            assert len(snap) == 2
            for entry in snap:
                assert entry["consecutive_failures"] == 1
                assert entry["last_error"] is not None
                assert "RuntimeError" in entry["last_error"]
        finally:
            reader.close()

    def test_partial_error(self):
        nodes = [_node(1), _node(2), _node(3)]
        fakes = {
            "n01": FakeReader(["a"]),
            "n02": FakeReader(raise_exc=RuntimeError("boom")),
            "n03": FakeReader(["c"]),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            result = reader.query_txt_record("mbox.example.com")
            assert result is not None
            assert set(result) == {"a", "c"}
            snap = {e["node_id"]: e for e in reader.snapshot()}
            assert snap["n01"]["consecutive_failures"] == 0
            assert snap["n02"]["consecutive_failures"] == 1
            assert "RuntimeError" in (snap["n02"]["last_error"] or "")
            assert snap["n03"]["consecutive_failures"] == 0
        finally:
            reader.close()

    def test_none_return_is_not_a_failure(self):
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(return_none=True)}
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        try:
            assert reader.query_txt_record("name") is None
            snap = reader.snapshot()
            assert snap[0]["consecutive_failures"] == 0
            assert snap[0]["last_error"] is None
            assert snap[0]["last_success_ts"] > 0
        finally:
            reader.close()


# ---------------------------------------------------------------------
# Timeout behavior
# ---------------------------------------------------------------------


class TestTimeout:
    def test_slow_node_times_out_but_fast_nodes_contribute(self):
        nodes = [_node(1), _node(2), _node(3)]
        fakes = {
            "n01": FakeReader(["fast1"]),
            "n02": FakeReader(["slow"], latency_ms=10_000),
            "n03": FakeReader(["fast2"]),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes), timeout=0.5)
        try:
            start = time.monotonic()
            result = reader.query_txt_record("name")
            elapsed = time.monotonic() - start
            assert result is not None
            assert set(result) == {"fast1", "fast2"}
            # Must return within a reasonable fudge above the timeout.
            assert elapsed < 2.0, f"took {elapsed:.2f}s"
            snap = {e["node_id"]: e for e in reader.snapshot()}
            assert snap["n01"]["consecutive_failures"] == 0
            assert snap["n03"]["consecutive_failures"] == 0
            # Slow node timed out → failure counted.
            assert snap["n02"]["consecutive_failures"] == 1
            assert "TimeoutError" in (snap["n02"]["last_error"] or "")
        finally:
            reader.close()

    def test_all_nodes_time_out(self):
        nodes = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader(["a"], latency_ms=10_000),
            "n02": FakeReader(["b"], latency_ms=10_000),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes), timeout=0.3)
        try:
            assert reader.query_txt_record("name") is None
            snap = reader.snapshot()
            for entry in snap:
                assert entry["consecutive_failures"] == 1
        finally:
            reader.close()


# ---------------------------------------------------------------------
# Health tracking
# ---------------------------------------------------------------------


class TestHealthTracking:
    def test_consecutive_failures_increment_on_error(self):
        nodes = [_node(1)]
        fake = FakeReader(raise_exc=RuntimeError("x"))
        reader = UnionReader(_manifest(nodes), _factory({"n01": fake}))
        try:
            reader.query_txt_record("a")
            reader.query_txt_record("b")
            reader.query_txt_record("c")
            snap = reader.snapshot()
            assert snap[0]["consecutive_failures"] == 3
            assert snap[0]["last_failure_ts"] > 0
        finally:
            reader.close()

    def test_success_resets_consecutive_failures(self):
        nodes = [_node(1)]

        # Use a sentinel class that flips behavior per call.
        class FlakyReader(DNSRecordReader):
            def __init__(self) -> None:
                self.calls = 0

            def query_txt_record(self, name):
                self.calls += 1
                if self.calls <= 2:
                    raise RuntimeError("flaky")
                return ["ok"]

        flaky = FlakyReader()
        reader = UnionReader(_manifest(nodes), _factory({"n01": flaky}))
        try:
            reader.query_txt_record("a")  # fail
            reader.query_txt_record("b")  # fail
            snap = reader.snapshot()
            assert snap[0]["consecutive_failures"] == 2
            reader.query_txt_record("c")  # success
            snap = reader.snapshot()
            assert snap[0]["consecutive_failures"] == 0
            assert snap[0]["last_error"] is None
            assert snap[0]["last_success_ts"] > 0
        finally:
            reader.close()

    def test_last_failure_ts_is_reasonable(self):
        nodes = [_node(1)]
        fake = FakeReader(raise_exc=RuntimeError("x"))
        reader = UnionReader(_manifest(nodes), _factory({"n01": fake}))
        try:
            before = time.time()
            reader.query_txt_record("a")
            after = time.time()
            snap = reader.snapshot()
            assert before <= snap[0]["last_failure_ts"] <= after
        finally:
            reader.close()

    def test_snapshot_keys(self):
        nodes = [_node(1)]
        reader = UnionReader(_manifest(nodes), _factory({"n01": FakeReader(["a"])}))
        try:
            snap = reader.snapshot()
            assert snap[0].keys() >= {
                "node_id",
                "http_endpoint",
                "consecutive_failures",
                "last_failure_ts",
                "last_success_ts",
                "last_error",
            }
        finally:
            reader.close()


# ---------------------------------------------------------------------
# Manifest refresh
# ---------------------------------------------------------------------


class TestManifestRefresh:
    def test_install_higher_seq_accepted(self):
        nodes_v1 = [_node(1), _node(2)]
        # Mutable mapping so the closure sees updates for new nodes.
        fakes = {
            "n01": FakeReader(["a"]),
            "n02": FakeReader(["b"]),
        }
        reader = UnionReader(_manifest(nodes_v1, seq=5), _factory(fakes))
        try:
            fakes["n03"] = FakeReader(["c"])
            nodes_v2 = [_node(1), _node(2), _node(3)]
            ok = reader.install_manifest(_manifest(nodes_v2, seq=6))
            assert ok is True
            # The new manifest's nodes are now visible to queries.
            assert {e["node_id"] for e in reader.snapshot()} == {
                "n01",
                "n02",
                "n03",
            }
        finally:
            reader.close()

    def test_install_lower_seq_rejected(self):
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        reader = UnionReader(_manifest(nodes, seq=10), _factory(fakes))
        try:
            ok = reader.install_manifest(_manifest(nodes, seq=5))
            assert ok is False
        finally:
            reader.close()

    def test_install_equal_seq_rejected(self):
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        reader = UnionReader(_manifest(nodes, seq=10), _factory(fakes))
        try:
            ok = reader.install_manifest(_manifest(nodes, seq=10))
            assert ok is False
        finally:
            reader.close()

    def test_install_expired_manifest_rejected(self):
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        reader = UnionReader(_manifest(nodes, seq=1), _factory(fakes))
        try:
            expired = _manifest(nodes, seq=2, exp_delta=-10)
            ok = reader.install_manifest(expired)
            assert ok is False
        finally:
            reader.close()

    def test_install_retains_health_for_common_nodes(self):
        nodes_v1 = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader(raise_exc=RuntimeError("down")),
            "n02": FakeReader(["b"]),
        }
        reader = UnionReader(_manifest(nodes_v1, seq=1), _factory(fakes))
        try:
            # Generate one failure on n01.
            reader.query_txt_record("foo")
            snap = {e["node_id"]: e for e in reader.snapshot()}
            assert snap["n01"]["consecutive_failures"] == 1

            # Install a new manifest that still contains n01 with the
            # SAME http_endpoint — counters must persist.
            fakes["n03"] = FakeReader(["c"])
            nodes_v2 = [_node(1), _node(2), _node(3)]
            ok = reader.install_manifest(_manifest(nodes_v2, seq=2))
            assert ok is True
            snap = {e["node_id"]: e for e in reader.snapshot()}
            assert (
                snap["n01"]["consecutive_failures"] == 1
            ), "common-node health must be retained across manifest refresh"
        finally:
            reader.close()

    def test_install_drops_removed_nodes(self):
        nodes_v1 = [_node(1), _node(2), _node(3)]
        fakes = {
            "n01": FakeReader(["a"]),
            "n02": FakeReader(["b"]),
            "n03": FakeReader(["c"]),
        }
        reader = UnionReader(_manifest(nodes_v1, seq=1), _factory(fakes))
        try:
            assert {e["node_id"] for e in reader.snapshot()} == {
                "n01",
                "n02",
                "n03",
            }
            ok = reader.install_manifest(_manifest([_node(1), _node(2)], seq=2))
            assert ok is True
            assert {e["node_id"] for e in reader.snapshot()} == {"n01", "n02"}
        finally:
            reader.close()

    def test_install_rebuilds_reader_when_endpoint_changes(self):
        # If http_endpoint differs, the factory is re-invoked to build a
        # fresh reader — same node_id, different address.
        nodes_v1 = [_node(1)]
        old_fake = FakeReader(["old"])
        new_fake = FakeReader(["new"])

        def factory(node: ClusterNode) -> DNSRecordReader:
            if node.http_endpoint == _node(1).http_endpoint:
                return old_fake
            return new_fake

        reader = UnionReader(_manifest(nodes_v1, seq=1), factory)
        try:
            assert reader.query_txt_record("x") == ["old"]
            new_node = ClusterNode(
                node_id="n01",
                http_endpoint="https://NEW.example.com:9999",
            )
            ok = reader.install_manifest(_manifest([new_node], seq=2))
            assert ok is True
            assert reader.query_txt_record("x") == ["new"]
        finally:
            reader.close()


# ---------------------------------------------------------------------
# Stable ordering
# ---------------------------------------------------------------------


class TestStableOrdering:
    def test_first_completed_first_positioned(self):
        """Two nodes both return ["a", "b"]; the node that completes
        first dictates the order of `a` and `b` in the union."""
        # Fire n01 first by making it fast, n02 much slower.
        nodes = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader(["a", "b"], latency_ms=0),
            "n02": FakeReader(["a", "b"], latency_ms=100),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes), timeout=5.0)
        try:
            result = reader.query_txt_record("x")
            assert result == ["a", "b"]
        finally:
            reader.close()

    def test_first_completed_dictates_position_reversed(self):
        """Reverse-order completion: slow node has records, fast node
        reverses them. The order the first completion saw wins.
        """
        nodes = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader(["a", "b"], latency_ms=100),
            "n02": FakeReader(["b", "a"], latency_ms=0),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes), timeout=5.0)
        try:
            result = reader.query_txt_record("x")
            # n02 completes first and seeds ["b", "a"]; n01's later
            # contribution adds nothing new (both already present).
            assert result == ["b", "a"]
        finally:
            reader.close()

    def test_explicit_completion_order_via_events(self):
        """Use release events for deterministic ordering independent of
        sleep timings, pinning the first-completed-first contract."""
        n01_gate = threading.Event()
        n02_gate = threading.Event()
        nodes = [_node(1), _node(2)]
        fakes = {
            "n01": FakeReader(["x", "y"], release_event=n01_gate),
            "n02": FakeReader(["y", "z"], release_event=n02_gate),
        }
        reader = UnionReader(_manifest(nodes), _factory(fakes), timeout=5.0)
        try:
            result_holder: List[Optional[List[str]]] = [None]
            finished = threading.Event()

            def runner():
                result_holder[0] = reader.query_txt_record("name")
                finished.set()

            t = threading.Thread(target=runner)
            t.start()
            try:
                # Release n01 first → it seeds the union.
                n01_gate.set()
                # Give the pool a beat to actually complete n01's future.
                time.sleep(0.05)
                n02_gate.set()
                assert finished.wait(timeout=3.0)
                assert result_holder[0] == ["x", "y", "z"]
            finally:
                # Safety: always release events so background thread exits.
                n01_gate.set()
                n02_gate.set()
                t.join(timeout=3.0)
        finally:
            reader.close()


# ---------------------------------------------------------------------
# Construction / validation
# ---------------------------------------------------------------------


class TestConstruction:
    def test_rejects_non_positive_timeout(self):
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        with pytest.raises(ValueError):
            UnionReader(_manifest(nodes), _factory(fakes), timeout=0)
        with pytest.raises(ValueError):
            UnionReader(_manifest(nodes), _factory(fakes), timeout=-1)

    def test_max_workers_override(self):
        nodes = [_node(i) for i in range(1, 6)]
        fakes = {n.node_id: FakeReader([n.node_id]) for n in nodes}
        # max_workers=2 should still produce a correct union.
        reader = UnionReader(
            _manifest(nodes),
            _factory(fakes),
            max_workers=2,
        )
        try:
            result = reader.query_txt_record("x")
            assert result is not None
            assert set(result) == {n.node_id for n in nodes}
        finally:
            reader.close()

    def test_snapshot_empty_manifest(self):
        reader = UnionReader(_manifest([]), _factory({}))
        try:
            assert reader.snapshot() == []
        finally:
            reader.close()

    def test_rejects_expired_manifest_on_init(self):
        """An already-expired manifest must be rejected on construction,
        mirroring install_manifest's invariant. Otherwise a direct call
        or reload path silently queries stale nodes until the next
        refresh."""
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        expired = _manifest(nodes, seq=1, exp_delta=-60)
        with pytest.raises(ValueError, match="expired"):
            UnionReader(expired, _factory(fakes))


# ---------------------------------------------------------------------
# Endpoint-change semantics (DNS and HTTP parity with FanoutWriter)
# ---------------------------------------------------------------------


class _TrackingFactory:
    """Factory that records every call and hands back a fresh FakeReader each time.

    Mirrors tests/test_fanout_writer.py's _TrackingFactory. Lets tests
    assert how many readers were built and inspect each generation.
    """

    def __init__(self, records_per_node: Optional[dict] = None) -> None:
        # node_id -> list[FakeReader] (one entry per factory call).
        self.readers: dict = {}
        # (node_id, http_endpoint, dns_endpoint) per factory call.
        self.calls: list = []
        self._records_per_node = records_per_node or {}

    def __call__(self, node: ClusterNode) -> DNSRecordReader:
        recs = self._records_per_node.get(node.node_id, [node.node_id])
        r = FakeReader(list(recs))
        self.calls.append((node.node_id, node.http_endpoint, node.dns_endpoint))
        self.readers.setdefault(node.node_id, []).append(r)
        return r

    def latest(self, node_id: str) -> FakeReader:
        return self.readers[node_id][-1]

    def first(self, node_id: str) -> FakeReader:
        return self.readers[node_id][0]


class TestEndpointChange:
    def test_http_endpoint_change_triggers_new_reader(self):
        """HTTP endpoint drift rebuilds the reader via the factory."""
        factory = _TrackingFactory()
        n00_v1 = ClusterNode(node_id="n00", http_endpoint="https://e1.example:8053")
        m1 = _manifest([n00_v1], seq=1)
        with UnionReader(m1, factory) as reader:
            reader.query_txt_record("x")
            assert len(factory.first("n00").query_calls) == 1

            n00_v2 = ClusterNode(node_id="n00", http_endpoint="https://e2.example:8053")
            m2 = _manifest([n00_v2], seq=2)
            assert reader.install_manifest(m2) is True
            # Factory must have been called again for the rebuilt reader.
            assert [(c[0], c[1]) for c in factory.calls] == [
                ("n00", "https://e1.example:8053"),
                ("n00", "https://e2.example:8053"),
            ]
            # Next query hits E2's reader, not E1's.
            reader.query_txt_record("y")
            assert len(factory.first("n00").query_calls) == 1  # E1 unchanged
            assert len(factory.latest("n00").query_calls) == 1  # E2 got the new one
            snap = reader.snapshot()
            assert snap[0]["http_endpoint"] == "https://e2.example:8053"

    def test_dns_endpoint_change_triggers_new_reader(self):
        """DNS-only endpoint drift (HTTP identical) must still rebuild.

        This is the Codex P1 fix: the pre-fix code only compared
        http_endpoint and silently kept the stale reader around.
        """
        factory = _TrackingFactory()
        n00_v1 = ClusterNode(
            node_id="n00",
            http_endpoint="https://e.example:8053",
            dns_endpoint="203.0.113.1:53",
        )
        m1 = _manifest([n00_v1], seq=1)
        with UnionReader(m1, factory) as reader:
            n00_v2 = ClusterNode(
                node_id="n00",
                http_endpoint="https://e.example:8053",  # unchanged
                dns_endpoint="203.0.113.2:53",  # changed
            )
            m2 = _manifest([n00_v2], seq=2)
            assert reader.install_manifest(m2) is True
            # HTTP endpoint is the same but dns_endpoint changed; still
            # expect the reader to be rebuilt.
            assert len(factory.calls) == 2

    def test_both_endpoints_unchanged_reuses_reader(self):
        """Refresh with identical node entry must not call the factory again."""
        factory = _TrackingFactory()
        node = ClusterNode(
            node_id="n00",
            http_endpoint="https://e.example:8053",
            dns_endpoint="203.0.113.1:53",
        )
        m1 = _manifest([node], seq=1)
        with UnionReader(m1, factory) as reader:
            # Identical second manifest — only seq advances.
            m2 = _manifest([node], seq=2)
            assert reader.install_manifest(m2) is True
            # One factory call only: the initial construction.
            assert len(factory.calls) == 1
            # And the reader instance survived the refresh.
            assert reader.query_txt_record("x") == ["n00"]
            assert len(factory.first("n00").query_calls) == 1

    def test_health_preserved_across_endpoint_change(self):
        """consecutive_failures must survive the endpoint swap."""
        # Custom factory: first reader raises (fails), second succeeds.
        made: List[FakeReader] = []

        def factory(node: ClusterNode) -> DNSRecordReader:
            if not made:
                r = FakeReader(raise_exc=RuntimeError("down"))
            else:
                r = FakeReader(["ok"])
            made.append(r)
            return r

        n00_v1 = ClusterNode(node_id="n00", http_endpoint="https://e1.example:8053")
        m1 = _manifest([n00_v1], seq=1)
        with UnionReader(m1, factory) as reader:
            # Drive consecutive_failures up on the E1 reader.
            reader.query_txt_record("a")
            reader.query_txt_record("b")
            pre = reader.snapshot()[0]
            assert pre["consecutive_failures"] == 2
            pre_last_failure_ts = pre["last_failure_ts"]

            # Refresh to E2 (HTTP change). Health counters must survive.
            n00_v2 = ClusterNode(node_id="n00", http_endpoint="https://e2.example:8053")
            m2 = _manifest([n00_v2], seq=2)
            assert reader.install_manifest(m2) is True
            post = reader.snapshot()[0]
            assert post["consecutive_failures"] == 2
            assert post["last_failure_ts"] == pre_last_failure_ts
            assert post["http_endpoint"] == "https://e2.example:8053"

    def test_endpoint_change_retains_old_reader_until_close(self):
        """The rebuilt reader must not be close()'d at swap time."""

        class ClosableReader(FakeReader):
            def __init__(self, records=None) -> None:
                super().__init__(records=records)
                self.close_calls = 0

            def close(self) -> None:
                self.close_calls += 1

        made: List[ClosableReader] = []

        def factory(node: ClusterNode) -> DNSRecordReader:
            r = ClosableReader([node.node_id])
            made.append(r)
            return r

        n00_v1 = ClusterNode(node_id="n00", http_endpoint="https://e1.example:8053")
        m1 = _manifest([n00_v1], seq=1)
        reader = UnionReader(m1, factory)
        try:
            n00_v2 = ClusterNode(node_id="n00", http_endpoint="https://e2.example:8053")
            m2 = _manifest([n00_v2], seq=2)
            assert reader.install_manifest(m2) is True
            # The E1 reader is retained, not yet closed.
            assert made[0].close_calls == 0
        finally:
            reader.close()
        # After close, the retained E1 reader is drained.
        assert made[0].close_calls == 1

    def test_inflight_future_on_old_reader_does_not_mutate_new_state(self):
        """An endpoint change must give in-flight futures their original
        reader. If install_manifest mutated `_NodeState.reader` in place,
        a future submitted against the old reader would (a) potentially
        route its call to the new reader on late execution, and (b)
        record its late success/failure against the new endpoint's
        health counters. Creating a fresh _NodeState isolates both.

        Mirrors tests/test_fanout_writer.py::
        test_inflight_future_on_old_writer_does_not_mutate_new_state.
        """
        slow_old = FakeReader(["old"], latency_ms=200)
        new_reader_obj = FakeReader(["new"])
        call_log: list = []

        def factory(node: ClusterNode) -> DNSRecordReader:
            call_log.append(node.http_endpoint)
            if node.http_endpoint == "https://n0.example.com:8053":
                return slow_old
            return new_reader_obj

        n00 = ClusterNode(node_id="n00", http_endpoint="https://n0.example.com:8053")
        m1 = _manifest([n00], seq=1)
        reader = UnionReader(m1, factory, timeout=2.0)

        # Fire a query in a thread so install_manifest can race it.
        result: dict = {}

        def do_query():
            result["out"] = reader.query_txt_record("x")

        t = threading.Thread(target=do_query, daemon=True)
        t.start()
        # Give the executor a moment to dispatch.
        time.sleep(0.02)
        # Rotate the endpoint. slow_old is in flight; a fresh
        # _NodeState is created for the new endpoint.
        n00_rot = ClusterNode(
            node_id="n00", http_endpoint="https://n0-rotated.example.com:8053"
        )
        m2 = _manifest([n00_rot], seq=2)
        assert reader.install_manifest(m2) is True
        # Old reader's call should still complete on slow_old (its
        # original binding), not on new_reader_obj.
        t.join(timeout=3.0)
        assert result["out"] == ["old"]
        # Factory called exactly twice.
        assert len(call_log) == 2
        # The late old-reader success landed on the retired _NodeState,
        # not on the new endpoint's counters. The new _NodeState
        # inherited the old's counters at refresh time (all zeros) and
        # has NOT been updated since — because the late future still
        # holds a reference to the ORIGINAL _NodeState.
        snap = reader.snapshot()
        assert len(snap) == 1
        new_entry = snap[0]
        assert new_entry["http_endpoint"] == "https://n0-rotated.example.com:8053"
        # No query has been issued against new_reader_obj yet.
        assert new_reader_obj.query_calls == []
        # slow_old DID see the query.
        assert len(slow_old.query_calls) == 1
        reader.close()


# ---------------------------------------------------------------------
# Close / post-close behavior
# ---------------------------------------------------------------------


class TestCloseBehavior:
    def test_install_rejected_after_close(self):
        """A close() in flight must block further installs; otherwise
        we'd allocate readers / a new executor that close() already
        committed to not draining."""
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        reader = UnionReader(_manifest(nodes, seq=1), _factory(fakes))
        reader.close()
        fakes["n02"] = FakeReader(["b"])
        nodes_v2 = [_node(1), _node(2)]
        assert reader.install_manifest(_manifest(nodes_v2, seq=2)) is False

    def test_close_is_idempotent(self):
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        reader = UnionReader(_manifest(nodes), _factory(fakes))
        reader.close()
        reader.close()  # Must not raise.

    def test_close_waits_for_inflight_before_closing_retired_readers(self):
        """close() must wait for in-flight query futures to finish
        before closing retained readers. Otherwise the mid-flight race
        the retention list was supposed to fix reappears at teardown.

        Mirrors test_fanout_writer's
        test_close_waits_for_inflight_before_closing_retired_writers.
        """
        order: list = []

        class OrderingReader(FakeReader):
            def __init__(self, records=None, *, latency_ms=0):
                super().__init__(records=records, latency_ms=latency_ms)
                self.close_calls = 0

            def query_txt_record(self, name: str):
                if self.latency_ms:
                    time.sleep(self.latency_ms / 1000.0)
                order.append("query-done")
                self.query_calls.append(name)
                return list(self.records) if self.records else []

            def close(self) -> None:
                order.append("close")
                self.close_calls += 1

        slow = OrderingReader(records=["slow"], latency_ms=300)
        fast = OrderingReader(records=["fast"])
        mapping = {"n01": slow, "n02": fast}

        def factory(node):
            return mapping[node.node_id]

        nodes_v1 = [_node(1), _node(2)]
        m1 = _manifest(nodes_v1, seq=1)
        # Long timeout → union waits for every node, so no straggler
        # left behind at query-return time. But retirement via
        # install_manifest happens AFTER a subsequent query that leaves
        # slow still in flight? Simpler: fire a slow-latency query,
        # retire n01 mid-flight, and close().
        reader = UnionReader(m1, factory, timeout=5.0)
        # Kick off a query with a short client-side join so slow is
        # still mid-execution when install_manifest runs.
        q_done = threading.Event()

        def do_query():
            reader.query_txt_record("x")
            q_done.set()

        t = threading.Thread(target=do_query, daemon=True)
        t.start()
        # Wait until fast has finished and slow is still running.
        time.sleep(0.05)
        # Retire slow by dropping n01 from the manifest.
        m2 = _manifest([_node(2)], seq=2)
        assert reader.install_manifest(m2) is True
        # Close must drain slow's in-flight query BEFORE calling its
        # close(). Ordering assertion proves the race is fixed.
        reader.close()
        assert q_done.wait(timeout=5.0)
        t.join(timeout=5.0)
        assert "query-done" in order
        # The retired slow reader was closed after its in-flight query
        # completed. We can't assert a fixed relative index (fast's
        # query-done also lives in order) but we can assert that
        # slow's "close" followed slow's "query-done".
        # Find the index of slow's own close (there's only one close
        # for the retired reader; fast is live and never closed).
        assert slow.close_calls == 1
        # slow's query_calls must have been recorded (it finished).
        assert slow.query_calls == ["x"]
        # fast was not retired; never closed.
        assert fast.close_calls == 0


# ---------------------------------------------------------------------
# Manifest deepcopy isolation
# ---------------------------------------------------------------------


class TestManifestDeepcopy:
    def test_mutating_caller_manifest_after_install_does_not_affect_reader(self):
        """UnionReader must deepcopy installed manifests so a caller
        that reuses and mutates the dataclass after install can't
        corrupt our retained comparison state (e.g. sneaking in a
        lower-seq refresh on the next call).
        """
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        m1 = _manifest(nodes, seq=1)
        reader = UnionReader(m1, _factory(fakes))
        try:
            # Mutate the caller's manifest after the constructor accepted it.
            object.__setattr__(m1, "seq", 999)
            # The reader's snapshot of the manifest still reflects seq=1.
            assert reader.manifest.seq == 1
            # A refresh to seq=2 must still be accepted (would be
            # rejected as <=999 if UnionReader had retained the
            # mutated dataclass).
            fakes["n02"] = FakeReader(["b"])
            m2 = _manifest([_node(1), _node(2)], seq=2)
            assert reader.install_manifest(m2) is True
        finally:
            reader.close()

    def test_install_manifest_deepcopy(self):
        """install_manifest must also deepcopy — otherwise a caller
        that mutates the post-install manifest dataclass could corrupt
        our monotonicity check."""
        nodes = [_node(1)]
        fakes = {"n01": FakeReader(["a"])}
        reader = UnionReader(_manifest(nodes, seq=1), _factory(fakes))
        try:
            m2 = _manifest(nodes, seq=2)
            assert reader.install_manifest(m2) is True
            # Mutate the caller-side dataclass after install.
            object.__setattr__(m2, "seq", 999)
            # Reader's retained seq is still 2.
            assert reader.manifest.seq == 2
            # So seq=3 is accepted.
            m3 = _manifest(nodes, seq=3)
            assert reader.install_manifest(m3) is True
        finally:
            reader.close()


# ---------------------------------------------------------------------
# max_workers preservation on growth
# ---------------------------------------------------------------------


class TestMaxWorkersPreservation:
    def test_user_cap_preserved_across_manifest_growth(self):
        """max_workers=2 caller must still get 2 threads even when a
        manifest refresh grows from 1 node to 10.

        Mirrors test_fanout_writer's
        test_user_cap_preserved_across_manifest_growth.
        """
        nodes_v1 = [_node(0)]
        fakes = {f"n{i:02d}": FakeReader([f"n{i:02d}"]) for i in range(10)}
        reader = UnionReader(_manifest(nodes_v1, seq=1), _factory(fakes), max_workers=2)
        try:
            nodes_v2 = [_node(i) for i in range(10)]
            assert reader.install_manifest(_manifest(nodes_v2, seq=2)) is True
            # Active executor still honors the caller's cap.
            assert reader._executor._max_workers == 2  # type: ignore[attr-defined]
        finally:
            reader.close()

    def test_default_heuristic_when_user_did_not_pin(self):
        """When max_workers is None, min(N, 16) applies on resize."""
        nodes_v1 = [_node(0)]
        fakes = {f"n{i:02d}": FakeReader([f"n{i:02d}"]) for i in range(8)}
        reader = UnionReader(_manifest(nodes_v1, seq=1), _factory(fakes))
        try:
            nodes_v2 = [_node(i) for i in range(8)]
            assert reader.install_manifest(_manifest(nodes_v2, seq=2)) is True
            assert reader._executor._max_workers == 8  # type: ignore[attr-defined]
        finally:
            reader.close()


# ---------------------------------------------------------------------
# Pending-future cancellation on timeout
# ---------------------------------------------------------------------


class TestTimeoutCancelsPending:
    def test_pending_future_cancelled_on_timeout(self):
        """On timeout, Future.cancel() is called on every unfinished
        future. Futures that were PENDING (never started) are actually
        cancelled and their queue slots freed; futures that were
        RUNNING keep going (cancel() returns False on them) but we at
        least call cancel() on all of them.

        Setup: pool sized to 1 worker. First node holds the worker
        indefinitely. Second node is QUEUED and never gets to run. On
        timeout, its future must be cancelled (future.cancelled() is
        True).
        """
        gate = threading.Event()
        n01_reader = FakeReader(["n01"], release_event=gate)
        n02_reader = FakeReader(["n02"])
        mapping = {"n01": n01_reader, "n02": n02_reader}

        def factory(node):
            return mapping[node.node_id]

        nodes = [_node(1), _node(2)]
        # Force the pool to 1 worker so n02 is PENDING (still in the
        # queue) while n01 is RUNNING. This is what lets us observe a
        # real cancelled=True rather than just future.cancel() ==
        # False on a running future.
        reader = UnionReader(_manifest(nodes), factory, timeout=0.3, max_workers=1)
        try:
            # Patch submit to capture the futures as they're created.
            captured: list = []
            original_submit = reader._executor.submit

            def capture_submit(*args, **kwargs):
                f = original_submit(*args, **kwargs)
                captured.append(f)
                return f

            reader._executor.submit = capture_submit  # type: ignore[method-assign]

            # Fire the query. n01 blocks on `gate`; n02 stays pending
            # (queue) because the pool has 1 worker. Timeout fires at
            # 0.3s.
            result = reader.query_txt_record("x")
            # No fast node succeeded (n01 is blocked on gate, n02
            # never ran) → None.
            assert result is None
            # The pending future (n02's) MUST be cancelled after the
            # timeout path. Running futures (n01's) return False on
            # cancel() and may or may not be marked cancelled — the
            # important, testable assertion is that the pending one
            # is cancelled.
            assert len(captured) == 2
            # n02's future is index 1 (submitted second, queued).
            assert captured[1].cancelled() is True, (
                "pending future must be cancelled on timeout to free " "its queue slot"
            )
        finally:
            # Release n01 so the worker thread unblocks before
            # reader.close() tries to drain it.
            gate.set()
            reader.close()
