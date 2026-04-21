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
