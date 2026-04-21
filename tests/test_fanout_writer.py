"""Tests for the M2.2 FanoutWriter.

Covers:
- _ceil_half quorum arithmetic.
- Quorum-met / quorum-missed / all-fail / all-succeed paths.
- Empty-manifest vacuous success.
- Per-call timeout: fast-path returns on quorum; slow-path returns on timeout.
- Per-node health tracking (consecutive_failures, last_error, reset on success).
- install_manifest: seq-monotonicity, expiry rejection, state preservation,
  removed-node cleanup.
- Writer-raised exceptions do not crash the fan-out.

Never performs real network I/O; everything runs against a FakeWriter that
records calls and can be configured to fail, sleep, or raise.
"""

from __future__ import annotations

import time
from typing import List, Optional

import pytest

from dmp.core.cluster import ClusterManifest, ClusterNode
from dmp.core.crypto import DMPCrypto
from dmp.network.fanout_writer import FanoutWriter, _ceil_half

# --------------------------------------------------------------------------- helpers


class FakeWriter:
    """Duck-typed DNSRecordWriter for testing.

    Configurable via ``fail`` (return False), ``latency_ms``
    (sleep in publish/delete), ``raise_exc`` (raise that exception on
    every call).
    """

    def __init__(
        self,
        *,
        fail: bool = False,
        latency_ms: int = 0,
        raise_exc: Optional[BaseException] = None,
    ) -> None:
        self.fail = fail
        self.latency_ms = latency_ms
        self.raise_exc = raise_exc
        self.publish_calls: List[tuple] = []
        self.delete_calls: List[tuple] = []
        self.close_calls = 0

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000.0)
        if self.raise_exc is not None:
            raise self.raise_exc
        self.publish_calls.append((name, value, ttl))
        return not self.fail

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000.0)
        if self.raise_exc is not None:
            raise self.raise_exc
        self.delete_calls.append((name, value))
        return not self.fail

    def close(self) -> None:
        self.close_calls += 1


def _node(i: int) -> ClusterNode:
    return ClusterNode(
        node_id=f"n{i:02d}",
        http_endpoint=f"https://n{i}.example.com:8053",
    )


def _manifest(
    n_nodes: int,
    *,
    seq: int = 1,
    exp_delta: int = 3600,
    operator: Optional[DMPCrypto] = None,
    cluster_name: str = "mesh.example.com",
) -> ClusterManifest:
    op = operator or DMPCrypto()
    return ClusterManifest(
        cluster_name=cluster_name,
        operator_spk=op.get_signing_public_key_bytes(),
        nodes=[_node(i) for i in range(n_nodes)],
        seq=seq,
        exp=int(time.time()) + exp_delta,
    )


def _make_factory(per_node):
    """Factory that returns the same ``per_node`` FakeWriter for every call.

    For multi-node tests use ``_make_keyed_factory`` which returns a
    distinct writer per node_id.
    """

    def factory(node: ClusterNode):
        return per_node

    return factory


def _make_keyed_factory(writers: dict):
    """Factory that hands back writers keyed by node_id."""

    def factory(node: ClusterNode):
        if node.node_id not in writers:
            writers[node.node_id] = FakeWriter()
        return writers[node.node_id]

    return factory


def _poll_until(predicate, *, timeout: float = 1.0, step: float = 0.01) -> None:
    """Spin until ``predicate()`` is true or the (generous) deadline hits.

    Used to wait for background fan-out futures to drain in tests that
    need every node's side effects to have landed before asserting.
    Step is 10 ms, timeout is 1 s — well under the "no sleeps longer
    than 100 ms in passing-path tests" gate because each individual
    sleep is 10 ms and the predicate trips almost immediately.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(step)
    raise AssertionError("timed out waiting for background fan-out to drain")


# --------------------------------------------------------------------------- _ceil_half


class TestCeilHalf:
    @pytest.mark.parametrize(
        "n,expected",
        [(0, 0), (1, 1), (2, 1), (3, 2), (4, 2), (5, 3), (6, 3), (7, 4)],
    )
    def test_ceil_half_values(self, n: int, expected: int) -> None:
        assert _ceil_half(n) == expected


# --------------------------------------------------------------------------- quorum property


class TestQuorumProperty:
    @pytest.mark.parametrize("n,expected", [(1, 1), (2, 1), (3, 2), (4, 2), (5, 3)])
    def test_quorum_matches_ceil_half(self, n: int, expected: int) -> None:
        writers: dict = {}
        with FanoutWriter(_manifest(n), _make_keyed_factory(writers)) as fw:
            assert fw.quorum == expected

    def test_empty_manifest_quorum_is_zero(self) -> None:
        with FanoutWriter(_manifest(0), _make_keyed_factory({})) as fw:
            assert fw.quorum == 0


# --------------------------------------------------------------------------- publish/delete quorum


class TestPublishQuorum:
    def test_all_nodes_succeed_returns_true(self) -> None:
        # Pre-populate writers so every node's factory call finds its
        # FakeWriter ready. All are fast, so the executor completes
        # them well before the poll loop below expires.
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(5)}
        with FanoutWriter(_manifest(5), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("foo.example.com", "v=dmp1;x", ttl=60)
            # FanoutWriter returns once quorum is met (3 of 5 here) so
            # the last two writes may still be in flight. Poll briefly
            # for them to land — deterministic because every FakeWriter
            # is instant and in-process.
            _poll_until(
                lambda: sum(len(w.publish_calls) for w in writers.values()) == 5
            )
        all_calls = sum(len(w.publish_calls) for w in writers.values())
        assert all_calls == 5
        for w in writers.values():
            assert w.publish_calls[0] == ("foo.example.com", "v=dmp1;x", 60)

    def test_3_of_5_succeed_meets_quorum(self) -> None:
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(5)}
        # 2 fail, 3 succeed; quorum for N=5 is 3 → True.
        writers["n00"].fail = True
        writers["n01"].fail = True
        with FanoutWriter(_manifest(5), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("foo", "bar") is True

    def test_2_of_5_succeed_misses_quorum(self) -> None:
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(5)}
        for i in (0, 1, 2):
            writers[f"n{i:02d}"].fail = True
        with FanoutWriter(_manifest(5), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("foo", "bar") is False

    def test_0_of_5_succeed_all_raise(self) -> None:
        writers: dict = {
            f"n{i:02d}": FakeWriter(raise_exc=RuntimeError(f"boom-{i}"))
            for i in range(5)
        }
        with FanoutWriter(_manifest(5), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("foo", "bar") is False
            snap = {s["node_id"]: s for s in fw.snapshot()}
        for i in range(5):
            st = snap[f"n{i:02d}"]
            assert st["consecutive_failures"] == 1
            assert st["last_error"] is not None
            assert "RuntimeError" in st["last_error"]

    def test_empty_manifest_publish_vacuously_true(self) -> None:
        with FanoutWriter(_manifest(0), _make_keyed_factory({})) as fw:
            assert fw.publish_txt_record("foo", "bar") is True
            assert fw.delete_txt_record("foo") is True
            assert fw.snapshot() == []

    def test_delete_fan_out_same_semantics(self) -> None:
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(3)}
        writers["n00"].fail = True  # 2 of 3 succeed; quorum for N=3 is 2.
        with FanoutWriter(_manifest(3), _make_keyed_factory(writers)) as fw:
            assert fw.delete_txt_record("foo", value="bar") is True
        # Every node observes the call (fail=True still records it in
        # our fake's failure path via the return value, not the list).
        assert writers["n01"].delete_calls == [("foo", "bar")]
        assert writers["n02"].delete_calls == [("foo", "bar")]

    def test_delete_without_value_passes_through(self) -> None:
        writers: dict = {"n00": FakeWriter()}
        with FanoutWriter(_manifest(1), _make_keyed_factory(writers)) as fw:
            assert fw.delete_txt_record("foo") is True
        assert writers["n00"].delete_calls == [("foo", None)]


# --------------------------------------------------------------------------- timeout


class TestTimeout:
    def test_fast_path_meets_quorum_before_slow_node(self) -> None:
        """Two fast nodes + one slow node; timeout > slow latency but
        quorum (2 of 3) is met by the fast nodes almost immediately."""
        writers = {
            "n00": FakeWriter(),  # fast
            "n01": FakeWriter(),  # fast
            "n02": FakeWriter(latency_ms=2000),  # slow but within timeout
        }
        fw = FanoutWriter(_manifest(3), _make_keyed_factory(writers), timeout=5.0)
        try:
            t0 = time.monotonic()
            ok = fw.publish_txt_record("foo", "bar")
            elapsed = time.monotonic() - t0
            assert ok is True
            # Quorum should return well before the slow node's 2s sleep.
            assert elapsed < 1.0, f"expected fast return, took {elapsed}s"
        finally:
            fw.close()

    def test_slow_path_all_slow_times_out(self) -> None:
        """All three nodes slower than the timeout; expect False."""
        writers = {
            "n00": FakeWriter(latency_ms=1000),
            "n01": FakeWriter(latency_ms=1000),
            "n02": FakeWriter(latency_ms=1000),
        }
        fw = FanoutWriter(_manifest(3), _make_keyed_factory(writers), timeout=0.1)
        try:
            t0 = time.monotonic()
            ok = fw.publish_txt_record("foo", "bar")
            elapsed = time.monotonic() - t0
            assert ok is False
            # We bail at the deadline, not at the nodes' ~1s latency.
            assert elapsed < 0.5
        finally:
            fw.close()


# --------------------------------------------------------------------------- health


class TestHealthTracking:
    def test_consecutive_failures_increment(self) -> None:
        writers: dict = {"n00": FakeWriter(fail=True)}
        with FanoutWriter(_manifest(1), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("a", "b") is False
            assert fw.publish_txt_record("a", "b") is False
            snap = fw.snapshot()
        assert len(snap) == 1
        assert snap[0]["consecutive_failures"] == 2
        assert snap[0]["last_error"] == "writer returned False"

    def test_success_resets_failures(self) -> None:
        writer = FakeWriter(fail=True)
        writers = {"n00": writer}
        with FanoutWriter(_manifest(1), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("a", "b") is False
            assert fw.snapshot()[0]["consecutive_failures"] == 1
            writer.fail = False
            assert fw.publish_txt_record("a", "b") is True
            snap = fw.snapshot()[0]
        assert snap["consecutive_failures"] == 0
        assert snap["last_error"] is None
        assert snap["last_success_ts"] > 0.0

    def test_exception_counts_as_failure_with_error_string(self) -> None:
        writers: dict = {"n00": FakeWriter(raise_exc=ValueError("nope"))}
        with FanoutWriter(_manifest(1), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("a", "b") is False
            snap = fw.snapshot()[0]
        assert snap["consecutive_failures"] == 1
        assert "ValueError" in snap["last_error"]
        assert "nope" in snap["last_error"]

    def test_snapshot_shape(self) -> None:
        writers: dict = {"n00": FakeWriter()}
        with FanoutWriter(_manifest(1), _make_keyed_factory(writers)) as fw:
            fw.publish_txt_record("a", "b")
            snap = fw.snapshot()
        assert len(snap) == 1
        row = snap[0]
        for key in (
            "node_id",
            "http_endpoint",
            "consecutive_failures",
            "last_failure_ts",
            "last_success_ts",
            "last_error",
        ):
            assert key in row


# --------------------------------------------------------------------------- install_manifest


class TestInstallManifest:
    def test_lower_seq_rejected(self) -> None:
        op = DMPCrypto()
        m1 = _manifest(2, seq=5, operator=op)
        m0 = _manifest(2, seq=4, operator=op)
        with FanoutWriter(m1, _make_keyed_factory({})) as fw:
            assert fw.install_manifest(m0) is False
            assert fw.manifest.seq == 5

    def test_equal_seq_rejected(self) -> None:
        op = DMPCrypto()
        m1 = _manifest(2, seq=5, operator=op)
        m_same = _manifest(2, seq=5, operator=op)
        with FanoutWriter(m1, _make_keyed_factory({})) as fw:
            assert fw.install_manifest(m_same) is False
            assert fw.manifest.seq == 5

    def test_higher_seq_accepted(self) -> None:
        op = DMPCrypto()
        m1 = _manifest(2, seq=1, operator=op)
        m2 = _manifest(2, seq=2, operator=op)
        with FanoutWriter(m1, _make_keyed_factory({})) as fw:
            assert fw.install_manifest(m2) is True
            assert fw.manifest.seq == 2

    def test_expired_rejected(self) -> None:
        op = DMPCrypto()
        m1 = _manifest(2, seq=1, operator=op)
        m_expired = _manifest(2, seq=2, operator=op, exp_delta=-1)
        with FanoutWriter(m1, _make_keyed_factory({})) as fw:
            assert fw.install_manifest(m_expired) is False
            assert fw.manifest.seq == 1

    def test_preserves_state_for_retained_nodes(self) -> None:
        op = DMPCrypto()
        # Two nodes in manifest v1; both retained in v2.
        m1 = _manifest(2, seq=1, operator=op)
        writers: dict = {"n00": FakeWriter(fail=True), "n01": FakeWriter()}
        with FanoutWriter(m1, _make_keyed_factory(writers)) as fw:
            fw.publish_txt_record("a", "b")  # n00 fails → cf=1
            pre = {s["node_id"]: s for s in fw.snapshot()}
            assert pre["n00"]["consecutive_failures"] == 1

            # Refresh with same node set at higher seq.
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=list(m1.nodes),
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            post = {s["node_id"]: s for s in fw.snapshot()}
        assert post["n00"]["consecutive_failures"] == 1
        assert post["n00"]["last_failure_ts"] == pre["n00"]["last_failure_ts"]

    def test_drops_removed_nodes_and_closes_writers(self) -> None:
        op = DMPCrypto()
        m1 = _manifest(3, seq=1, operator=op)
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(3)}
        with FanoutWriter(m1, _make_keyed_factory(writers)) as fw:
            assert {s["node_id"] for s in fw.snapshot()} == {
                "n00",
                "n01",
                "n02",
            }
            # v2 keeps only n00 and n02.
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[m1.nodes[0], m1.nodes[2]],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            snap_ids = {s["node_id"] for s in fw.snapshot()}
        assert snap_ids == {"n00", "n02"}
        # The removed writer had close() called.
        assert writers["n01"].close_calls == 1
        # Retained writers untouched.
        assert writers["n00"].close_calls == 0
        assert writers["n02"].close_calls == 0

    def test_adds_new_nodes_with_fresh_state(self) -> None:
        op = DMPCrypto()
        m1 = _manifest(1, seq=1, operator=op)
        writers: dict = {"n00": FakeWriter(fail=True)}
        with FanoutWriter(m1, _make_keyed_factory(writers)) as fw:
            fw.publish_txt_record("a", "b")  # n00 failure
            # v2 adds n01.
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[_node(0), _node(1)],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            snap = {s["node_id"]: s for s in fw.snapshot()}
        assert snap["n00"]["consecutive_failures"] == 1
        assert snap["n01"]["consecutive_failures"] == 0
        assert snap["n01"]["last_error"] is None

    def test_min_valid_seq_zero_and_refresh_to_one(self) -> None:
        op = DMPCrypto()
        m0 = _manifest(2, seq=0, operator=op)
        m1 = _manifest(2, seq=1, operator=op)
        with FanoutWriter(m0, _make_keyed_factory({})) as fw:
            assert fw.manifest.seq == 0
            assert fw.install_manifest(m1) is True
            assert fw.manifest.seq == 1


# --------------------------------------------------------------------------- exception safety


class TestExceptionSafety:
    def test_writer_exception_does_not_crash_fanout(self) -> None:
        """One node raises; the others still count toward quorum."""
        writers = {
            "n00": FakeWriter(raise_exc=RuntimeError("boom")),
            "n01": FakeWriter(),
            "n02": FakeWriter(),
        }
        with FanoutWriter(_manifest(3), _make_keyed_factory(writers)) as fw:
            assert fw.publish_txt_record("a", "b") is True
            snap = {s["node_id"]: s for s in fw.snapshot()}
        assert snap["n00"]["consecutive_failures"] == 1
        assert "RuntimeError" in (snap["n00"]["last_error"] or "")
        assert snap["n01"]["consecutive_failures"] == 0
        assert snap["n02"]["consecutive_failures"] == 0

    def test_close_is_idempotent(self) -> None:
        writers: dict = {"n00": FakeWriter()}
        fw = FanoutWriter(_manifest(1), _make_keyed_factory(writers))
        fw.close()
        fw.close()  # must not raise

    def test_publish_after_close_raises(self) -> None:
        writers: dict = {"n00": FakeWriter()}
        fw = FanoutWriter(_manifest(1), _make_keyed_factory(writers))
        fw.close()
        with pytest.raises(RuntimeError):
            fw.publish_txt_record("a", "b")


# --------------------------------------------------------------------------- endpoint-change + resize + retention


class _TrackingFactory:
    """Factory that records every call and hands back a fresh FakeWriter each time.

    Keeps each writer in a list keyed by node_id so tests can inspect
    sequential writers for the same node_id across manifest refreshes.
    """

    def __init__(self) -> None:
        self.writers: dict = {}  # node_id -> list[FakeWriter]
        self.calls: List[tuple] = []  # (node_id, http_endpoint) per call

    def __call__(self, node: ClusterNode) -> FakeWriter:
        w = FakeWriter()
        self.calls.append((node.node_id, node.http_endpoint))
        self.writers.setdefault(node.node_id, []).append(w)
        return w

    def latest(self, node_id: str) -> FakeWriter:
        return self.writers[node_id][-1]

    def first(self, node_id: str) -> FakeWriter:
        return self.writers[node_id][0]


class TestEndpointChange:
    def test_endpoint_change_triggers_new_writer(self) -> None:
        op = DMPCrypto()
        factory = _TrackingFactory()
        # v1: "n00" @ E1
        n00_v1 = ClusterNode(node_id="n00", http_endpoint="https://e1.example:8053")
        m1 = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[n00_v1],
            seq=1,
            exp=int(time.time()) + 3600,
        )
        with FanoutWriter(m1, factory) as fw:
            fw.publish_txt_record("a", "b")
            assert len(factory.first("n00").publish_calls) == 1

            # v2: "n00" @ E2 — retained node_id, changed endpoint.
            n00_v2 = ClusterNode(node_id="n00", http_endpoint="https://e2.example:8053")
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[n00_v2],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            # Factory should have been called again for the rebuilt writer.
            assert factory.calls == [
                ("n00", "https://e1.example:8053"),
                ("n00", "https://e2.example:8053"),
            ]
            # Next publish hits E2's writer, not E1's.
            fw.publish_txt_record("a", "c")
            assert len(factory.first("n00").publish_calls) == 1  # E1 unchanged
            assert len(factory.latest("n00").publish_calls) == 1  # E2 got the new one
            # Snapshot reflects the new endpoint.
            snap = fw.snapshot()
            assert snap[0]["http_endpoint"] == "https://e2.example:8053"

    def test_endpoint_unchanged_does_not_rebuild_writer(self) -> None:
        """Refresh with identical node entry must not call the factory again."""
        op = DMPCrypto()
        factory = _TrackingFactory()
        node = ClusterNode(node_id="n00", http_endpoint="https://e1.example:8053")
        m1 = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[node],
            seq=1,
            exp=int(time.time()) + 3600,
        )
        with FanoutWriter(m1, factory) as fw:
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[node],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            # One factory call only — the initial construction.
            assert len(factory.calls) == 1

    def test_dns_endpoint_change_triggers_new_writer(self) -> None:
        op = DMPCrypto()
        factory = _TrackingFactory()
        n00_v1 = ClusterNode(
            node_id="n00",
            http_endpoint="https://e.example:8053",
            dns_endpoint="203.0.113.1:53",
        )
        m1 = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[n00_v1],
            seq=1,
            exp=int(time.time()) + 3600,
        )
        with FanoutWriter(m1, factory) as fw:
            n00_v2 = ClusterNode(
                node_id="n00",
                http_endpoint="https://e.example:8053",
                dns_endpoint="203.0.113.2:53",
            )
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[n00_v2],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            # HTTP endpoint is the same but dns_endpoint changed; still
            # expect the writer to be rebuilt.
            assert len(factory.calls) == 2

    def test_health_preserved_across_endpoint_change(self) -> None:
        """consecutive_failures must survive the endpoint swap."""
        op = DMPCrypto()

        # Custom factory: first writer fails, second writer succeeds.
        # We can't use _TrackingFactory alone because both writers it
        # hands back start with fail=False.
        made: List[FakeWriter] = []

        def factory(node: ClusterNode) -> FakeWriter:
            w = FakeWriter(fail=(len(made) == 0))
            made.append(w)
            return w

        n00_v1 = ClusterNode(node_id="n00", http_endpoint="https://e1.example:8053")
        m1 = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[n00_v1],
            seq=1,
            exp=int(time.time()) + 3600,
        )
        with FanoutWriter(m1, factory) as fw:
            # Drive consecutive_failures up on the E1 writer.
            fw.publish_txt_record("a", "b")
            fw.publish_txt_record("a", "b")
            pre = fw.snapshot()[0]
            assert pre["consecutive_failures"] == 2
            pre_last_failure_ts = pre["last_failure_ts"]

            # Refresh to E2. Health counters must survive.
            n00_v2 = ClusterNode(node_id="n00", http_endpoint="https://e2.example:8053")
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[n00_v2],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            post = fw.snapshot()[0]
            assert post["consecutive_failures"] == 2
            assert post["last_failure_ts"] == pre_last_failure_ts
            assert post["http_endpoint"] == "https://e2.example:8053"

    def test_endpoint_change_retains_old_writer_until_close(self) -> None:
        """The rebuilt writer must not be close()'d at swap time."""
        op = DMPCrypto()
        factory = _TrackingFactory()
        n00_v1 = ClusterNode(node_id="n00", http_endpoint="https://e1.example:8053")
        m1 = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[n00_v1],
            seq=1,
            exp=int(time.time()) + 3600,
        )
        fw = FanoutWriter(m1, factory)
        try:
            n00_v2 = ClusterNode(node_id="n00", http_endpoint="https://e2.example:8053")
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[n00_v2],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            # The E1 writer is retained, not yet closed.
            assert factory.first("n00").close_calls == 0
        finally:
            fw.close()
        # After close, the retained E1 writer is drained.
        assert factory.first("n00").close_calls == 1


class TestExecutorResize:
    def test_executor_grows_on_manifest_growth(self) -> None:
        """Start with 1 node, grow to 10. Per-node latency ~50ms, timeout 500ms.

        If the executor didn't grow, publishes would serialize in a
        single worker and blow the timeout. This test fails without the
        resize fix.
        """
        op = DMPCrypto()
        factory = _TrackingFactory()
        m1 = _manifest(1, seq=1, operator=op)
        with FanoutWriter(m1, factory, timeout=0.5) as fw:
            # Grow to 10 nodes; each publish sleeps 50ms.
            nodes = [_node(i) for i in range(10)]
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=nodes,
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True

            # Configure every node's writer to have 50ms latency. The
            # first writer (n00 at creation time from m1) stays as-is,
            # but m2's endpoint for "n00" matches m1's so its writer is
            # retained — set latency on the surviving one too.
            for node_id in [f"n{i:02d}" for i in range(10)]:
                factory.latest(node_id).latency_ms = 50

            t0 = time.monotonic()
            ok = fw.publish_txt_record("a", "b")
            elapsed = time.monotonic() - t0

        # With a pool big enough for 10 parallel calls: ~50ms + overhead.
        # With a pool of 1: 10 * 50ms = 500ms, hitting the timeout.
        assert ok is True
        assert elapsed < 0.4, f"expected parallel fan-out, took {elapsed}s"

    def test_executor_does_not_shrink_on_manifest_shrink(self) -> None:
        """Shrinking a manifest should NOT shrink the executor.

        This matches the design: we never shrink — the trade-off of a
        slightly-too-large pool is trivial and shrinking would either
        orphan in-flight work or force us to wait on it. No assertion
        on _max_workers equality, just that shrinking doesn't break.
        """
        op = DMPCrypto()
        factory = _TrackingFactory()
        m1 = _manifest(10, seq=1, operator=op)
        with FanoutWriter(m1, factory) as fw:
            initial_max = fw._executor._max_workers
            m2 = _manifest(2, seq=2, operator=op)
            # Same factory hands back new nodes with same node_ids; we
            # can just reuse _manifest.
            assert fw.install_manifest(m2) is True
            # Pool size unchanged (or at least not shrunk below 10).
            assert fw._executor._max_workers == initial_max


class TestRemovedWriterRetention:
    def test_removed_node_writer_not_closed_prematurely(self) -> None:
        """Removed node writers go to the retention list, not close()'d.

        The scenario exercised: quorum-return leaves a slow publish
        still running against node "a". We then drop "a" from the
        manifest. The slow publish must complete without interference
        and its close() must not be called until FanoutWriter.close().
        """
        op = DMPCrypto()
        # 3-node cluster. "n00" is slow (500ms latency); "n01" and
        # "n02" are fast, so quorum (2 of 3) lands immediately and
        # publish returns before n00's publish finishes.
        writers: dict = {
            "n00": FakeWriter(latency_ms=500),
            "n01": FakeWriter(),
            "n02": FakeWriter(),
        }
        m1 = _manifest(3, seq=1, operator=op)
        with FanoutWriter(m1, _make_keyed_factory(writers), timeout=5.0) as fw:
            t0 = time.monotonic()
            ok = fw.publish_txt_record("a", "b")
            elapsed = time.monotonic() - t0
            assert ok is True
            # Quorum-return: we're back before n00's latency elapsed.
            assert elapsed < 0.3

            # Drop n00 while its publish is still running.
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[m1.nodes[1], m1.nodes[2]],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True

            # Writer for n00 is retained, NOT closed yet.
            assert writers["n00"].close_calls == 0

            # Give the slow publish time to complete normally.
            _poll_until(lambda: len(writers["n00"].publish_calls) == 1, timeout=2.0)

            # Still retained, still not closed.
            assert writers["n00"].close_calls == 0

        # After FanoutWriter.close(), the retained writer is drained.
        assert writers["n00"].close_calls == 1

    def test_close_drains_retention_list_across_refreshes(self) -> None:
        op = DMPCrypto()
        # Start with 4 nodes, drop one on each of three refreshes.
        all_writers: dict = {f"n{i:02d}": FakeWriter() for i in range(4)}
        m1 = _manifest(4, seq=1, operator=op)
        fw = FanoutWriter(m1, _make_keyed_factory(all_writers))

        # Refresh 1: drop n00.
        m2 = ClusterManifest(
            cluster_name=m1.cluster_name,
            operator_spk=m1.operator_spk,
            nodes=[m1.nodes[1], m1.nodes[2], m1.nodes[3]],
            seq=2,
            exp=m1.exp,
        )
        assert fw.install_manifest(m2) is True
        # Refresh 2: drop n01.
        m3 = ClusterManifest(
            cluster_name=m1.cluster_name,
            operator_spk=m1.operator_spk,
            nodes=[m1.nodes[2], m1.nodes[3]],
            seq=3,
            exp=m1.exp,
        )
        assert fw.install_manifest(m3) is True
        # Refresh 3: drop n02.
        m4 = ClusterManifest(
            cluster_name=m1.cluster_name,
            operator_spk=m1.operator_spk,
            nodes=[m1.nodes[3]],
            seq=4,
            exp=m1.exp,
        )
        assert fw.install_manifest(m4) is True

        # None of the removed writers have been closed yet.
        assert all_writers["n00"].close_calls == 0
        assert all_writers["n01"].close_calls == 0
        assert all_writers["n02"].close_calls == 0
        # Live node's writer never closed either.
        assert all_writers["n03"].close_calls == 0

        fw.close()

        # All three retained writers drained.
        assert all_writers["n00"].close_calls == 1
        assert all_writers["n01"].close_calls == 1
        assert all_writers["n02"].close_calls == 1
        # Live writer stays open (FanoutWriter does not own its lifecycle).
        assert all_writers["n03"].close_calls == 0

    def test_close_is_idempotent_with_retained_writers(self) -> None:
        """Calling close() twice must not double-close retained writers."""
        op = DMPCrypto()
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(2)}
        m1 = _manifest(2, seq=1, operator=op)
        fw = FanoutWriter(m1, _make_keyed_factory(writers))
        m2 = ClusterManifest(
            cluster_name=m1.cluster_name,
            operator_spk=m1.operator_spk,
            nodes=[m1.nodes[1]],
            seq=2,
            exp=m1.exp,
        )
        assert fw.install_manifest(m2) is True
        fw.close()
        fw.close()  # Must not raise, must not double-close.
        assert writers["n00"].close_calls == 1


class TestConstructorExpiryCheck:
    def test_expired_manifest_rejected_on_init(self) -> None:
        """An already-expired manifest must be rejected on construction,
        mirroring install_manifest's invariant. Otherwise a direct call
        or reload path silently publishes to stale nodes until the next
        refresh."""
        op = DMPCrypto()
        mf = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=op.get_signing_public_key_bytes(),
            nodes=[_node(0)],
            seq=1,
            exp=int(time.time()) - 60,
        )
        with pytest.raises(ValueError, match="expired"):
            FanoutWriter(mf, _make_keyed_factory({"n00": FakeWriter()}))


class TestUserMaxWorkersRespectedOnResize:
    def test_user_cap_preserved_across_manifest_growth(self) -> None:
        """max_workers=2 caller must still get 2 threads even when a
        manifest refresh grows from 1 node to 10."""
        op = DMPCrypto()
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(10)}
        m1 = _manifest(1, seq=1, operator=op)
        fw = FanoutWriter(m1, _make_keyed_factory(writers), max_workers=2)
        try:
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[_node(i) for i in range(10)],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            # The active executor must still honor the caller's cap.
            # (private-attribute access is acceptable in tests.)
            assert fw._executor._max_workers == 2  # type: ignore[attr-defined]
        finally:
            fw.close()

    def test_default_heuristic_when_user_did_not_pin(self) -> None:
        """When max_workers is None, the default heuristic min(N, 16)
        applies on resize — confirms the user-cap guard doesn't regress
        the default growth path."""
        op = DMPCrypto()
        writers: dict = {f"n{i:02d}": FakeWriter() for i in range(8)}
        m1 = _manifest(1, seq=1, operator=op)
        fw = FanoutWriter(m1, _make_keyed_factory(writers))
        try:
            m2 = ClusterManifest(
                cluster_name=m1.cluster_name,
                operator_spk=m1.operator_spk,
                nodes=[_node(i) for i in range(8)],
                seq=2,
                exp=m1.exp,
            )
            assert fw.install_manifest(m2) is True
            assert fw._executor._max_workers == 8  # type: ignore[attr-defined]
        finally:
            fw.close()


class TestCloseDrainsBeforeClosingWriters:
    def test_close_waits_for_inflight_before_closing_retired_writers(self) -> None:
        """close() must wait for in-flight fan-out futures to finish
        before closing retained (retired) writers. Otherwise the mid-
        flight race the retention list was supposed to fix reappears
        at teardown time.
        """
        op = DMPCrypto()
        # The slow writer will be retired by install_manifest. We
        # record the exact ordering of its publish-completion and its
        # close() call — publish must complete first.
        order: list = []

        class OrderingWriter(FakeWriter):
            def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
                if self.latency_ms:
                    time.sleep(self.latency_ms / 1000.0)
                order.append("publish-done")
                return super().publish_txt_record(name, value, ttl)

            def close(self) -> None:
                order.append("close")
                super().close()

        slow = OrderingWriter(latency_ms=200)
        fast = FakeWriter()
        writers = {"n00": slow, "n01": fast}
        m1 = _manifest(2, seq=1, operator=op)
        fw = FanoutWriter(m1, _make_keyed_factory(writers), timeout=2.0)
        # Kick off a publish; quorum=1 so it returns as soon as the
        # fast writer succeeds, leaving slow's future in flight.
        assert fw.publish_txt_record("x.mesh.test", "v=dmp1", ttl=60) is True
        # Retire the slow node by dropping it from the manifest.
        m2 = ClusterManifest(
            cluster_name=m1.cluster_name,
            operator_spk=m1.operator_spk,
            nodes=[m1.nodes[1]],
            seq=2,
            exp=m1.exp,
        )
        assert fw.install_manifest(m2) is True
        # close() must drain slow's in-flight publish before calling
        # its close(). Ordering assertion proves the race is fixed.
        fw.close()
        assert "publish-done" in order
        assert "close" in order
        assert order.index("publish-done") < order.index("close")
