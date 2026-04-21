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
