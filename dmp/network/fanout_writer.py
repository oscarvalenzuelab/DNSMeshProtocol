"""Quorum-write fan-out across cluster nodes (M2.2).

A :class:`FanoutWriter` is a :class:`DNSRecordWriter` that wraps a
:class:`~dmp.core.cluster.ClusterManifest` and fans every publish/delete
across the nodes in the manifest, returning success iff at least
``r_w = ceil(N/2)`` nodes acknowledge.

Design summary
==============

* **Quorum.** ``N`` nodes, quorum ``ceil(N/2)``. Empty manifest (``N=0``)
  is an edge case: quorum 0, publish returns True vacuously. The caller
  has "nothing to fan out to" and that is not an error.
* **Concurrency.** Each call fires all per-node writes in parallel via a
  single ``ThreadPoolExecutor`` owned by the FanoutWriter instance. The
  main thread blocks on :func:`concurrent.futures.as_completed` with a
  deadline; as soon as the in-flight ack count reaches quorum the call
  returns ``True`` without waiting for the slowpokes. Slow futures
  complete in the background and update per-node health on arrival.
* **Timeout.** The per-call ``timeout`` covers the entire fan-out. If
  the deadline expires before quorum, the call returns ``False`` and
  late-arriving futures still update health in the background.
* **Per-node health.** Each node has a :class:`_NodeState` that tracks
  ``consecutive_failures``, ``last_failure_ts``, ``last_success_ts``,
  and ``last_error``. Updates happen under a lock. ``snapshot()``
  returns read-only dicts suitable for logging / CLI status.
* **Manifest refresh.** :meth:`install_manifest` replaces the active
  manifest if the new ``seq`` is strictly higher than the current
  ``seq`` and the new manifest is not already expired. Node state is
  preserved across refresh for retained ``node_id``s; new nodes get
  fresh state; removed nodes' writer instances are closed (if they
  expose a ``close()`` method) and their state is dropped.

Security boundary
-----------------

``FanoutWriter`` does **not** verify manifest signatures. The caller
(typically the DMP client) is expected to validate the manifest via
:meth:`ClusterManifest.parse_and_verify` — which checks the operator
signature, embedded pubkey, expiry, and cluster-name binding — before
handing it to :meth:`install_manifest`. FanoutWriter enforces only the
two invariants it can: seq-monotonicity (no regressions) and
non-expiry-at-install. Installing a manifest signed by a different
operator, or for the wrong cluster, is the caller's responsibility.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from dmp.core.cluster import ClusterManifest, ClusterNode
from dmp.network.base import DNSRecordWriter

# A factory takes a single ClusterNode and returns a DNSRecordWriter
# bound to that node. Typically this wraps an HTTP client talking to the
# node's /dns API endpoint. The factory never raises on ordinary
# construction failures; a flaky factory should return a writer whose
# every call returns False so the quorum path can still make progress.
WriterFactory = Callable[[ClusterNode], DNSRecordWriter]


def _ceil_half(n: int) -> int:
    """Return the write quorum for a cluster of ``n`` nodes.

    * ``n == 0`` → ``0`` (no one to fan out to; trivially satisfied)
    * ``n > 0``  → ``ceil(n / 2)`` = ``(n + 1) // 2``

    Examples: ``0→0, 1→1, 2→1, 3→2, 4→2, 5→3``.
    """
    if n <= 0:
        return 0
    return (n + 1) // 2


@dataclass
class _NodeState:
    """Mutable health state for one fan-out target.

    Mirrors :class:`dmp.network.resolver_pool._HostState` in spirit:
    monotonically counts consecutive failures, stamps the wall-clock of
    each success/failure, and carries the last error string for
    operators to read out of ``snapshot()``.
    """

    node_id: str
    http_endpoint: str
    writer: DNSRecordWriter
    consecutive_failures: int = 0
    last_failure_ts: float = 0.0
    last_success_ts: float = 0.0
    last_error: Optional[str] = None

    def record_success(self, now: float) -> None:
        self.consecutive_failures = 0
        self.last_success_ts = now
        self.last_error = None

    def record_failure(self, now: float, err: str) -> None:
        self.consecutive_failures += 1
        self.last_failure_ts = now
        self.last_error = err


class FanoutWriter(DNSRecordWriter):
    """Fan publishes/deletes across a cluster; return True on quorum.

    The caller must pre-verify any :class:`ClusterManifest` (signature,
    operator pubkey, expected cluster name) before passing it to the
    constructor or :meth:`install_manifest`. FanoutWriter itself
    enforces only seq-monotonicity and non-expiry at install time.

    Parameters
    ----------
    manifest:
        The initial (already-verified) cluster manifest.
    writer_factory:
        Called once per node to produce that node's per-node
        ``DNSRecordWriter``. Receives the full :class:`ClusterNode`
        (not just ``http_endpoint``) so factories that need the
        ``dns_endpoint`` or ``node_id`` can access them.
    timeout:
        Default per-call timeout (seconds) covering the *entire*
        fan-out. Can be overridden per invocation in the future, but
        today it is a constructor-wide setting. Defaults to 5.0.
    max_workers:
        Size of the thread pool. Defaults to ``min(N, 16)``; pools of
        0 nodes still create a 1-worker pool so that an ``install_manifest``
        adding nodes does not need to recreate the executor.
    """

    def __init__(
        self,
        manifest: ClusterManifest,
        writer_factory: WriterFactory,
        *,
        timeout: float = 5.0,
        max_workers: Optional[int] = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        self._factory = writer_factory
        self._timeout = float(timeout)
        self._lock = threading.Lock()
        # Current manifest (always the most recently installed one).
        self._manifest: ClusterManifest = manifest
        # Per-node state, keyed by node_id. Insertion order is the
        # manifest's node order, which makes snapshot() deterministic.
        self._nodes: Dict[str, _NodeState] = {}
        for node in manifest.nodes:
            self._nodes[node.node_id] = _NodeState(
                node_id=node.node_id,
                http_endpoint=node.http_endpoint,
                writer=self._factory(node),
            )
        # Executor sized to accommodate the initial manifest; we keep at
        # least one worker so a manifest that grows from empty to N
        # nodes still has somewhere to schedule work without needing a
        # pool recreate. 16 is the same cap used across the stdlib's
        # default pool heuristic and is plenty for typical clusters.
        if max_workers is None:
            max_workers = max(1, min(len(manifest.nodes), 16))
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="fanout-writer",
        )
        self._closed = False

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Shut down the executor. Idempotent."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            executor = self._executor
        # shutdown(wait=False) lets in-flight futures drain in the
        # background threads. We do not cancel because the per-node
        # writes have already been dispatched and their side effects
        # (HTTP requests, etc.) are out of our hands.
        executor.shutdown(wait=False)

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self) -> "FanoutWriter":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ properties

    @property
    def quorum(self) -> int:
        """Current ``ceil(N/2)`` threshold; ``N == 0`` → ``0``."""
        with self._lock:
            return _ceil_half(len(self._nodes))

    @property
    def manifest(self) -> ClusterManifest:
        """The currently active cluster manifest (read-only reference)."""
        with self._lock:
            return self._manifest

    # ------------------------------------------------------------------ manifest

    def install_manifest(self, manifest: ClusterManifest) -> bool:
        """Replace the active cluster manifest.

        Returns ``True`` if the new manifest was applied, ``False`` if
        rejected. Rejection reasons:

        * ``manifest.seq`` is not strictly greater than the active
          manifest's ``seq`` (no regressions, no no-ops).
        * ``manifest.is_expired()`` — installing a stale manifest would
          immediately strand the client.

        On accept, per-node state is preserved for ``node_id``s that
        appear in both manifests. Writers for nodes that dropped out
        get their ``close()`` method invoked if they expose one (duck
        typed; missing ``close`` is fine).

        Note: FanoutWriter does **not** re-verify the manifest
        signature. See the module docstring's security boundary note.
        """
        if manifest.is_expired():
            return False
        with self._lock:
            if manifest.seq <= self._manifest.seq:
                return False

            old_states = self._nodes
            new_states: Dict[str, _NodeState] = {}
            for node in manifest.nodes:
                existing = old_states.get(node.node_id)
                if existing is not None:
                    # Preserve health state; refresh the recorded
                    # endpoint in case it changed across the manifest
                    # rev, but keep the writer instance so any
                    # node-local state (HTTP keepalive pool, auth
                    # token, etc.) stays warm.
                    existing.http_endpoint = node.http_endpoint
                    new_states[node.node_id] = existing
                else:
                    new_states[node.node_id] = _NodeState(
                        node_id=node.node_id,
                        http_endpoint=node.http_endpoint,
                        writer=self._factory(node),
                    )

            # Nodes that disappeared: close their writer if possible,
            # then drop them. Suppress any exceptions; a buggy close()
            # on a removed writer must not prevent the refresh.
            removed_ids = set(old_states.keys()) - set(new_states.keys())
            for rid in removed_ids:
                writer = old_states[rid].writer
                closer = getattr(writer, "close", None)
                if callable(closer):
                    try:
                        closer()
                    except Exception:
                        pass

            self._manifest = manifest
            self._nodes = new_states
        return True

    # ------------------------------------------------------------------ snapshot

    def snapshot(self) -> List[dict]:
        """Return a list of per-node health dicts.

        Ordering matches the current manifest's node order. Each entry
        contains: ``node_id``, ``http_endpoint``, ``consecutive_failures``,
        ``last_failure_ts``, ``last_success_ts``, ``last_error``.
        """
        with self._lock:
            return [
                {
                    "node_id": s.node_id,
                    "http_endpoint": s.http_endpoint,
                    "consecutive_failures": s.consecutive_failures,
                    "last_failure_ts": s.last_failure_ts,
                    "last_success_ts": s.last_success_ts,
                    "last_error": s.last_error,
                }
                for s in self._nodes.values()
            ]

    # ------------------------------------------------------------------ core fan-out

    def _run_on_node(
        self,
        state: _NodeState,
        op: Callable[[DNSRecordWriter], bool],
    ) -> bool:
        """Execute ``op`` on one node's writer; record health; return bool.

        Exceptions in the per-node writer are caught and counted as
        failures (never propagated out of the thread). A ``False``
        return value from the writer is also a failure for health
        purposes.
        """
        now = time.time()
        try:
            ok = bool(op(state.writer))
        except Exception as e:
            with self._lock:
                state.record_failure(now, f"{type(e).__name__}: {e}")
            return False
        with self._lock:
            if ok:
                state.record_success(now)
            else:
                state.record_failure(now, "writer returned False")
        return ok

    def _fanout(self, op: Callable[[DNSRecordWriter], bool]) -> bool:
        """Dispatch ``op`` to every node and return True on quorum.

        Timing: we call ``as_completed(..., timeout=remaining_budget)``
        and break as soon as the success count hits the quorum. Unfinished
        futures are left running in the executor; their completion will
        still update per-node health through :meth:`_run_on_node`.
        """
        # Snapshot the state set under the lock; we hand the executor a
        # fixed list so a concurrent install_manifest doesn't race with
        # an in-flight fan-out. The state objects themselves outlive
        # the snapshot as long as they remain referenced by the
        # captured futures, so health updates on slow nodes still
        # land correctly even if the node is removed mid-flight.
        with self._lock:
            if self._closed:
                raise RuntimeError("FanoutWriter is closed")
            states = list(self._nodes.values())
            quorum = _ceil_half(len(states))

        # Vacuous success: nothing to fan out to, quorum zero.
        if not states:
            return True

        deadline = time.monotonic() + self._timeout

        futures: List[Future] = [
            self._executor.submit(self._run_on_node, s, op) for s in states
        ]

        successes = 0
        try:
            # Track budget across iterations. as_completed's own
            # timeout fires once for the whole generator; we re-enter
            # with a fresh budget on each cycle so quorum-met returns
            # fast regardless of straggler latency.
            for fut in as_completed(
                futures, timeout=max(0.0, deadline - time.monotonic())
            ):
                try:
                    if fut.result():
                        successes += 1
                except Exception:
                    # Defensive: _run_on_node already catches, but a
                    # truly exotic exception (e.g. executor shutdown
                    # during result()) shouldn't bubble up as an
                    # unhandled error either — treat it as a failure.
                    pass
                if successes >= quorum:
                    return True
        except TimeoutError:
            # Deadline exceeded before quorum; remaining futures stay
            # running and will update health on completion.
            return False

        return successes >= quorum

    # ------------------------------------------------------------------ DNSRecordWriter

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        return self._fanout(lambda w: w.publish_txt_record(name, value, ttl))

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        return self._fanout(lambda w: w.delete_txt_record(name, value))
