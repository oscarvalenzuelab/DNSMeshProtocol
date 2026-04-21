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
  preserved across refresh for retained ``node_id``s — **including**
  when only the endpoint changes (the writer is rebuilt but health
  counters are kept). New nodes get fresh state. Removed nodes' and
  endpoint-swapped nodes' writers are parked in a retention list and
  closed at :meth:`close` time: ``_fanout`` returns on quorum and lets
  slow-path futures keep running, so calling ``.close()`` on a
  removed writer mid-flight would race the still-running call. The
  retention list grows with (cluster_size * refresh_frequency) across
  the lifetime of the instance — acceptable for production clusters
  that refresh manifests on the order of minutes/hours, not seconds.
  If you run a pathological workload that refreshes manifests in a
  tight loop, ref-count the writers or destroy/recreate the
  FanoutWriter periodically.
* **Executor growth.** The executor is sized from the initial manifest
  and grown when :meth:`install_manifest` installs a manifest with more
  nodes than the current executor can run in parallel. Old executors
  are retired to a list and drained on :meth:`close`; in-flight work
  continues in their worker threads unmolested.

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

import copy
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
    dns_endpoint: Optional[str] = None
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
        # Match install_manifest's expiry check: an already-expired
        # manifest handed to the constructor would otherwise silently
        # publish to stale nodes until the next refresh.
        if manifest.is_expired():
            raise ValueError("cluster manifest is expired")
        self._factory = writer_factory
        self._timeout = float(timeout)
        self._lock = threading.Lock()
        # Current manifest (always the most recently installed one).
        # Stored as a deepcopy so caller-side mutation of the passed
        # ClusterManifest can't corrupt our monotonicity check.
        self._manifest: ClusterManifest = copy.deepcopy(manifest)
        # Per-node state, keyed by node_id. Insertion order is the
        # manifest's node order, which makes snapshot() deterministic.
        self._nodes: Dict[str, _NodeState] = {}
        for node in manifest.nodes:
            self._nodes[node.node_id] = _NodeState(
                node_id=node.node_id,
                http_endpoint=node.http_endpoint,
                dns_endpoint=node.dns_endpoint,
                writer=self._factory(node),
            )
        # Writers dropped by a manifest refresh (either because the
        # node_id disappeared or because its endpoint changed and the
        # writer was rebuilt) are moved here instead of being closed
        # eagerly. The fan-out path can have slow-path futures still
        # operating on those writers after it returned on quorum; calling
        # close() on them mid-flight risks crashing the background call
        # or corrupting state. We drain this list in :meth:`close`.
        self._retired_writers: List[DNSRecordWriter] = []
        # Executor sized to accommodate the initial manifest; we keep at
        # least one worker so a manifest that grows from empty to N
        # nodes still has somewhere to schedule work without needing a
        # pool recreate. 16 is the same cap used across the stdlib's
        # default pool heuristic and is plenty for typical clusters.
        # Remember whether the caller pinned a worker cap. On manifest
        # growth we honor that cap rather than reverting to the default
        # heuristic — a deployment that capped concurrency for rate
        # limits or fd budget must not have that cap quietly erased by
        # a refresh.
        self._user_max_workers: Optional[int] = max_workers
        if max_workers is None:
            max_workers = max(1, min(len(manifest.nodes), 16))
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="fanout-writer",
        )
        # Executors that were superseded by an install_manifest call
        # that grew the worker pool. Their in-flight futures keep
        # running in their own threads (wait=False semantics); we hold
        # onto them so close() can shut them all down, and so the
        # running threads are not orphaned on GC of the superseded
        # pool. See `install_manifest` for the resize logic.
        self._retired_executors: List[ThreadPoolExecutor] = []
        self._closed = False

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Shut down the executor and drain retained resources. Idempotent.

        Waits for every in-flight fan-out future (current + retired
        executors) to complete before closing retained writers. This
        preserves the mid-flight-safety invariant: a background fan-out
        that survived a manifest refresh must finish its call on the
        retired writer before that writer's ``close()`` runs. Without
        the wait, ``close()`` would reintroduce the exact race the
        retention list was designed to prevent.

        Current/live per-node writers are **not** closed here — the
        FanoutWriter does not own their lifecycle; the caller (client)
        that supplied ``writer_factory`` decides when those shut down.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            executor = self._executor
            retired_writers = self._retired_writers
            self._retired_writers = []
            retired_executors = self._retired_executors
            self._retired_executors = []
        # shutdown(wait=True) waits for in-flight futures to finish, so
        # any background fan-out still operating on a retired writer
        # completes before we close that writer below.
        executor.shutdown(wait=True)
        for old in retired_executors:
            try:
                old.shutdown(wait=True)
            except Exception:
                pass
        # All futures have drained; it is now safe to close retained
        # writers. A buggy close() on one must not block the others.
        for writer in retired_writers:
            closer = getattr(writer, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass

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

        On accept:

        * Per-node state is preserved for ``node_id``s that appear in
          both manifests with the **same** ``http_endpoint`` and
          ``dns_endpoint``.
        * If a retained ``node_id``'s endpoint changed, a fresh writer
          is built via ``writer_factory`` and swapped in. Health
          counters (``consecutive_failures``, timestamps, last error)
          are preserved across the swap — the node is semantically the
          same, only its address moved. The old writer is retained
          (not closed) so in-flight fan-outs that already dispatched to
          it don't race with a ``close()``.
        * New ``node_id``s get a fresh ``_NodeState`` and a new writer.
        * Removed ``node_id``s have their writers **retained** (not
          closed) for the same race-avoidance reason as endpoint
          swaps: quorum-return leaves slow-path futures running
          against those writers; closing them mid-flight would crash
          the background call. They're drained in :meth:`close`.
        * If the new manifest has more nodes than the current executor
          can run in parallel, the executor is replaced with a larger
          one. The old executor is retired (shutdown deferred to
          :meth:`close`) so in-flight fan-outs continue to run on it.

        Note: FanoutWriter does **not** re-verify the manifest
        signature. See the module docstring's security boundary note.
        """
        if manifest.is_expired():
            return False
        with self._lock:
            if self._closed:
                # A close()-in-flight must block further installs;
                # otherwise we allocate writers / a new executor that
                # close() already committed to not draining.
                return False
            if manifest.seq <= self._manifest.seq:
                return False

            old_states = self._nodes
            new_states: Dict[str, _NodeState] = {}
            for node in manifest.nodes:
                existing = old_states.get(node.node_id)
                if existing is None:
                    # New node_id → fresh state + new writer.
                    new_states[node.node_id] = _NodeState(
                        node_id=node.node_id,
                        http_endpoint=node.http_endpoint,
                        dns_endpoint=node.dns_endpoint,
                        writer=self._factory(node),
                    )
                    continue

                # Retained node_id. Compare endpoints; if either HTTP
                # or DNS endpoint changed the old writer is pointing at
                # a stale address and must be rebuilt. Node-level
                # health counters survive the swap.
                endpoint_changed = (
                    existing.http_endpoint != node.http_endpoint
                    or existing.dns_endpoint != node.dns_endpoint
                )
                if endpoint_changed:
                    # Retain old writer rather than closing it: a
                    # slow-path future may still be calling into it.
                    self._retired_writers.append(existing.writer)
                    # Build a FRESH _NodeState rather than mutating
                    # `existing` in place. In-flight futures captured
                    # `existing` at submit-time and still reference it
                    # for health updates; if we overwrote
                    # `existing.writer` they would either (a) route a
                    # write scheduled for the old endpoint to the new
                    # endpoint on late execution, or (b) record the
                    # old call's late success/failure against the new
                    # endpoint's health counters. Snapshotting into a
                    # new object isolates old-future effects to the
                    # retained _NodeState (which is now orphaned from
                    # self._nodes but still alive while those futures
                    # hold a reference). Health counters are copied
                    # forward so the new endpoint inherits a sensible
                    # starting position.
                    new_states[node.node_id] = _NodeState(
                        node_id=existing.node_id,
                        http_endpoint=node.http_endpoint,
                        dns_endpoint=node.dns_endpoint,
                        writer=self._factory(node),
                        consecutive_failures=existing.consecutive_failures,
                        last_failure_ts=existing.last_failure_ts,
                        last_success_ts=existing.last_success_ts,
                        last_error=existing.last_error,
                    )
                else:
                    # Endpoints unchanged; keep the writer warm (HTTP
                    # keepalive pool, auth token, etc.).
                    new_states[node.node_id] = existing

            # Nodes that disappeared: retain their writers; close
            # them at FanoutWriter.close() time. Rationale: _fanout
            # returns on quorum and lets slow-path futures keep
            # running. A quorum-return that left a call dispatched to
            # the about-to-be-removed node would race a
            # close()-in-refresh, crashing the background call or
            # corrupting writer state. Retention list growth is
            # bounded by cluster size * refresh frequency; manifest
            # refreshes are infrequent in practice.
            removed_ids = set(old_states.keys()) - set(new_states.keys())
            for rid in removed_ids:
                self._retired_writers.append(old_states[rid].writer)

            # Executor resize: grow the pool if the new manifest has
            # more nodes than the current pool can run in parallel.
            # We never shrink — shrinking would force us to wait for
            # in-flight work (or orphan it) and the memory cost of a
            # slightly-too-large pool is trivial. Approach chosen:
            # retention list ("retired executors"), drained on close.
            # Alternative considered: shutdown(wait=False) and drop
            # the reference. Rejected because, although the Python
            # threads keep running without an owning reference, we'd
            # lose the ability to deterministically shut them down on
            # close() — leaving daemon threads hanging past the
            # client's lifetime. Retention is simpler and bounded in
            # the same way as retired writers above.
            new_n = len(new_states)
            # Honor the caller's max_workers cap if they pinned one.
            # Otherwise fall back to the default heuristic. Growing
            # beyond a user-supplied cap would silently defeat a rate
            # limit / fd budget set at construction time.
            if self._user_max_workers is not None:
                target_workers = max(1, min(new_n or 1, self._user_max_workers))
            else:
                target_workers = max(1, min(new_n, 16))
            if target_workers > self._executor._max_workers:  # type: ignore[attr-defined]
                # Spin up the new executor BEFORE moving the old one
                # aside, so no window exists where self._executor is
                # unusable.
                new_executor = ThreadPoolExecutor(
                    max_workers=target_workers,
                    thread_name_prefix="fanout-writer",
                )
                self._retired_executors.append(self._executor)
                self._executor = new_executor

            # Snapshot the manifest so a caller that reuses and
            # mutates the dataclass after install (e.g. bumping seq
            # on the next refresh) can't corrupt the installed state
            # we compare future refreshes against.
            self._manifest = copy.deepcopy(manifest)
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
        # Snapshot state AND submit under the lock. Holding through
        # submit prevents a race where close() sees _closed=False, we
        # drop the lock, then close() shuts down the executor before
        # our executor.submit() — which would raise RuntimeError into
        # the caller instead of returning a clean False. Submit is
        # non-blocking so the lock-hold window is bounded by N
        # executor queue operations, not by writer latency.
        with self._lock:
            if self._closed:
                raise RuntimeError("FanoutWriter is closed")
            states = list(self._nodes.values())
            quorum = _ceil_half(len(states))
            if not states:
                # Vacuous success: nothing to fan out to.
                return True
            try:
                futures: List[Future] = [
                    self._executor.submit(self._run_on_node, s, op) for s in states
                ]
            except RuntimeError:
                # Executor was shut down between our _closed check and
                # submit (can happen if close() doesn't take the lock
                # on the shutdown path; defense in depth). Surface as
                # a failed write rather than a traceback.
                return False

        deadline = time.monotonic() + self._timeout

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
                    # Quorum met early. Cancel any futures that haven't
                    # started yet so they release their queue slots;
                    # futures that are already running can't be
                    # cancelled (cancel() returns False) but any of
                    # them that we can free prevents gradual pool
                    # exhaustion from abandoned-write stragglers on
                    # backends without their own request timeouts.
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    return True
        except TimeoutError:
            # Deadline exceeded before quorum; cancel pending futures
            # so their queue slots don't accumulate across calls. Any
            # currently-running ones will finish in their own time and
            # update health through _run_on_node.
            for f in futures:
                if not f.done():
                    f.cancel()
            return False

        return successes >= quorum

    # ------------------------------------------------------------------ DNSRecordWriter

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        return self._fanout(lambda w: w.publish_txt_record(name, value, ttl))

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        return self._fanout(lambda w: w.delete_txt_record(name, value))
