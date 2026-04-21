"""Union reader: fan a TXT query across every node in a ClusterManifest.

M2.3 complement to M2.2's fan-out writer. Writes want a majority
(quorum); reads want completeness. A message written to `r_w = ceil(N/2)`
replicas may not have reached the remaining nodes yet — late-arriving
clients must still be able to see it. So reads contact every node in
the manifest concurrently and return the *union* of their TXT answers,
dedup'd by exact string equality.

Semantics
---------
- `None` or `[]` from a node contributes nothing to the union.
- An exception (including timeout) contributes nothing.
- `None` return means "this name does not exist" — a valid, healthy
  response, not a failure. Only raised exceptions and timeouts count
  against per-node health.
- If every node errors, returns None; the record is "not seen." If
  every node returns None/empty, also returns None (no union to serve).
- Otherwise returns the dedup'd union as a list, preserving
  *first-completed-first* order: when two nodes produce overlapping
  strings, the string appears at the position of the future that
  completed first. Manifest order is NOT used for ordering — a
  deterministic test would need to serialize completion order, and
  the alternative (sort after the fact) would hide useful locality.
- Empty manifest (N=0) → None.

Concurrency
-----------
A single `ThreadPoolExecutor` is owned by the reader. Queries run via
`as_completed` with a remaining-budget countdown. Unlike FanoutWriter,
we do not short-circuit on "enough" nodes — we wait out the full
timeout so every node gets its chance. On timeout, we collect what
we have and return.

Note on pool saturation: the pool is sized ``min(N, 16)`` by default.
If many pathologically slow backends pin all workers, subsequent queries
will wait for slots as stragglers eventually finish. On timeout we
cancel *pending* futures (not yet started) so their queue slots are
freed — this prevents gradual pool exhaustion from abandoned stragglers
on backends without their own request timeouts. Futures that are
already running cannot be cancelled cooperatively; deploy per-reader
timeouts in the factory to bound individual call latency.

Manifest refresh
----------------
`install_manifest` mirrors FanoutWriter's seq-monotonicity contract:
lower-or-equal seq is rejected; expired manifests are rejected;
post-close refresh is rejected. On accept, per-node state is diff'd
by ``node_id``: common ids with identical endpoints retain their
reader and health counters; common ids whose ``http_endpoint`` *or*
``dns_endpoint`` changed are rebuilt (fresh reader via the factory;
health counters copied forward into a fresh ``_NodeState`` so the
old in-flight futures keep their original reader/state reference);
removed ids and rebuilt readers are parked in a retention list and
drained on :meth:`close`.

Retention: ``query_txt_record`` does not close readers that have
in-flight futures pointing at them, because a late result would race
``close()``. Retention list growth is bounded by cluster size ×
refresh frequency over the reader's lifetime — acceptable for
production refreshes on the order of minutes/hours.

Security boundary
-----------------
The caller is responsible for verifying the manifest signature
(`ClusterManifest.parse_and_verify`) before passing it to the
constructor or `install_manifest`. UnionReader itself only enforces
seq ordering and expiry — it does NOT re-verify signatures. This
keeps UnionReader composable with offline test manifests and delegates
trust anchoring to a single, well-tested path.
"""

from __future__ import annotations

import copy
import threading
import time
from concurrent.futures import (
    Future,
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeoutError,
    as_completed,
)
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from dmp.core.cluster import ClusterManifest, ClusterNode
from dmp.network.base import DNSRecordReader

ReaderFactory = Callable[[ClusterNode], DNSRecordReader]


@dataclass
class _NodeState:
    """Per-node health + the reader instance used to query it.

    Mirrors the fields FanoutWriter exposes; documented as a copy, not
    a shared import — the two modules evolve independently.

    ``http_endpoint`` and ``dns_endpoint`` are stored on the state so
    :meth:`install_manifest` can detect endpoint drift without reaching
    back into the (now-retired) manifest entry that built the state.
    """

    node_id: str
    http_endpoint: str
    reader: DNSRecordReader
    dns_endpoint: Optional[str] = None
    consecutive_failures: int = 0
    last_failure_ts: float = 0.0
    last_success_ts: float = 0.0
    last_error: Optional[str] = None


class UnionReader(DNSRecordReader):
    """Queries every node in a ClusterManifest concurrently, unions the
    TXT answers, and dedups by exact string value.

    See module docstring for full semantics.
    """

    def __init__(
        self,
        manifest: ClusterManifest,
        reader_factory: ReaderFactory,
        *,
        timeout: float = 5.0,
        max_workers: Optional[int] = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        # Match install_manifest's expiry check: an already-expired
        # manifest handed to the constructor would otherwise silently
        # query stale nodes until the next refresh.
        if manifest.is_expired():
            raise ValueError("cluster manifest is expired")
        self._reader_factory = reader_factory
        self._timeout = float(timeout)
        # Remember whether the caller pinned a worker cap. On manifest
        # growth we honor that cap rather than reverting to the default
        # heuristic — a deployment that capped concurrency for a
        # resolver-pool or fd budget must not have that cap quietly
        # erased by a refresh.
        self._user_max_workers = max_workers
        self._lock = threading.Lock()
        # Stored as a deepcopy so caller-side mutation of the passed
        # ClusterManifest can't corrupt our monotonicity check or
        # retained dns_endpoint/http_endpoint comparisons.
        self._manifest: ClusterManifest = copy.deepcopy(manifest)
        # Per-node state, keyed by node_id. Insertion order is the
        # manifest's node order, which makes snapshot() deterministic.
        self._states: Dict[str, _NodeState] = {}
        for node in manifest.nodes:
            self._states[node.node_id] = _NodeState(
                node_id=node.node_id,
                http_endpoint=node.http_endpoint,
                dns_endpoint=node.dns_endpoint,
                reader=self._reader_factory(node),
            )
        # Readers dropped by a manifest refresh (either because the
        # node_id disappeared or because its endpoint changed and the
        # reader was rebuilt) are moved here instead of being closed
        # eagerly. The query path can have still-running futures
        # operating on those readers after the query returned on
        # timeout; calling close() on them mid-flight risks crashing
        # the background call. We drain this list in :meth:`close`.
        self._retired_readers: List[DNSRecordReader] = []
        # Executor sized to accommodate the initial manifest; we keep
        # at least one worker so a manifest that grows from empty to N
        # nodes still has somewhere to schedule work without needing a
        # pool recreate. 16 matches the stdlib's default pool heuristic
        # and is plenty for typical clusters.
        if max_workers is None:
            workers = max(1, min(len(manifest.nodes), 16))
        else:
            if max_workers < 1:
                raise ValueError("max_workers must be >= 1")
            workers = max_workers
        self._executor = ThreadPoolExecutor(
            max_workers=workers,
            thread_name_prefix="union-reader",
        )
        # Executors superseded by an install_manifest call that grew
        # the worker pool. Their in-flight futures keep running in
        # their own threads (wait=False semantics); we hold onto them
        # so close() can shut them all down, and so the running
        # threads are not orphaned on GC of the superseded pool.
        self._retired_executors: List[ThreadPoolExecutor] = []
        self._closed = False

    # ------------------------------------------------------------------
    # Manifest lifecycle
    # ------------------------------------------------------------------

    def install_manifest(self, manifest: ClusterManifest) -> bool:
        """Swap in a newer manifest. Returns True iff accepted.

        Rejected (returns False):
        - `manifest.seq <= current.seq` (stale or replayed)
        - `manifest.is_expired()` at wall-clock `now`
        - UnionReader has been closed (a close() in flight must block
          further installs; otherwise we'd allocate readers / a new
          executor that close() already committed to not draining).

        On accept:
        - Common ``node_id``s with identical HTTP and DNS endpoints
          retain their reader and health counters.
        - Common ``node_id``s whose ``http_endpoint`` OR
          ``dns_endpoint`` changed have their reader rebuilt via
          ``reader_factory``. Health counters are carried forward into
          a FRESH ``_NodeState`` (not an in-place mutation) so
          in-flight futures submitted against the old state keep
          seeing their original reader, and any late success/failure
          they record lands on the retired state — not on the new
          endpoint's counters.
        - New ``node_id``s get a fresh ``_NodeState`` + new reader.
        - Removed ``node_id``s and the superseded readers from
          endpoint-change rebuilds are parked in ``_retired_readers``
          and drained on :meth:`close`.
        - Executor is grown if the new node count exceeds current
          pool capacity; the caller's ``max_workers`` cap, if any, is
          honored. Old executor is retired (shutdown deferred to
          :meth:`close`).
        - Manifest itself is deepcopied on install so a caller that
          mutates the dataclass post-install can't corrupt our
          retained comparison state.
        """
        if manifest.is_expired():
            return False
        with self._lock:
            if self._closed:
                return False
            if manifest.seq <= self._manifest.seq:
                return False

            old_states = self._states
            new_states: Dict[str, _NodeState] = {}
            for node in manifest.nodes:
                existing = old_states.get(node.node_id)
                if existing is None:
                    # New node_id → fresh state + new reader.
                    new_states[node.node_id] = _NodeState(
                        node_id=node.node_id,
                        http_endpoint=node.http_endpoint,
                        dns_endpoint=node.dns_endpoint,
                        reader=self._reader_factory(node),
                    )
                    continue

                # Retained node_id. Compare endpoints; if either HTTP
                # or DNS endpoint changed the old reader is pointing
                # at a stale address and must be rebuilt. Node-level
                # health counters survive the swap.
                endpoint_changed = (
                    existing.http_endpoint != node.http_endpoint
                    or existing.dns_endpoint != node.dns_endpoint
                )
                if endpoint_changed:
                    # Retain old reader rather than closing it: a
                    # slow-path future may still be calling into it.
                    self._retired_readers.append(existing.reader)
                    # Build a FRESH _NodeState rather than mutating
                    # `existing` in place. In-flight futures captured
                    # `existing` at submit-time and still reference it
                    # for health updates; if we overwrote
                    # `existing.reader` they would either (a) route a
                    # query scheduled for the old endpoint to the new
                    # endpoint on late execution, or (b) record the
                    # old call's late success/failure against the new
                    # endpoint's health counters. Snapshotting into a
                    # new object isolates old-future effects to the
                    # retired _NodeState (orphaned from self._states
                    # but still alive while those futures hold a
                    # reference). Health counters copy forward so the
                    # new endpoint inherits a sensible starting
                    # position.
                    new_states[node.node_id] = _NodeState(
                        node_id=existing.node_id,
                        http_endpoint=node.http_endpoint,
                        dns_endpoint=node.dns_endpoint,
                        reader=self._reader_factory(node),
                        consecutive_failures=existing.consecutive_failures,
                        last_failure_ts=existing.last_failure_ts,
                        last_success_ts=existing.last_success_ts,
                        last_error=existing.last_error,
                    )
                else:
                    # Endpoints unchanged; keep the reader warm (any
                    # internal cache / keepalive survives).
                    new_states[node.node_id] = existing

            # Nodes that disappeared: retain their readers; close
            # them at UnionReader.close() time. Rationale: a query
            # may have returned on timeout while a slow future was
            # still dispatched against the about-to-be-removed node;
            # close()-in-refresh would race the background call.
            removed_ids = set(old_states.keys()) - set(new_states.keys())
            for rid in removed_ids:
                self._retired_readers.append(old_states[rid].reader)

            # Executor resize. Grow only — shrinking would force us
            # to wait for in-flight work (or orphan it) and the
            # memory cost of a slightly-too-large pool is trivial.
            # Honor the caller's max_workers cap if pinned; otherwise
            # fall back to min(N, 16). Growing beyond a user-supplied
            # cap would silently defeat a rate-limit / fd budget set
            # at construction time.
            new_n = len(new_states)
            if self._user_max_workers is not None:
                target_workers = max(1, min(new_n or 1, self._user_max_workers))
            else:
                target_workers = max(1, min(new_n, 16))
            if target_workers > self._executor._max_workers:  # type: ignore[attr-defined]
                # Spin up the new executor BEFORE retiring the old,
                # so no window exists where self._executor is unusable.
                new_executor = ThreadPoolExecutor(
                    max_workers=target_workers,
                    thread_name_prefix="union-reader",
                )
                self._retired_executors.append(self._executor)
                self._executor = new_executor

            # Snapshot the manifest so a caller that reuses and
            # mutates the dataclass after install (e.g. bumping seq
            # on the next refresh) can't corrupt the installed state
            # we compare future refreshes against.
            self._manifest = copy.deepcopy(manifest)
            self._states = new_states
        return True

    # ------------------------------------------------------------------
    # DNSRecordReader contract
    # ------------------------------------------------------------------

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        # Snapshot AND submit under the lock. Holding through submit
        # prevents a race where close() sees _closed=False, we drop
        # the lock, then close() shuts down the executor before our
        # executor.submit() — which would raise RuntimeError into the
        # caller instead of returning a clean None. Submit is
        # non-blocking so the lock-hold window is bounded by N
        # executor queue operations, not by reader latency.
        with self._lock:
            if self._closed:
                # A query on a closed reader is a programmer error,
                # but we return None rather than raising to keep the
                # DNSRecordReader contract clean (None means "not
                # seen"). Callers that want an error should check
                # the lifecycle themselves.
                return None
            executor = self._executor
            states = list(self._states.values())
            if not states:
                return None
            try:
                future_to_state: Dict[Future, _NodeState] = {
                    executor.submit(self._safe_query, s, name): s for s in states
                }
            except RuntimeError:
                # Executor was shut down between our _closed check and
                # submit (defense in depth: close() without the lock
                # on the shutdown path would still be handled cleanly).
                return None

        # Dedup via dict-as-ordered-set (Python 3.7+ preserves insertion
        # order). `first-completed-first` positions each unique string
        # at the point its originating future finished — documented in
        # the module docstring.
        union: Dict[str, None] = {}
        any_success = False

        deadline = time.monotonic() + self._timeout

        try:
            remaining = max(0.0, deadline - time.monotonic())
            # `as_completed` with a total-timeout yields results as they
            # arrive up to the budget; anything still in flight when the
            # budget runs out raises `FuturesTimeoutError` out of the
            # iterator. We catch it, cancel any pending (not-yet-started)
            # futures to free their queue slots, and count the pending
            # ones as failures.
            for fut in as_completed(future_to_state, timeout=remaining):
                state = future_to_state[fut]
                try:
                    result = fut.result()
                except Exception as exc:  # pragma: no cover - safety net
                    # _safe_query wraps exceptions; if something else
                    # slips through, still count it as a failure.
                    self._mark_failure(state, exc)
                    continue
                records, error = result
                if error is not None:
                    self._mark_failure(state, error)
                    continue
                # No error raised — successful call. Reset streak.
                self._mark_success(state)
                any_success = True
                if records:
                    for s in records:
                        if s not in union:
                            union[s] = None
                # records == None or [] contributes nothing to the
                # union, but still counts as a healthy response.
        except FuturesTimeoutError:
            # Deadline exceeded. Cancel pending futures so their queue
            # slots don't accumulate across calls (Future.cancel() only
            # works on PENDING futures — RUNNING ones keep going and
            # update health on completion). Count each still-pending
            # node as a failure.
            timeout_err = TimeoutError(f"query timed out after {self._timeout}s")
            for fut, state in future_to_state.items():
                if not fut.done():
                    fut.cancel()
                    self._mark_failure(state, timeout_err)

        if not any_success and not union:
            return None
        if not union:
            # At least one node succeeded but nothing returned records.
            # The name is "not seen anywhere" — same contract as
            # DNSRecordReader.query_txt_record: None.
            return None
        return list(union.keys())

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def manifest(self) -> ClusterManifest:
        """The currently active cluster manifest (read-only reference)."""
        with self._lock:
            return self._manifest

    def snapshot(self) -> List[dict]:
        """Return a copy of per-node health for debugging / CLI display.

        Order matches manifest order (stable across calls that don't
        mutate the manifest).
        """
        with self._lock:
            out: List[dict] = []
            for node in self._manifest.nodes:
                state = self._states.get(node.node_id)
                if state is None:
                    continue
                out.append(
                    {
                        "node_id": state.node_id,
                        "http_endpoint": state.http_endpoint,
                        "consecutive_failures": state.consecutive_failures,
                        "last_failure_ts": state.last_failure_ts,
                        "last_success_ts": state.last_success_ts,
                        "last_error": state.last_error,
                    }
                )
            return out

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Shut down the executor and drain retained resources. Idempotent.

        Waits for every in-flight query future (current + retired
        executors) to complete before closing retained readers. This
        preserves the mid-flight-safety invariant: a background query
        that survived a manifest refresh must finish its call on the
        retired reader before that reader's ``close()`` runs. Without
        the wait, ``close()`` would reintroduce the exact race the
        retention list was designed to prevent.

        Current/live per-node readers are **not** closed here — the
        UnionReader does not own their lifecycle; the caller (client)
        that supplied ``reader_factory`` decides when those shut down.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            executor = self._executor
            retired_readers = self._retired_readers
            self._retired_readers = []
            retired_executors = self._retired_executors
            self._retired_executors = []
        # shutdown(wait=True) waits for in-flight futures to finish, so
        # any background query still operating on a retired reader
        # completes before we close that reader below.
        executor.shutdown(wait=True)
        for old in retired_executors:
            try:
                old.shutdown(wait=True)
            except Exception:
                pass
        # All futures have drained; it is now safe to close retained
        # readers. A buggy close() on one must not block the others.
        for reader in retired_readers:
            closer = getattr(reader, "close", None)
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

    def __enter__(self) -> "UnionReader":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_query(
        state: _NodeState, name: str
    ) -> "tuple[Optional[List[str]], Optional[BaseException]]":
        """Invoke state.reader.query_txt_record(name), never raising.

        Returns `(records, None)` on success (records may be None or a
        list) or `(None, exc)` on failure. Keeping the executor's future
        result exception-free simplifies the as_completed loop above.
        """
        try:
            records = state.reader.query_txt_record(name)
            return records, None
        except BaseException as exc:  # noqa: BLE001 - deliberate
            return None, exc

    def _mark_success(self, state: _NodeState) -> None:
        with self._lock:
            state.consecutive_failures = 0
            state.last_success_ts = time.time()
            state.last_error = None

    def _mark_failure(self, state: _NodeState, error: BaseException) -> None:
        with self._lock:
            state.consecutive_failures += 1
            state.last_failure_ts = time.time()
            # Keep a short repr — full stack traces belong in logs, not
            # health snapshots.
            state.last_error = f"{type(error).__name__}: {error}"
