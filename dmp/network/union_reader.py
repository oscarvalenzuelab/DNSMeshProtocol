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

Manifest refresh
----------------
`install_manifest` mirrors FanoutWriter's seq-monotonicity contract:
lower-or-equal seq is rejected; expired manifests are rejected. On
accept, per-node state is diff'd by `node_id`: common ids retain their
health counters; new ids get fresh state; removed ids are dropped.

Security boundary
-----------------
The caller is responsible for verifying the manifest signature
(`ClusterManifest.parse_and_verify`) before passing it to
`install_manifest`. UnionReader itself only enforces seq ordering and
expiry — it does NOT re-verify signatures. This keeps UnionReader
composable with offline test manifests and delegates trust anchoring
to a single, well-tested path.
"""

from __future__ import annotations

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
    """

    node_id: str
    http_endpoint: str
    reader: DNSRecordReader
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
        self._reader_factory = reader_factory
        self._timeout = timeout
        self._max_workers_override = max_workers
        self._lock = threading.Lock()
        self._manifest: ClusterManifest = manifest
        self._states: Dict[str, _NodeState] = {}
        self._executor: Optional[ThreadPoolExecutor] = None
        self._build_states_from_manifest(manifest)
        self._rebuild_executor()

    # ------------------------------------------------------------------
    # Manifest lifecycle
    # ------------------------------------------------------------------

    def install_manifest(self, manifest: ClusterManifest) -> bool:
        """Swap in a newer manifest. Returns True iff accepted.

        Rejected (returns False):
        - `manifest.seq <= current.seq` (stale or replayed)
        - `manifest.is_expired()` at wall-clock `now`
        """
        if manifest.seq <= self._manifest.seq:
            return False
        if manifest.is_expired():
            return False

        # Set-diff by node_id: retain health state for common ids,
        # rebuild for new, drop removed. Mirrors FanoutWriter.
        with self._lock:
            retained: Dict[str, _NodeState] = {}
            for node in manifest.nodes:
                existing = self._states.get(node.node_id)
                if (
                    existing is not None
                    and existing.http_endpoint == node.http_endpoint
                ):
                    # Same id, same endpoint — keep counters AND the
                    # existing reader. Swapping in a fresh reader would
                    # reset any internal caches the factory built up.
                    retained[node.node_id] = existing
                else:
                    retained[node.node_id] = _NodeState(
                        node_id=node.node_id,
                        http_endpoint=node.http_endpoint,
                        reader=self._reader_factory(node),
                    )
            # Removed ids are simply not carried forward.
            self._states = retained
            self._manifest = manifest
            self._rebuild_executor_locked()
        return True

    def _build_states_from_manifest(self, manifest: ClusterManifest) -> None:
        # Called from __init__ (no lock needed — not yet published).
        self._states = {
            node.node_id: _NodeState(
                node_id=node.node_id,
                http_endpoint=node.http_endpoint,
                reader=self._reader_factory(node),
            )
            for node in manifest.nodes
        }

    def _rebuild_executor(self) -> None:
        with self._lock:
            self._rebuild_executor_locked()

    def _rebuild_executor_locked(self) -> None:
        """Replace the thread pool so it's sized for the new manifest.

        Caller holds self._lock.
        """
        if self._executor is not None:
            self._executor.shutdown(wait=False)
        n = len(self._states)
        if n == 0:
            self._executor = None
            return
        if self._max_workers_override is not None:
            workers = max(1, self._max_workers_override)
        else:
            workers = min(n, 16)
        self._executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="union-reader"
        )

    # ------------------------------------------------------------------
    # DNSRecordReader contract
    # ------------------------------------------------------------------

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        # Snapshot under lock so a concurrent install_manifest doesn't
        # yank states out mid-dispatch. The futures we queue will run
        # against the readers we captured here, regardless of any later
        # refresh.
        with self._lock:
            executor = self._executor
            states = list(self._states.values())

        if not states or executor is None:
            return None

        # Dedup via dict-as-ordered-set (Python 3.7+ preserves insertion
        # order). `first-completed-first` positions each unique string
        # at the point its originating future finished — documented in
        # the module docstring.
        union: Dict[str, None] = {}
        any_success = False

        deadline = time.monotonic() + self._timeout

        future_to_state: Dict[Future, _NodeState] = {
            executor.submit(self._safe_query, state, name): state for state in states
        }

        try:
            remaining = max(0.0, deadline - time.monotonic())
            # `as_completed` with a total-timeout yields results as they
            # arrive up to the budget; anything still in flight when the
            # budget runs out raises `FuturesTimeoutError` out of the
            # iterator. We catch it and drop those futures as "timed
            # out," counting each as a failure.
            try:
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
                # Any future that didn't complete before the deadline
                # remains pending. Count each as a failure and attempt
                # to cancel (best-effort; running tasks keep running).
                for fut, state in future_to_state.items():
                    if not fut.done():
                        fut.cancel()
                        self._mark_failure(
                            state,
                            TimeoutError(f"query timed out after {self._timeout}s"),
                        )
        finally:
            # Executor is shared across queries; do NOT shut it down here.
            # We simply abandon any still-pending futures — their results
            # will be discarded when they eventually complete. The shared
            # executor is shut down in `close()` / __del__.
            pass

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
        """Shut down the worker pool. Safe to call multiple times."""
        with self._lock:
            if self._executor is not None:
                self._executor.shutdown(wait=False)
                self._executor = None

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup
        try:
            self.close()
        except Exception:
            pass

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
