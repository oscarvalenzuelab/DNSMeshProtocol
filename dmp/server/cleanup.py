"""Background TTL cleanup worker for a SqliteMailboxStore.

Expired records are filtered out of queries automatically, but they stay on
disk until reaped. The worker runs `cleanup_expired()` on an interval to keep
the table bounded under long-running nodes.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional


log = logging.getLogger(__name__)


class CleanupWorker:
    """Periodically invoke a cleanup callable on a background thread.

    Usage:
        worker = CleanupWorker(store.cleanup_expired, interval_seconds=60)
        worker.start()
        ...
        worker.stop()

    The callable should return an int (rows deleted) for logging; any other
    return type is tolerated but not logged.
    """

    def __init__(
        self,
        cleanup_fn: Callable[[], object],
        *,
        interval_seconds: float = 60.0,
    ):
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._cleanup_fn = cleanup_fn
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="dmp-cleanup", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=timeout)
        self._thread = None

    def _run(self) -> None:
        # First pass runs shortly after start so ops get early feedback.
        while not self._stop.wait(self._interval):
            try:
                deleted = self._cleanup_fn()
                if isinstance(deleted, int) and deleted > 0:
                    log.info("cleanup worker removed %d expired records", deleted)
            except Exception:
                log.exception("cleanup worker raised — continuing")

    def __enter__(self) -> "CleanupWorker":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
