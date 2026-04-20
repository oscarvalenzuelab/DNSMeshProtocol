"""Tests for the TTL cleanup worker."""

import time
from threading import Event

import pytest

from dmp.server.cleanup import CleanupWorker


class TestCleanupWorker:
    def test_calls_callable_on_interval(self):
        calls = []
        fire = Event()

        def fn():
            calls.append(1)
            if len(calls) >= 2:
                fire.set()
            return 0

        worker = CleanupWorker(fn, interval_seconds=0.05)
        worker.start()
        try:
            assert fire.wait(timeout=2.0), "cleanup worker didn't fire twice"
        finally:
            worker.stop()
        assert len(calls) >= 2

    def test_stop_is_idempotent(self):
        worker = CleanupWorker(lambda: 0, interval_seconds=0.05)
        worker.start()
        worker.stop()
        worker.stop()  # must not raise

    def test_rejects_non_positive_interval(self):
        with pytest.raises(ValueError):
            CleanupWorker(lambda: 0, interval_seconds=0)

    def test_exception_from_callable_does_not_kill_thread(self):
        counter = {"n": 0}

        def fn():
            counter["n"] += 1
            if counter["n"] == 1:
                raise RuntimeError("boom")
            return 0

        worker = CleanupWorker(fn, interval_seconds=0.05)
        worker.start()
        try:
            # Give the worker time for at least two invocations so we can
            # observe recovery from the first one blowing up.
            time.sleep(0.25)
        finally:
            worker.stop()
        assert counter["n"] >= 2
