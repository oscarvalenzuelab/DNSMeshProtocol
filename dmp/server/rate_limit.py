"""Per-source-IP token bucket rate limiter.

Cheap, in-process, sized-bounded. Not a substitute for a real reverse-proxy
rate limit (Caddy, nginx) but enough to stop casual abuse before the sqlite
store fills up.

Buckets evict the oldest entry when the map reaches `max_tracked`. That
bounds memory in the face of a distributed attacker cycling source IPs.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class RateLimit:
    """Tokens refill at `rate_per_second`, capped at `burst`."""

    rate_per_second: float
    burst: float

    @classmethod
    def disabled(cls) -> "RateLimit":
        return cls(rate_per_second=0.0, burst=0.0)

    @property
    def enabled(self) -> bool:
        return self.rate_per_second > 0 and self.burst > 0


class TokenBucketLimiter:
    """Thread-safe per-key token-bucket rate limiter."""

    def __init__(self, limit: RateLimit, max_tracked: int = 10_000) -> None:
        self._limit = limit
        self._max_tracked = max_tracked
        self._lock = threading.Lock()
        # Key → (tokens_remaining, last_refill_ts).
        # OrderedDict so we can LRU-evict when the map grows.
        self._buckets: "OrderedDict[str, Tuple[float, float]]" = OrderedDict()

    @property
    def enabled(self) -> bool:
        return self._limit.enabled

    def allow(self, key: str, cost: float = 1.0) -> bool:
        """Return True if a `cost`-token request is permitted for `key`."""
        if not self.enabled:
            return True
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self._limit.burst, now))
            # Refill up to burst.
            tokens = min(
                self._limit.burst,
                tokens + (now - last) * self._limit.rate_per_second,
            )
            if tokens < cost:
                self._buckets[key] = (tokens, now)
                self._buckets.move_to_end(key)
                self._evict_if_needed()
                return False
            self._buckets[key] = (tokens - cost, now)
            self._buckets.move_to_end(key)
            self._evict_if_needed()
            return True

    def _evict_if_needed(self) -> None:
        while len(self._buckets) > self._max_tracked:
            self._buckets.popitem(last=False)

    def size(self) -> int:
        with self._lock:
            return len(self._buckets)
