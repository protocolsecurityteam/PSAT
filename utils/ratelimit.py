"""In-process sliding-window rate limiter. Per-process by design, so N workers allow N×limit in aggregate."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Hashable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


def client_ip(request: Request) -> str:
    """Only the boundary's verified visitor identity, else the socket peer.

    Keep uvicorn proxy-header rewriting disabled.
    """
    state = getattr(request, "state", None)
    trusted = getattr(state, "edge_visitor_ip", None)
    if trusted:
        return trusted
    client = getattr(request, "client", None)
    return client.host if client else "<unknown>"


class SlidingWindowRateLimiter:
    """Per-key sliding-window limiter.

    ``hit(key)`` returns ``None`` within budget, else seconds to wait (>=1). Over-limit hits aren't recorded, so
    hammering doesn't extend the window. ``limit <= 0`` disables it.

    Hits are O(1) in active keys: only the hit key is pruned, a full sweep runs every ``sweep_every`` hits, and
    ``max_keys`` caps memory against key-spraying.
    """

    def __init__(
        self,
        limit: int,
        window_s: float,
        *,
        max_keys: int = 100_000,
        sweep_every: int = 4096,
    ) -> None:
        self.limit = limit
        self.window_s = window_s
        self._max_keys = max_keys
        self._sweep_every = max(1, sweep_every)
        self._buckets: dict[Hashable, deque[float]] = {}
        # Sync handlers run in the threadpool.
        self._lock = threading.Lock()
        self._hits_since_sweep = 0
        # Must grow far slower than hits (amortized); a test spy.
        self._full_sweeps = 0

    def _sweep(self, now: float) -> None:
        self._full_sweeps += 1
        self._hits_since_sweep = 0
        for key in list(self._buckets.keys()):
            bucket = self._buckets[key]
            while bucket and bucket[0] + self.window_s < now:
                bucket.popleft()
            if not bucket:
                del self._buckets[key]

    def hit(self, key: Hashable, now: float | None = None) -> int | None:
        if self.limit <= 0:
            return None
        now = time.time() if now is None else now
        with self._lock:
            self._hits_since_sweep += 1
            if self._hits_since_sweep >= self._sweep_every:
                self._sweep(now)

            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._max_keys:
                    # At cap: never evict an in-window bucket for a new key, or a flood of fresh keys resets legitimate
                    # windows and bypasses the limit.
                    return max(1, int(self.window_s))
                bucket = deque()
                self._buckets[key] = bucket

            while bucket and bucket[0] + self.window_s < now:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return max(0, int(bucket[0] + self.window_s - now)) + 1
            bucket.append(now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
            self._hits_since_sweep = 0
            self._full_sweeps = 0
