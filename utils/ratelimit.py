"""In-process sliding-window rate limiter.

Single-web-machine deployment: state is per-process and memory-only by
design (no Redis / shared store). A multi-worker deployment therefore
permits up to workers×limit requests in aggregate — an accepted first cut,
not a defect.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Hashable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.requests import Request


def client_ip(request: Request) -> str:
    """Use only the boundary's verified visitor identity, otherwise the socket peer.

    Uvicorn proxy-header rewriting must remain disabled. Local/private previews
    intentionally ignore all forwarded headers; network access grants no identity.
    """
    state = getattr(request, "state", None)
    trusted = getattr(state, "edge_visitor_ip", None)
    if trusted:
        return trusted
    client = getattr(request, "client", None)
    return client.host if client else "<unknown>"


class SlidingWindowRateLimiter:
    """Per-key sliding-window limiter.

    ``hit(key)`` records one request and returns ``None`` when within
    budget, or the integer seconds to wait before retrying (>=1) when the
    key has already reached ``limit`` requests inside the trailing
    ``window_s`` seconds. An over-limit call is NOT recorded, so a client
    that keeps hammering does not push its own window forward indefinitely.

    ``limit <= 0`` disables the limiter (every request is allowed) — the
    env-override escape hatch used to turn a route's limit off.

    Cost invariant: this runs on every request, so a hit must be O(1) in the
    number of active keys. The hot path prunes only the hit key's own window;
    stale buckets are reclaimed by an amortized full sweep every
    ``sweep_every`` hits, and ``max_keys`` caps memory so one distributed (or
    IPv6-/64-spraying) source cannot inflate the bucket count and turn the
    limiter into a self-DoS amplifier.
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
        # Sync route handlers run in the threadpool, so concurrent hits on
        # one key can race the read-modify-write below; the lock keeps the
        # count exact.
        self._lock = threading.Lock()
        self._hits_since_sweep = 0
        # Full-sweep counter — observability and a test spy: it must grow far
        # slower than the hit count (amortized), never once per hit.
        self._full_sweeps = 0

    def _sweep(self, now: float) -> None:
        """Full O(active keys) reclaim. Amortized: called once per
        ``sweep_every`` hits, never on the per-hit hot path."""
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
                    # At cap. Expired/empty buckets are already reclaimed by
                    # the amortized sweep above; anything left is an in-window
                    # bucket. Invariant: an in-window bucket is NEVER evicted
                    # to admit a new key — a new key that cannot get a slot is
                    # limited, not let through. Evicting an active bucket would
                    # reset a legitimate client's window, so a flood of fresh
                    # keys could bypass the limit; rejecting cannot.
                    return max(1, int(self.window_s))
                bucket = deque()
                self._buckets[key] = bucket

            # Hot path: prune only THIS key's window — O(bucket), independent
            # of the number of active keys.
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
