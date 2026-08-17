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
    """Trusted per-IP identity for rate limiting.

    Invariant: a limiter must never be keyed on an attacker-controllable
    value. Fly sets ``Fly-Client-IP`` to the real client and *appends* the
    client to ``X-Forwarded-For`` — so the RIGHT-most XFF hop is the
    least-forgeable fallback; the LEFT-most hop is fully client-supplied and
    would hand every request a fresh bucket. When Cloudflare is later placed
    in front, the trusted header becomes ``CF-Connecting-IP`` — not handled
    here yet.
    """
    fly = request.headers.get("fly-client-ip")
    if fly and fly.strip():
        return fly.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        if hops:
            return hops[-1]
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
    """

    def __init__(self, limit: int, window_s: float) -> None:
        self.limit = limit
        self.window_s = window_s
        self._buckets: dict[Hashable, deque[float]] = {}
        # Sync route handlers run in the threadpool, so concurrent hits on
        # one key can race the read-modify-write below; the lock keeps the
        # count exact.
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        for key, bucket in list(self._buckets.items()):
            while bucket and bucket[0] + self.window_s < now:
                bucket.popleft()
            if not bucket:
                self._buckets.pop(key, None)

    def hit(self, key: Hashable, now: float | None = None) -> int | None:
        if self.limit <= 0:
            return None
        now = time.time() if now is None else now
        with self._lock:
            self._prune(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = deque()
                self._buckets[key] = bucket
            if len(bucket) >= self.limit:
                return max(0, int(bucket[0] + self.window_s - now)) + 1
            bucket.append(now)
            return None

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
