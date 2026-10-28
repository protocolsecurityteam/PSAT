"""Bound company-response memory through construction, serialization and gzip.

Install inside the authentication boundary and outside response compression.
Queued requests have not entered a route and cannot hold database sessions.
"""

from __future__ import annotations

import asyncio
import math
import os
import re
from collections import deque

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_PATH = re.compile(r"/api/company/[^/]+(?:/functions)?/?$")
# Exports render PDF/DOCX in memory; a separate, smaller pool keeps a download loop from holding page-read slots.
EXPORT_PATH = re.compile(r"/api/company/[^/]+/export/?$")


class _PathLimit:
    """Bounded in-flight plus queued GETs for paths matching ``path``; settings read ``<env_prefix>_*``."""

    def __init__(
        self,
        app: ASGIApp,
        max_inflight: int | None = None,
        max_queued: int | None = None,
        queue_timeout: float | None = None,
        *,
        path: re.Pattern[str],
        env_prefix: str,
        defaults: tuple[int, int, float],
    ):
        self.app = app
        self.path = path
        default_active, default_queued, default_timeout = defaults
        env = os.environ
        active = int(env.get(f"{env_prefix}_MAX_INFLIGHT", default_active)) if max_inflight is None else max_inflight
        queued = int(env.get(f"{env_prefix}_MAX_QUEUED", default_queued)) if max_queued is None else max_queued
        timeout = (
            float(env.get(f"{env_prefix}_QUEUE_TIMEOUT", default_timeout)) if queue_timeout is None else queue_timeout
        )
        if active < 1 or queued < 0 or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Company limits require inflight >= 1, queued >= 0 and a finite positive timeout")
        self.slots = asyncio.Semaphore(active)
        self.capacity = active + queued
        self.queue_timeout = timeout
        self.admitted = 0
        self.running: set[asyncio.Task] = set()

    async def _acquire(self, receive: Receive, buffered: deque[Message]) -> bool:
        if not self.slots.locked():
            await self.slots.acquire()
            return True

        async def disconnected():
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                buffered.append(message)

        acquire = asyncio.create_task(self.slots.acquire())
        disconnect = asyncio.create_task(disconnected())
        owned = False
        try:
            done, _ = await asyncio.wait(
                (acquire, disconnect), timeout=self.queue_timeout, return_when=asyncio.FIRST_COMPLETED
            )
            if disconnect in done:
                disconnect.result()
                return False
            if acquire in done:
                acquire.result()
                owned = True
                return True
            raise TimeoutError
        finally:
            for task in (acquire, disconnect):
                if not task.done():
                    task.cancel()
            try:
                await asyncio.gather(acquire, disconnect, return_exceptions=True)
            except BaseException:
                # Cancellation during cleanup means ownership never reaches
                # the caller, even if acquisition had already succeeded.
                owned = False
                raise
            finally:
                if not owned and acquire.done() and not acquire.cancelled() and acquire.exception() is None:
                    self.slots.release()

    def _finished(self, task: asyncio.Task) -> None:
        self.running.discard(task)
        self.slots.release()
        self.admitted -= 1
        if not task.cancelled():
            # Retrieve even when the caller left; connected callers still get it via shield().
            task.exception()

    async def _busy(self, scope: Scope, receive: Receive, send: Send) -> None:
        await JSONResponse(
            {"detail": "Company data is busy. Please try again shortly."},
            status_code=503,
            headers={"Cache-Control": "private, no-store", "Retry-After": "2"},
        )(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "GET" or not self.path.fullmatch(scope["path"]):
            await self.app(scope, receive, send)
            return
        if self.admitted >= self.capacity:
            await self._busy(scope, receive, send)
            return

        self.admitted += 1
        buffered: deque[Message] = deque()
        acquired = False
        transferred = False
        try:
            try:
                acquired = await self._acquire(receive, buffered)
            except TimeoutError:
                await self._busy(scope, receive, send)
                return
            if not acquired:
                return

            async def replay_receive() -> Message:
                return buffered.popleft() if buffered else await receive()

            # A cancelled HTTP caller must not free a slot while a synchronous
            # handler is still running in the threadpool. The child owns its
            # slot until the whole ASGI response has finished, including gzip.
            async def serve() -> None:
                await self.app(scope, replay_receive, send)

            task = asyncio.create_task(serve())
            self.running.add(task)
            task.add_done_callback(self._finished)
            transferred = True
            await asyncio.shield(task)
        finally:
            if not transferred:
                self.admitted -= 1
                if acquired:
                    self.slots.release()


class CompanyReadLimit(_PathLimit):
    def __init__(
        self,
        app: ASGIApp,
        max_inflight: int | None = None,
        max_queued: int | None = None,
        queue_timeout: float | None = None,
    ):
        limits = (max_inflight, max_queued, queue_timeout)
        super().__init__(app, *limits, path=_PATH, env_prefix="PSAT_COMPANY", defaults=(2, 8, 30.0))


class CompanyExportLimit(_PathLimit):
    """One export at a time by default (``PSAT_EXPORT_MAX_INFLIGHT``), with a short queue."""

    def __init__(
        self,
        app: ASGIApp,
        max_inflight: int | None = None,
        max_queued: int | None = None,
        queue_timeout: float | None = None,
    ):
        limits = (max_inflight, max_queued, queue_timeout)
        super().__init__(app, *limits, path=EXPORT_PATH, env_prefix="PSAT_EXPORT", defaults=(1, 2, 30.0))
