"""Admission bounds without external services, including disconnect races."""

import asyncio
import threading

import pytest
from anyio.to_thread import run_sync
from starlette.responses import JSONResponse

from utils.company_limit import CompanyReadLimit


class Call:
    def __init__(self, app, path="/api/company/example"):
        self.messages = []
        self.incoming = asyncio.Queue()
        self.incoming.put_nowait({"type": "http.request", "body": b"", "more_body": False})
        scope = {"type": "http", "method": "GET", "path": path}

        async def send(message):
            self.messages.append(message)

        self.task = asyncio.create_task(app(scope, self.incoming.get, send))

    @property
    def status(self):
        return next(m["status"] for m in self.messages if m["type"] == "http.response.start")


async def until(predicate):
    async def wait():
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(wait(), 2)


def run(scenario):
    asyncio.run(asyncio.wait_for(scenario(), 5))


def test_bounds_queue_overflow_and_lightweight_routes():
    async def scenario():
        release = asyncio.Event()
        entered = []

        async def app(scope, receive, send):
            if scope["path"] != "/api/health":
                entered.append(scope["path"])
                await release.wait()
            await JSONResponse({"ok": True})(scope, receive, send)

        gate = CompanyReadLimit(app, max_inflight=2, max_queued=1)
        a = Call(gate)
        b = Call(gate, "/api/company/example/functions")
        await until(lambda: len(entered) == 2)
        queued = Call(gate, "/api/company/queued")
        await until(lambda: gate.admitted == 3)
        overflow = Call(gate)
        health = Call(gate, "/api/health")
        await asyncio.gather(overflow.task, health.task)
        assert overflow.status == 503
        headers = dict(overflow.messages[0]["headers"])
        assert headers[b"cache-control"] == b"private, no-store"
        assert headers[b"retry-after"] == b"2"
        assert health.status == 200
        assert len(entered) == 2
        release.set()
        await asyncio.gather(a.task, b.task, queued.task)
        assert queued.status == 200
        assert gate.admitted == 0

    run(scenario)


@pytest.mark.parametrize("end", ["timeout", "cancel", "disconnect", "release_cancel_race"])
def test_waiter_cleanup(end):
    async def scenario():
        release = asyncio.Event()
        entries = []

        async def app(scope, receive, send):
            entries.append(scope["path"])
            await release.wait()
            await JSONResponse({})(scope, receive, send)

        gate = CompanyReadLimit(app, max_inflight=1, max_queued=1, queue_timeout=0.02 if end == "timeout" else 2)
        active = Call(gate)
        await until(lambda: len(entries) == 1)
        waiting = Call(gate, "/api/company/waiting")
        await until(lambda: gate.admitted == 2)
        if end in {"cancel", "release_cancel_race"}:
            if end == "release_cancel_race":
                release.set()
            waiting.task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiting.task
        elif end == "disconnect":
            waiting.incoming.put_nowait({"type": "http.disconnect"})
            await waiting.task
            assert not waiting.messages
        else:
            await waiting.task
            assert waiting.status == 503
        assert "/api/company/waiting" not in entries
        release.set()
        await active.task
        await until(lambda: gate.admitted == 0)
        recovery = Call(gate)
        await recovery.task
        assert recovery.status == 200
        assert gate.admitted == 0

    run(scenario)


def test_active_cancellation_does_not_release_work_still_running():
    async def scenario():
        release = asyncio.Event()
        entered = asyncio.Event()

        async def app(scope, receive, send):
            entered.set()
            await release.wait()
            await JSONResponse({})(scope, receive, send)

        gate = CompanyReadLimit(app, max_inflight=1, max_queued=0)
        active = Call(gate)
        await entered.wait()
        active.task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await active.task
        assert gate.admitted == 1
        overflow = Call(gate)
        await overflow.task
        assert overflow.status == 503
        release.set()
        await until(lambda: gate.admitted == 0)
        recovery = Call(gate)
        await recovery.task
        assert recovery.status == 200

    run(scenario)


def test_exception_releases_slot():
    async def scenario():
        async def app(scope, receive, send):
            raise RuntimeError("builder failed")

        gate = CompanyReadLimit(app, max_inflight=1, max_queued=0)
        for _ in range(2):
            call = Call(gate)
            with pytest.raises(RuntimeError, match="builder failed"):
                await call.task
            assert gate.admitted == 0

    run(scenario)


def test_cancelled_caller_keeps_slot_until_sync_thread_finishes():
    async def scenario():
        started = threading.Event()
        release = threading.Event()

        def build():
            started.set()
            assert release.wait(3)

        async def app(scope, receive, send):
            await run_sync(build)
            await JSONResponse({})(scope, receive, send)

        gate = CompanyReadLimit(app, max_inflight=1, max_queued=0)
        active = Call(gate)
        try:
            await until(started.is_set)
            active.task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await active.task
            overflow = Call(gate)
            await overflow.task
            assert overflow.status == 503
        finally:
            release.set()
        await until(lambda: gate.admitted == 0)

    run(scenario)


def test_real_api_queues_get_without_content_length(monkeypatch):
    """Body completion must not masquerade as a disconnect in the full stack."""
    from contextlib import nullcontext

    from httpx import ASGITransport, AsyncClient

    import api
    from routers import company, deps

    started = threading.Event()
    release = threading.Event()

    def build(*_):
        started.set()
        assert release.wait(3)
        return {"company": "example", "contracts": []}

    monkeypatch.setenv("PSAT_COMPANY_MAX_INFLIGHT", "1")
    monkeypatch.setenv("PSAT_COMPANY_MAX_QUEUED", "1")
    monkeypatch.setattr(api.app, "middleware_stack", None)
    monkeypatch.setattr(deps, "SessionLocal", lambda: nullcontext(None))
    monkeypatch.setattr(company, "build_company_overview", build)

    async def scenario():
        async with AsyncClient(transport=ASGITransport(app=api.app), base_url="http://test") as client:
            first = asyncio.create_task(client.get("/api/company/example"))
            try:
                await until(started.is_set)
                gate = api.app.middleware_stack
                while not isinstance(gate, CompanyReadLimit):
                    gate = getattr(gate, "app")
                second = asyncio.create_task(client.get("/api/company/example"))
                await until(lambda: gate.admitted == 2)
                assert (await client.get("/api/version")).status_code == 200
                assert not second.done()
            finally:
                release.set()
            results = await asyncio.gather(first, second)
            assert [r.status_code for r in results] == [200, 200]
            assert results[0].json() == results[1].json()

    run(scenario)


def test_slot_covers_body_send_and_replays_queued_request_messages():
    async def scenario():
        release_body = asyncio.Event()
        body_started = asyncio.Event()
        received = []

        async def app(scope, receive, send):
            received.append(await receive())
            await send({"type": "http.response.start", "status": 200, "headers": []})
            body_started.set()
            await release_body.wait()
            await send({"type": "http.response.body", "body": b"complete", "more_body": False})

        gate = CompanyReadLimit(app, max_inflight=1, max_queued=1)
        first = Call(gate)
        await body_started.wait()
        second = Call(gate)
        await until(lambda: gate.admitted == 2)
        await asyncio.sleep(0)
        assert len(received) == 1
        release_body.set()
        await asyncio.gather(first.task, second.task)
        assert len(received) == 2
        assert received[0] == received[1]

    run(scenario)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_inflight": 0},
        {"max_queued": -1},
        {"queue_timeout": 0},
        {"queue_timeout": float("nan")},
        {"queue_timeout": float("inf")},
    ],
)
def test_invalid_limits_fail_closed(kwargs):
    with pytest.raises(ValueError):
        CompanyReadLimit(JSONResponse({}), **kwargs)
