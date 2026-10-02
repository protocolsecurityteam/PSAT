from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import api

    api._global_limiter.reset()
    # Exercises a route past its rate check without a live database.
    return TestClient(api.app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def _reset_limiters():
    import api
    from routers import predicate_capabilities as pc

    api._global_limiter.reset()
    pc._capabilities_limiter.reset()
    pc._probe_limiter.reset()
    yield
    api._global_limiter.reset()
    pc._capabilities_limiter.reset()
    pc._probe_limiter.reset()


def test_content_length_exactly_at_limit_passes(client, monkeypatch):
    import api

    monkeypatch.setattr(api, "_MAX_BODY_BYTES", 100)
    at_limit = client.post(
        "/api/analyze",
        content=b"a" * 100,
        headers={"Content-Length": "100", "Content-Type": "application/json"},
    )
    over_limit = client.post(
        "/api/analyze",
        content=b"a" * 101,
        headers={"Content-Length": "101", "Content-Type": "application/json"},
    )
    assert at_limit.status_code != 413
    assert over_limit.status_code == 413


def _drive_body_middleware(body_chunks: list[bytes], max_bytes: int):
    import asyncio

    import api

    app_called = {"hit": False}

    async def downstream(scope, receive, send):
        app_called["hit"] = True
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect" or not msg.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = api.BodySizeLimitMiddleware(downstream)
    scope = {"type": "http", "method": "POST", "path": "/x", "headers": []}
    queue = [
        {"type": "http.request", "body": c, "more_body": i < len(body_chunks) - 1} for i, c in enumerate(body_chunks)
    ]
    sent: list[dict] = []

    async def receive():
        return queue.pop(0)

    async def send(message):
        sent.append(message)

    async def _run():
        import unittest.mock

        with unittest.mock.patch.object(api, "_MAX_BODY_BYTES", max_bytes):
            await mw(scope, receive, send)

    asyncio.run(_run())
    return sent, app_called["hit"]


def test_chunked_within_limit_reaches_app():
    sent, app_called = _drive_body_middleware([b"x" * 30, b"x" * 30], max_bytes=100)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200
    assert app_called is True


def test_client_ip_ignores_untrusted_forwarding_headers():
    from types import SimpleNamespace
    from typing import cast

    from starlette.requests import Request

    from utils.ratelimit import client_ip

    def req(headers, host="1.1.1.1"):
        return cast(Request, SimpleNamespace(headers=headers, client=SimpleNamespace(host=host)))

    assert client_ip(req({"fly-client-ip": "8.8.8.8", "x-forwarded-for": "1.2.3.4"})) == "1.1.1.1"
    assert client_ip(req({"x-forwarded-for": "1.2.3.4, 5.6.7.8"})) == "1.1.1.1"
    assert client_ip(req({})) == "1.1.1.1"


@pytest.mark.parametrize(
    "url",
    [
        "/api/contract/0x0000000000000000000000000000000000000000/capabilities",
        "/api/company/does-not-exist/semantic_capabilities",
    ],
)
def test_capability_routes_are_rate_limited(client, url):
    from routers import predicate_capabilities as pc

    original = pc._capabilities_limiter.limit
    pc._capabilities_limiter.limit = 1
    pc._capabilities_limiter.reset()
    try:
        first = client.get(url)
        second = client.get(url)
    finally:
        pc._capabilities_limiter.limit = original
        pc._capabilities_limiter.reset()
    assert first.status_code != 429
    assert second.status_code == 429
    assert "Retry-After" in second.headers


def test_sliding_window_flood_cannot_evict_active_key():
    # A flood of fresh keys must not evict an active client's window and reset its budget.
    from utils.ratelimit import SlidingWindowRateLimiter

    lim = SlidingWindowRateLimiter(limit=2, window_s=100, max_keys=10, sweep_every=4)
    assert lim.hit("victim", now=1.0) is None
    assert lim.hit("victim", now=1.0) is None
    assert lim.hit("victim", now=1.0) is not None  # at limit
    rejected = 0
    for i in range(1000):
        if lim.hit(("spray", i), now=1.0) is not None:
            rejected += 1
    assert rejected > 0  # cap was reached and newcomers were turned away
    assert "victim" in lim._buckets  # incumbent never evicted
    assert lim.hit("victim", now=1.0) is not None


def test_sliding_window_full_sweep_is_amortized_not_per_hit():
    # The full sweep runs only on the interval, never per hit.
    from utils.ratelimit import SlidingWindowRateLimiter

    lim = SlidingWindowRateLimiter(limit=5, window_s=100, max_keys=1_000_000, sweep_every=100)
    hits = 1000
    for i in range(hits):
        lim.hit(("k", i), now=1.0)
    assert lim._full_sweeps <= hits // 100 + 2
    assert lim._full_sweeps < hits
