"""Security-hardening middleware + validation coverage (offline).

Covers findings 8, 9, 10, 12, 13: security headers, body-size cap, global
per-IP rate limit, per-route capability rate limit, trace-id sanitization,
and probe address regex.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def client():
    import api

    api._global_limiter.reset()
    # DB failures surface as 500 responses rather than re-raising, so a route
    # can be exercised past its rate check without a live database.
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


# --- FINDING 9: security headers -------------------------------------------


def test_security_headers_present_on_normal_response(client):
    resp = client.get("/api/version")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'self'" in csp
    assert "https://fonts.gstatic.com" in csp
    assert "https://fonts.googleapis.com" in csp
    assert "https://api.coingecko.com" in csp


# --- FINDING 10: body-size cap ---------------------------------------------


def test_oversized_content_length_rejected_with_413(client):
    import api

    oversized = str(api._MAX_BODY_BYTES + 1)
    resp = client.post(
        "/api/analyze",
        content=b"x",
        headers={"Content-Length": oversized, "Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    # Security headers stamp even the early rejection.
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_normal_body_not_rejected(client):
    resp = client.get("/api/version")
    assert resp.status_code == 200


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
    """Drive BodySizeLimitMiddleware at the ASGI layer with a chunked body that
    carries no Content-Length, returning the messages it sent downstream."""
    import asyncio

    import api

    app_called = {"hit": False}

    async def downstream(scope, receive, send):
        app_called["hit"] = True
        # Drain the (replayed) body then answer 200.
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


def test_chunked_oversized_body_rejected_without_content_length():
    # Two 60-byte chunks = 120 bytes, no Content-Length; cap 100 -> 413 before
    # the downstream app is ever invoked.
    sent, app_called = _drive_body_middleware([b"x" * 60, b"x" * 60], max_bytes=100)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413
    assert app_called is False
    header_names = {name.decode().lower() for name, _ in start["headers"]}
    assert "content-security-policy" in header_names
    assert "x-content-type-options" in header_names


def test_chunked_within_limit_reaches_app():
    sent, app_called = _drive_body_middleware([b"x" * 30, b"x" * 30], max_bytes=100)
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200
    assert app_called is True


# --- FINDING 10: global per-IP rate limit ----------------------------------


def test_global_rate_limit_triggers_429(client):
    import api

    original = api._global_limiter.limit
    api._global_limiter.limit = 3
    api._global_limiter.reset()
    try:
        codes = [client.get("/api/version").status_code for _ in range(4)]
    finally:
        api._global_limiter.limit = original
        api._global_limiter.reset()
    assert codes[:3] == [200, 200, 200]
    assert codes[3] == 429


def test_rotating_xff_does_not_escape_limit_when_fly_client_ip_constant(client):
    import api

    original = api._global_limiter.limit
    api._global_limiter.limit = 3
    api._global_limiter.reset()
    try:
        # Rotate the client-controlled X-Forwarded-For every request; Fly-Client-IP
        # (set by the proxy) stays constant, so all four land in one bucket.
        codes = [
            client.get(
                "/api/version",
                headers={"Fly-Client-IP": "9.9.9.9", "X-Forwarded-For": f"{i}.{i}.{i}.{i}"},
            ).status_code
            for i in range(1, 5)
        ]
    finally:
        api._global_limiter.limit = original
        api._global_limiter.reset()
    assert codes[3] == 429


def test_rotating_left_xff_hop_does_not_escape_limit(client):
    import api

    original = api._global_limiter.limit
    api._global_limiter.limit = 3
    api._global_limiter.reset()
    try:
        # No Fly-Client-IP: the trusted identity is the RIGHT-most XFF hop
        # (appended by our proxy). Rotating the left-most (spoofable) hop must
        # not mint fresh buckets.
        codes = [
            client.get(
                "/api/version",
                headers={"X-Forwarded-For": f"{i}.{i}.{i}.{i}, 5.5.5.5"},
            ).status_code
            for i in range(1, 5)
        ]
    finally:
        api._global_limiter.limit = original
        api._global_limiter.reset()
    assert codes[3] == 429


def test_client_ip_prefers_fly_then_rightmost_xff():
    from types import SimpleNamespace

    from utils.ratelimit import client_ip

    def req(headers, host="1.1.1.1"):
        return SimpleNamespace(headers=headers, client=SimpleNamespace(host=host))

    assert client_ip(req({"fly-client-ip": "8.8.8.8", "x-forwarded-for": "1.2.3.4"})) == "8.8.8.8"
    assert client_ip(req({"x-forwarded-for": "1.2.3.4, 5.6.7.8"})) == "5.6.7.8"
    assert client_ip(req({})) == "1.1.1.1"


# --- FINDING 8: capability-route rate limit --------------------------------


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
    # First passes the rate check (whatever the downstream status); the second
    # is throttled by the per-route limiter.
    assert first.status_code != 429
    assert second.status_code == 429
    assert "Retry-After" in second.headers


# --- FINDING 13: trace-id sanitization -------------------------------------


def test_valid_trace_id_reflected(client):
    resp = client.get("/api/version", headers={"X-PSAT-Trace-Id": "abc-123"})
    assert resp.headers["X-PSAT-Trace-Id"] == "abc-123"


@pytest.mark.parametrize(
    "bad",
    [
        "x" * 33,  # too long for String(32)
        "has space",
        "inject\r\nSet-Cookie: x=y",
        "semi;colon",
        "",
    ],
)
def test_bad_trace_id_not_reflected(client, bad):
    resp = client.get("/api/version", headers={"X-PSAT-Trace-Id": bad})
    reflected = resp.headers["X-PSAT-Trace-Id"]
    assert reflected != bad
    # A fresh 16-char hex id is minted instead.
    assert len(reflected) == 16
    assert all(c in "0123456789abcdef" for c in reflected)


# --- FINDING 12: probe address regex ---------------------------------------


def test_probe_membership_rejects_non_hex_address():
    from routers.predicate_capabilities import _ProbeMembershipRequest

    with pytest.raises(ValueError):
        _ProbeMembershipRequest(
            function_signature="grantRole(bytes32,address)",
            predicate_index=0,
            member="0x" + "z" * 40,
        )
    with pytest.raises(ValueError):
        # 0x + 41 chars: right prefix, wrong length.
        _ProbeMembershipRequest(
            function_signature="grantRole(bytes32,address)",
            predicate_index=0,
            member="0x" + "a" * 41,
        )
    ok = _ProbeMembershipRequest(
        function_signature="grantRole(bytes32,address)",
        predicate_index=0,
        member="0x" + "A" * 40,
    )
    assert ok.member == "0x" + "a" * 40


def test_probe_signature_rejects_non_hex_address():
    from routers.predicate_capabilities import _ProbeSignatureRequest

    with pytest.raises(ValueError):
        _ProbeSignatureRequest(
            function_signature="execute(bytes32,bytes)",
            predicate_index=0,
            recovered_signer="0xnot-a-valid-hex-address-000000000000000",
        )
    ok = _ProbeSignatureRequest(
        function_signature="execute(bytes32,bytes)",
        predicate_index=0,
        recovered_signer="0x" + "b" * 40,
    )
    assert ok.recovered_signer == "0x" + "b" * 40


# --- unit: limiter ---------------------------------------------------------


def test_sliding_window_limiter_basic():
    from utils.ratelimit import SlidingWindowRateLimiter

    lim = SlidingWindowRateLimiter(limit=2, window_s=100)
    assert lim.hit("k", now=0.0) is None
    assert lim.hit("k", now=1.0) is None
    retry = lim.hit("k", now=2.0)
    assert retry is not None and retry >= 1
    # Distinct key has its own budget.
    assert lim.hit("other", now=2.0) is None
    # Window slides: the first hit ages out.
    assert lim.hit("k", now=101.5) is None


def test_sliding_window_limiter_disabled_when_limit_zero():
    from utils.ratelimit import SlidingWindowRateLimiter

    lim = SlidingWindowRateLimiter(limit=0, window_s=100)
    for i in range(50):
        assert lim.hit("k", now=float(i)) is None
