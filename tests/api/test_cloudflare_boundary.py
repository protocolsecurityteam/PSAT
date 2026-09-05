"""Local application contracts; no Cloudflare/Fly/prod requests."""

from __future__ import annotations

import io
import json
import re
import time
import urllib.error
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from utils.edge import CACHE_PATHS, PRIVATE, PUBLIC_CACHE, AccessVerifier, EdgeConfig, public_read

CONFIG = EdgeConfig(
    "cloudflare", "a" * 64, "https://test-team.cloudflareaccess.com", "b" * 64, frozenset({"operator@example.com"})
)
ORIGIN = {"X-PSAT-Origin-Secret": CONFIG.secret, "X-PSAT-Visitor-IP": "192.0.2.1"}


@pytest.fixture(scope="module")
def signing_keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]


def token(keys, index=0, **overrides):
    claims = {
        "iss": CONFIG.issuer,
        "aud": [CONFIG.audience],
        "iat": int(time.time()) - 10,
        "exp": int(time.time()) + 300,
        "type": "app",
        "sub": "user-id",
        "email": "operator@example.com",
    }
    claims.update(overrides)
    return jwt.encode(claims, keys[index], algorithm="RS256", headers={"kid": str(index)})


@pytest.fixture
def jwks_wire(monkeypatch, signing_keys):
    state = {"index": 0, "calls": 0, "error": False}

    def urlopen(request, **kwargs):
        assert request.full_url == CONFIG.issuer + "/cdn-cgi/access/certs"
        assert kwargs["timeout"] == 3
        state["calls"] += 1
        if state["error"]:
            raise urllib.error.URLError("mock timeout")
        key = RSAAlgorithm.to_jwk(signing_keys[state["index"]].public_key(), as_dict=True)
        key.update(kid=str(state["index"]), use="sig")
        return io.BytesIO(json.dumps({"keys": [key]}).encode())

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    return state


@pytest.fixture
def edge_client(monkeypatch, jwks_wire):
    import api
    from routers import deps

    monkeypatch.setattr(EdgeConfig, "from_env", classmethod(lambda cls, env=None: CONFIG))
    monkeypatch.setattr(api.app, "middleware_stack", None)
    monkeypatch.setattr(deps, "ADMIN_KEY", "test-admin-key")
    override = api.app.dependency_overrides.pop(deps.require_admin_key, None)
    api._global_limiter.reset()
    try:
        yield TestClient(api.app, raise_server_exceptions=False)
    finally:
        api._global_limiter.reset()
        if override is not None:
            api.app.dependency_overrides[deps.require_admin_key] = override


def test_valid_jwt_and_jwks_cache(signing_keys, jwks_wire):
    verifier = AccessVerifier(CONFIG)
    for _ in range(3):
        assert verifier.verify(token(signing_keys))["sub"] == "user-id"
    assert jwks_wire["calls"] == 1


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": 1},
        {"iss": "https://wrong.cloudflareaccess.com"},
        {"aud": ["wrong"]},
        {"iat": int(time.time()) + 3600},
        {"nbf": int(time.time()) + 3600},
        {"type": "org"},
        {"sub": ""},
        {"sub": None},
        {"email": "attacker@example.com"},
        {"email": None},
        {"exp": None},
        {"exp": str(int(time.time()) + 300)},
    ],
)
def test_invalid_claims(signing_keys, jwks_wire, claims):
    with pytest.raises(HTTPException) as exc:
        AccessVerifier(CONFIG).verify(token(signing_keys, **claims))
    assert exc.value.status_code == 403


def test_missing_claim_bad_signature_and_algorithm(signing_keys, jwks_wire):
    valid = token(signing_keys)
    claims = jwt.decode(valid, options={"verify_signature": False})
    del claims["exp"]
    missing = jwt.encode(claims, signing_keys[0], algorithm="RS256", headers={"kid": "0"})
    bad_sig = jwt.encode(claims, signing_keys[1], algorithm="RS256", headers={"kid": "0"})
    hs = jwt.encode(claims, "c" * 64, algorithm="HS256", headers={"kid": "0"})
    for value in (missing, bad_sig, hs, "", "garbage", "a" * 17000):
        with pytest.raises(HTTPException):
            AccessVerifier(CONFIG).verify(value)


def test_jwks_rotation_expiry_outage_and_cooldown(signing_keys, jwks_wire):
    verifier = AccessVerifier(CONFIG)
    verifier.verify(token(signing_keys))
    jwks_wire["index"] = 1
    # A just-published key may be denied for at most the refresh cooldown.
    with pytest.raises(HTTPException):
        verifier.verify(token(signing_keys, 1))
    verifier.jwks.next_fetch = 0
    verifier.verify(token(signing_keys, 1))
    assert jwks_wire["calls"] == 2
    with pytest.raises(HTTPException):
        verifier.verify(token(signing_keys))
    jwks_wire["error"] = True
    assert verifier.jwks.jwk_set_cache is not None
    verifier.jwks.jwk_set_cache.lifespan = 0
    verifier.jwks.next_fetch = 0
    for _ in range(3):
        with pytest.raises(HTTPException):
            verifier.verify(token(signing_keys, 1))
    assert jwks_wire["calls"] == 3


def test_fail_closed_config():
    for env in (
        {"FLY_APP_NAME": "psat"},
        {"FLY_APP_NAME": "psat", "PSAT_EDGE_MODE": "preview"},
        {"PSAT_EDGE_MODE": "typo"},
        {"PSAT_EDGE_MODE": "cloudflare"},
        {"FLY_APP_NAME": "psat-pr-test"},
    ):
        with pytest.raises(ValueError):
            EdgeConfig.from_env(env)
    assert EdgeConfig.from_env({}).mode == "local"
    assert EdgeConfig.from_env({"FLY_APP_NAME": "psat-pr-test", "PSAT_EDGE_MODE": "preview"}).mode == "preview"
    env = {
        "PSAT_EDGE_MODE": "cloudflare",
        "PSAT_ORIGIN_SECRET": CONFIG.secret,
        "PSAT_ACCESS_ISSUER": CONFIG.issuer,
        "PSAT_ACCESS_AUDIENCE": CONFIG.audience,
        "PSAT_ACCESS_EMAILS": "operator@example.com",
    }
    assert EdgeConfig.from_env(env) == CONFIG
    for name in ("PSAT_ORIGIN_SECRET", "PSAT_ACCESS_ISSUER", "PSAT_ACCESS_AUDIENCE", "PSAT_ACCESS_EMAILS"):
        with pytest.raises(ValueError):
            EdgeConfig.from_env({**env, name: "REPLACE_ME"})


@pytest.mark.parametrize("path", ["/", "/api/version", "/api/health", "/monitor", "/api/jobs", "/operator/api/jobs"])
def test_direct_origin_and_forged_headers_denied(edge_client, path):
    response = edge_client.get(
        path,
        headers={
            "Host": "snif.sh",
            "CF-Connecting-IP": "192.0.2.2",
            "Fly-Client-IP": "192.0.2.3",
            "X-Forwarded-For": "192.0.2.4",
            "CF-Access-Jwt-Assertion": "fake",
            "X-PSAT-Admin-Key": "test-admin-key",
        },
    )
    assert response.status_code == 403
    assert response.headers["cache-control"] == PRIVATE


def test_duplicate_origin_missing_ip_and_invalid_ip(edge_client):
    for headers in (
        [("X-PSAT-Origin-Secret", CONFIG.secret)] * 2,
        {"X-PSAT-Origin-Secret": CONFIG.secret},
        {**ORIGIN, "X-PSAT-Visitor-IP": "1.2.3.4, 5.6.7.8"},
        {**ORIGIN, "X-PSAT-Origin-Secret": "invalid"},
    ):
        assert edge_client.get("/api/version", headers=headers).status_code == 403


def test_every_registered_operator_route_denies_admin_key_alone(edge_client):
    import api

    for route in api.app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/"):
            continue
        path = re.sub(r"\{[^}]+\}", "1", route.path)
        for method in route.methods:
            if public_read(method, path):
                continue
            response = edge_client.request(method, path, headers={**ORIGIN, "X-PSAT-Admin-Key": "test-admin-key"})
            assert response.status_code == 403, (method, path, response.text)
            assert response.headers["cache-control"] == PRIVATE
    # Dynamic artifact routes must match their handler's consumer allowlist.
    for path in ("/api/analyses/1/artifact/stage_errors", "/api/new-private-route", "/openapi.json"):
        assert edge_client.get(path, headers=ORIGIN).status_code == 403


def test_access_and_admin_key_both_required(edge_client, signing_keys, monkeypatch):
    from unittest.mock import MagicMock

    from routers import deps
    from tests.conftest import SessionFactory

    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = []
    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(session))
    jwt_headers = {**ORIGIN, "CF-Access-Jwt-Assertion": token(signing_keys)}
    assert edge_client.get("/api/jobs", headers=jwt_headers).status_code == 401
    assert edge_client.get("/api/jobs", headers={**jwt_headers, "X-PSAT-Admin-Key": "bad"}).status_code == 401
    for path in ("/api/jobs", "/operator/api/jobs"):
        response = edge_client.get(path, headers={**jwt_headers, "X-PSAT-Admin-Key": "test-admin-key"})
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == PRIVATE
    response = edge_client.get(
        "/api/jobs",
        headers={**ORIGIN, "Cookie": f"CF_Authorization={token(signing_keys)}", "X-PSAT-Admin-Key": "test-admin-key"},
    )
    assert response.status_code == 200


def test_visitor_buckets_and_forwarding_spoofing(edge_client, monkeypatch):
    import api

    monkeypatch.setattr(api._global_limiter, "limit", 2)
    for visitor in ("192.0.2.1", "192.0.2.2"):
        codes = [
            edge_client.get(
                "/api/version",
                headers={
                    **ORIGIN,
                    "X-PSAT-Visitor-IP": visitor,
                    "CF-Connecting-IP": f"198.51.100.{i}",
                    "Fly-Client-IP": f"203.0.113.{i}",
                    "X-Forwarded-For": f"203.0.113.{i}",
                },
            ).status_code
            for i in range(3)
        ]
        assert codes == [200, 200, 429]
    assert edge_client.get("/api/version", headers={**ORIGIN, "X-PSAT-Visitor-IP": "2001:db8::1"}).status_code == 200
    assert (
        edge_client.get("/api/version", headers={**ORIGIN, "X-PSAT-Visitor-IP": "2001:0db8:0:0::1"}).status_code == 200
    )
    assert edge_client.get("/api/version", headers={**ORIGIN, "X-PSAT-Visitor-IP": "2001:db8::1"}).status_code == 429


@pytest.mark.parametrize("mode", ["local", "preview"])
def test_non_cloudflare_mode_preserves_admin_and_ignores_headers(monkeypatch, mode):
    import api
    from routers import deps

    monkeypatch.setattr(EdgeConfig, "from_env", classmethod(lambda cls, env=None: EdgeConfig(mode)))
    monkeypatch.setattr(api.app, "middleware_stack", None)
    api.app.dependency_overrides.pop(deps.require_admin_key, None)
    client = TestClient(api.app)
    assert client.get("/api/version", headers={"CF-Access-Jwt-Assertion": "fake"}).status_code == 200
    assert client.get("/api/jobs").status_code == 401


def test_company_payload_equality_and_cache_matrix(edge_client, signing_keys, monkeypatch):
    from contextlib import nullcontext

    from routers import company, deps

    monkeypatch.setattr(deps, "SessionLocal", lambda: nullcontext(None))
    monkeypatch.setattr(company, "build_company_overview", lambda *_: {"company": "Example", "contracts": []})
    path = "/api/company/Example"
    anonymous = edge_client.get(path, headers=ORIGIN)
    assert anonymous.status_code == 200
    assert anonymous.headers["cache-control"] == PUBLIC_CACHE
    for extra in (
        {"Cookie": "any=1"},
        {"Origin": "https://snif.sh"},
        {"CF-Access-Jwt-Assertion": token(signing_keys)},
        {"CF-Access-Jwt-Assertion": token(signing_keys), "X-PSAT-Admin-Key": "test-admin-key"},
    ):
        response = edge_client.get(path, headers={**ORIGIN, **extra})
        assert response.json() == anonymous.json()
        assert response.headers["cache-control"] == PRIVATE
    for suffix in ("?chain=base", "?x=1&x=2", "?x=2&x=1", "?unused="):
        response = edge_client.get(path + suffix, headers=ORIGIN)
        assert response.json() == anonymous.json()
        assert response.headers["cache-control"] == PRIVATE
    assert edge_client.get(path, headers={**ORIGIN, "X-PSAT-Admin-Key": "test-admin-key"}).status_code == 403


@pytest.mark.parametrize("status", [200, 302, 400, 401, 403, 404, 422, 429, 500, 503])
@pytest.mark.parametrize("set_cookie", [False, True])
def test_errors_and_set_cookie_never_cache(status, set_cookie, jwks_wire):
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse

    from utils.edge import CloudflareBoundary

    app = FastAPI()

    @app.get("/api/company/Example")
    def response():
        headers = {"Set-Cookie": "session=x"} if set_cookie else {}
        return JSONResponse({}, status_code=status, headers=headers)

    app.add_middleware(CloudflareBoundary, config=CONFIG)
    result = TestClient(app).get("/api/company/Example", headers=ORIGIN, follow_redirects=False)
    assert result.status_code == status
    assert result.headers["cache-control"] == (PUBLIC_CACHE if status == 200 and not set_cookie else PRIVATE)


def test_registered_route_inventory_is_reviewed():
    import api

    actual = sorted((method, r.path) for r in api.app.routes if isinstance(r, APIRoute) for method in r.methods)
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "cloudflare_routes.json"
    reviewed = json.loads(fixture.read_text())
    assert actual == sorted(tuple(route) for route in reviewed)
    for path in CACHE_PATHS:
        assert ("GET", path) in actual


def test_internal_health_requires_distinct_secret_and_never_grants_operator_access(monkeypatch):
    from dataclasses import replace

    from fastapi import FastAPI

    from utils.edge import CloudflareBoundary
    from utils.ratelimit import client_ip

    app = FastAPI()

    @app.get("/api/health")
    def health(request: Request):
        return {"ip": client_ip(request)}

    app.add_middleware(CloudflareBoundary, config=replace(CONFIG, health_secret="c" * 64))
    client = TestClient(app)
    good = {"X-PSAT-Health-Secret": "c" * 64}
    result = client.get("/api/health", headers={**good, "Fly-Client-IP": "forged"})
    assert result.json() == {"ip": "<authenticated-health-check>"}
    assert result.headers["cache-control"] == PRIVATE
    for path in ("/api/jobs", "/operator/api/health", "/api/version"):
        assert client.get(path, headers=good).status_code == 403
    for headers in ({}, {**good, "X-PSAT-Admin-Key": "test-admin-key"}, {"X-PSAT-Health-Secret": "wrong"}):
        assert client.get("/api/health", headers=headers).status_code == 403
    assert client.post("/api/health", headers=good).status_code == 403


@pytest.mark.parametrize("suffix", ["/addresses", "/functions"])
def test_other_cacheable_payloads_equal_across_callers(edge_client, signing_keys, monkeypatch, suffix):
    from contextlib import nullcontext

    from routers import company, deps

    monkeypatch.setattr(deps, "SessionLocal", lambda: nullcontext(None))
    monkeypatch.setattr(company, "resolve_company_jobs", lambda *_: (object(), []))
    monkeypatch.setattr(company, "all_addresses_for_protocol", lambda *_: [{"address": "0x1"}])
    monkeypatch.setattr(company, "build_functions_for_protocol", lambda *_: {"ethereum::0x1": []})
    anonymous = edge_client.get("/api/company/Example" + suffix, headers=ORIGIN)
    authenticated = edge_client.get(
        "/api/company/Example" + suffix,
        headers={**ORIGIN, "X-PSAT-Admin-Key": "test-admin-key", "CF-Access-Jwt-Assertion": token(signing_keys)},
    )
    assert anonymous.status_code == authenticated.status_code == 200
    assert anonymous.json() == authenticated.json()
    assert anonymous.headers["cache-control"] == PUBLIC_CACHE
    assert authenticated.headers["cache-control"] == PRIVATE


def test_invalid_access_still_consumes_global_budget(edge_client, monkeypatch, jwks_wire):
    import api

    monkeypatch.setattr(api._global_limiter, "limit", 2)
    codes = [
        edge_client.get("/api/jobs", headers={**ORIGIN, "CF-Access-Jwt-Assertion": "fake"}).status_code
        for _ in range(3)
    ]
    assert codes == [403, 403, 429]
    assert jwks_wire["calls"] == 0
    direct = edge_client.get("/api/version")
    assert direct.status_code == 403
    assert direct.headers["x-content-type-options"] == "nosniff"
