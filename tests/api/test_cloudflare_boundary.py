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


def assert_bounded_company_cache(response):
    value = response.headers["cache-control"]
    ttl = int(value.split("s-maxage=")[1].split(",")[0])
    assert 0 < ttl <= 60
    assert re.sub(r"s-maxage=\d+", "s-maxage=60", value) == PUBLIC_CACHE
    assert "x-psat-fresh-until" not in response.headers


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
    override = api.app.dependency_overrides.pop(deps.require_admin, None)
    api._global_limiter.reset()
    try:
        yield TestClient(api.app, raise_server_exceptions=False)
    finally:
        api._global_limiter.reset()
        if override is not None:
            api.app.dependency_overrides[deps.require_admin] = override


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


def test_company_payload_equality_and_cache_matrix(edge_client, signing_keys, monkeypatch):
    from contextlib import nullcontext

    from routers import company, deps

    monkeypatch.setattr(deps, "SessionLocal", lambda: nullcontext(None))
    monkeypatch.setattr(company, "build_company_overview", lambda *_: {"company": "Example", "contracts": []})
    path = "/api/company/Example"
    anonymous = edge_client.get(path, headers=ORIGIN)
    assert anonymous.status_code == 200
    assert_bounded_company_cache(anonymous)
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


def test_company_admission_is_after_authentication_and_includes_operator_alias(edge_client, signing_keys, monkeypatch):
    import api
    from utils.company_limit import CompanyReadLimit

    assert edge_client.get("/api/version", headers=ORIGIN).status_code == 200
    middleware = api.app.middleware_stack
    while not isinstance(middleware, CompanyReadLimit):
        middleware = getattr(middleware, "app")
    # Exercise the real middleware ordering with a saturated gate; the gate's
    # concurrent lifecycle is tested separately without a second TestClient loop.
    monkeypatch.setattr(middleware, "admitted", middleware.capacity)
    for path in ("/api/company/Example", "/api/company/Example/functions", "/operator/api/company/Example"):
        assert edge_client.get(path).status_code == 403
        headers = {**ORIGIN, "CF-Access-Jwt-Assertion": token(signing_keys)}
        response = edge_client.get(path, headers=headers)
        assert response.status_code == 503
        assert response.headers["cache-control"] == PRIVATE
        assert response.headers["retry-after"] == "2"
        assert response.headers["x-content-type-options"] == "nosniff"
    assert edge_client.get("/api/version", headers=ORIGIN).status_code == 200


def test_prepared_freshness_headers_cannot_reset_edge_ttl():
    from fastapi import FastAPI
    from starlette.responses import JSONResponse

    from utils.edge import CloudflareBoundary

    app = FastAPI()
    deadline = str(time.time() + 20)

    @app.get("/api/company/example")
    def prepared():
        return JSONResponse({"company": "example"}, headers={"X-PSAT-Fresh-Until": deadline})

    app.add_middleware(CloudflareBoundary, config=EdgeConfig("local"))
    client = TestClient(app)
    response = client.get("/api/company/example")
    assert "x-psat-fresh-until" not in response.headers
    ttl = int(response.headers["cache-control"].split("s-maxage=")[1].split(",")[0])
    assert 0 < ttl <= 20
    for value in ("nan", "inf", "bad", str(time.time() - 1)):
        deadline = value
        response = client.get("/api/company/example")
        assert "s-maxage=0," in response.headers["cache-control"]
    response = client.get("/api/company/example?x=1")
    assert response.headers["cache-control"] == PRIVATE
    assert "x-psat-fresh-until" not in response.headers


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
    assert_bounded_company_cache(anonymous)
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


def test_account_routes_skip_operator_access_but_cookies_never_unlock_operator_routes(edge_client, monkeypatch):
    from unittest.mock import MagicMock

    from routers import deps
    from tests.conftest import SessionFactory
    from utils.edge import account_route

    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(MagicMock()))
    for path in ("/api/me", "/api/me/webhooks", "/api/auth/config", "/api/auth/neon/get-session"):
        assert account_route(path)
        response = edge_client.get(path, headers=ORIGIN, follow_redirects=False)
        assert response.status_code != 403, (path, response.text)
        assert response.headers["cache-control"] == PRIVATE
    assert edge_client.get("/api/me", headers=ORIGIN).status_code == 401
    # Origin authentication still applies.
    assert edge_client.get("/api/me").status_code == 403
    for path in ("/api/mex", "/api/authx", "/api/jobs"):
        assert not account_route(path)
    session_cookie = {**ORIGIN, "Cookie": "psat_session=anything"}
    assert edge_client.get("/api/jobs", headers=session_cookie).status_code == 403
    assert edge_client.post("/api/analyze", headers=session_cookie, json={}).status_code == 403


def test_admin_account_must_be_the_operator_access_authenticated(edge_client, signing_keys, monkeypatch):
    import uuid
    from unittest.mock import MagicMock

    from db.models import User
    from routers import deps
    from tests.conftest import SessionFactory

    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.return_value = []
    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(session))
    monkeypatch.setenv("PSAT_ADMIN_EMAILS", "operator@example.com,boss@example.com")
    signed_in: dict[str, User] = {}
    monkeypatch.setattr(deps, "current_user", lambda request: signed_in.get("user"))
    headers = {**ORIGIN, "CF-Access-Jwt-Assertion": token(signing_keys)}

    signed_in["user"] = User(id=uuid.uuid4(), email="operator@example.com", email_verified=True, is_admin=True)
    assert edge_client.get("/api/jobs", headers=headers).status_code == 200
    # Another admin account riding on this operator's Access session is refused.
    signed_in["user"] = User(id=uuid.uuid4(), email="boss@example.com", email_verified=True, is_admin=True)
    assert edge_client.get("/api/jobs", headers=headers).status_code == 401
