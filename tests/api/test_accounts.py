from __future__ import annotations

import functools
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
import pytest

from tests.conftest import requires_postgres

HOOK = "https://discord.com/api/webhooks/123456789012345678/SECRETtoken"
SAME_ORIGIN = {"Origin": "http://testserver"}
NEON = "https://ep-test.neonauth.example/neondb/auth"


@pytest.fixture(autouse=True)
def _auth_env(monkeypatch):
    monkeypatch.setenv("NEON_AUTH_BASE_URL", NEON)
    monkeypatch.setenv("PSAT_ADMIN_EMAILS", "boss@example.com")
    for name in ("PSAT_PUBLIC_BASE_URL", "PSAT_SITE_ORIGIN", "FLY_APP_NAME", "PSAT_AUTH_DEV_LOGIN"):
        monkeypatch.delenv(name, raising=False)


class FakeNeon:
    """Stands in for Neon Auth: records each upstream request and answers from ``routes``."""

    def __init__(self, monkeypatch):
        self.requests: list[httpx.Request] = []
        self.routes: dict[str, httpx.Response] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return self.routes.get(f"{request.method} {request.url.path}", httpx.Response(404, json={}))

        monkeypatch.setattr(
            "services.auth.neon.httpx.Client", functools.partial(httpx.Client, transport=httpx.MockTransport(handler))
        )

    def session(self, user: dict | None, set_cookie: str | None = None):
        headers = [("set-cookie", set_cookie)] if set_cookie else []
        body = {"session": {"id": "s"}, "user": user} if user else None
        self.routes["GET /neondb/auth/get-session"] = httpx.Response(200, json=body, headers=headers)


@pytest.fixture()
def fake_neon(monkeypatch):
    return FakeNeon(monkeypatch)


def neon_user(email="boss@example.com", verified: object = True, uid="neon-1", **extra):
    return {"id": uid, "email": email, "emailVerified": verified, "name": "Boss", "image": None, **extra}


# --- Cookie handling (no DB) -----------------------------------------------------------------------------------------


def test_only_neon_cookies_are_forwarded_upstream():
    from services.auth.neon import neon_cookies

    header = "psat_session=ours; __Secure-neon-auth.session_token=t1; CF_Authorization=x; __Secure-neon-auth.x=2"
    assert neon_cookies(header) == "__Secure-neon-auth.session_token=t1; __Secure-neon-auth.x=2"
    assert neon_cookies(None) == ""


def test_upstream_cookies_become_first_party_and_others_are_dropped():
    from services.auth.neon import first_party_cookie

    rewritten = first_party_cookie(
        "__Secure-neon-auth.session_token=abc; Domain=neonauth.example; Path=/; HttpOnly; SameSite=None; "
        "Secure; Partitioned; Max-Age=600"
    )
    assert rewritten == "__Secure-neon-auth.session_token=abc; Path=/; HttpOnly; Max-Age=600; Secure; SameSite=Lax"
    assert first_party_cookie("psat_session=evil; Path=/") is None


# --- Proxy ------------------------------------------------------------------------------------------------------------


@pytest.fixture()
def client(db_session):
    @contextmanager
    def fake_session_local():
        yield db_session

    with patch("routers.deps.SessionLocal", fake_session_local):
        from fastapi.testclient import TestClient

        import api

        yield TestClient(api.app)


def test_proxy_forwards_to_neon_with_only_its_cookies(client, fake_neon):
    fake_neon.routes["POST /neondb/auth/sign-in/email"] = httpx.Response(
        200,
        json={"user": {"id": "neon-1"}},
        headers=[
            ("set-cookie", "__Secure-neon-auth.session_token=new; Domain=x; SameSite=None; Secure; HttpOnly"),
            ("set-cookie", "psat_session=hijack; Path=/"),
            ("set-auth-jwt", "jwt"),
            ("x-internal", "nope"),
        ],
    )
    client.cookies.set("psat_session", "ours")
    client.cookies.set("__Secure-neon-auth.session_challenge", "c")
    resp = client.post(
        "/api/auth/neon/sign-in/email?x=1", json={"email": "a@example.com", "password": "pw"}, headers=SAME_ORIGIN
    )
    assert resp.status_code == 200
    upstream = fake_neon.requests[-1]
    assert str(upstream.url) == f"{NEON}/sign-in/email?x=1"
    assert upstream.headers["cookie"] == "__Secure-neon-auth.session_challenge=c"
    assert upstream.headers["origin"] == "http://testserver"
    assert resp.headers.get_list("set-cookie") == [
        "__Secure-neon-auth.session_token=new; HttpOnly; Secure; SameSite=Lax"
    ]
    assert resp.headers["set-auth-jwt"] == "jwt"
    assert "x-internal" not in resp.headers
    # Served from our origin, so the site's no-inline-script CSP must cover whatever Neon returns.
    assert "script-src 'self'" in resp.headers["content-security-policy"]
    assert resp.headers["x-content-type-options"] == "nosniff"


@pytest.mark.parametrize(
    "path, headers, status",
    [
        ("sign-in/email", {}, 403),
        ("sign-in/email", {"Origin": "https://evil.example"}, 403),
        ("get-session%2F..%2F..%2Fadmin", SAME_ORIGIN, 404),
    ],
)
def test_proxy_refuses_cross_origin_posts_and_odd_paths(client, fake_neon, path, headers, status):
    assert client.post(f"/api/auth/neon/{path}", json={}, headers=headers).status_code == status
    assert fake_neon.requests == []


def test_auth_is_off_without_a_neon_url(client, fake_neon, monkeypatch):
    monkeypatch.delenv("NEON_AUTH_BASE_URL")
    assert client.get("/api/auth/config").json() == {"enabled": False, "providers": [], "dev_login": False}
    assert client.get("/api/auth/neon/get-session").status_code == 404
    assert client.post("/api/auth/session", headers=SAME_ORIGIN).status_code == 404


# --- Establishing our session -----------------------------------------------------------------------------------------


@requires_postgres
def test_verified_neon_session_opens_ours_and_grants_admin(client, fake_neon):
    fake_neon.session(neon_user(), set_cookie="__Secure-neon-auth.session_token=t; Path=/; Secure")
    client.cookies.set("__Secure-neon-auth.session_challenge", "c")
    resp = client.post("/api/auth/session", params={"neon_auth_session_verifier": "v&1"}, headers=SAME_ORIGIN)
    assert resp.status_code == 200
    assert fake_neon.requests[-1].url.params["neon_auth_session_verifier"] == "v&1"
    cookies = resp.headers.get_list("set-cookie")
    assert any(c.startswith("psat_session=") and "httponly" in c.lower() for c in cookies)
    assert any(c.startswith("__Secure-neon-auth.session_token=t") for c in cookies)

    me = client.get("/api/me").json()
    assert (me["email"], me["display_name"], me["is_admin"]) == ("boss@example.com", "Boss", True)


@requires_postgres
@pytest.mark.parametrize(
    "user, status",
    [(None, 401), (neon_user(verified=False), 403), (neon_user(verified="true"), 403)],
    ids=["no_neon_session", "unverified", "truthy_not_true"],
)
def test_no_session_without_a_verified_neon_user(client, fake_neon, user, status):
    fake_neon.session(user)
    resp = client.post("/api/auth/session", headers=SAME_ORIGIN)
    assert resp.status_code == status
    assert not any(c.startswith("psat_session=") for c in resp.headers.get_list("set-cookie"))
    assert client.get("/api/me").status_code == 401


@requires_postgres
def test_session_exchange_is_same_origin_only(client, fake_neon):
    fake_neon.session(neon_user())
    assert client.post("/api/auth/session", headers={"Origin": "https://evil.example"}).status_code == 403
    assert fake_neon.requests == []


@requires_postgres
def test_neon_outage_is_a_502_not_a_sign_in(client, fake_neon):
    fake_neon.routes["GET /neondb/auth/get-session"] = httpx.Response(503)
    assert client.post("/api/auth/session", headers=SAME_ORIGIN).status_code == 502


@requires_postgres
def test_recreated_neon_user_relinks_only_with_a_verified_email(client, fake_neon, db_session):
    from db.models import User

    fake_neon.session(neon_user("alice@example.com", uid="neon-old"))
    client.post("/api/auth/session", headers=SAME_ORIGIN)
    original = db_session.query(User).filter_by(email="alice@example.com").one().id

    fake_neon.session(neon_user("alice@example.com", uid="neon-new", verified=False))
    assert client.post("/api/auth/session", headers=SAME_ORIGIN).status_code == 403

    fake_neon.session(neon_user("alice@example.com", uid="neon-new"))
    assert client.post("/api/auth/session", headers=SAME_ORIGIN).status_code == 200
    db_session.expire_all()
    user = db_session.query(User).filter_by(email="alice@example.com").one()
    assert (user.id, user.neon_auth_id) == (original, "neon-new")


def _sign_in(db_session, client, email="user@example.com"):
    from services.auth.sessions import SESSION_COOKIE, create_session, upsert_neon_user

    user = upsert_neon_user(
        db_session, neon_auth_id=email, email=email, email_verified=True, display_name=None, avatar_url=None
    )
    token = create_session(db_session, user)
    db_session.commit()
    client.cookies.set(SESSION_COOKIE, token)
    return user


def _protocol(db_session, name="__acct_proto__"):
    from db.models import Protocol

    proto = Protocol(name=name)
    db_session.add(proto)
    db_session.commit()
    return proto


@requires_postgres
def test_logout_revokes_our_session_and_signs_out_of_neon(client, db_session, fake_neon):
    from services.auth.sessions import SESSION_COOKIE

    fake_neon.routes["POST /neondb/auth/sign-out"] = httpx.Response(
        200, json={}, headers=[("set-cookie", "__Secure-neon-auth.session_token=; Max-Age=0")]
    )
    _sign_in(db_session, client)
    client.cookies.set("__Secure-neon-auth.session_token", "t")
    token = client.cookies.get(SESSION_COOKIE)
    resp = client.post("/api/auth/logout", headers=SAME_ORIGIN)
    assert resp.status_code == 200
    assert fake_neon.requests[-1].url.path == "/neondb/auth/sign-out"
    assert any(c.startswith("__Secure-neon-auth.session_token=;") for c in resp.headers.get_list("set-cookie"))
    client.cookies.set(SESSION_COOKIE, token)  # replaying the old cookie
    assert client.get("/api/me").status_code == 401


@requires_postgres
def test_expired_session_is_rejected(client, db_session):
    from db.models import UserSession

    _sign_in(db_session, client)
    for row in db_session.query(UserSession).all():
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    assert client.get("/api/me").status_code == 401
    assert db_session.query(UserSession).count() == 0


@requires_postgres
def test_dev_login_is_off_by_default_and_never_on_fly(client, monkeypatch):
    assert client.post("/api/auth/dev-login", json={"email": "d@example.com"}, headers=SAME_ORIGIN).status_code == 404
    monkeypatch.setenv("PSAT_AUTH_DEV_LOGIN", "1")
    monkeypatch.setenv("FLY_APP_NAME", "psat-pr-1")
    assert client.post("/api/auth/dev-login", json={"email": "d@example.com"}, headers=SAME_ORIGIN).status_code == 404
    monkeypatch.delenv("FLY_APP_NAME")
    assert client.post("/api/auth/dev-login", json={"email": "d@example.com"}, headers=SAME_ORIGIN).status_code == 200
    assert client.get("/api/me").json()["email"] == "d@example.com"


# --- Admin gating ---------------------------------------------------------------------------------------------------


@pytest.fixture()
def real_admin_gate(monkeypatch):
    import api
    from routers import deps

    monkeypatch.delitem(api.app.dependency_overrides, deps.require_admin, raising=False)
    monkeypatch.setattr(deps, "ADMIN_KEY", "test-admin-key")


@requires_postgres
def test_admin_routes_accept_key_or_admin_account_only(client, db_session, real_admin_gate, monkeypatch):
    proto = _protocol(db_session)
    path = f"/api/protocols/{proto.id}/subscriptions"
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"X-PSAT-Admin-Key": "test-admin-key"}).status_code == 200

    _sign_in(db_session, client, "user@example.com")
    assert client.get(path).status_code == 401

    _sign_in(db_session, client, "boss@example.com")
    assert client.get(path).status_code == 200
    # A wrong key never falls back to the cookie.
    assert client.get(path, headers={"X-PSAT-Admin-Key": "stale"}).status_code == 401

    # Removing the email from the allowlist demotes the open session at once.
    monkeypatch.setenv("PSAT_ADMIN_EMAILS", "")
    assert client.get(path).status_code == 401


@requires_postgres
def test_cookie_writes_require_same_origin(client, db_session, real_admin_gate):
    proto = _protocol(db_session)
    _sign_in(db_session, client, "boss@example.com")
    body = {"discord_webhook_url": HOOK}
    for headers in ({}, {"Origin": "https://evil.example"}):
        assert client.post("/api/me/webhooks", json=body, headers=headers).status_code == 403
        assert client.post(f"/api/protocols/{proto.id}/subscribe", json=body, headers=headers).status_code == 403
    assert client.post("/api/me/webhooks", json=body, headers=SAME_ORIGIN).status_code == 201


# --- Saved webhooks and subscriptions -------------------------------------------------------------------------------


@requires_postgres
def test_webhook_crud_masks_url_and_rejects_non_discord(client, db_session):
    _sign_in(db_session, client)
    bad = client.post("/api/me/webhooks", json={"discord_webhook_url": "https://evil.com/x"}, headers=SAME_ORIGIN)
    assert bad.status_code == 422

    created = client.post("/api/me/webhooks", json={"discord_webhook_url": HOOK, "label": "ops"}, headers=SAME_ORIGIN)
    assert created.status_code == 201
    hook = created.json()
    assert "SECRETtoken" not in created.text
    assert client.get("/api/me/webhooks").json() == [hook]

    renamed = client.patch(f"/api/me/webhooks/{hook['id']}", json={"label": "alerts"}, headers=SAME_ORIGIN)
    assert renamed.json()["label"] == "alerts"
    assert client.delete(f"/api/me/webhooks/{hook['id']}", headers=SAME_ORIGIN).json() == {"status": "removed"}
    assert client.get("/api/me/webhooks").json() == []


@requires_postgres
def test_users_cannot_see_or_touch_each_others_rows(client, db_session):
    proto = _protocol(db_session)
    _sign_in(db_session, client, "alice@example.com")
    hook = client.post("/api/me/webhooks", json={"discord_webhook_url": HOOK}, headers=SAME_ORIGIN).json()
    sub = client.post(
        "/api/me/subscriptions", json={"protocol_id": proto.id, "webhook_id": hook["id"]}, headers=SAME_ORIGIN
    ).json()

    _sign_in(db_session, client, "mallory@example.com")
    assert client.get("/api/me/webhooks").json() == []
    assert client.get("/api/me/subscriptions").json() == []
    assert client.patch(f"/api/me/webhooks/{hook['id']}", json={"label": "x"}, headers=SAME_ORIGIN).status_code == 404
    assert client.delete(f"/api/me/webhooks/{hook['id']}", headers=SAME_ORIGIN).status_code == 404
    assert client.post(f"/api/me/webhooks/{hook['id']}/test", headers=SAME_ORIGIN).status_code == 404
    assert client.delete(f"/api/me/subscriptions/{sub['id']}", headers=SAME_ORIGIN).status_code == 404
    # Nor subscribe a protocol to someone else's webhook.
    stolen = client.post(
        "/api/me/subscriptions", json={"protocol_id": proto.id, "webhook_id": hook["id"]}, headers=SAME_ORIGIN
    )
    assert stolen.status_code == 404


@requires_postgres
def test_deleting_a_webhook_removes_its_subscriptions(client, db_session):
    from db.models import ProtocolSubscription

    proto = _protocol(db_session)
    _sign_in(db_session, client)
    hook = client.post("/api/me/webhooks", json={"discord_webhook_url": HOOK}, headers=SAME_ORIGIN).json()
    resp = client.post(
        "/api/me/subscriptions",
        json={"protocol_id": proto.id, "webhook_id": hook["id"], "event_filter": {"event_types": ["upgraded"]}},
        headers=SAME_ORIGIN,
    )
    assert resp.status_code == 201
    assert resp.json()["protocol_name"] == "__acct_proto__"
    client.delete(f"/api/me/webhooks/{hook['id']}", headers=SAME_ORIGIN)
    db_session.expire_all()
    assert db_session.query(ProtocolSubscription).filter_by(protocol_id=proto.id).count() == 0


@requires_postgres
def test_send_test_message_posts_to_the_saved_webhook(client, db_session):
    _sign_in(db_session, client)
    hook = client.post("/api/me/webhooks", json={"discord_webhook_url": HOOK}, headers=SAME_ORIGIN).json()
    with patch("services.monitoring.notifier._send_discord", return_value=True) as send:
        resp = client.post(f"/api/me/webhooks/{hook['id']}/test", headers=SAME_ORIGIN)
    assert resp.json() == {"delivered": True}
    assert send.call_args.args[0] == HOOK


@requires_postgres
def test_admin_subscription_list_shows_account_rows_with_owner(client, db_session):
    proto = _protocol(db_session)
    _sign_in(db_session, client, "alice@example.com")
    hook = client.post("/api/me/webhooks", json={"discord_webhook_url": HOOK}, headers=SAME_ORIGIN).json()
    client.post("/api/me/subscriptions", json={"protocol_id": proto.id, "webhook_id": hook["id"]}, headers=SAME_ORIGIN)
    rows = client.get(f"/api/protocols/{proto.id}/subscriptions").json()
    assert [r["owner_email"] for r in rows] == ["alice@example.com"]
    assert rows[0]["discord_webhook_url"].endswith("<redacted>")


@requires_postgres
def test_notifier_delivers_through_saved_webhook(db_session):
    from db.models import ProtocolSubscription, User, UserWebhook
    from services.monitoring.notifier import _deliverable_subscriptions

    proto = _protocol(db_session)
    user = User(email=f"{uuid.uuid4().hex}@example.com")
    db_session.add(user)
    db_session.flush()
    hook = UserWebhook(user_id=user.id, discord_webhook_url=HOOK)
    db_session.add(hook)
    db_session.flush()
    db_session.add_all(
        [
            ProtocolSubscription(protocol_id=proto.id, user_id=user.id, webhook_id=hook.id),
            ProtocolSubscription(protocol_id=proto.id, discord_webhook_url=HOOK + "2"),
            ProtocolSubscription(protocol_id=proto.id),  # no target: never delivered
        ]
    )
    db_session.commit()
    urls = sorted(str(s.delivery_url) for s in _deliverable_subscriptions(db_session, [proto.id]))
    assert urls == [HOOK, HOOK + "2"]
