from __future__ import annotations

import functools
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from tests.conftest import requires_postgres

HOOK = "https://discord.com/api/webhooks/123456789012345678/SECRETtoken"
SAME_ORIGIN = {"Origin": "http://testserver"}


@pytest.fixture(autouse=True)
def _auth_env(monkeypatch):
    monkeypatch.setenv("PSAT_SESSION_SECRET", "s" * 48)
    monkeypatch.setenv("PSAT_GITHUB_CLIENT_ID", "gh-id")
    monkeypatch.setenv("PSAT_GITHUB_CLIENT_SECRET", "gh-secret")
    monkeypatch.setenv("PSAT_ADMIN_EMAILS", "boss@example.com")
    for name in ("PSAT_PUBLIC_BASE_URL", "PSAT_SITE_ORIGIN", "PSAT_GOOGLE_CLIENT_ID", "FLY_APP_NAME"):
        monkeypatch.delenv(name, raising=False)


# --- OAuth provider parsing (no DB) -------------------------------------------------------------------------------


def _mock_httpx(monkeypatch, routes: dict[str, httpx.Response]):
    def handler(request: httpx.Request) -> httpx.Response:
        return routes[f"{request.method} {request.url.copy_with(query=None)}"]

    monkeypatch.setattr(
        "services.auth.oauth.httpx.Client", functools.partial(httpx.Client, transport=httpx.MockTransport(handler))
    )


def _github_routes(emails):
    return {
        "POST https://github.com/login/oauth/access_token": httpx.Response(200, json={"access_token": "tok"}),
        "GET https://api.github.com/user": httpx.Response(200, json={"id": 42, "login": "octo", "avatar_url": "a"}),
        "GET https://api.github.com/user/emails": httpx.Response(200, json=emails),
    }


def test_github_identity_requires_verified_primary_email(monkeypatch):
    from services.auth import oauth

    _mock_httpx(
        monkeypatch,
        _github_routes(
            [
                {"email": "alt@example.com", "primary": False, "verified": True},
                {"email": "Octo@Example.com", "primary": True, "verified": True},
            ]
        ),
    )
    identity = oauth.exchange(oauth.PROVIDERS["github"], "code", "verifier", "http://testserver/cb")
    assert (identity.subject, identity.email, identity.display_name) == ("42", "Octo@Example.com", "octo")

    _mock_httpx(monkeypatch, _github_routes([{"email": "o@example.com", "primary": True, "verified": False}]))
    with pytest.raises(oauth.OAuthError, match="verified"):
        oauth.exchange(oauth.PROVIDERS["github"], "code", "verifier", "http://testserver/cb")


@pytest.mark.parametrize("email_verified", [False, "true", None])
def test_google_identity_rejects_unverified_email(monkeypatch, email_verified):
    from services.auth import oauth

    _mock_httpx(
        monkeypatch,
        {
            "POST https://oauth2.googleapis.com/token": httpx.Response(200, json={"access_token": "tok"}),
            "GET https://openidconnect.googleapis.com/v1/userinfo": httpx.Response(
                200, json={"sub": "g1", "email": "g@example.com", "email_verified": email_verified}
            ),
        },
    )
    with pytest.raises(oauth.OAuthError):
        oauth.exchange(oauth.PROVIDERS["google"], "code", "verifier", "http://testserver/cb")


def test_rejected_token_exchange_is_an_oauth_error(monkeypatch):
    from services.auth import oauth

    _mock_httpx(
        monkeypatch,
        {"POST https://github.com/login/oauth/access_token": httpx.Response(200, json={"error": "bad_code"})},
    )
    with pytest.raises(oauth.OAuthError, match="rejected"):
        oauth.exchange(oauth.PROVIDERS["github"], "code", "verifier", "http://testserver/cb")


@pytest.mark.parametrize(
    "cookie_tamper",
    [
        pytest.param(lambda c: c[:-2] + "xx", id="bad_signature"),
        pytest.param(lambda c: "garbage", id="malformed"),
        pytest.param(lambda c: None, id="missing"),
    ],
)
def test_state_cookie_must_be_intact(cookie_tamper):
    from services.auth import oauth

    provider = oauth.PROVIDERS["github"]
    url, cookie = oauth.begin(provider, "http://testserver/cb", "/company/x")
    state = parse_qs(urlsplit(url).query)["state"][0]
    assert oauth.check_state(provider, cookie, state)[1] == "/company/x"
    with pytest.raises(oauth.OAuthError):
        oauth.check_state(provider, cookie_tamper(cookie), state)
    with pytest.raises(oauth.OAuthError, match="mismatch"):
        oauth.check_state(provider, cookie, "other-state")
    with pytest.raises(oauth.OAuthError):
        oauth.check_state(oauth.PROVIDERS["google"], cookie, state)


@pytest.mark.parametrize("raw", [None, "", "https://evil.com", "//evil.com", "/\\evil.com", "relative"])
def test_next_path_is_never_an_open_redirect(raw):
    from services.auth.oauth import safe_next

    assert safe_next(raw) == "/"


# --- Routes (DB-backed) -------------------------------------------------------------------------------------------


@pytest.fixture()
def client(db_session):
    @contextmanager
    def fake_session_local():
        yield db_session

    with patch("routers.deps.SessionLocal", fake_session_local):
        from fastapi.testclient import TestClient

        import api

        yield TestClient(api.app)


def _sign_in(db_session, client, email="user@example.com"):
    from services.auth.sessions import SESSION_COOKIE, create_session, upsert_oauth_user

    user = upsert_oauth_user(
        db_session, provider="github", subject=email, email=email, display_name=None, avatar_url=None
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
def test_oauth_login_round_trip_signs_in_and_links_by_email(client, db_session, monkeypatch):
    from db.models import OAuthIdentity
    from services.auth import oauth

    login = client.get("/api/auth/github/login", params={"next": "/company/aave"}, follow_redirects=False)
    assert login.status_code == 302
    location = urlsplit(login.headers["location"])
    query = parse_qs(location.query)
    assert location.netloc == "github.com"
    assert query["redirect_uri"] == ["http://testserver/api/auth/github/callback"]
    assert query["code_challenge_method"] == ["S256"]

    seen = {}

    def fake_exchange(provider, code, verifier, redirect_uri):
        seen.update(code=code, redirect_uri=redirect_uri)
        return oauth.VerifiedIdentity("gh-7", "Boss@Example.com", "Boss", None)

    monkeypatch.setattr(oauth, "exchange", fake_exchange)
    callback = client.get(
        "/api/auth/github/callback", params={"code": "c0de", "state": query["state"][0]}, follow_redirects=False
    )
    assert callback.status_code == 303
    assert callback.headers["location"] == "/company/aave"
    assert seen == {"code": "c0de", "redirect_uri": "http://testserver/api/auth/github/callback"}
    assert "httponly" in callback.headers["set-cookie"].lower()

    me = client.get("/api/me").json()
    assert me["email"] == "boss@example.com"
    assert me["is_admin"] is True

    # A second provider with the same verified email lands on the same account.
    monkeypatch.setenv("PSAT_GOOGLE_CLIENT_ID", "g-id")
    monkeypatch.setenv("PSAT_GOOGLE_CLIENT_SECRET", "g-secret")
    monkeypatch.setattr(oauth, "exchange", lambda *a: oauth.VerifiedIdentity("g-9", "boss@example.com", None, None))
    state = parse_qs(urlsplit(client.get("/api/auth/google/login", follow_redirects=False).headers["location"]).query)
    client.get("/api/auth/google/callback", params={"code": "x", "state": state["state"][0]}, follow_redirects=False)
    identities = db_session.query(OAuthIdentity).all()
    assert {i.provider for i in identities} == {"github", "google"}
    assert len({i.user_id for i in identities}) == 1


@requires_postgres
def test_callback_with_wrong_state_does_not_sign_in(client, monkeypatch):
    from services.auth import oauth

    client.get("/api/auth/github/login", follow_redirects=False)
    monkeypatch.setattr(oauth, "exchange", lambda *a: pytest.fail("exchange must not run"))
    resp = client.get("/api/auth/github/callback", params={"code": "c", "state": "forged"}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/account?auth_error=")
    assert client.get("/api/me").status_code == 401


def test_disabled_provider_is_404(client, monkeypatch):
    monkeypatch.delenv("PSAT_GITHUB_CLIENT_SECRET")
    assert client.get("/api/auth/github/login", follow_redirects=False).status_code == 404
    assert client.get("/api/auth/providers").json()["providers"] == []


@requires_postgres
def test_logout_revokes_the_session_server_side(client, db_session):
    from services.auth.sessions import SESSION_COOKIE

    _sign_in(db_session, client)
    token = client.cookies.get(SESSION_COOKIE)
    assert client.post("/api/auth/logout", headers=SAME_ORIGIN).status_code == 200
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
