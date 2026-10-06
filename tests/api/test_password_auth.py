from __future__ import annotations

import re
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from tests.conftest import requires_postgres

pytestmark = requires_postgres

SAME_ORIGIN = {"Origin": "http://testserver"}
PASSWORD = "correct horse battery"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("PSAT_SMTP_HOST", "smtp.test")
    monkeypatch.setenv("PSAT_MAIL_FROM", "psat@test")
    monkeypatch.setenv("PSAT_ADMIN_EMAILS", "boss@example.com")
    for name in ("PSAT_PUBLIC_BASE_URL", "PSAT_SITE_ORIGIN", "FLY_APP_NAME", "PSAT_AUTH_DEV_LOGIN"):
        monkeypatch.delenv(name, raising=False)
    from routers import me, password_auth

    limiters = [
        password_auth._link_by_ip,
        password_auth._link_by_email,
        password_auth._login_by_ip,
        password_auth._login_by_email,
        me._password_limiter,
    ]
    for limiter in limiters:
        limiter.reset()
    yield
    for limiter in limiters:
        limiter.reset()


@pytest.fixture()
def outbox():
    sent = []
    with patch(
        "services.auth.mailer.send_email", side_effect=lambda to, subject, body: sent.append((to, subject, body))
    ):
        yield sent


@pytest.fixture()
def client(db_session):
    @contextmanager
    def fake_session_local():
        yield db_session

    with patch("routers.deps.SessionLocal", fake_session_local):
        from fastapi.testclient import TestClient

        import api

        yield TestClient(api.app)


def _link_token(outbox, to):
    to_mail = [body for addr, _subject, body in outbox if addr == to]
    assert to_mail, f"no mail to {to}"
    match = re.search(r"/set-password\?token=(\S+)", to_mail[-1])
    assert match, to_mail[-1]
    return match.group(1)


def _sign_up(client, outbox, email="alice@example.com", password=PASSWORD):
    assert client.post("/api/auth/register", json={"email": email}, headers=SAME_ORIGIN).status_code == 202
    resp = client.post(
        "/api/auth/password/set", json={"token": _link_token(outbox, email), "password": password}, headers=SAME_ORIGIN
    )
    assert resp.status_code == 200, resp.text
    return resp


def test_sign_up_sets_the_password_through_the_emailed_link(client, db_session, outbox):
    from db.models import User

    resp = client.post("/api/auth/register", json={"email": "Alice@Example.com"}, headers=SAME_ORIGIN)
    assert resp.json() == {"status": "check_email"}
    user = db_session.query(User).filter_by(email="alice@example.com").one()
    # Registration alone proves nothing: no password, unverified, not signed in.
    assert (user.password_hash, user.email_verified) == (None, False)
    assert client.get("/api/me").status_code == 401

    token = _link_token(outbox, "alice@example.com")
    assert "Finish creating" in outbox[-1][1]
    resp = client.post("/api/auth/password/set", json={"token": token, "password": PASSWORD}, headers=SAME_ORIGIN)
    assert resp.status_code == 200
    me = client.get("/api/me").json()
    assert (me["email"], me["has_password"]) == ("alice@example.com", True)
    db_session.refresh(user)
    assert user.email_verified and user.password_hash.startswith("$argon2id$")

    # Single use.
    again = client.post(
        "/api/auth/password/set", json={"token": token, "password": "another password"}, headers=SAME_ORIGIN
    )
    assert again.status_code == 400


def test_login_accepts_only_the_right_password_and_never_says_which_part_was_wrong(client, outbox):
    _sign_up(client, outbox)
    client.cookies.clear()
    wrong = client.post(
        "/api/auth/password/login", json={"email": "alice@example.com", "password": "nope"}, headers=SAME_ORIGIN
    )
    unknown = client.post(
        "/api/auth/password/login", json={"email": "nobody@example.com", "password": PASSWORD}, headers=SAME_ORIGIN
    )
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    ok = client.post(
        "/api/auth/password/login", json={"email": "ALICE@example.com", "password": PASSWORD}, headers=SAME_ORIGIN
    )
    assert ok.status_code == 200
    assert client.get("/api/me").json()["email"] == "alice@example.com"


def test_unverified_registration_cannot_sign_in(client, outbox):
    client.post("/api/auth/register", json={"email": "alice@example.com"}, headers=SAME_ORIGIN)
    resp = client.post(
        "/api/auth/password/login", json={"email": "alice@example.com", "password": PASSWORD}, headers=SAME_ORIGIN
    )
    assert resp.status_code == 401


def test_register_and_forgot_do_not_reveal_whether_an_account_exists(client, outbox):
    _sign_up(client, outbox)
    outbox.clear()
    for path in ("/api/auth/register", "/api/auth/password/forgot"):
        existing = client.post(path, json={"email": "alice@example.com"}, headers=SAME_ORIGIN)
        missing = client.post(path, json={"email": "ghost@example.com"}, headers=SAME_ORIGIN)
        assert (
            (existing.status_code, existing.json())
            == (missing.status_code, missing.json())
            == (202, {"status": "check_email"})
        )
    # The existing (verified) account gets a reset link, never a second sign-up.
    assert {subject for _to, subject, _body in outbox if _to == "alice@example.com"} == {"Set your snif password"}
    # Register created a pending account for the unknown address, so it only ever gets sign-up links.
    assert {s for to, s, _ in outbox if to == "ghost@example.com"} == {"Finish creating your snif account"}


def test_reset_signs_out_every_other_session(client, db_session, outbox):
    from db.models import UserSession

    _sign_up(client, outbox)
    stolen_cookie = dict(client.cookies)
    client.cookies.clear()
    client.post("/api/auth/password/forgot", json={"email": "alice@example.com"}, headers=SAME_ORIGIN)
    client.post(
        "/api/auth/password/set",
        json={"token": _link_token(outbox, "alice@example.com"), "password": "a brand new password"},
        headers=SAME_ORIGIN,
    )
    assert db_session.query(UserSession).count() == 1
    client.cookies.clear()
    client.cookies.update(stolen_cookie)
    assert client.get("/api/me").status_code == 401


def test_expired_link_is_rejected(client, db_session, outbox):
    from db.models import EmailToken

    client.post("/api/auth/register", json={"email": "alice@example.com"}, headers=SAME_ORIGIN)
    for row in db_session.query(EmailToken).all():
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db_session.commit()
    resp = client.post(
        "/api/auth/password/set",
        json={"token": _link_token(outbox, "alice@example.com"), "password": PASSWORD},
        headers=SAME_ORIGIN,
    )
    assert resp.status_code == 400


def test_a_pre_registered_account_goes_to_whoever_proves_the_email_by_oauth(client, db_session, outbox, monkeypatch):
    """An attacker registers the victim's email first; the victim then signs in with GitHub."""
    from db.models import EmailToken, User
    from services.auth.sessions import upsert_oauth_user

    client.post("/api/auth/register", json={"email": "victim@example.com"}, headers=SAME_ORIGIN)
    planted = _link_token(outbox, "victim@example.com")  # suppose it leaked to the attacker somehow

    user = upsert_oauth_user(
        db_session, provider="github", subject="v1", email="victim@example.com", display_name=None, avatar_url=None
    )
    db_session.commit()
    assert user.email_verified
    assert db_session.query(EmailToken).count() == 0
    resp = client.post("/api/auth/password/set", json={"token": planted, "password": PASSWORD}, headers=SAME_ORIGIN)
    assert resp.status_code == 400
    assert db_session.query(User).filter_by(email="victim@example.com").one().password_hash is None


def test_admin_requires_a_verified_email(db_session):
    from db.models import User
    from services.auth.sessions import is_admin

    user = User(email="boss@example.com", is_admin=True, email_verified=False)
    assert not is_admin(user)
    user.email_verified = True
    assert is_admin(user)


def test_password_sign_in_grants_admin_from_the_allowlist(client, outbox):
    _sign_up(client, outbox, email="boss@example.com")
    assert client.get("/api/me").json()["is_admin"] is True


def test_change_password_requires_the_current_one(client, outbox):
    _sign_up(client, outbox)
    bad = client.post(
        "/api/me/password",
        json={"current_password": "wrong", "new_password": "a brand new password"},
        headers=SAME_ORIGIN,
    )
    assert bad.status_code == 403
    ok = client.post(
        "/api/me/password",
        json={"current_password": PASSWORD, "new_password": "a brand new password"},
        headers=SAME_ORIGIN,
    )
    assert ok.status_code == 200
    client.cookies.clear()
    login = client.post(
        "/api/auth/password/login",
        json={"email": "alice@example.com", "password": "a brand new password"},
        headers=SAME_ORIGIN,
    )
    assert login.status_code == 200


def test_provider_account_can_add_a_password_without_a_current_one(client, db_session):
    from services.auth.sessions import SESSION_COOKIE, create_session, upsert_oauth_user

    user = upsert_oauth_user(
        db_session, provider="github", subject="g1", email="gh@example.com", display_name=None, avatar_url=None
    )
    client.cookies.set(SESSION_COOKIE, create_session(db_session, user))
    db_session.commit()
    assert client.get("/api/me").json()["has_password"] is False
    resp = client.post("/api/me/password", json={"new_password": "a brand new password"}, headers=SAME_ORIGIN)
    assert resp.status_code == 200
    assert client.get("/api/me").json()["has_password"] is True


def test_short_passwords_are_rejected(client, outbox):
    client.post("/api/auth/register", json={"email": "alice@example.com"}, headers=SAME_ORIGIN)
    resp = client.post(
        "/api/auth/password/set",
        json={"token": _link_token(outbox, "alice@example.com"), "password": "short"},
        headers=SAME_ORIGIN,
    )
    assert resp.status_code == 422


def test_login_attempts_are_rate_limited_per_account(client, outbox):
    _sign_up(client, outbox)
    client.cookies.clear()
    codes = [
        client.post(
            "/api/auth/password/login", json={"email": "alice@example.com", "password": "nope"}, headers=SAME_ORIGIN
        ).status_code
        for _ in range(11)
    ]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


def test_password_sign_in_is_off_without_a_mail_transport(client, monkeypatch, outbox):
    monkeypatch.delenv("PSAT_SMTP_HOST")
    assert client.get("/api/auth/providers").json()["password"] is False
    assert client.post("/api/auth/register", json={"email": "a@example.com"}, headers=SAME_ORIGIN).status_code == 404
    # Local dev-login setups log the link instead of sending it.
    monkeypatch.setenv("PSAT_AUTH_DEV_LOGIN", "1")
    assert client.get("/api/auth/providers").json()["password"] is True


def test_cross_origin_password_posts_are_refused(client, outbox):
    for path, body in (
        ("/api/auth/register", {"email": "a@example.com"}),
        ("/api/auth/password/login", {"email": "a@example.com", "password": "x"}),
        ("/api/auth/password/set", {"token": "t", "password": PASSWORD}),
    ):
        assert client.post(path, json=body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert outbox == []


def test_mailer_logs_link_only_in_local_dev(monkeypatch, caplog):
    import logging

    from services.auth import mailer

    monkeypatch.delenv("PSAT_SMTP_HOST", raising=False)
    monkeypatch.setenv("PSAT_AUTH_DEV_LOGIN", "1")
    with caplog.at_level(logging.INFO, logger="services.auth.mailer"):
        mailer.send_email("a@example.com", "s", "link-123")
    assert "link-123" in caplog.text
    caplog.clear()
    monkeypatch.setenv("FLY_APP_NAME", "psat")
    assert not mailer.can_send()
    with caplog.at_level(logging.INFO, logger="services.auth.mailer"):
        mailer.send_email("a@example.com", "s", "link-123")
    assert "link-123" not in caplog.text


@pytest.mark.parametrize("port,tls_class", [("587", "SMTP"), ("465", "SMTP_SSL")])
def test_mailer_uses_tls_and_never_logs_the_body_on_failure(monkeypatch, caplog, port, tls_class):
    import logging
    import smtplib
    from unittest.mock import MagicMock

    from services.auth import mailer

    monkeypatch.setenv("PSAT_SMTP_PORT", port)
    monkeypatch.setenv("PSAT_SMTP_USERNAME", "user")
    monkeypatch.setenv("PSAT_SMTP_PASSWORD", "pw")
    client = MagicMock()
    client.__enter__.return_value = client
    with patch.object(smtplib, tls_class, return_value=client) as factory:
        mailer.send_email("a@example.com", "Subject", "secret-link-token")
    factory.assert_called_once()
    if tls_class == "SMTP":
        client.starttls.assert_called_once()
    client.login.assert_called_once_with("user", "pw")
    sent = client.send_message.call_args.args[0]
    assert (sent["To"], sent["From"], sent["Subject"]) == ("a@example.com", "psat@test", "Subject")

    client.send_message.side_effect = smtplib.SMTPException("boom")
    with patch.object(smtplib, tls_class, return_value=client), caplog.at_level(logging.WARNING):
        mailer.send_email("a@example.com", "Subject", "secret-link-token")
    assert "account email failed" in caplog.text
    assert "secret-link-token" not in caplog.text
