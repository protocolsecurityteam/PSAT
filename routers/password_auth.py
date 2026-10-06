"""Email/password sign-in.

Sign-up takes only an email; the emailed link is where the password is chosen (see ``services.auth.passwords``).
Register and forgot-password answer identically whether or not the email has an account, so neither enumerates users.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from db.models import User
from services.auth import mailer
from services.auth.passwords import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    check_password,
    consume_token,
    issue_token,
    set_password,
)
from services.auth.sessions import admin_emails
from utils.ratelimit import SlidingWindowRateLimiter, client_ip

from . import deps
from .auth import open_session, public_base

router = APIRouter()

_EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
_SENT = {"status": "check_email"}

# Per-address limits stop mail-bombing one inbox and credential stuffing one account; per-IP limits bound a client.
_link_by_ip = SlidingWindowRateLimiter(limit=10, window_s=3600)
_link_by_email = SlidingWindowRateLimiter(limit=3, window_s=3600)
_login_by_ip = SlidingWindowRateLimiter(limit=30, window_s=900)
_login_by_email = SlidingWindowRateLimiter(limit=10, window_s=900)


def _limit(*hits: int | None) -> None:
    retry = max((h for h in hits if h is not None), default=None)
    if retry is not None:
        raise HTTPException(
            status_code=429, detail="Too many attempts; try again later", headers={"Retry-After": str(retry)}
        )


class _EmailBody(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=_EMAIL_PATTERN)

    @field_validator("email")
    @classmethod
    def _normalize(cls, v: str) -> str:
        return v.strip().lower()


class RegisterRequest(_EmailBody):
    display_name: str | None = Field(default=None, max_length=80)


class LoginRequest(_EmailBody):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class SetPasswordRequest(BaseModel):
    token: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)


def _require_mail() -> None:
    if not mailer.can_send():
        raise HTTPException(status_code=404, detail="Email sign-in is not available")


def _queue_password_link(session, request: Request, background: BackgroundTasks, user: User) -> None:
    """Email ``user`` a link to set their password: finishing sign-up if unverified, else a reset."""
    purpose = "reset" if user.email_verified else "verify"
    token = issue_token(session, user, purpose)
    session.commit()
    link = f"{public_base(request)}/set-password?token={token}"
    if purpose == "verify":
        subject = "Finish creating your snif account"
        body = (
            f"Choose a password to finish creating your snif account:\n\n{link}\n\n"
            "The link works once and expires in 24 hours. If you didn't sign up, ignore this email."
        )
    else:
        subject = "Set your snif password"
        body = (
            f"Someone (hopefully you) asked to set a new password for your snif account:\n\n{link}\n\n"
            "The link works once and expires in 1 hour. If it wasn't you, ignore this email; your password is "
            "unchanged."
        )
    background.add_task(mailer.send_email, user.email, subject, body)


def _link_limits(request: Request, email: str) -> None:
    _limit(_link_by_ip.hit(client_ip(request)), _link_by_email.hit(email))


@router.post("/api/auth/register", status_code=202)
def register(body: RegisterRequest, request: Request, background: BackgroundTasks) -> dict[str, str]:
    _require_mail()
    deps.check_same_origin(request)
    _link_limits(request, body.email)
    with deps.SessionLocal() as session:
        user = session.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
        if user is None:
            user = User(email=body.email, display_name=body.display_name)
            session.add(user)
            session.flush()
        _queue_password_link(session, request, background, user)
    return _SENT


@router.post("/api/auth/password/forgot", status_code=202)
def forgot_password(body: _EmailBody, request: Request, background: BackgroundTasks) -> dict[str, str]:
    _require_mail()
    deps.check_same_origin(request)
    _link_limits(request, body.email)
    with deps.SessionLocal() as session:
        user = session.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
        if user is not None:
            _queue_password_link(session, request, background, user)
    return _SENT


@router.post("/api/auth/password/set")
def set_password_from_link(body: SetPasswordRequest, request: Request) -> JSONResponse:
    deps.check_same_origin(request)
    with deps.SessionLocal() as session:
        user = consume_token(session, body.token)
        if user is None:
            session.commit()  # the spent/expired token stays deleted
            raise HTTPException(status_code=400, detail="This link is invalid or has expired; request a new one")
        set_password(session, user, body.password)
        user.is_admin = user.email in admin_emails()
        user.last_login_at = datetime.now(timezone.utc)
        response = JSONResponse({"status": "signed_in"})
        open_session(session, request, response, user)
    return response


@router.post("/api/auth/password/login")
def password_login(body: LoginRequest, request: Request) -> JSONResponse:
    deps.check_same_origin(request)
    _limit(_login_by_ip.hit(client_ip(request)), _login_by_email.hit(body.email))
    with deps.SessionLocal() as session:
        user = session.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
        # A password exists only once its email was proven, so no separate verified check is needed.
        if not check_password(session, user, body.password) or user is None:
            raise HTTPException(status_code=401, detail="Incorrect email or password")
        user.is_admin = user.email in admin_emails()
        user.last_login_at = datetime.now(timezone.utc)
        response = JSONResponse({"status": "signed_in"})
        open_session(session, request, response, user)
    return response
