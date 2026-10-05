"""Sign-in: GitHub/Google OAuth, logout, and a local-only dev login. Email/password lives in ``password_auth``."""

from __future__ import annotations

import os
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

from services.auth import mailer, oauth
from services.auth.sessions import SESSION_COOKIE, SESSION_TTL, create_session, revoke_session, upsert_oauth_user

from . import deps

router = APIRouter()

_PROVIDER_LABELS = {"github": "GitHub", "google": "Google"}


def public_base(request: Request) -> str:
    # OAuth redirect URIs must match what the provider app registered, so prefer configured origins over Host.
    configured = os.environ.get("PSAT_PUBLIC_BASE_URL") or os.environ.get("PSAT_SITE_ORIGIN", "").split(",")[0]
    return (configured.strip() or str(request.base_url)).rstrip("/")


def _secure(request: Request) -> bool:
    return public_base(request).startswith("https://")


def _dev_login_enabled() -> bool:
    # Never on a Fly app (preview or production), whatever the flag says.
    return os.environ.get("PSAT_AUTH_DEV_LOGIN") == "1" and not os.environ.get("FLY_APP_NAME")


def _provider_or_404(name: str) -> oauth.Provider:
    provider = oauth.PROVIDERS.get(name)
    if provider is None or not provider.enabled:
        raise HTTPException(status_code=404, detail="Sign-in provider not available")
    return provider


def _redirect_uri(request: Request, provider: oauth.Provider) -> str:
    return f"{public_base(request)}/api/auth/{provider.name}/callback"


def open_session(session, request: Request, response: Response, user) -> None:
    """Open a session for ``user`` and set its cookie on ``response``; commits."""
    token = create_session(session, user)
    session.commit()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        secure=_secure(request),
        samesite="lax",
        path="/",
    )


def _sign_in(session, request: Request, response: Response, **identity) -> None:
    open_session(session, request, response, upsert_oauth_user(session, **identity))


@router.get("/api/auth/providers")
def list_providers() -> dict:
    return {
        "providers": [
            {"name": p.name, "label": _PROVIDER_LABELS[p.name]} for p in oauth.PROVIDERS.values() if p.enabled
        ],
        "dev_login": _dev_login_enabled(),
        "password": mailer.can_send(),
    }


@router.get("/api/auth/{provider_name}/login")
def oauth_login(provider_name: str, request: Request, next: str | None = None) -> RedirectResponse:
    provider = _provider_or_404(provider_name)
    try:
        url, state_cookie = oauth.begin(provider, _redirect_uri(request, provider), next)
    except oauth.OAuthError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(
        oauth.STATE_COOKIE,
        state_cookie,
        max_age=oauth.STATE_TTL_S,
        httponly=True,
        secure=_secure(request),
        samesite="lax",
        path="/api/auth/",
    )
    return response


@router.get("/api/auth/{provider_name}/callback")
def oauth_callback(
    provider_name: str, request: Request, code: str | None = None, state: str | None = None, error: str | None = None
) -> RedirectResponse:
    provider = _provider_or_404(provider_name)
    try:
        if error or not code:
            raise oauth.OAuthError("Sign-in was cancelled")
        verifier, next_path = oauth.check_state(provider, request.cookies.get(oauth.STATE_COOKIE), state)
        identity = oauth.exchange(provider, code, verifier, _redirect_uri(request, provider))
    except oauth.OAuthError as exc:
        response = RedirectResponse(f"/account?{urlencode({'auth_error': str(exc)})}", status_code=303)
        response.delete_cookie(oauth.STATE_COOKIE, path="/api/auth/")
        return response

    response = RedirectResponse(next_path, status_code=303)
    response.delete_cookie(oauth.STATE_COOKIE, path="/api/auth/")
    with deps.SessionLocal() as session:
        _sign_in(
            session,
            request,
            response,
            provider=provider.name,
            subject=identity.subject,
            email=identity.email,
            display_name=identity.display_name,
            avatar_url=identity.avatar_url,
        )
    return response


@router.post("/api/auth/logout")
def logout(request: Request) -> JSONResponse:
    deps.check_same_origin(request)
    with deps.SessionLocal() as session:
        revoke_session(session, request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


class DevLoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254, pattern=r"^[^@\s]+@[^@\s]+$")


@router.post("/api/auth/dev-login")
def dev_login(body: DevLoginRequest, request: Request) -> JSONResponse:
    if not _dev_login_enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    deps.check_same_origin(request)
    response = JSONResponse({"status": "signed_in"})
    with deps.SessionLocal() as session:
        _sign_in(
            session,
            request,
            response,
            provider="dev",
            subject=body.email.lower(),
            email=body.email,
            display_name=None,
            avatar_url=None,
        )
    return response
