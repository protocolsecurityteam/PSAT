"""Sign-in through Neon Auth (managed Better Auth), our own session cookie, logout, and a local-only dev login.

Neon Auth owns identity: email/password, verification and reset emails, GitHub/Google. The browser reaches it only
through the same-origin proxy below. After any sign-in the browser calls ``POST /api/auth/session``; we ask Neon,
server-side, whose session that is and open our own ``psat_session``, so the rest of the API never depends on Neon.
"""

from __future__ import annotations

import logging
import os
import re

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from services.auth import neon
from services.auth.sessions import (
    SESSION_COOKIE,
    SESSION_TTL,
    create_session,
    revoke_session,
    upsert_dev_user,
    upsert_neon_user,
)
from utils.ratelimit import SlidingWindowRateLimiter, client_ip

from . import deps

logger = logging.getLogger(__name__)
router = APIRouter()

# Neon rate-limits by its own view of the client, which behind this proxy is our server; bound each visitor here.
_proxy_limiter = SlidingWindowRateLimiter(limit=120, window_s=300)
_session_limiter = SlidingWindowRateLimiter(limit=30, window_s=300)
_NEON_PATH = re.compile(r"[A-Za-z0-9_\-/.]+")


def public_base(request: Request) -> str:
    configured = os.environ.get("PSAT_PUBLIC_BASE_URL") or os.environ.get("PSAT_SITE_ORIGIN", "").split(",")[0]
    return (configured.strip() or str(request.base_url)).rstrip("/")


def _secure(request: Request) -> bool:
    return public_base(request).startswith("https://")


def _dev_login_enabled() -> bool:
    # Never on a Fly app (preview or production), whatever the flag says.
    return os.environ.get("PSAT_AUTH_DEV_LOGIN") == "1" and not os.environ.get("FLY_APP_NAME")


def _browser_origin(request: Request) -> str:
    # Neon checks this against its trusted domains, so it must be the origin the user actually sees.
    origin = request.headers.get("origin")
    return origin if origin and deps.is_site_origin(request, origin) else public_base(request)


def _limit(limiter: SlidingWindowRateLimiter, request: Request) -> None:
    retry = limiter.hit(client_ip(request))
    if retry is not None:
        raise HTTPException(status_code=429, detail="Too many requests", headers={"Retry-After": str(retry)})


def _relay_cookies(response: Response, upstream: neon.Upstream) -> None:
    for cookie in upstream.set_cookies:
        response.headers.append("set-cookie", cookie)


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


def _social_providers() -> list[str]:
    # Neon doesn't advertise which providers a branch has credentials for, so the deployment says which to offer.
    raw = os.environ.get("PSAT_AUTH_PROVIDERS", "github,google")
    return [p for p in (x.strip().lower() for x in raw.split(",")) if p in {"github", "google"}]


@router.get("/api/auth/config")
def auth_config() -> dict:
    enabled = neon.enabled()
    return {"enabled": enabled, "providers": _social_providers() if enabled else [], "dev_login": _dev_login_enabled()}


@router.api_route("/api/auth/neon/{path:path}", methods=["GET", "POST"])
async def neon_proxy(path: str, request: Request) -> Response:
    if not neon.enabled():
        raise HTTPException(status_code=404, detail="Sign-in is not available")
    if not _NEON_PATH.fullmatch(path) or ".." in path:
        raise HTTPException(status_code=404, detail="Not Found")
    if request.method == "POST":
        deps.check_same_origin(request)
    _limit(_proxy_limiter, request)
    body = await request.body() if request.method == "POST" else None
    try:
        upstream = await run_in_threadpool(
            neon.forward,
            request.method,
            path,
            query=request.url.query,
            headers=dict(request.headers),
            cookie_header=request.headers.get("cookie"),
            origin=_browser_origin(request),
            body=body,
        )
    except neon.NeonAuthError as exc:
        logger.warning("neon auth proxy failed", extra={"neon_path": path, "error": str(exc)})
        raise HTTPException(status_code=502, detail="Sign-in service unavailable") from None
    response = Response(content=upstream.body, status_code=upstream.status)
    for name, value in upstream.headers:
        response.headers[name] = value
    _relay_cookies(response, upstream)
    return response


@router.post("/api/auth/session")
def establish_session(request: Request, neon_auth_session_verifier: str | None = None) -> JSONResponse:
    """Turn the browser's Neon Auth session into a ``psat_session``. Requires a verified email."""
    if not neon.enabled():
        raise HTTPException(status_code=404, detail="Sign-in is not available")
    deps.check_same_origin(request)
    _limit(_session_limiter, request)
    try:
        neon_user, upstream = neon.fetch_session(
            cookie_header=request.headers.get("cookie"),
            origin=_browser_origin(request),
            verifier=neon_auth_session_verifier,
        )
    except neon.NeonAuthError as exc:
        logger.warning("neon auth session lookup failed", extra={"error": str(exc)})
        raise HTTPException(status_code=502, detail="Sign-in service unavailable") from None
    if neon_user is None:
        response = JSONResponse({"detail": "Not signed in"}, status_code=401)
    elif not neon_user.email_verified:
        response = JSONResponse({"detail": "Verify your email address, then sign in again"}, status_code=403)
    else:
        response = JSONResponse({"status": "signed_in"})
        with deps.SessionLocal() as session:
            try:
                user = upsert_neon_user(
                    session,
                    neon_auth_id=neon_user.id,
                    email=neon_user.email,
                    email_verified=neon_user.email_verified,
                    display_name=neon_user.name,
                    avatar_url=neon_user.image,
                )
            except PermissionError:
                session.rollback()
                response = JSONResponse({"detail": "That email belongs to another account"}, status_code=409)
            else:
                open_session(session, request, response, user)
    _relay_cookies(response, upstream)
    return response


@router.post("/api/auth/logout")
def logout(request: Request) -> JSONResponse:
    deps.check_same_origin(request)
    with deps.SessionLocal() as session:
        revoke_session(session, request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"status": "signed_out"})
    response.delete_cookie(SESSION_COOKIE, path="/")
    if neon.enabled() and neon.neon_cookies(request.headers.get("cookie")):
        try:
            upstream = neon.forward(
                "POST",
                "sign-out",
                query="",
                headers={"content-type": "application/json"},
                cookie_header=request.headers.get("cookie"),
                origin=_browser_origin(request),
                body=b"{}",
            )
            _relay_cookies(response, upstream)
        except neon.NeonAuthError as exc:
            # Our session is gone either way; Neon's expires on its own.
            logger.warning("neon auth sign-out failed", extra={"error": str(exc)})
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
        open_session(session, request, response, upsert_dev_user(session, body.email))
    return response
