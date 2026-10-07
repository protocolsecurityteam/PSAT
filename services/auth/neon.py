"""Neon Auth (managed Better Auth) behind a same-origin proxy.

The browser talks to Neon Auth only through ``/api/auth/neon/*`` on our origin, so its cookies are first-party (Safari
and other third-party-cookie blockers never see a cross-site auth host). This mirrors ``@neondatabase/auth``'s own
server proxy: forward a fixed header set plus only the ``__Secure-neon-auth`` cookies, relay a fixed response header
set, and pin relayed cookies to SameSite=Lax, Secure, host-only.

``NEON_AUTH_BASE_URL`` is the branch's Auth URL, including its path (e.g. ``https://ep-x.neonauth.../neondb/auth``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

COOKIE_PREFIX = "__Secure-neon-auth"
SESSION_VERIFIER_PARAM = "neon_auth_session_verifier"
_REQUEST_HEADERS = ("user-agent", "referer", "content-type")
_RESPONSE_HEADERS = ("content-type", "set-auth-jwt", "set-auth-token", "x-neon-ret-request-id")
_TIMEOUT_S = 15


class NeonAuthError(Exception):
    """Neon Auth could not be reached or answered unexpectedly."""


def base_url() -> str | None:
    url = os.environ.get("NEON_AUTH_BASE_URL", "").strip().rstrip("/")
    return url or None


def enabled() -> bool:
    return base_url() is not None


def neon_cookies(cookie_header: str | None) -> str:
    """Only Neon Auth's own cookies leave our origin, never ``psat_session`` or anything else."""
    pairs = (part.strip().partition("=") for part in (cookie_header or "").split(";"))
    return "; ".join(f"{name}={value}" for name, _, value in pairs if name.startswith(COOKIE_PREFIX))


def first_party_cookie(set_cookie: str) -> str | None:
    """Rewrite an upstream Set-Cookie for our origin: host-only, Secure, SameSite=Lax, unpartitioned.

    Anything not named with Neon's prefix is dropped, so the upstream can never set or clobber our cookies.
    """
    head, _, attrs = set_cookie.partition(";")
    name = head.split("=", 1)[0].strip()
    if not name.startswith(COOKIE_PREFIX):
        return None
    kept = [
        a.strip()
        for a in attrs.split(";")
        if a.strip()
        and a.strip().split("=", 1)[0].strip().lower() not in {"domain", "samesite", "secure", "partitioned"}
    ]
    return "; ".join([head.strip(), *kept, "Secure", "SameSite=Lax"])


@dataclass(frozen=True)
class Upstream:
    status: int
    headers: list[tuple[str, str]]
    set_cookies: list[str]
    body: bytes


def forward(
    method: str,
    path: str,
    *,
    query: str,
    headers: dict[str, str],
    cookie_header: str | None,
    origin: str,
    body: bytes | None,
) -> Upstream:
    base = base_url()
    if base is None:
        raise NeonAuthError("Neon Auth is not configured")
    out = {k: v for k, v in headers.items() if k.lower() in _REQUEST_HEADERS}
    out["Origin"] = origin
    out["x-neon-auth-middleware"] = "true"
    cookies = neon_cookies(cookie_header)
    if cookies:
        out["Cookie"] = cookies
    url = f"{base}/{path}" + (f"?{query}" if query else "")
    try:
        with httpx.Client(timeout=_TIMEOUT_S, follow_redirects=False) as client:
            resp = client.request(method, url, headers=out, content=body)
    except httpx.HTTPError as exc:
        raise NeonAuthError(f"Neon Auth unreachable: {type(exc).__name__}") from None
    relayed = [(k, resp.headers[k]) for k in _RESPONSE_HEADERS if k in resp.headers]
    cookies_out = [c for c in (first_party_cookie(v) for v in resp.headers.get_list("set-cookie")) if c]
    return Upstream(resp.status_code, relayed, cookies_out, resp.content)


@dataclass(frozen=True)
class NeonUser:
    id: str
    email: str
    email_verified: bool
    name: str | None
    image: str | None


def fetch_session(*, cookie_header: str | None, origin: str, verifier: str | None) -> tuple[NeonUser | None, Upstream]:
    """Ask Neon Auth who the browser's Neon session belongs to.

    ``verifier`` completes a social sign-in: Neon redirects back with it, and exchanging it here sets the session
    cookie (relayed in the returned ``Upstream``).
    """
    query = urlencode({SESSION_VERIFIER_PARAM: verifier}) if verifier else ""
    upstream = forward(
        "GET", "get-session", query=query, headers={}, cookie_header=cookie_header, origin=origin, body=None
    )
    if upstream.status != 200:
        if upstream.status >= 500:
            raise NeonAuthError(f"Neon Auth answered {upstream.status}")
        return None, upstream
    if not upstream.body.strip():
        return None, upstream
    try:
        data = httpx.Response(200, content=upstream.body).json()
    except ValueError:
        raise NeonAuthError("Neon Auth returned a non-JSON session") from None
    user = (data or {}).get("user") if isinstance(data, dict) else None
    if not isinstance(user, dict) or not user.get("id") or not user.get("email"):
        return None, upstream
    return (
        NeonUser(
            id=str(user["id"]),
            email=str(user["email"]).strip().lower(),
            email_verified=user.get("emailVerified") is True,
            name=user.get("name") or None,
            image=user.get("image") or None,
        ),
        upstream,
    )
