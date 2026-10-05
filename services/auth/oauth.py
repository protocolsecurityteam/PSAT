"""GitHub and Google OAuth (authorization code + PKCE).

``state`` and the PKCE verifier ride in a short-lived HMAC-signed cookie rather than a server table, so a login that
is abandoned leaves nothing behind. Only a provider-verified email is ever returned: accounts link through it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx

STATE_COOKIE = "psat_oauth_state"
STATE_TTL_S = 600
_HTTP_TIMEOUT = 10


class OAuthError(Exception):
    """The provider exchange failed or returned no verified email; the message is safe to show."""


@dataclass(frozen=True)
class Provider:
    name: str
    authorize_url: str
    token_url: str
    scope: str
    env_prefix: str

    @property
    def client_id(self) -> str:
        return os.environ.get(f"{self.env_prefix}_CLIENT_ID", "")

    @property
    def client_secret(self) -> str:
        return os.environ.get(f"{self.env_prefix}_CLIENT_SECRET", "")

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret)


PROVIDERS = {
    "github": Provider(
        name="github",
        authorize_url="https://github.com/login/oauth/authorize",
        token_url="https://github.com/login/oauth/access_token",
        scope="read:user user:email",
        env_prefix="PSAT_GITHUB",
    ),
    "google": Provider(
        name="google",
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        scope="openid email profile",
        env_prefix="PSAT_GOOGLE",
    ),
}


@dataclass(frozen=True)
class VerifiedIdentity:
    subject: str
    email: str
    display_name: str | None
    avatar_url: str | None


def _secret() -> bytes:
    secret = os.environ.get("PSAT_SESSION_SECRET", "")
    if len(secret) < 32:
        raise OAuthError("Sign-in is not configured on this server")
    return secret.encode()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(payload: str) -> str:
    return _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())


def safe_next(path: str | None) -> str:
    # Relative paths only: "//evil.com" and "/\evil.com" are protocol-relative redirects in browsers.
    if not path or not path.startswith("/") or path.startswith(("//", "/\\")):
        return "/"
    return path


def begin(provider: Provider, redirect_uri: str, next_path: str | None) -> tuple[str, str]:
    """Return (provider authorize URL, signed state cookie value)."""
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    params = {
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": provider.scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if provider.name == "google":
        params["prompt"] = "select_account"
    payload = ".".join(
        [provider.name, state, verifier, str(int(time.time()) + STATE_TTL_S), _b64(safe_next(next_path).encode())]
    )
    return f"{provider.authorize_url}?{urlencode(params)}", f"{payload}.{_sign(payload)}"


def _read_state_cookie(provider: Provider, cookie: str | None) -> tuple[str, str, str] | None:
    """(state, PKCE verifier, next path) from an intact, unexpired cookie for this provider; else ``None``."""
    try:
        name, state, verifier, expires, next_b64, sig = (cookie or "").split(".")
        payload = ".".join([name, state, verifier, expires, next_b64])
        if not hmac.compare_digest(sig, _sign(payload)) or name != provider.name or int(expires) < time.time():
            return None
        return state, verifier, base64.urlsafe_b64decode(next_b64 + "=" * (-len(next_b64) % 4)).decode()
    except (ValueError, TypeError):  # bad base64, non-int expiry, non-ASCII digest input
        return None


def check_state(provider: Provider, cookie: str | None, state: str | None) -> tuple[str, str]:
    """Return (PKCE verifier, next path) when the callback's state matches the signed cookie."""
    parsed = _read_state_cookie(provider, cookie)
    if parsed is None:
        raise OAuthError("Sign-in session expired; please try again")
    expected, verifier, next_path = parsed
    if not state or not hmac.compare_digest(state.encode(), expected.encode()):
        raise OAuthError("Sign-in state mismatch; please try again")
    return verifier, safe_next(next_path)


def _token(client: httpx.Client, provider: Provider, code: str, verifier: str, redirect_uri: str) -> str:
    resp = client.post(
        provider.token_url,
        data={
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        headers={"Accept": "application/json"},
    )
    token = resp.json().get("access_token") if resp.is_success else None
    if not token:
        raise OAuthError("The sign-in provider rejected the login")
    return token


def _github_identity(client: httpx.Client, token: str) -> VerifiedIdentity:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    user = client.get("https://api.github.com/user", headers=headers)
    emails = client.get("https://api.github.com/user/emails", headers=headers)
    if not (user.is_success and emails.is_success):
        raise OAuthError("Could not read your GitHub profile")
    profile = user.json()
    primary = next((e for e in emails.json() if e.get("primary") and e.get("verified")), None)
    if primary is None:
        raise OAuthError("Your GitHub account needs a verified primary email")
    return VerifiedIdentity(
        subject=str(profile["id"]),
        email=primary["email"],
        display_name=profile.get("name") or profile.get("login"),
        avatar_url=profile.get("avatar_url"),
    )


def _google_identity(client: httpx.Client, token: str) -> VerifiedIdentity:
    resp = client.get("https://openidconnect.googleapis.com/v1/userinfo", headers={"Authorization": f"Bearer {token}"})
    if not resp.is_success:
        raise OAuthError("Could not read your Google profile")
    info = resp.json()
    if info.get("email_verified") is not True or not info.get("email") or not info.get("sub"):
        raise OAuthError("Your Google account needs a verified email")
    return VerifiedIdentity(
        subject=str(info["sub"]), email=info["email"], display_name=info.get("name"), avatar_url=info.get("picture")
    )


def exchange(provider: Provider, code: str, verifier: str, redirect_uri: str) -> VerifiedIdentity:
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
            token = _token(client, provider, code, verifier, redirect_uri)
            if provider.name == "github":
                return _github_identity(client, token)
            return _google_identity(client, token)
    except httpx.HTTPError:
        raise OAuthError("The sign-in provider is unreachable; please try again") from None
    except (ValueError, KeyError, TypeError):
        raise OAuthError("The sign-in provider returned an unexpected response") from None
