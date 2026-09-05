"""Cloudflare provenance, Access identity, and conservative shared-cache policy.

No provider management credentials or remote configuration writes belong here.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Mapping

import jwt
from fastapi import HTTPException
from jwt import PyJWKClient
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.responses import JSONResponse

PRIVATE = "private, no-store"
PUBLIC_CACHE = "public, max-age=0, s-maxage=60, must-revalidate"
CACHE_PATHS = (
    "/api/company/{company_name}",
    "/api/company/{company_name}/addresses",
    "/api/company/{company_name}/functions",
)
# Everything else under /api (including new routes) is operator-only by default.
PUBLIC_READS = (
    *CACHE_PATHS,
    "/api/health",
    "/api/version",
    "/api/analyses",
    "/api/analyses/{run_name:path}",
    "/api/company/{company_name}/audits",
    "/api/company/{company_name}/audit_coverage",
    "/api/company/{company_name}/score",
    "/api/company/{company_name}/semantic_capabilities",
    "/api/contract/{address}/capabilities",
    "/api/address_labels",
    "/api/audits/{audit_id}",
    "/api/audits/{audit_id}/pdf",
    "/api/audits/{audit_id}/text",
    "/api/audits/{audit_id}/scope",
    "/api/contracts/{contract_id}/audit_timeline",
    "/api/protocols/{protocol_id}/monitoring",
    "/api/protocols/{protocol_id}/events",
    "/api/protocols/{protocol_id}/tvl",
    "/api/monitored-contracts",
    "/api/monitored-events",
)
SAFE_ARTIFACTS = frozenset({"upgrade_history", "dependencies", "dependency_graph_viz", "policy_state"})


def matches(template: str, path: str) -> bool:
    pattern = re.sub(r"\{[^}]+\}", "[^/]+", template)
    return re.fullmatch(pattern, path) is not None


def public_read(method: str, path: str) -> bool:
    if method not in {"GET", "HEAD"}:
        return False
    if path == "/api/audits/pipeline":
        return False
    if path.startswith("/api/analyses/"):
        if "/artifact/" in path:
            artifact = path.rsplit("/artifact/", 1)[1]
            if artifact.endswith((".json", ".txt")):
                artifact = artifact.rsplit(".", 1)[0]
            return artifact.lower() in SAFE_ARTIFACTS
        return True
    return any(matches(template, path) for template in PUBLIC_READS)


@dataclass(frozen=True)
class EdgeConfig:
    mode: str
    secret: str = ""
    issuer: str = ""
    audience: str = ""
    emails: frozenset[str] = frozenset()
    health_secret: str = ""

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> EdgeConfig:
        env = os.environ if env is None else env
        production = env.get("FLY_APP_NAME") == "psat"
        mode = env.get("PSAT_EDGE_MODE", "cloudflare" if production else "local")
        if mode not in {"local", "preview", "cloudflare"} or (production and mode != "cloudflare"):
            raise ValueError("Invalid PSAT_EDGE_MODE for this deployment")
        if env.get("FLY_APP_NAME") and not production and mode == "local":
            raise ValueError("Fly previews must explicitly set PSAT_EDGE_MODE=preview")
        if mode != "cloudflare":
            return cls(mode)
        secret = env.get("PSAT_ORIGIN_SECRET", "")
        issuer = env.get("PSAT_ACCESS_ISSUER", "")
        audience = env.get("PSAT_ACCESS_AUDIENCE", "")
        emails = frozenset(x.strip().lower() for x in env.get("PSAT_ACCESS_EMAILS", "").split(",") if x.strip())
        if not re.fullmatch(r"[a-f0-9]{64}", secret):
            raise ValueError("PSAT_ORIGIN_SECRET must be a random 32-byte hex secret")
        if not re.fullmatch(r"https://[a-z0-9-]+\.cloudflareaccess\.com", issuer):
            raise ValueError("PSAT_ACCESS_ISSUER must be the exact HTTPS team URL")
        if not re.fullmatch(r"[a-f0-9]{64}", audience):
            raise ValueError("PSAT_ACCESS_AUDIENCE must be the operator application's AUD")
        if not emails or any(
            not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e) or e.endswith(".invalid") for e in emails
        ):
            raise ValueError("PSAT_ACCESS_EMAILS must contain the approved operator emails")
        health_secret = env.get("PSAT_HEALTH_SECRET", "")
        if health_secret and (not re.fullmatch(r"[a-f0-9]{64}", health_secret) or health_secret == secret):
            raise ValueError("PSAT_HEALTH_SECRET must be a distinct random 32-byte hex secret")
        return cls(mode, secret, issuer, audience, emails, health_secret)


class BoundedJWKClient(PyJWKClient):
    """Bound unknown-kid floods and outages to one refresh attempt per 5 seconds."""

    next_fetch = 0.0

    def fetch_data(self):
        now = time.monotonic()
        if now < self.next_fetch:
            raise jwt.PyJWKClientError("JWKS refresh cooldown")
        self.next_fetch = now + 5
        return super().fetch_data()


class AccessVerifier:
    def __init__(self, config: EdgeConfig):
        self.config = config
        # No indefinite per-key cache: removed signing keys expire with the set.
        self.jwks = BoundedJWKClient(config.issuer + "/cdn-cgi/access/certs", cache_keys=False, lifespan=300, timeout=3)
        self.lock = threading.Lock()

    def verify(self, token: str) -> dict:
        try:
            if len(token) > 16384:
                raise jwt.InvalidTokenError("Token too long")
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str) or not header["kid"]:
                raise jwt.InvalidTokenError("Invalid signing header")
            # Serialise refreshes; PyJWKClient refreshes once on an unknown kid.
            with self.lock:
                key = self.jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.config.issuer,
                audience=self.config.audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "type", "email"]},
            )
            if any(type(claims[c]) not in (int, float) for c in ("iat", "exp")) or claims["exp"] <= claims["iat"]:
                raise jwt.InvalidTokenError("Invalid token lifetime")
            if claims["type"] != "app" or not isinstance(claims["sub"], str) or not claims["sub"]:
                raise jwt.InvalidTokenError("Human application identity required")
            if not isinstance(claims["email"], str) or claims["email"].lower() not in self.config.emails:
                raise jwt.InvalidTokenError("Operator not allowed")
            return claims
        except (jwt.PyJWTError, ValueError, TypeError, KeyError):
            raise HTTPException(403, "Operator Access required; sign in at /operator/?admin=1") from None


def has_credentials(request: Request) -> bool:
    return any(
        name in request.headers
        for name in (
            "authorization",
            "origin",
            "x-psat-admin-key",
            "cookie",
            "cf-access-jwt-assertion",
            "cf-access-client-id",
            "cf-access-client-secret",
        )
    )


class CloudflareBoundary:
    def __init__(
        self,
        app,
        config: EdgeConfig | None = None,
        verifier: AccessVerifier | None = None,
        rate_limit=None,
        denial_headers: dict[str, str] | None = None,
    ):
        self.app = app
        self.rate_limit = rate_limit
        self.denial_headers = denial_headers or {}
        self.config = config if config is not None else EdgeConfig.from_env()
        self.verifier = verifier or (AccessVerifier(self.config) if self.config.mode == "cloudflare" else None)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        path = scope["path"]
        alias = path.startswith("/operator/api/")
        target = path[len("/operator") :] if alias else path
        operator = (
            alias
            or path == "/operator"
            or path.startswith("/operator/")
            or path == "/monitor"
            or path.startswith("/monitor/")
        )
        operator = operator or target in {"/docs", "/redoc", "/openapi.json"}
        operator = operator or (target.startswith("/api/") and not public_read(request.method, target))
        operator = operator or "x-psat-admin-key" in request.headers or "authorization" in request.headers
        scope.setdefault("state", {})["edge_visitor_ip"] = None

        async def response_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                cacheable = (
                    request.method == "GET"
                    and not operator
                    and not has_credentials(request)
                    and not scope.get("query_string")
                    and message["status"] == 200
                    and any(matches(p, target) for p in CACHE_PATHS)
                    and "set-cookie" not in headers
                    and headers.get("content-type", "").startswith("application/json")
                    and all(
                        v.strip().lower() == "accept-encoding"
                        for v in headers.get("vary", "Accept-Encoding").split(",")
                    )
                )
                if cacheable:
                    headers["Cache-Control"] = PUBLIC_CACHE
                elif target.startswith("/api/") or operator or message["status"] >= 400 or has_credentials(request):
                    headers["Cache-Control"] = PRIVATE
                # Credentials are never response headers.
                for name in (
                    "x-psat-origin-secret",
                    "x-psat-health-secret",
                    "x-psat-visitor-ip",
                    "cf-access-jwt-assertion",
                ):
                    if name in headers:
                        del headers[name]
            await send(message)

        async def deny(detail: str):
            await JSONResponse(
                {"detail": detail}, status_code=403, headers={**self.denial_headers, "Cache-Control": PRIVATE}
            )(scope, receive, response_send)

        health_values = request.headers.getlist("x-psat-health-secret")
        trusted_health = (
            self.config.mode == "cloudflare"
            and bool(self.config.health_secret)
            and request.method == "GET"
            and path == "/api/health"
            and not operator
            and not has_credentials(request)
            and len(health_values) == 1
            and hmac.compare_digest(health_values[0].encode(), self.config.health_secret.encode())
        )
        if trusted_health:
            scope["state"]["edge_visitor_ip"] = "<authenticated-health-check>"
        if self.config.mode == "cloudflare" and not trusted_health:
            values = request.headers.getlist("x-psat-origin-secret")
            if len(values) != 1 or not hmac.compare_digest(values[0].encode(), self.config.secret.encode()):
                await deny("Origin authentication required")
                return
            ips = request.headers.getlist("x-psat-visitor-ip")
            try:
                if len(ips) != 1:
                    raise ValueError("Missing or repeated visitor IP")
                visitor = str(ipaddress.ip_address(ips[0]))
            except ValueError:
                await deny("Trusted visitor IP required")
                return
            scope["state"]["edge_visitor_ip"] = visitor
        # Charge verified visitors before doing cryptography or fetching JWKS.
        if self.rate_limit is not None:
            limited = self.rate_limit(request)
            if limited is not None:
                await limited(scope, receive, response_send)
                return
        if self.config.mode == "cloudflare" and not trusted_health:
            if operator:
                tokens = request.headers.getlist("cf-access-jwt-assertion")
                if len(tokens) > 1:
                    await deny("Operator Access required")
                    return
                token = tokens[0] if tokens else request.cookies.get("CF_Authorization", "")
                try:
                    assert self.verifier is not None
                    scope["state"]["access_identity"] = await run_in_threadpool(self.verifier.verify, token)
                except HTTPException as exc:
                    await deny(exc.detail)
                    return
        if alias:
            scope = dict(scope, path=target, raw_path=target.encode())
        await self.app(scope, receive, response_send)
