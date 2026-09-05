"""Loopback-only simulated edge for Playwright, with the real application boundary.

The explicit clean environment in playwright.cloudflare.config.js is mandatory. All
business data is mocked. Test login and direct-origin prefixes never ship in api.
"""

from __future__ import annotations

import os
import time
from contextlib import nullcontext
from unittest.mock import MagicMock

assert os.environ.get("PYTHON_DOTENV_DISABLED") == "1"
assert os.environ.get("PSAT_CLOUDFLARE_BROWSER_FIXTURE") == "1"

# The existing socket guard also fences any accidentally unmocked provider call.
import jwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from jwt.algorithms import RSAAlgorithm  # noqa: E402
from starlette.responses import RedirectResponse  # noqa: E402

import api  # noqa: E402
import local_netguard  # noqa: E402,F401
from routers import company, deps  # noqa: E402
from utils.edge import AccessVerifier, CloudflareBoundary, EdgeConfig  # noqa: E402

config = EdgeConfig.from_env()
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
jwk.update(kid="browser", use="sig")
verifier = AccessVerifier(config)
assert verifier.jwks.jwk_set_cache is not None
# PyJWKClient stores the decoded JWKS dictionary despite its cache's annotation.
verifier.jwks.jwk_set_cache.put({"keys": [jwk]})  # pyright: ignore[reportArgumentType]
for middleware in api.app.user_middleware:
    if middleware.cls is CloudflareBoundary:
        middleware.kwargs.update(config=config, verifier=verifier)

session = MagicMock()
session.execute.return_value.scalars.return_value.all.return_value = []
deps.SessionLocal = lambda: nullcontext(session)
company.build_company_overview = lambda *_: {"company": "Example", "contracts": [], "ownership_hierarchy": []}


class SimulatedEdge:
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return
        path = scope["path"]
        if path == "/__test_login":
            now = int(time.time())
            token = jwt.encode(
                {
                    "iss": config.issuer,
                    "aud": [config.audience],
                    "iat": now,
                    "exp": now + 300,
                    "sub": "browser-operator",
                    "type": "app",
                    "email": "operator@example.com",
                },
                key,
                algorithm="RS256",
                headers={"kid": "browser"},
            )
            response = RedirectResponse("/operator/?admin=1", status_code=302)
            response.set_cookie("CF_Authorization", token, httponly=True, samesite="lax")
            await response(scope, receive, send)
            return
        scope = dict(scope)
        if path.startswith("/__direct/"):
            scope["path"] = path[len("/__direct") :]
            scope["raw_path"] = scope["path"].encode()
        else:
            # Emulate Transform Rules' overwrite, including forged incoming values.
            scope["headers"] = [
                (k, v) for k, v in scope["headers"] if k.lower() not in {b"x-psat-origin-secret", b"x-psat-visitor-ip"}
            ]
            scope["headers"] += [
                (b"x-psat-origin-secret", config.secret.encode()),
                (b"x-psat-visitor-ip", b"192.0.2.10"),
            ]
        await api.app(scope, receive, send)


app = SimulatedEdge()
