"""Use the same gzip negotiation for live and precompressed responses."""

import math

from starlette.datastructures import Headers
from starlette.middleware.gzip import GZipMiddleware, GZipResponder, IdentityResponder
from starlette.types import ASGIApp, Receive, Scope, Send


def accepts_gzip(value: str) -> bool:
    qualities: dict[str, float] = {}
    for item in value.lower().split(","):
        parts = [p.strip() for p in item.split(";")]
        quality = 1.0
        for parameter in parts[1:]:
            if parameter.startswith("q="):
                try:
                    quality = float(parameter[2:])
                except ValueError:
                    quality = 0.0
        qualities[parts[0]] = quality if math.isfinite(quality) and 0 <= quality <= 1 else 0.0
    return qualities.get("gzip", qualities.get("*", 0.0)) > 0


class NegotiatedGZipMiddleware(GZipMiddleware):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # Starlette's substring test treats gzip;q=0 as consent and would
        # re-compress a prepared response we deliberately decoded for identity.
        responder: ASGIApp
        if accepts_gzip(Headers(scope=scope).get("accept-encoding", "")):
            responder = GZipResponder(self.app, self.minimum_size, compresslevel=self.compresslevel)
        else:
            responder = IdentityResponder(self.app, self.minimum_size)
        await responder(scope, receive, send)
