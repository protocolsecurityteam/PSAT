"""CORS enforcement. Raw requests throughout — the wrapper's auth header and raise-for-status both get in the way."""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest
import requests

ATTACKER_ORIGIN = "https://attacker.example"


def _expected_allowed_origin(live_base_url: str) -> str:
    parsed = urlparse(live_base_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def test_cors_rejects_attacker_origin(live_base_url: str):
    r = requests.options(
        live_base_url + "/api/stats",
        headers={
            "Origin": ATTACKER_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
        timeout=15,
    )
    allowed = r.headers.get("Access-Control-Allow-Origin")
    assert allowed not in (ATTACKER_ORIGIN, "*"), (
        f"CORS echoed attacker origin: ACAO={allowed!r}; "
        f"PSAT_SITE_ORIGIN may be misconfigured (set to '*' or echoing arbitrary origins)"
    )


def test_cors_allows_configured_origin(live_base_url: str):
    expected = os.environ.get("PSAT_LIVE_SITE_ORIGIN", "").rstrip("/")
    if not expected:
        expected = _expected_allowed_origin(live_base_url)
    if not (expected.endswith(".fly.dev") or expected.endswith(".flycast")):
        pytest.skip(
            f"origin {expected} is not a Fly preview; PSAT_SITE_ORIGIN is only guaranteed for preview deployments"
        )

    r = requests.options(
        live_base_url + "/api/stats",
        headers={
            "Origin": expected,
            "Access-Control-Request-Method": "GET",
        },
        timeout=15,
    )
    allowed = r.headers.get("Access-Control-Allow-Origin")
    assert allowed == expected, (
        f"expected ACAO={expected!r}, got {allowed!r}; PSAT_SITE_ORIGIN is "
        "either unset or doesn't include the preview's own origin"
    )
