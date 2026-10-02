from __future__ import annotations

import re

import pytest
import requests

from tests.live.conftest import LiveClient


def test_health_reports_ok(public_live_client: LiveClient):
    r = public_live_client.health()
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("status") == "ok"
    assert body.get("db") == "ok"
    # "inline" is legacy Postgres-only storage.
    assert body.get("storage") in ("ok", "inline")


def test_stats_returns_counts(live_client: LiveClient):
    body = live_client.stats()
    for key in ("unique_addresses", "total_jobs", "completed_jobs", "failed_jobs"):
        assert key in body, f"Missing {key} in /api/stats response"
        assert isinstance(body[key], int)
        assert body[key] >= 0


def test_spa_fallback_serves_frontend(live_base_url: str):
    r = requests.get(live_base_url + "/", timeout=15)
    assert r.status_code == 200, r.text
    ctype = r.headers.get("Content-Type", "")
    assert "html" in ctype.lower() or "text/plain" in ctype.lower(), (
        f"Root path should return HTML (or the build-not-found text fallback), got {ctype!r}"
    )


def test_frontend_assets_served(live_base_url: str):
    html = requests.get(live_base_url + "/", timeout=15).text
    m = re.search(r"/assets/([\w.\-]+\.js)", html)
    if not m:
        pytest.skip("no JS asset URL found in frontend HTML (likely no built frontend)")
    asset_path = "/assets/" + m.group(1)
    r = requests.get(live_base_url + asset_path, timeout=15)
    assert r.status_code == 200, f"asset {asset_path} returned {r.status_code}"
    ctype = r.headers.get("Content-Type", "")
    assert ctype.startswith(("application/javascript", "text/javascript")), (
        f"asset {asset_path} served with non-JS content-type {ctype!r}"
    )
