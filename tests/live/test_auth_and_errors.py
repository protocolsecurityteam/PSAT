"""Auth enforcement + error-response contracts. Raw requests: tests need to inspect non-2xx codes."""

from __future__ import annotations

import requests


def test_analyze_without_admin_key_rejected(live_base_url: str):
    r = requests.post(
        live_base_url + "/api/analyze",
        json={"address": "0x" + "a" * 40},
        timeout=15,
    )
    assert r.status_code in (401, 403), f"unauth POST /api/analyze returned {r.status_code}: {r.text}"


def test_analyze_malformed_address_rejected(live_base_url: str, live_admin_key: str):
    # 42 chars (passes the length bound) but no 0x prefix — fails the
    # AnalyzeRequest field validator, so FastAPI rejects at the schema layer
    # with a standard 422 before the handler runs. That schema-layer contract
    # is what we pin here.
    bad_address = "ab" + "c" * 40
    assert len(bad_address) == 42 and not bad_address.startswith("0x")
    r = requests.post(
        live_base_url + "/api/analyze",
        json={"address": bad_address},
        headers={"X-PSAT-Admin-Key": live_admin_key},
        timeout=15,
    )
    assert r.status_code == 422, f"malformed address should 422, got {r.status_code}: {r.text}"


def test_unknown_job_id_returns_404(live_base_url: str, live_admin_key: str):
    # The job read is operator-gated: an anonymous caller gets 401; a valid key
    # reaches the handler, where a non-existent id is the 404 we're pinning.
    missing_id = "00000000-0000-0000-0000-000000000000"
    url = live_base_url + f"/api/jobs/{missing_id}"

    anon = requests.get(url, timeout=15)
    assert anon.status_code == 401, f"gated job read without key should 401, got {anon.status_code}: {anon.text}"

    r = requests.get(url, headers={"X-PSAT-Admin-Key": live_admin_key}, timeout=15)
    assert r.status_code == 404, f"unknown job_id should 404, got {r.status_code}: {r.text}"


def test_unknown_run_name_returns_404(live_base_url: str, live_admin_key: str):
    # Artifact reads split by name: consumer-safe names stay public, every other
    # name is operator-gated before any lookup. Either way an authorized caller
    # gets a 404 for a missing run — that not-found contract is what we pin here.
    base = live_base_url + "/api/analyses/psat-live-test-unknown-run/artifact/"
    gated = base + "static_facts.json"

    # Consumer-safe name: no key needed; an unknown run is a clean 404, not a leak.
    pub = requests.get(base + "dependencies.json", timeout=15)
    assert pub.status_code == 404, f"public artifact, unknown run should 404, got {pub.status_code}: {pub.text}"

    # Gated name without a key: 401 before the lookup runs (no existence signal).
    anon = requests.get(gated, timeout=15)
    assert anon.status_code == 401, f"gated artifact without key should 401, got {anon.status_code}: {anon.text}"

    # Gated name with a key: reaches the lookup, where the unknown run is a 404.
    r = requests.get(gated, headers={"X-PSAT-Admin-Key": live_admin_key}, timeout=15)
    assert r.status_code == 404, f"gated artifact, unknown run should 404, got {r.status_code}: {r.text}"
