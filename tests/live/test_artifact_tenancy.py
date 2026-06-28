"""Cross-PR artifact tenancy: per-PR Neon DBs isolate run_name lookups even on a shared bucket."""

from __future__ import annotations

import os
import re

import pytest
import requests

from tests.live.conftest import LiveClient

_PR_HOST_RE = re.compile(r"https?://psat-pr-(\d+)\.fly\.dev", re.IGNORECASE)


def _other_pr_base_url(self_url: str) -> str | None:
    m = _PR_HOST_RE.match(self_url.rstrip("/"))
    if not m:
        return None
    self_pr = m.group(1)
    other_pr = os.environ.get("PSAT_LIVE_OTHER_PR", "").strip()
    if not other_pr or other_pr == self_pr:
        return None
    return f"https://psat-pr-{other_pr}.fly.dev"


def _first_listed_run_name(base_url: str) -> str | None:
    try:
        r = requests.get(base_url + "/api/analyses", timeout=15)
        r.raise_for_status()
    except requests.RequestException:
        return None
    for entry in r.json():
        run_name = entry.get("run_name")
        if isinstance(run_name, str) and run_name:
            return run_name
    return None


def test_other_prs_artifacts_not_readable(live_client: LiveClient, live_base_url: str, live_admin_key: str):
    other_url = _other_pr_base_url(live_base_url)
    if other_url is None:
        pytest.skip(
            "no second preview available; set PSAT_LIVE_OTHER_PR=<pr_number> to enable cross-PR tenancy verification"
        )

    other_run = _first_listed_run_name(other_url)
    if not other_run:
        pytest.skip(f"no analyses listed on {other_url} to use as a tenancy probe")

    # Confirm the probe artifact is actually served on the other PR, else the negative below is moot.
    # contract_analysis is operator-gated, so the probe authenticates — the same posture as the own-PR
    # read below, so the 200-vs-404 contrast isolates DB tenancy, not auth. Previews share one admin key.
    other_resp = requests.get(
        f"{other_url}/api/analyses/{other_run}/artifact/contract_analysis.json",
        headers={"X-PSAT-Admin-Key": live_admin_key},
        timeout=15,
    )
    if other_resp.status_code != 200:
        pytest.skip(
            f"other PR's artifact at {other_url}/api/analyses/{other_run}/... "
            f"returned {other_resp.status_code}; cannot use as tenancy probe"
        )

    own_resp = live_client._session.get(
        live_client._url(f"/api/analyses/{other_run}/artifact/contract_analysis.json"),
        timeout=15,
    )
    assert own_resp.status_code == 404, (
        f"cross-PR artifact leak: {live_base_url}/api/analyses/{other_run}/... "
        f"returned {own_resp.status_code} (expected 404). "
        "Tenancy isolation is broken — either the DB is shared across previews "
        "or the API is bypassing the DB lookup and hitting storage directly."
    )
