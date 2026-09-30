from __future__ import annotations

import pytest

from tests.live.conftest import DEFAULT_TEST_COMPANY, LiveClient


@pytest.fixture
def _drain_etherfi_queue(live_client: LiveClient):
    """``analyze-remaining`` queues hundreds of rows that would starve later tests on the same preview."""
    yield
    live_client.cancel_queued_company_jobs(DEFAULT_TEST_COMPANY)


def test_analyze_remaining_response_shape(analyzed_company, live_client: LiveClient, _drain_etherfi_queue):
    body = live_client.analyze_remaining(DEFAULT_TEST_COMPANY)
    assert isinstance(body.get("queued"), int)
    assert body["queued"] >= 0
    assert isinstance(body.get("jobs"), list)
    if body["jobs"]:
        first = body["jobs"][0]
        for key in ("job_id", "address"):
            assert key in first, f"queued job entry missing {key!r}: {first}"


def test_analyze_remaining_unknown_company_404(live_client: LiveClient):
    r = live_client._session.post(
        live_client._url("/api/company/psat-unknown-company-xyz/analyze-remaining"),
        timeout=15,
    )
    assert r.status_code == 404, f"unknown company should 404, got {r.status_code}: {r.text[:200]}"


def test_refresh_coverage_returns_count(analyzed_company, live_client: LiveClient):
    body = live_client.refresh_company_coverage(DEFAULT_TEST_COMPANY)
    assert body["company"] == DEFAULT_TEST_COMPANY
    assert isinstance(body.get("protocol_id"), int)
    assert isinstance(body.get("coverage_rows"), int)
    assert body["coverage_rows"] >= 0
    assert body.get("verify_source_equivalence") is False


def test_refresh_coverage_unknown_company_404(live_client: LiveClient):
    r = live_client._session.post(
        live_client._url("/api/company/psat-unknown-company-xyz/refresh_coverage"),
        params={"verify_source_equivalence": "false"},
        timeout=30,
    )
    assert r.status_code == 404, f"unknown company should 404, got {r.status_code}: {r.text[:200]}"


def test_refresh_coverage_idempotent(analyzed_company, live_client: LiveClient):
    """Growth means a dup bug, shrink a race bug."""
    first = live_client.refresh_company_coverage(DEFAULT_TEST_COMPANY)
    second = live_client.refresh_company_coverage(DEFAULT_TEST_COMPANY)
    assert first["coverage_rows"] == second["coverage_rows"], (
        "refresh_coverage is not idempotent: "
        f"first call={first['coverage_rows']} rows, second={second['coverage_rows']} rows"
    )


def test_analyze_remaining_unauth_rejected(live_base_url: str):
    import requests

    r = requests.post(
        live_base_url + f"/api/company/{DEFAULT_TEST_COMPANY}/analyze-remaining",
        timeout=15,
    )
    assert r.status_code in (401, 403), (
        f"unauth POST analyze-remaining should be 401/403, got {r.status_code}: {r.text[:200]}"
    )
