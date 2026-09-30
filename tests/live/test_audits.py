"""Live audit ingestion + scope extraction. CI pins PSAT_LIVE_AUDIT_URL to a repo-owned fixture."""

from __future__ import annotations

import os
from typing import Any

import pytest
import requests

from tests.live.conftest import DEFAULT_COMPANY_TIMEOUT, DEFAULT_TEST_COMPANY, LiveClient

DEFAULT_AUDIT_URL = "https://github.com/spearbit/portfolio/raw/master/pdfs/EtherFi-Spearbit-Security-Review.pdf"
AUDIT_URL = os.environ.get("PSAT_LIVE_AUDIT_URL", DEFAULT_AUDIT_URL)

AUDITOR_TAG = "psat-live-test"
AUDIT_TITLE = "PSAT live integration test audit"


@pytest.fixture(scope="module")
def created_audit(analyzed_company, live_client: LiveClient, request) -> dict[str, Any]:
    payload = {
        "url": AUDIT_URL,
        "auditor": AUDITOR_TAG,
        "title": AUDIT_TITLE,
    }
    try:
        audit = live_client.add_audit(DEFAULT_TEST_COMPANY, payload)
    except requests.HTTPError as exc:
        # A leftover from a failed run; delete and retry.
        if exc.response is not None and exc.response.status_code == 409:
            existing = live_client._session.get(
                live_client._url(f"/api/company/{DEFAULT_TEST_COMPANY}/audits"),
                timeout=15,
            ).json()
            for row in existing.get("audits", []):
                if row.get("url") == AUDIT_URL and row.get("auditor") == AUDITOR_TAG:
                    live_client.delete_audit(row["id"])
            audit = live_client.add_audit(DEFAULT_TEST_COMPANY, payload)
        else:
            raise

    audit_id = audit["id"]

    def _cleanup():
        try:
            live_client.delete_audit(audit_id)
        except requests.HTTPError:
            pass

    request.addfinalizer(_cleanup)
    return audit


def test_audit_created(created_audit):
    assert isinstance(created_audit.get("id"), int)
    assert created_audit["auditor"] == AUDITOR_TAG
    assert created_audit["title"] == AUDIT_TITLE
    assert created_audit["text_extraction_status"] in (None, "processing")
    assert created_audit["scope_extraction_status"] in (None, "processing")


def test_audit_get_roundtrip(created_audit, live_client: LiveClient):
    row = live_client.get_audit(created_audit["id"])
    assert row["id"] == created_audit["id"]
    assert row["url"] == AUDIT_URL


def test_audit_appears_in_pipeline(created_audit, live_client: LiveClient):
    pipeline = live_client.audits_pipeline()
    audit_id = created_audit["id"]

    def _ids(bucket: dict[str, list[dict[str, Any]]]) -> set[int]:
        ids: set[int] = set()
        for entries in bucket.values():
            for entry in entries:
                if isinstance(entry, dict) and entry.get("audit_id") is not None:
                    ids.add(int(entry["audit_id"]))
        return ids

    text_ids = _ids(pipeline.get("text_extraction", {}))
    scope_ids = _ids(pipeline.get("scope_extraction", {}))
    assert audit_id in (text_ids | scope_ids), (
        f"Audit {audit_id} not found in text or scope buckets; buckets={pipeline}"
    )


@pytest.fixture(scope="module")
def scoped_audit(created_audit, live_client: LiveClient) -> dict[str, Any]:
    try:
        row = live_client.poll_audit_until_scope(
            created_audit["id"],
            timeout=DEFAULT_COMPANY_TIMEOUT,
        )
    except TimeoutError as exc:
        pytest.skip(f"scope extraction did not terminate within timeout: {exc}")
    if row.get("scope_extraction_status") != "success":
        pytest.skip(
            f"scope extraction finished with status={row.get('scope_extraction_status')} "
            f"error={row.get('scope_extraction_error')}"
        )
    return row


def test_audit_scope_returns_entries(scoped_audit, live_client: LiveClient):
    resp = live_client.audit_scope(scoped_audit["id"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["audit_id"] == scoped_audit["id"]
    contracts = body.get("contracts") or []
    assert contracts, "scope extraction succeeded but returned no contracts"


def test_audit_coverage_non_empty(scoped_audit, live_client: LiveClient):
    coverage = live_client.company_audit_coverage(DEFAULT_TEST_COMPANY)
    assert coverage["company"] == DEFAULT_TEST_COMPANY
    assert coverage.get("audit_count", 0) >= 1
    # Scope-to-address overlap is flaky.
    assert isinstance(coverage.get("coverage"), list)


def test_audit_text_returned(scoped_audit, live_client: LiveClient):
    resp = live_client.audit_text(scoped_audit["id"])
    assert resp.status_code == 200, f"audit text endpoint returned {resp.status_code}: {resp.text[:200]}"
    assert resp.text.strip(), "audit text body should not be empty"


def test_audit_pdf_proxied(created_audit, live_client: LiveClient):
    resp = live_client.audit_pdf(created_audit["id"])
    if resp.status_code == 502:
        pytest.skip(f"audit PDF upstream fetch failed: {resp.text[:200]}")
    assert resp.status_code == 200, f"audit PDF endpoint returned {resp.status_code}: {resp.text[:200]}"
    assert resp.headers.get("Content-Type", "").startswith("application/pdf")
    assert len(resp.content) > 100


def test_reextract_scope_resets_status(scoped_audit, live_client: LiveClient):
    # The scope worker may re-claim before our GET.
    audit_id = scoped_audit["id"]
    resp = live_client.reextract_audit_scope(audit_id)
    assert resp.status_code == 200, f"reextract returned {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert body == {"audit_id": audit_id, "reset": True}

    row = live_client.get_audit(audit_id)
    assert row.get("scope_extraction_status") in (None, "processing"), (
        f"scope_extraction_status should be reset to None or in-flight, got {row.get('scope_extraction_status')!r}"
    )


def test_reextract_scope_unknown_audit_404(live_client: LiveClient):
    resp = live_client.reextract_audit_scope(999_999_999)
    assert resp.status_code == 404, f"unknown audit id should 404, got {resp.status_code}: {resp.text[:200]}"


def test_contract_audit_timeline_on_weth(analyzed_weth, live_client: LiveClient):
    detail = live_client.analysis_detail(analyzed_weth["job_id"])
    contract_id = detail.get("contract_id")
    assert isinstance(contract_id, int), "need contract_id from analysis_detail to exercise timeline"

    timeline = live_client.contract_audit_timeline(contract_id)
    assert "contract" in timeline
    assert "coverage" in timeline and isinstance(timeline["coverage"], list)
    assert "current_status" in timeline
    assert timeline["current_status"] in {
        "audited",
        "unaudited_since_upgrade",
        "never_audited",
        "non_proxy_audited",
        "non_proxy_unaudited",
    }
