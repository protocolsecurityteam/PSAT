"""Shared fixtures for the live test suite. See CLAUDE.md for the full writeup."""

from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import pytest
import requests

WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5c4F27eAD9083C756Cc2"

DEFAULT_SINGLE_TIMEOUT = 600
# Company runs on a cold preview (shared-cpu-2x, 2GB RAM) spend ~2 min
# in selection alone because ranking calls Etherscan per candidate and
# inventories grow past 400 rows after the first run. The multichain
# bridge work added in alex/feat-add-multichain extends this further:
# every LayerZero teller spawns per-peer peer-analysis jobs across
# Optimism/Scroll/Base/etc. 60 min covers the new tail; trim it when
# preview scaling or cache behaviour improves.
DEFAULT_COMPANY_TIMEOUT = 3600
DEFAULT_POLL_INTERVAL = 5


def _parse_dt(s: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return datetime.fromisoformat(s)


class LiveClient:
    """Thin wrapper over a deployed PSAT API."""

    def __init__(self, base_url: str, admin_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        self._session.headers.update({"X-PSAT-Admin-Key": admin_key})
        # Retry idempotent reads on transient 5xx. Previews occasionally return
        # a one-shot 500 when a worker commits and the read lands mid-refresh
        # (e.g. ``/api/analyses`` right after a fixture finishes). 3 retries
        # with exponential backoff erase the flake without masking real 5xx.
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        retry = Retry(
            total=3,
            read=3,
            connect=3,
            backoff_factor=0.5,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def health(self, timeout: float = 5) -> requests.Response:
        # Bare requests (no auth) so a bad admin key doesn't mask reachability.
        return requests.get(self._url("/api/health"), timeout=timeout)

    def is_healthy(self) -> bool:
        try:
            return self.health().status_code == 200
        except requests.RequestException:
            return False

    def config(self) -> dict[str, Any]:
        r = self._session.get(self._url("/api/config"), timeout=15)
        r.raise_for_status()
        return r.json()

    def stats(self) -> dict[str, Any]:
        r = self._session.get(self._url("/api/stats"), timeout=15)
        r.raise_for_status()
        return r.json()

    # -- analyze -------------------------------------------------------------

    def analyze(self, address: str) -> dict[str, Any]:
        r = self._session.post(self._url("/api/analyze"), json={"address": address}, timeout=15)
        r.raise_for_status()
        return r.json()

    def analyze_company(self, company: str, limit: int = 2) -> dict[str, Any]:
        r = self._session.post(
            self._url("/api/analyze"),
            json={"company": company, "analyze_limit": limit},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def analyze_remaining(self, company: str) -> dict[str, Any]:
        r = self._session.post(
            self._url(f"/api/company/{company}/analyze-remaining"),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def cancel_queued_company_jobs(self, company: str) -> dict[str, Any]:
        """Delete every ``queued`` job tagged to *company*; teardown for analyze-remaining."""
        r = self._session.delete(
            self._url(f"/api/company/{company}/queued-jobs"),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def refresh_company_coverage(self, company: str, verify_source_equivalence: bool = False) -> dict[str, Any]:
        # Skip the per-file Etherscan equivalence pass — rate-limited, irrelevant to row count.
        r = self._session.post(
            self._url(f"/api/company/{company}/refresh_coverage"),
            params={"verify_source_equivalence": str(verify_source_equivalence).lower()},
            timeout=120,
        )
        r.raise_for_status()
        return r.json()

    def reextract_audit_scope(self, audit_id: int) -> requests.Response:
        # Raw Response so callers can inspect 409 (text extraction not complete).
        return self._session.post(self._url(f"/api/audits/{audit_id}/reextract_scope"), timeout=15)

    # -- reads ---------------------------------------------------------------

    def job(self, job_id: str) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/jobs/{job_id}"), timeout=15)
        r.raise_for_status()
        return r.json()

    def jobs(self) -> list[dict[str, Any]]:
        r = self._session.get(self._url("/api/jobs"), timeout=15)
        r.raise_for_status()
        return r.json()

    def children_of(self, parent_job_id: str) -> list[dict[str, Any]]:
        return [j for j in self.jobs() if (j.get("request") or {}).get("parent_job_id") == parent_job_id]

    def artifact(self, run_name: str, artifact_name: str) -> dict | str | None:
        """Fetch an artifact. Returns dict for JSON, None on 404."""
        r = self._session.get(
            self._url(f"/api/analyses/{run_name}/artifact/{artifact_name}.json"),
            timeout=15,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()

    def analyses(self) -> list[dict[str, Any]]:
        r = self._session.get(self._url("/api/analyses"), timeout=15)
        r.raise_for_status()
        return r.json()

    def analysis_detail(self, run_name: str) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/analyses/{run_name}"), timeout=15)
        r.raise_for_status()
        return r.json()

    # -- company -------------------------------------------------------------

    def company_overview(self, company: str) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/company/{company}"), timeout=30)
        r.raise_for_status()
        return r.json()

    def list_company_audits(self, company: str) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/company/{company}/audits"), timeout=15)
        r.raise_for_status()
        return r.json()

    # -- address labels ------------------------------------------------------

    def list_address_labels(self) -> dict[str, Any]:
        r = self._session.get(self._url("/api/address_labels"), timeout=15)
        r.raise_for_status()
        return r.json()

    def put_address_label(self, address: str, payload: dict[str, Any]) -> dict[str, Any]:
        r = self._session.put(self._url(f"/api/address_labels/{address}"), json=payload, timeout=15)
        r.raise_for_status()
        return r.json()

    def delete_address_label(self, address: str) -> dict[str, Any]:
        r = self._session.delete(self._url(f"/api/address_labels/{address}"), timeout=15)
        r.raise_for_status()
        return r.json()

    # -- monitoring ----------------------------------------------------------

    def list_monitored_events(self, limit: int = 50) -> list[dict[str, Any]]:
        r = self._session.get(self._url("/api/monitored-events"), params={"limit": limit}, timeout=15)
        r.raise_for_status()
        return r.json()

    def contract_audit_timeline(self, contract_id: int) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/contracts/{contract_id}/audit_timeline"), timeout=30)
        r.raise_for_status()
        return r.json()

    def audit_text(self, audit_id: int) -> requests.Response:
        # Raw Response so tests can distinguish 200 / 409 (in progress) / 503 (storage down).
        return self._session.get(self._url(f"/api/audits/{audit_id}/text"), timeout=30)

    def audit_pdf(self, audit_id: int) -> requests.Response:
        return self._session.get(self._url(f"/api/audits/{audit_id}/pdf"), timeout=60)

    # -- audits --------------------------------------------------------------

    def add_audit(self, company: str, payload: dict[str, Any]) -> dict[str, Any]:
        r = self._session.post(
            self._url(f"/api/company/{company}/audits"),
            json=payload,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def get_audit(self, audit_id: int) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/audits/{audit_id}"), timeout=15)
        r.raise_for_status()
        return r.json()

    def audit_scope(self, audit_id: int) -> requests.Response:
        # Raw Response so callers can inspect 409 ("not ready yet").
        return self._session.get(self._url(f"/api/audits/{audit_id}/scope"), timeout=15)

    def delete_audit(self, audit_id: int) -> dict[str, Any]:
        r = self._session.delete(self._url(f"/api/audits/{audit_id}"), timeout=15)
        r.raise_for_status()
        return r.json()

    def audits_pipeline(self) -> dict[str, Any]:
        r = self._session.get(self._url("/api/audits/pipeline"), timeout=15)
        r.raise_for_status()
        return r.json()

    def company_audit_coverage(self, company: str) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/company/{company}/audit_coverage"), timeout=15)
        r.raise_for_status()
        return r.json()

    def poll_audit_until_scope(
        self,
        audit_id: int,
        timeout: float = DEFAULT_COMPANY_TIMEOUT,
        interval: float = DEFAULT_POLL_INTERVAL * 2,
    ) -> dict[str, Any]:
        """Poll the audit row until scope extraction reaches success/failed.

        Also bails out early if text extraction failed: the scope worker only
        claims rows where ``text_extraction_status == 'success'``
        (workers/audit_scope_extraction.py), so a transient PDF-download
        failure would otherwise stall the poll for the full timeout.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            row = self.get_audit(audit_id)
            if row.get("scope_extraction_status") in ("success", "failed"):
                return row
            if row.get("text_extraction_status") == "failed":
                return row
            time.sleep(interval)
        raise TimeoutError(f"Audit {audit_id} did not finish scope extraction within {timeout}s")

    # -- monitored contracts (PATCH) ----------------------------------------

    def list_monitored_contracts(
        self,
        protocol_id: int | None = None,
        chain: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {}
        if protocol_id is not None:
            params["protocol_id"] = protocol_id
        if chain is not None:
            params["chain"] = chain
        r = self._session.get(self._url("/api/monitored-contracts"), params=params, timeout=15)
        r.raise_for_status()
        return r.json()

    def patch_monitored_contract(self, contract_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        r = self._session.patch(
            self._url(f"/api/monitored-contracts/{contract_id}"),
            json=payload,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    # -- protocol monitoring -------------------------------------------------

    def protocol_monitoring(self, protocol_id: int) -> list[dict[str, Any]]:
        r = self._session.get(self._url(f"/api/protocols/{protocol_id}/monitoring"), timeout=15)
        r.raise_for_status()
        return r.json()

    def upsert_protocol_monitoring(self, protocol_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        r = self._session.post(
            self._url(f"/api/protocols/{protocol_id}/monitoring"),
            json=payload,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def protocol_subscriptions(self, protocol_id: int) -> list[dict[str, Any]]:
        r = self._session.get(self._url(f"/api/protocols/{protocol_id}/subscriptions"), timeout=15)
        r.raise_for_status()
        return r.json()

    def protocol_events(self, protocol_id: int, limit: int = 50) -> list[dict[str, Any]]:
        r = self._session.get(self._url(f"/api/protocols/{protocol_id}/events"), params={"limit": limit}, timeout=15)
        r.raise_for_status()
        return r.json()

    def protocol_tvl(self, protocol_id: int, days: int = 30) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/protocols/{protocol_id}/tvl"), params={"days": days}, timeout=30)
        r.raise_for_status()
        return r.json()

    def re_enroll_protocol(self, protocol_id: int, chain: str = "ethereum") -> dict[str, Any]:
        # Hits live RPC + classifier; generous timeout for cold previews.
        r = self._session.post(
            self._url(f"/api/protocols/{protocol_id}/re-enroll"),
            params={"chain": chain},
            timeout=120,
        )
        r.raise_for_status()
        return r.json()

    def subscribe_protocol(self, protocol_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        r = self._session.post(
            self._url(f"/api/protocols/{protocol_id}/subscribe"),
            json=payload,
            timeout=15,
        )
        r.raise_for_status()
        return r.json()

    def delete_protocol_subscription(self, sub_id: str) -> dict[str, Any]:
        r = self._session.delete(self._url(f"/api/protocol-subscriptions/{sub_id}"), timeout=15)
        r.raise_for_status()
        return r.json()

    # -- polling -------------------------------------------------------------

    def poll_job_until_done(
        self,
        job_id: str,
        timeout: float = DEFAULT_SINGLE_TIMEOUT,
        interval: float = DEFAULT_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """Poll ``/api/jobs/{id}`` until status is terminal or timeout fires.

        ``failed_terminal`` is a distinct ``JobStatus`` enum value introduced
        for deterministic-from-the-start failures (and retry-exhausted
        transient failures); it is just as terminal as ``completed`` /
        ``failed``. Treating it as non-terminal keeps the loop alive
        forever and times out on rows that already settled.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self.job(job_id)
            if status["status"] in ("completed", "failed", "failed_terminal"):
                return status
            time.sleep(interval)
        raise TimeoutError(f"Job {job_id} did not reach a terminal status within {timeout}s")

    def poll_children_until_done(
        self,
        parent_job_id: str,
        timeout: float = DEFAULT_COMPANY_TIMEOUT,
        interval: float = DEFAULT_POLL_INTERVAL * 2,
    ) -> list[dict[str, Any]]:
        """Poll ``/api/jobs`` until every child of *parent_job_id* is terminal."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            children = self.children_of(parent_job_id)
            if children and all(c["status"] in ("completed", "failed", "failed_terminal") for c in children):
                return children
            time.sleep(interval)
        return self.children_of(parent_job_id)

    # -- utilities -----------------------------------------------------------

    @staticmethod
    def job_duration_seconds(job: dict[str, Any]) -> float:
        return (_parse_dt(job["updated_at"]) - _parse_dt(job["created_at"])).total_seconds()

    @staticmethod
    def job_window(job: dict[str, Any]) -> tuple[datetime, datetime]:
        """Return the (created_at, updated_at) datetimes for a job."""
        return _parse_dt(job["created_at"]), _parse_dt(job["updated_at"])

    def submit_and_wait(
        self,
        address: str,
        timeout: float = DEFAULT_SINGLE_TIMEOUT,
    ) -> dict[str, Any]:
        return self.poll_job_until_done(self.analyze(address)["job_id"], timeout=timeout)

    def submit_company_and_wait(
        self,
        company: str,
        limit: int = 2,
        timeout: float = DEFAULT_COMPANY_TIMEOUT,
    ) -> dict[str, Any]:
        return self.poll_job_until_done(
            self.analyze_company(company, limit=limit)["job_id"],
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
# Pytest hooks / fixtures
# ---------------------------------------------------------------------------


# Files whose tests are provably read-only AND environment-agnostic — i.e. their
# assertions don't depend on preview-specific config or pre-existing prod state.
# These get @pytest.mark.smoke so `pytest -m "live and smoke"` can run against
# prod post-deploy without touching real data and without false positives from
# unrelated drift.
#
# Audited 2026-04-24:
# - test_health.py: pure GETs (/api/health, /api/config, /api/stats, /, /assets)
# - test_monitoring_reads.py: GET monitoring/event/proxy-event lists, shape-only
# - test_auth_and_errors.py: 4 tests; 2 GETs, 2 POSTs that 401/400 BEFORE any
#   DB write (admin-key dependency + 0x-prefix check both run pre-handler-body)
#
# Deliberately excluded from smoke (still run on PR previews via `live` marker):
# - test_cors.py: asserts ACAO == preview's own origin; prod uses a custom origin
# - test_pipeline_health.py: flags wedged jobs, which is pre-existing state, not
#   a deploy regression — would cause false rollbacks
SMOKE_SAFE_FILES = {
    "test_health.py",
    "test_monitoring_reads.py",
    "test_auth_and_errors.py",
}


def pytest_collection_modifyitems(config, items):
    """Auto-tag every test under ``tests/live/`` with @pytest.mark.live;
    tag the read-only subset with @pytest.mark.smoke as well."""
    live_mark = pytest.mark.live
    smoke_mark = pytest.mark.smoke
    for item in items:
        path = str(item.fspath)
        if "/tests/live/" not in path and "\\tests\\live\\" not in path:
            continue
        item.add_marker(live_mark)
        if os.path.basename(path) in SMOKE_SAFE_FILES:
            item.add_marker(smoke_mark)


@pytest.fixture(scope="session")
def live_base_url() -> str:
    return os.environ.get("PSAT_LIVE_URL", "http://127.0.0.1:8000").rstrip("/")


@pytest.fixture(scope="session")
def live_admin_key() -> str:
    key = os.environ.get("PSAT_ADMIN_KEY", "")
    if not key:
        pytest.skip("PSAT_ADMIN_KEY not set (required for POST /api/analyze)")
    return key


@pytest.fixture(scope="session")
def live_client(live_base_url: str, live_admin_key: str) -> LiveClient:
    return LiveClient(live_base_url, live_admin_key)


@pytest.fixture(scope="session", autouse=True)
def _require_live_api(live_client: LiveClient):
    """Health-gate the entire live suite once per session."""
    if not live_client.is_healthy():
        pytest.skip(f"API not reachable at {live_client.base_url}")


@pytest.fixture(scope="session")
def analyzed_weth(live_client: LiveClient) -> dict[str, Any]:
    """Submit WETH once per session; dependent tests reuse the result."""
    job = live_client.submit_and_wait(WETH_ADDRESS)
    if job["status"] != "completed":
        pytest.fail(f"WETH analysis did not complete on {live_client.base_url}: {job.get('error')}")
    return job


@pytest.fixture(scope="session")
def cached_weth(analyzed_weth, live_client: LiveClient) -> dict[str, Any]:
    """Second WETH submission — exercised by test_cache.py to verify the static cache.

    Session-scoped and ordered before ``analyzed_company`` so the cache-hit run
    doesn't queue behind etherfi child analyses on contended previews. A real
    incident saw this submission sit 12min in worker queues behind concurrent
    company children before completing; with this ordering it finishes in seconds.
    """
    job = live_client.submit_and_wait(WETH_ADDRESS)
    if job["status"] != "completed":
        pytest.fail(f"Cached WETH run did not complete on {live_client.base_url}: {job.get('error')}")
    return job


@pytest.fixture
def analyze_and_wait(live_client: LiveClient):
    """Factory for tests that need their own fresh analysis of an address."""

    def _fn(address: str, timeout: float = DEFAULT_SINGLE_TIMEOUT) -> dict[str, Any]:
        return live_client.submit_and_wait(address, timeout=timeout)

    return _fn


# Shared with test_cache.py so its inventory is warm. Queue two candidates so
# one terminal source/discovery failure does not make every company test fail.
DEFAULT_TEST_COMPANY = "etherfi"
DEFAULT_TEST_COMPANY_LIMIT = 2


@pytest.fixture(scope="session")
def analyzed_company(cached_weth, live_client: LiveClient) -> dict[str, Any]:
    """Ensure a Protocol row exists for ``DEFAULT_TEST_COMPANY`` (else POSTs 404).

    Depends on ``cached_weth`` so the WETH cache-hit submission completes
    before company children start saturating per-stage workers.
    """
    parent = live_client.submit_company_and_wait(DEFAULT_TEST_COMPANY, limit=DEFAULT_TEST_COMPANY_LIMIT)
    if parent["status"] != "completed":
        pytest.fail(
            f"Company fixture for '{DEFAULT_TEST_COMPANY}' did not complete "
            f"on {live_client.base_url}: {parent.get('error')}"
        )
    children = live_client.poll_children_until_done(parent["job_id"])
    completed = [child for child in children if child["status"] == "completed"]
    if not completed:
        jobs = live_client.jobs()
        child_ids = {child["job_id"] for child in children}
        descendants = [job for job in jobs if (job.get("request") or {}).get("parent_job_id") in child_ids]
        completed = [job for job in descendants if job.get("status") == "completed"]
    if not completed:
        pytest.fail(
            f"Company fixture for '{DEFAULT_TEST_COMPANY}' produced no completed child jobs "
            f"on {live_client.base_url}: statuses={[child.get('status') for child in children]}"
        )
    return parent


@pytest.fixture(scope="session")
def company_protocol_id(analyzed_company, live_client: LiveClient) -> int:
    """Resolve Protocol.id for the test company via GET — doubles as an upsert sanity check."""
    overview = live_client.company_overview(DEFAULT_TEST_COMPANY)
    pid = overview.get("protocol_id")
    if not isinstance(pid, int):
        pytest.fail(
            f"Company '{DEFAULT_TEST_COMPANY}' has no Protocol row after analysis "
            f"(overview.protocol_id={pid!r}); cannot exercise protocol endpoints."
        )
    return pid
