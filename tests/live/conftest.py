from __future__ import annotations

import os
import time
from datetime import datetime
from typing import Any

import pytest
import requests

WETH_ADDRESS = "0xC02aaA39b223FE8D0A0e5c4F27eAD9083C756Cc2"

# These bound worker-side job completion, not the polling HTTP calls. Starved CI workers stretch ~3 min jobs well past
# 10 min; override via PSAT_LIVE_SINGLE_TIMEOUT / PSAT_LIVE_COMPANY_TIMEOUT.
DEFAULT_SINGLE_TIMEOUT = int(os.environ.get("PSAT_LIVE_SINGLE_TIMEOUT", "1800"))
# Cold-preview company runs spend minutes in selection alone.
DEFAULT_COMPANY_TIMEOUT = int(os.environ.get("PSAT_LIVE_COMPANY_TIMEOUT", "3600"))
DEFAULT_POLL_INTERVAL = 5


def _parse_dt(s: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return datetime.fromisoformat(s)


class LiveClient:
    def __init__(self, base_url: str, admin_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = requests.Session()
        if admin_key:
            self._session.headers.update({"X-PSAT-Admin-Key": admin_key})
        # Preparation has its own bounded retry loop, without adapter retries.
        self._company_session = requests.Session()
        self._company_session.headers.update(self._session.headers)
        # Previews occasionally 500 once when a read lands mid-refresh.
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
        # No auth, so a bad admin key doesn't mask reachability.
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
        r = self._session.delete(
            self._url(f"/api/company/{company}/queued-jobs"),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def refresh_company_coverage(self, company: str, verify_source_equivalence: bool = False) -> dict[str, Any]:
        # The Etherscan equivalence pass is rate-limited and irrelevant to row count.
        r = self._session.post(
            self._url(f"/api/company/{company}/refresh_coverage"),
            params={"verify_source_equivalence": str(verify_source_equivalence).lower()},
            timeout=120,
        )
        r.raise_for_status()
        return r.json()

    def reextract_audit_scope(self, audit_id: int) -> requests.Response:
        return self._session.post(self._url(f"/api/audits/{audit_id}/reextract_scope"), timeout=15)

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

    def artifact(self, job_id: str, artifact_name: str) -> dict | str | None:
        r = self._session.get(
            self._url(f"/api/analyses/{job_id}/artifact/{artifact_name}.json"),
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

    def company_response(self, company: str, section: str = "", *, wait_seconds: float = 60) -> requests.Response:
        suffix = f"/{section}" if section else ""
        deadline = time.monotonic() + wait_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"Company {company}{suffix} was not prepared within {wait_seconds}s")
            r = self._company_session.get(self._url(f"/api/company/{company}{suffix}"), timeout=min(30, remaining))
            if r.status_code != 503:
                r.raise_for_status()
                return r
            try:
                preparing = r.json().get("code") == "company_preparing"
            except (ValueError, AttributeError):
                preparing = False
            if not preparing:
                r.raise_for_status()
            time.sleep(min(2, max(0, deadline - time.monotonic())))

    def company_overview(self, company: str) -> dict[str, Any]:
        return self.company_response(company).json()

    def list_company_audits(self, company: str) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/company/{company}/audits"), timeout=15)
        r.raise_for_status()
        return r.json()

    def company_score(self, company: str) -> requests.Response:
        # 404 is legitimate on a fresh preview; the caller decides skip vs failure.
        return self._session.get(self._url(f"/api/company/{company}/score"), timeout=30)

    def fleet(self) -> dict[str, Any]:
        r = self._session.get(self._url("/api/fleet"), timeout=30)
        r.raise_for_status()
        return r.json()

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

    def list_monitored_events(self, limit: int = 50) -> list[dict[str, Any]]:
        r = self._session.get(self._url("/api/monitored-events"), params={"limit": limit}, timeout=15)
        r.raise_for_status()
        return r.json()

    def contract_audit_timeline(self, contract_id: int) -> dict[str, Any]:
        r = self._session.get(self._url(f"/api/contracts/{contract_id}/audit_timeline"), timeout=30)
        r.raise_for_status()
        return r.json()

    def audit_text(self, audit_id: int) -> requests.Response:
        return self._session.get(self._url(f"/api/audits/{audit_id}/text"), timeout=30)

    def audit_pdf(self, audit_id: int) -> requests.Response:
        return self._session.get(self._url(f"/api/audits/{audit_id}/pdf"), timeout=60)

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
        """Bail early on a failed text extraction; the scope worker only claims text successes."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            row = self.get_audit(audit_id)
            if row.get("scope_extraction_status") in ("success", "failed"):
                return row
            if row.get("text_extraction_status") == "failed":
                return row
            time.sleep(interval)
        raise TimeoutError(f"Audit {audit_id} did not finish scope extraction within {timeout}s")

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

    def poll_job_until_done(
        self,
        job_id: str,
        timeout: float = DEFAULT_SINGLE_TIMEOUT,
        interval: float = DEFAULT_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """``failed_terminal`` is as terminal as ``completed``."""
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
        deadline = time.time() + timeout
        while time.time() < deadline:
            children = self.children_of(parent_job_id)
            if children and all(c["status"] in ("completed", "failed", "failed_terminal") for c in children):
                return children
            time.sleep(interval)
        return self.children_of(parent_job_id)

    @staticmethod
    def job_duration_seconds(job: dict[str, Any]) -> float:
        return (_parse_dt(job["updated_at"]) - _parse_dt(job["created_at"])).total_seconds()

    @staticmethod
    def job_window(job: dict[str, Any]) -> tuple[datetime, datetime]:
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


# Provably read-only, anonymous tests, tagged smoke so production CI can run them without an admin key.
# test_cors.py and test_pipeline_health.py are excluded: prod has a custom origin, and wedged jobs are pre-existing
# state that would cause false rollbacks.
SMOKE_SAFE_TESTS = {
    ("test_health.py", "test_health_reports_ok"),
    ("test_health.py", "test_spa_fallback_serves_frontend"),
    ("test_health.py", "test_frontend_assets_served"),
    ("test_monitoring_reads.py", "test_list_monitored_contracts_shape"),
    ("test_monitoring_reads.py", "test_list_monitored_events_shape"),
    ("test_auth_and_errors.py", "test_analyze_without_admin_key_rejected"),
}


def pytest_collection_modifyitems(config, items):
    live_mark = pytest.mark.live
    smoke_mark = pytest.mark.smoke
    for item in items:
        path = str(item.fspath)
        if "/tests/live/" not in path and "\\tests\\live\\" not in path:
            continue
        item.add_marker(live_mark)
        if (os.path.basename(path), item.name) in SMOKE_SAFE_TESTS:
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


@pytest.fixture(scope="session")
def public_live_client(live_base_url: str) -> LiveClient:
    return LiveClient(live_base_url, "")


@pytest.fixture(scope="session", autouse=True)
def _require_live_api(live_base_url: str):
    client = LiveClient(live_base_url, "")
    if not client.is_healthy():
        pytest.skip(f"API not reachable at {client.base_url}")


@pytest.fixture(scope="session")
def analyzed_weth(live_client: LiveClient) -> dict[str, Any]:
    job = live_client.submit_and_wait(WETH_ADDRESS)
    if job["status"] != "completed":
        pytest.fail(f"WETH analysis did not complete on {live_client.base_url}: {job.get('error')}")
    return job


@pytest.fixture(scope="session")
def cached_weth(analyzed_weth, live_client: LiveClient) -> dict[str, Any]:
    """Ordered before ``analyzed_company`` so it doesn't queue behind etherfi children."""
    job = live_client.submit_and_wait(WETH_ADDRESS)
    if job["status"] != "completed":
        pytest.fail(f"Cached WETH run did not complete on {live_client.base_url}: {job.get('error')}")
    return job


# Two candidates, so one terminal failure doesn't fail every company test.
DEFAULT_TEST_COMPANY = "etherfi"
DEFAULT_TEST_COMPANY_LIMIT = 2


@pytest.fixture(scope="session")
def analyzed_company(cached_weth, live_client: LiveClient) -> dict[str, Any]:
    """Depends on ``cached_weth`` so the cache-hit run finishes before company children saturate the workers."""
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
    overview = live_client.company_overview(DEFAULT_TEST_COMPANY)
    pid = overview.get("protocol_id")
    if not isinstance(pid, int):
        pytest.fail(
            f"Company '{DEFAULT_TEST_COMPANY}' has no Protocol row after analysis "
            f"(overview.protocol_id={pid!r}); cannot exercise protocol endpoints."
        )
    return pid
