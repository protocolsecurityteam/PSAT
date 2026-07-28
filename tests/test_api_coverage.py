"""Tests targeting uncovered paths in api.py for improved coverage.

Focuses on:
- _display_name() helper edge cases
- _merge_proxy_impl_entries() logic
- GET /api/stats
- GET /api/jobs (list with proxy flagging)
- POST /api/analyze (dapp_urls, defillama_protocol paths)
- GET /api/analyses/{run_name}/artifact/{artifact_name} (lookup by id/address, extension stripping)
- GET /api/analyses/{run_name} (relational-table fallback paths, control_snapshot, resolved_control_graph from tables)
- GET /api/company/{company_name}
- Proxy subscription endpoints
- SPA fallback for /api/* paths
"""

from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_client() -> TestClient:
    import api

    return TestClient(api.app)


def _admin_headers() -> dict[str, str]:
    """Header carrying the configured admin key, for now-gated internal reads."""
    from routers import deps

    return {"X-PSAT-Admin-Key": deps.ADMIN_KEY or ""}


def _mock_session_ctx(mock_session_cls, mock_session):
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)


def _fake_job(
    job_id=None,
    address=None,
    company=None,
    name=None,
    status="completed",
    stage="done",
    request=None,
    is_proxy=False,
):
    job = MagicMock()
    uid = uuid.UUID(job_id) if job_id else uuid.uuid4()
    job.id = uid
    job.address = address
    job.company = company
    job.name = name
    job.status = MagicMock(value=status)
    job.stage = MagicMock(value=stage)
    job.detail = "detail"
    job.request = request or {}
    job.error = None
    job.worker_id = None
    job.is_proxy = is_proxy
    job.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    job.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    job.to_dict.return_value = {
        "job_id": str(uid),
        "address": address,
        "company": company,
        "name": name,
        "status": status,
        "stage": stage,
        "detail": "detail",
        "request": request or {},
        "error": None,
        "worker_id": None,
        "is_proxy": is_proxy,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    return job


# ============================================================================
# 1. _display_name() unit tests
# ============================================================================


class TestDisplayName:
    def _dn(self, entry):
        from services.governance.proxies import _display_name

        return _display_name(entry)

    def test_explicit_display_name_is_used(self):
        assert self._dn({"display_name": "MyVault"}) == "MyVault"

    def test_explicit_display_name_with_chain_suffix(self):
        result = self._dn({"display_name": "MyVault", "chain": "ethereum"})
        assert result == "MyVault (ethereum)"

    def test_explicit_display_name_already_has_chain_suffix(self):
        result = self._dn({"display_name": "MyVault (ethereum)", "chain": "ethereum"})
        assert result == "MyVault (ethereum)"

    def test_contract_name_used_when_no_display_name(self):
        assert self._dn({"contract_name": "Vault"}) == "Vault"

    def test_generic_proxy_name_falls_through_to_run_name(self):
        result = self._dn({"contract_name": "ERC1967Proxy", "run_name": "MyRunName"})
        assert result == "MyRunName"

    def test_generic_proxy_name_case_insensitive(self):
        result = self._dn({"contract_name": "uupsproxy", "run_name": "run1"})
        assert result == "run1"

    def test_all_generic_proxy_names(self):
        from services.governance.proxies import GENERIC_PROXY_NAMES

        for gname in GENERIC_PROXY_NAMES:
            result = self._dn({"contract_name": gname, "run_name": "fallback"})
            assert result == "fallback", f"{gname} should be treated as generic"

    def test_fallback_to_contract_name_when_no_run_name(self):
        # When contract_name is generic AND no run_name, falls back to contract_name itself
        result = self._dn({"contract_name": "Proxy"})
        assert result == "Proxy"

    def test_empty_entry(self):
        result = self._dn({})
        assert result == ""

    def test_none_values(self):
        result = self._dn({"display_name": None, "contract_name": None, "run_name": None})
        assert result == ""

    def test_chain_suffix_not_added_to_empty_name(self):
        result = self._dn({"chain": "ethereum"})
        assert result == ""


# ============================================================================
# 2. _merge_proxy_impl_entries() unit tests
# ============================================================================


class TestMergeProxyImplEntries:
    def _merge(self, entries):
        from services.governance.proxies import _merge_proxy_impl_entries

        return _merge_proxy_impl_entries(entries)

    def test_no_entries(self):
        assert self._merge([]) == []

    def test_non_proxy_entries_pass_through(self):
        entry = {"address": "0xaaa", "run_name": "test"}
        result = self._merge([entry])
        assert len(result) == 1
        assert result[0]["address"] == "0xaaa"
        assert "display_name" in result[0]

    def test_impl_entry_without_matching_proxy_stays(self):
        # An impl entry (has proxy_address) but no proxy entry matches it
        impl = {"address": "0xbbb", "proxy_address": "0xaaa", "run_name": "impl"}
        result = self._merge([impl])
        # The impl entry should still appear as an unmerged impl
        assert len(result) == 1
        assert result[0]["address"] == "0xbbb"

    def test_proxy_and_impl_merge(self):
        proxy = {
            "address": "0xaaa",
            "is_proxy": True,
            "implementation_address": "0xbbb",
            "proxy_type": "ERC1967",
            "company": "etherfi",
            "chain": "ethereum",
            "rank_score": 10,
            "run_name": "ProxyRun",
        }
        impl = {
            "address": "0xbbb",
            "proxy_address": "0xaaa",
            "contract_name": "VaultImpl",
            "company": None,
            "chain": None,
            "rank_score": None,
            "run_name": "ImplRun",
        }
        result = self._merge([proxy, impl])
        assert len(result) == 1
        merged = result[0]
        assert merged["proxy_address_display"] == "0xaaa"
        assert merged["proxy_type_display"] == "ERC1967"
        assert merged["display_name"] == "VaultImpl"
        # Company comes from proxy when impl is None
        assert merged["company"] == "etherfi"
        # Chain comes from proxy
        assert merged["chain"] == "ethereum"
        # rank_score from proxy (not None)
        assert merged["rank_score"] == 10

    def test_proxy_without_impl_entry_passes_through(self):
        # Proxy entry but no matching impl entry in the list
        proxy = {
            "address": "0xaaa",
            "is_proxy": True,
            "implementation_address": "0xbbb",
            "run_name": "proxy_only",
        }
        result = self._merge([proxy])
        assert len(result) == 1
        assert result[0]["run_name"] == "proxy_only"

    def test_impl_rank_score_used_when_proxy_is_none(self):
        proxy = {
            "address": "0xaaa",
            "is_proxy": True,
            "implementation_address": "0xbbb",
            "rank_score": None,
            "run_name": "P",
        }
        impl = {
            "address": "0xbbb",
            "proxy_address": "0xaaa",
            "rank_score": 5,
            "contract_name": "Impl",
            "run_name": "I",
        }
        result = self._merge([proxy, impl])
        assert result[0]["rank_score"] == 5


# ============================================================================
# 3. GET /api/stats
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_pipeline_stats(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # session.execute().scalar() returns counts
    mock_session.execute.return_value.scalar.return_value = 42

    response = client.get("/api/stats")
    assert response.status_code == 200
    body = response.json()
    assert "unique_addresses" in body
    assert "total_jobs" in body
    assert "completed_jobs" in body
    assert "failed_jobs" in body


# ============================================================================
# 4. GET /api/jobs (list with proxy flagging)
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_list_jobs_with_proxy_flag(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # /api/jobs reads ``Job.is_proxy`` directly — no per-row artifact
    # resolve. The proxy flag is mirrored onto Job by ``store_artifact``
    # whenever ``contract_flags`` gets written.
    job1 = _fake_job(name="proxy_job", address="0xaaa", is_proxy=True)
    job2 = _fake_job(name="regular_job", address="0xbbb", is_proxy=False)

    mock_session.execute.return_value.scalars.return_value.all.return_value = [job1, job2]

    response = client.get("/api/jobs")
    assert response.status_code == 200
    jobs = response.json()
    assert len(jobs) == 2
    proxy_entry = next(j for j in jobs if j["name"] == "proxy_job")
    regular_entry = next(j for j in jobs if j["name"] == "regular_job")
    assert proxy_entry["is_proxy"] is True
    assert regular_entry["is_proxy"] is False


@patch("routers.deps.SessionLocal")
def test_list_jobs_empty(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_session.execute.return_value.scalars.return_value.all.return_value = []

    response = client.get("/api/jobs")
    assert response.status_code == 200
    assert response.json() == []


# ============================================================================
# 5. POST /api/analyze - dapp_urls and defillama_protocol paths
# ============================================================================


@patch("routers.deps.SessionLocal")
@patch("routers.deps.create_job")
def test_analyze_dapp_urls(mock_create_job, mock_session_cls):
    client = _make_client()
    fake_job = _fake_job(status="queued", stage="dapp_crawl")
    mock_create_job.return_value = fake_job
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    response = client.post(
        "/api/analyze",
        json={"dapp_urls": ["https://app.uniswap.org"]},
    )
    assert response.status_code == 200
    # Verify create_job was called with initial_stage=dapp_crawl
    from db.models import JobStage

    _, kwargs = mock_create_job.call_args
    assert kwargs.get("initial_stage") == JobStage.dapp_crawl


@patch("routers.deps.SessionLocal")
@patch("routers.deps.create_job")
def test_analyze_defillama_protocol(mock_create_job, mock_session_cls):
    client = _make_client()
    fake_job = _fake_job(status="queued", stage="defillama_scan")
    mock_create_job.return_value = fake_job
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    response = client.post(
        "/api/analyze",
        json={"defillama_protocol": "aave"},
    )
    assert response.status_code == 200
    from db.models import JobStage

    _, kwargs = mock_create_job.call_args
    assert kwargs.get("initial_stage") == JobStage.defillama_scan


def test_analyze_rejects_multiple_targets():
    """Cannot provide both dapp_urls and address."""
    client = _make_client()
    response = client.post(
        "/api/analyze",
        json={
            "address": "0x1111111111111111111111111111111111111111",
            "dapp_urls": ["https://example.com"],
        },
    )
    assert response.status_code == 422


# ============================================================================
# 6. GET /api/analyses/{run_name}/artifact/{artifact_name}
# ============================================================================


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_lookup_by_job_id(mock_session_cls, mock_get_artifact):
    """When name lookup fails, try by job ID."""
    client = _make_client()
    job_id = str(uuid.uuid4())
    fake_job = _fake_job(job_id=job_id, name="test_job")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # First execute (by name): returns None
    # Then session.get (by id): returns job
    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute
    mock_session.get.return_value = fake_job

    mock_get_artifact.return_value = {"data": "value"}

    response = client.get(f"/api/analyses/{job_id}/artifact/contract_analysis", headers=_admin_headers())
    assert response.status_code == 200
    assert response.json() == {"data": "value"}


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_lookup_by_address(mock_session_cls, mock_get_artifact):
    """When name and ID lookups fail, try by address."""
    client = _make_client()
    addr = "0x1111111111111111111111111111111111111111"
    fake_job = _fake_job(address=addr, name="addr_job")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] <= 1:
            # Name lookup fails
            result.scalar_one_or_none.return_value = None
        else:
            # Address lookup succeeds
            result.scalar_one_or_none.return_value = fake_job
        return result

    mock_session.execute.side_effect = route_execute
    # session.get for ID lookup raises (simulating invalid UUID)
    mock_session.get.side_effect = Exception("not a UUID")

    mock_get_artifact.return_value = {"found": True}

    response = client.get(f"/api/analyses/{addr}/artifact/contract_analysis", headers=_admin_headers())
    assert response.status_code == 200
    assert response.json()["found"] is True


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_not_found(mock_session_cls, mock_get_artifact):
    """Returns 404 when artifact doesn't exist."""
    client = _make_client()
    fake_job = _fake_job(name="test_job")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = fake_job
    mock_session.execute.return_value = mock_exec

    mock_get_artifact.return_value = None

    response = client.get("/api/analyses/test_job/artifact/nonexistent.json", headers=_admin_headers())
    assert response.status_code == 404


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_storage_error_returns_503_not_404(mock_session_cls, mock_get_artifact):
    """INVERTED (was ``test_artifact_storage_error_returns_404_not_500``, which
    asserted 404 and called it "degrading cleanly").

    That assertion pinned the defect at the published boundary: an unconfigured
    or unreachable backend answered with the same bytes as an artifact the job
    never produced, and the SPA's ``.catch()`` path draws that as an absence.
    Not-500 was the right instinct and still holds — it is now 503, which is a
    third answer rather than the second one repeated.
    """
    client = _make_client()
    fake_job = _fake_job(name="test_job")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = fake_job
    mock_session.execute.return_value = mock_exec

    mock_get_artifact.side_effect = RuntimeError("storage_key set but storage not configured")

    response = client.get("/api/analyses/test_job/artifact/dependencies")
    assert response.status_code == 503
    assert response.headers.get("X-PSAT-Artifact-State") == "not_determined"
    assert response.json()["artifact"] == "dependencies"


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_proven_absent_body_still_returns_404(mock_session_cls, mock_get_artifact):
    """Negative control for the test above: the bucket answering "no object at
    any candidate" is a determined negative and must stay a 404. A fix that
    turned every storage exception into 503 would erase the distinction it was
    written to make."""
    from db.storage import StorageKeyMissing

    client = _make_client()
    fake_job = _fake_job(name="test_job")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = fake_job
    mock_session.execute.return_value = mock_exec

    mock_get_artifact.side_effect = StorageKeyMissing("artifacts/j/dependencies")

    response = client.get("/api/analyses/test_job/artifact/dependencies")
    assert response.status_code == 404
    assert response.json() == {"detail": "Artifact not found"}
    assert "X-PSAT-Artifact-State" not in response.headers


@patch("services.discovery.upgrade_history.synthesize_from_events")
@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_upgrade_history_falls_back_to_synthesis(
    mock_session_cls,
    mock_get_artifact,
    mock_synth,
):
    """When storage can't serve upgrade_history, rebuild it from
    UpgradeEvent rows. The relational table is the source of truth for
    the count/last_block badges shown in the company overview, so the
    detail view should stay consistent when storage is unhappy."""
    client = _make_client()
    fake_job = _fake_job(name="test_job")
    fake_contract = MagicMock()
    fake_contract.id = 42

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # First execute resolves the job, second resolves the Contract row.
    job_exec = MagicMock()
    job_exec.scalar_one_or_none.return_value = fake_job
    contract_exec = MagicMock()
    contract_exec.scalar_one_or_none.return_value = fake_contract
    mock_session.execute.side_effect = [job_exec, contract_exec]

    mock_get_artifact.side_effect = RuntimeError("object 404")
    mock_synth.return_value = {
        "schema_version": "0.1",
        "target_address": "0xaaa",
        "proxies": {"0xaaa": {"upgrade_count": 3}},
        "total_upgrades": 3,
        "synthesized": True,
    }

    response = client.get("/api/analyses/test_job/artifact/upgrade_history")
    assert response.status_code == 200
    body = response.json()
    assert body["synthesized"] is True
    assert body["total_upgrades"] == 3
    mock_synth.assert_called_once()


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_txt_extension_stripping(mock_session_cls, mock_get_artifact):
    """The .txt extension is stripped for lookup."""
    client = _make_client()
    fake_job = _fake_job(name="job1")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = fake_job
    mock_session.execute.return_value = mock_exec

    # First call with stripped name returns None, second with original returns data
    mock_get_artifact.side_effect = [None, "report text"]

    response = client.get("/api/analyses/job1/artifact/analysis_report.txt", headers=_admin_headers())
    assert response.status_code == 200
    assert "report text" in response.text


@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_artifact_json_extension_stripping(mock_session_cls, mock_get_artifact):
    """The .json extension is stripped, and first lookup with stripped name succeeds."""
    client = _make_client()
    fake_job = _fake_job(name="job1")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)
    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = fake_job
    mock_session.execute.return_value = mock_exec

    mock_get_artifact.side_effect = [{"key": "val"}]

    response = client.get("/api/analyses/job1/artifact/contract_analysis.json", headers=_admin_headers())
    assert response.status_code == 200
    assert response.json() == {"key": "val"}


@patch("routers.deps.SessionLocal")
def test_artifact_job_not_found_returns_404(mock_session_cls):
    """Returns 404 when no job matches name/id/address."""
    client = _make_client()

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec
    mock_session.get.return_value = None

    response = client.get("/api/analyses/nonexistent/artifact/contract_analysis", headers=_admin_headers())
    assert response.status_code == 404


# ============================================================================
# 7. GET /api/analyses/{run_name} - relational table paths
# ============================================================================


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_relational_effective_permissions(mock_session_cls, mock_get_all_artifacts):
    """When contract_row exists with EffectiveFunctions, payload gets effective_permissions from relational tables."""
    client = _make_client()
    job = _fake_job(name="rel_job", address="0xaaa")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    contract_row = MagicMock()
    contract_row.id = uuid.uuid4()
    contract_row.is_proxy = False
    contract_row.implementation = None
    contract_row.contract_name = "TestContract"
    contract_row.address = "0xaaa"
    contract_row.summary = None
    contract_row.job_id = job.id

    ef = MagicMock()
    ef.id = uuid.uuid4()
    ef.abi_signature = "pause()"
    ef.function_name = "pause"
    ef.selector = "0x8456cb59"
    ef.effect_labels = ["pause_toggle"]
    ef.action_summary = "Pauses the contract"
    ef.authority_public = False

    fp = MagicMock()
    fp.address = "0xowner"
    fp.resolved_type = "eoa"
    fp.origin = "owner_slot"
    fp.details = {"role": "admin"}
    fp.principal_type = "controller"
    fp.function_id = ef.id
    # selectinload puts principals on ef.principals; no separate FP query.
    ef.principals = [fp]

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            # Job lookup
            result.scalar_one_or_none.return_value = job
        elif call_count["n"] == 2:
            # Contract lookup
            result.scalar_one_or_none.return_value = contract_row
        elif call_count["n"] == 3:
            # EffectiveFunction query (batched per contract, principals eager-loaded)
            result.scalars.return_value.all.return_value = [ef]
            result.scalars.return_value.__iter__ = lambda s: iter([ef])
        elif call_count["n"] == 4:
            # PrincipalLabel query
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 5:
            # ControllerValue query (for control_snapshot)
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 6:
            # ControlGraphNode query
            result.scalars.return_value.all.return_value = []
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
            result.scalars.return_value.__iter__ = lambda s: iter([])
        return result

    mock_session.execute.side_effect = route_execute

    mock_get_all_artifacts.return_value = {
        "contract_analysis": {
            "subject": {"name": "TestContract"},
            "summary": {"control_model": "ownable"},
        },
    }

    response = client.get("/api/analyses/rel_job")
    assert response.status_code == 200
    body = response.json()
    assert "effective_permissions" in body
    perms = body["effective_permissions"]
    assert perms["contract_name"] == "TestContract"
    assert len(perms["functions"]) == 1
    fn = perms["functions"][0]
    assert fn["function"] == "pause()"
    assert fn["selector"] == "0x8456cb59"
    assert fn["effect_labels"] == ["pause_toggle"]
    assert len(fn["controllers"]) == 1
    assert fn["controllers"][0]["principals"][0]["address"] == "0xowner"


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_relational_control_snapshot(mock_session_cls, mock_get_all_artifacts):
    """When control_snapshot is NOT in artifacts, build it from ControllerValue table."""
    client = _make_client()
    job = _fake_job(name="cv_job", address="0xaaa")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    contract_row = MagicMock()
    contract_row.id = uuid.uuid4()
    contract_row.is_proxy = False
    contract_row.implementation = None
    contract_row.contract_name = "CVContract"
    contract_row.address = "0xaaa"
    contract_row.summary = None

    cv = MagicMock()
    cv.controller_id = "owner"
    cv.value = "0xdeadbeef"
    cv.resolved_type = "eoa"
    cv.source = "storage_slot"
    cv.details = {"slot": "0x00"}

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = job
        elif call_count["n"] == 2:
            result.scalar_one_or_none.return_value = contract_row
        elif call_count["n"] == 3:
            # EffectiveFunction: empty
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 4:
            # PrincipalLabel: empty
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 5:
            # ControllerValue
            result.scalars.return_value.all.return_value = [cv]
        elif call_count["n"] == 6:
            # ControlGraphNode (for resolved_control_graph)
            result.scalars.return_value.all.return_value = []
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute

    # No control_snapshot in artifacts
    mock_get_all_artifacts.return_value = {
        "contract_analysis": {
            "subject": {"name": "CVContract"},
            "summary": {},
        },
    }

    response = client.get("/api/analyses/cv_job")
    assert response.status_code == 200
    body = response.json()
    assert "control_snapshot" in body
    cs = body["control_snapshot"]
    assert cs["contract_name"] == "CVContract"
    assert "owner" in cs["controller_values"]
    assert cs["controller_values"]["owner"]["value"] == "0xdeadbeef"


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_relational_control_graph(mock_session_cls, mock_get_all_artifacts):
    """When resolved_control_graph is NOT in artifacts, build it from CGN/CGE tables."""
    client = _make_client()
    job = _fake_job(name="cg_job", address="0xaaa")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    contract_row = MagicMock()
    contract_row.id = uuid.uuid4()
    contract_row.is_proxy = False
    contract_row.implementation = None
    contract_row.contract_name = "CGContract"
    contract_row.address = "0xaaa"
    contract_row.summary = None

    cgn = MagicMock()
    cgn.address = "0xnode1"
    cgn.node_type = "contract"
    cgn.resolved_type = "safe"
    cgn.label = "GnosisSafe"
    cgn.contract_name = "GnosisSafe"
    cgn.depth = 0
    cgn.analyzed = True

    cge = MagicMock()
    cge.from_node_id = "address:0xnode1"
    cge.to_node_id = "address:0xaaa"
    cge.relation = "owner"
    cge.label = "owns"

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = job
        elif call_count["n"] == 2:
            result.scalar_one_or_none.return_value = contract_row
        elif call_count["n"] == 3:
            # EffectiveFunction: empty
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 4:
            # PrincipalLabel: empty
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 5:
            # ControllerValue: empty (no control_snapshot)
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 6:
            # ControlGraphNode
            result.scalars.return_value.all.return_value = [cgn]
        elif call_count["n"] == 7:
            # ControlGraphEdge
            result.scalars.return_value.all.return_value = [cge]
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute

    # No resolved_control_graph in artifacts
    mock_get_all_artifacts.return_value = {
        "contract_analysis": {
            "subject": {"name": "CGContract"},
            "summary": {},
        },
    }

    response = client.get("/api/analyses/cg_job")
    assert response.status_code == 200
    body = response.json()
    assert "resolved_control_graph" in body
    rcg = body["resolved_control_graph"]
    assert rcg["root_contract_address"] == "0xaaa"
    assert len(rcg["nodes"]) == 1
    assert rcg["nodes"][0]["address"] == "0xnode1"
    assert len(rcg["edges"]) == 1
    assert rcg["edges"][0]["relation"] == "owner"


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_relational_principal_labels(mock_session_cls, mock_get_all_artifacts):
    """When PrincipalLabel rows exist, they populate principal_labels in payload."""
    client = _make_client()
    job = _fake_job(name="pl_job", address="0xaaa")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    contract_row = MagicMock()
    contract_row.id = uuid.uuid4()
    contract_row.is_proxy = False
    contract_row.implementation = None
    contract_row.contract_name = "PLContract"
    contract_row.address = "0xaaa"
    contract_row.summary = None

    pl = MagicMock()
    pl.address = "0xowner"
    pl.label = "Owner"
    pl.resolved_type = "eoa"

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = job
        elif call_count["n"] == 2:
            result.scalar_one_or_none.return_value = contract_row
        elif call_count["n"] == 3:
            # EffectiveFunction: empty
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 4:
            # PrincipalLabel
            result.scalars.return_value.all.return_value = [pl]
        elif call_count["n"] == 5:
            # ControllerValue: empty
            result.scalars.return_value.all.return_value = []
        elif call_count["n"] == 6:
            # ControlGraphNode: empty
            result.scalars.return_value.all.return_value = []
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute

    mock_get_all_artifacts.return_value = {
        "contract_analysis": {
            "subject": {"name": "PLContract"},
            "summary": {},
        },
    }

    response = client.get("/api/analyses/pl_job")
    assert response.status_code == 200
    body = response.json()
    assert "principal_labels" in body
    assert body["principal_labels"]["principals"][0]["address"] == "0xowner"
    assert body["principal_labels"]["principals"][0]["label"] == "Owner"


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_lookup_by_id(mock_session_cls, mock_get_all_artifacts):
    """Falls back to session.get(Job, run_name) when name lookup fails."""
    client = _make_client()
    job_id = str(uuid.uuid4())
    job = _fake_job(job_id=job_id, name="id_lookup_job", address="0xaaa")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            # Name lookup fails
            result.scalar_one_or_none.return_value = None
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute
    mock_session.get.return_value = job

    mock_get_all_artifacts.return_value = {}

    response = client.get(f"/api/analyses/{job_id}")
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_lookup_by_address(mock_session_cls, mock_get_all_artifacts):
    """Falls back to address lookup when name and ID fail."""
    client = _make_client()
    addr = "0x1111111111111111111111111111111111111111"
    job = _fake_job(address=addr, name="addr_job")

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            # Name lookup fails
            result.scalar_one_or_none.return_value = None
        elif call_count["n"] == 2:
            # Address lookup succeeds
            result.scalar_one_or_none.return_value = job
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute
    mock_session.get.side_effect = Exception("invalid UUID")

    mock_get_all_artifacts.return_value = {}

    response = client.get(f"/api/analyses/{addr}")
    assert response.status_code == 200
    assert response.json()["address"] == addr


# ============================================================================
# 8. GET /api/analyses - rank_scores and chain come from the contracts table
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_analyses_list_rank_scores_from_contracts_table(mock_session_cls):
    """rank_score + chain come from the ``contracts`` table (selection's single
    authoritative ranking pass), not from the legacy inventory artifact."""
    client = _make_client()
    company_job = _fake_job(
        name="company_disc",
        company="etherfi",
        address=None,
        request={"company": "etherfi"},
    )
    child_job = _fake_job(
        name="child_contract",
        address="0xcccc",
        request={"parent_job_id": str(company_job.id)},
    )

    from db.models import JobStatus

    company_job.status = JobStatus.completed
    child_job.status = JobStatus.completed

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # api.py now stores the full Contract row in contracts_by_address;
    # mocks must expose every column the listing reads.
    contract_row = SimpleNamespace(
        address="0xcccc",
        chain="ethereum",
        rank_score=8.5,
        contract_name="ContractX",
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )
    artifact_row = SimpleNamespace(
        job_id=child_job.id,
        name="contract_analysis",
        storage_key=None,
        data={"subject": {"name": "ContractX"}, "summary": {}},
        text_data=None,
        content_type=None,
    )

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            # First query: completed jobs
            result.scalars.return_value.all.return_value = [company_job, child_job]
        elif call_count["n"] == 2:
            # Second query: Contract rows for rank/chain/name/proxy lookup
            result.scalars.return_value = iter([contract_row])
        elif call_count["n"] == 3:
            # Third query: batched Artifact rows for all jobs
            result.scalars.return_value = iter([artifact_row])
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/analyses")
    assert response.status_code == 200
    entries = response.json()
    child = next((e for e in entries if e.get("address") == "0xcccc"), None)
    assert child is not None
    assert child["rank_score"] == 8.5
    assert child["chain"] == "ethereum"


# ============================================================================
# 9. GET /api/company/{company_name}
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_company_overview_not_found(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_exec

    response = client.get("/api/company/nonexistent")
    assert response.status_code == 404


def test_company_overview_basic(db_session, api_client):
    """Basic company overview with one non-proxy contract — real-DB integration.

    Replaces the previous mock-heavy positional-list test (which broke when
    the API switched to batched prefetches). Asserting against real DB state
    keeps the test truthful and resilient to query-structure changes.
    """
    from db.models import (
        Contract,
        ContractSummary,
        Job,
        JobStage,
        JobStatus,
        Protocol,
    )

    protocol = Protocol(name="etherfi_basic_test", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()

    job = Job(
        id=uuid.uuid4(),
        address="0x" + "a" * 40,
        company="etherfi_basic_test",
        name="Vault",
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"chain": "ethereum"},
        protocol_id=protocol.id,
    )
    db_session.add(job)
    db_session.flush()

    contract = Contract(
        job_id=job.id,
        protocol_id=protocol.id,
        address=("0x" + "a" * 40),
        chain="ethereum",
        contract_name="Vault",
        is_proxy=False,
        source_verified=True,
    )
    db_session.add(contract)
    db_session.flush()
    db_session.add(
        ContractSummary(
            contract_id=contract.id,
            control_model="ownable",
            is_upgradeable=False,
            is_pausable=True,
            has_timelock=False,
            risk_level="medium",
            is_factory=False,
            standards=["ERC20"],
            source_verified=True,
        )
    )
    db_session.commit()

    try:
        response = api_client.get("/api/company/etherfi_basic_test")
        assert response.status_code == 200
        body = response.json()
        assert body["company"] == "etherfi_basic_test"
        assert body["contract_count"] >= 1

        c = body["contracts"][0]
        assert c["address"] == ("0x" + "a" * 40)
        assert c["name"] == "Vault"
        assert c["is_proxy"] is False
        assert c["is_pausable"] is True
        assert "pause" in c["capabilities"]
        assert c["role"] == "token"
        assert c["standards"] == ["ERC20"]
        assert "ownership_hierarchy" in body
    finally:
        db_session.execute(text("DELETE FROM contracts WHERE protocol_id = :p"), {"p": protocol.id})
        db_session.execute(text("DELETE FROM jobs WHERE company = :c"), {"c": "etherfi_basic_test"})
        db_session.execute(text("DELETE FROM protocols WHERE id = :p"), {"p": protocol.id})
        db_session.commit()


@patch("routers.deps.SessionLocal")
def test_company_audit_coverage_reuses_strict_dependency_rows(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    target_addr = "0x" + "2" * 40
    protocol = SimpleNamespace(id=1, name="etherfi")
    target_contract = SimpleNamespace(
        id=10,
        address=target_addr,
        chain="ethereum",
        contract_name="Vault",
        is_proxy=False,
        implementation=None,
    )
    dep_protocol = SimpleNamespace(id=2, name="lido")
    dep_contract = SimpleNamespace(id=20, address=target_addr, chain="ethereum")
    dep_audit = SimpleNamespace(id=30, auditor="Sigma Prime", title="Lido Token Review", date="2024-11-01")
    cited_audit = SimpleNamespace(id=31, auditor="Noisy", title="Cited Only", date="2024-12-01")
    heuristic_audit = SimpleNamespace(id=32, auditor="Heuristic", title="Name Match", date="2024-10-01")

    def coverage_row(audit, *, match_type="reviewed_commit", proof_kind="clean", status="proven"):
        return SimpleNamespace(
            contract_id=dep_contract.id,
            audit_report_id=audit.id,
            protocol_id=dep_protocol.id,
            matched_name="Vault",
            match_type=match_type,
            match_confidence="high",
            covered_from_block=None,
            covered_to_block=None,
            equivalence_status=status,
            equivalence_reason=None,
            equivalence_checked_at=None,
            proof_kind=proof_kind,
            matched_commit_sha="a" * 40,
        )

    class Result:
        def __init__(self, *, scalar=None, scalars=None, rows=None):
            self._scalar = scalar
            self._scalars = scalars or []
            self._rows = rows

        def scalar_one_or_none(self):
            return self._scalar

        def scalars(self):
            return self

        def all(self):
            return self._rows if self._rows is not None else self._scalars

    mock_session.execute.side_effect = [
        Result(scalar=protocol),
        Result(scalars=[target_contract]),
        Result(scalars=[]),
        Result(scalars=[]),
        Result(
            rows=[
                (coverage_row(dep_audit), dep_audit, dep_contract, dep_protocol),
                (coverage_row(cited_audit, proof_kind="cited_only"), cited_audit, dep_contract, dep_protocol),
                (coverage_row(heuristic_audit, match_type="direct"), heuristic_audit, dep_contract, dep_protocol),
            ]
        ),
    ]

    response = client.get("/api/company/etherfi/audit_coverage")
    assert response.status_code == 200
    body = response.json()

    assert body["audit_count"] == 0
    vault = body["coverage"][0]
    assert vault["contract_name"] == "Vault"
    assert vault["audit_count"] == 1
    assert vault["last_audit"]["auditor"] == "Sigma Prime"
    assert vault["last_audit"]["match_type"] == "reviewed_commit"
    assert vault["last_audit"]["equivalence_status"] == "proven"
    assert vault["last_audit"]["coverage_source"] == "inherited"
    assert vault["last_audit"]["inherited_from_protocol"] == "lido"
    assert vault["last_audit"]["inherited_contract_address"] == target_addr


# ============================================================================
# 11. SPA fallback for /api/* paths
# ============================================================================


def test_spa_fallback_api_prefix_returns_404():
    """Requests starting with /api/ that don't match a route should return 404."""
    client = _make_client()
    response = client.get("/api/nonexistent_endpoint")
    assert response.status_code == 404


def test_spa_fallback_non_api_serves_html(spa_index):
    """Non-API deep links serve the SPA index."""
    client = _make_client()
    response = client.get("/some/random/path")
    assert response.status_code == 200


# ============================================================================
# 12. GET /api/analyses - company_for_job parent chain walking
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_analyses_company_from_parent_chain(mock_session_cls):
    """company_for_job() walks parent_job_id chain to find company."""
    client = _make_client()

    company_job_id = uuid.uuid4()
    child_job_id = uuid.uuid4()

    company_job = _fake_job(
        job_id=str(company_job_id),
        name="company_disc",
        company="compound",
        address=None,
    )
    child_job = _fake_job(
        job_id=str(child_job_id),
        name="child",
        address="0xcccc",
        company=None,
        request={"parent_job_id": str(company_job_id)},
    )

    from db.models import JobStatus

    company_job.status = JobStatus.completed
    child_job.status = JobStatus.completed

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    artifacts = [
        SimpleNamespace(
            job_id=child_job.id,
            name="contract_analysis",
            storage_key=None,
            data={"subject": {"name": "Child"}, "summary": {}},
            text_data=None,
            content_type=None,
        ),
    ]

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [company_job, child_job]
        elif call_count["n"] == 2:
            result.all.return_value = []
        elif call_count["n"] == 3:
            result.scalars.return_value = iter(artifacts)
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/analyses")
    assert response.status_code == 200
    entries = response.json()
    child_entry = next((e for e in entries if e.get("address") == "0xcccc"), None)
    assert child_entry is not None
    assert child_entry["company"] == "compound"


# ============================================================================
# 13. GET /api/analyses - proxy with incomplete impl is hidden
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_analyses_proxy_hidden_when_impl_not_completed(mock_session_cls):
    """A completed proxy is suppressed until its impl child also completes.

    Showing the proxy alone would render a half-populated card (no
    contract_analysis, generic proxy name) that mutates once the impl
    lands. jobs_by_address holds completed jobs only, so a missing entry
    is sufficient to suppress.
    """
    client = _make_client()

    proxy_job = _fake_job(
        name="proxy_hidden",
        address="0xaaaa",
        is_proxy=True,
    )

    from db.models import JobStatus

    proxy_job.status = JobStatus.completed

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # proxy_type / implementation come from Contract now.
    proxy_contract = SimpleNamespace(
        address="0xaaaa",
        chain=None,
        rank_score=None,
        contract_name="ProxyContract",
        is_proxy=True,
        proxy_type="ERC1967",
        implementation="0xbbbb",
    )

    artifacts = [
        SimpleNamespace(
            job_id=proxy_job.id,
            name="contract_analysis",
            storage_key=None,
            data={"subject": {"name": "ProxyContract"}, "summary": {}},
            text_data=None,
            content_type=None,
        ),
    ]

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [proxy_job]
        elif call_count["n"] == 2:
            result.scalars.return_value = iter([proxy_contract])
        elif call_count["n"] == 3:
            result.scalars.return_value = iter(artifacts)
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/analyses")
    assert response.status_code == 200
    entries = response.json()
    assert not any(e.get("address") == "0xaaaa" for e in entries)


# ============================================================================
# 15. POST /api/analyze - non-0x address
# ============================================================================


def test_analyze_address_not_starting_with_0x():
    """Address that doesn't start with 0x after length validation should get 400."""
    client = _make_client()
    # 42 chars but doesn't start with 0x — pydantic min_length=42 passes but
    # the endpoint's manual check should catch it
    response = client.post(
        "/api/analyze",
        json={"address": "xx1111111111111111111111111111111111111111"},
    )
    assert response.status_code == 400


# ============================================================================
# 16. GET /api/analyses/{run_name} - proxy job inherits impl relational tables
# ============================================================================


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_proxy_inherits_impl_relational_tables(
    mock_session_cls, mock_get_artifact, mock_get_all_artifacts
):
    """When loading a proxy job detail, effective_permissions / control_snapshot /
    resolved_control_graph / principal_labels should be inherited from impl's
    relational tables when not available from artifacts."""
    client = _make_client()

    proxy_addr = "0x1111111111111111111111111111111111111111"
    impl_addr = "0x2222222222222222222222222222222222222222"
    proxy_job_id = uuid.uuid4()
    impl_job_id = uuid.uuid4()

    proxy_job = _fake_job(
        job_id=str(proxy_job_id),
        address=proxy_addr,
        name="ProxyRelTest",
        request={"address": proxy_addr},
    )
    impl_job = _fake_job(
        job_id=str(impl_job_id),
        address=impl_addr,
        name="ProxyRelTest: (impl)",
        request={"address": impl_addr, "proxy_address": proxy_addr},
    )

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    proxy_contract = MagicMock()
    proxy_contract.id = uuid.uuid4()
    proxy_contract.is_proxy = True
    proxy_contract.implementation = impl_addr
    proxy_contract.contract_name = "ProxyRelTest"
    proxy_contract.address = proxy_addr
    proxy_contract.summary = None
    proxy_contract.job_id = proxy_job_id

    impl_contract = MagicMock()
    impl_contract.id = uuid.uuid4()
    impl_contract.is_proxy = False
    impl_contract.implementation = None
    impl_contract.contract_name = "ImplContract"
    impl_contract.address = impl_addr
    impl_contract.summary = MagicMock()
    impl_contract.summary.control_model = "authority"
    impl_contract.summary.is_upgradeable = True
    impl_contract.summary.is_pausable = False
    impl_contract.summary.has_timelock = False
    impl_contract.summary.risk_level = "high"
    impl_contract.summary.standards = ["ERC20"]

    ef = MagicMock()
    ef.id = uuid.uuid4()
    ef.abi_signature = "transfer(address,uint256)"
    ef.function_name = "transfer"
    ef.selector = "0xa9059cbb"
    ef.effect_labels = ["asset_send"]
    ef.action_summary = "Sends tokens"
    ef.authority_public = True

    fp_owner = MagicMock()
    fp_owner.address = "0xowner"
    fp_owner.resolved_type = "eoa"
    fp_owner.origin = "direct owner"
    fp_owner.principal_type = "direct_owner"
    fp_owner.details = {}

    fp_role = MagicMock()
    fp_role.address = "0xrole"
    fp_role.resolved_type = "safe"
    fp_role.origin = "role 1"
    fp_role.principal_type = "authority_role"
    fp_role.details = {"threshold": 2}

    fp_controller = MagicMock()
    fp_controller.address = "0xcontroller"
    fp_controller.resolved_type = "contract"
    fp_controller.origin = "roleRegistry"
    fp_controller.principal_type = "controller"
    fp_controller.details = {"authority_kind": "external_authority"}

    cv = MagicMock()
    cv.controller_id = "admin"
    cv.value = "0xadmin"
    cv.resolved_type = "eoa"
    cv.source = "slot"
    cv.details = {}

    cgn = MagicMock()
    cgn.address = "0xowner"
    cgn.node_type = "external"
    cgn.resolved_type = "eoa"
    cgn.label = "Owner"
    cgn.contract_name = None
    cgn.depth = 1
    cgn.analyzed = False

    cge = MagicMock()
    cge.from_node_id = "address:0xowner"
    cge.to_node_id = "address:0x2222222222222222222222222222222222222222"
    cge.relation = "owner"
    cge.label = "owns"

    pl = MagicMock()
    pl.address = "0xowner"
    pl.label = "Admin"
    pl.resolved_type = "eoa"

    mock_session.get.return_value = None

    fp_owner.function_id = ef.id
    fp_role.function_id = ef.id
    fp_controller.function_id = ef.id
    # selectinload puts principals on ef.principals; no separate FP query.
    ef.principals = [fp_owner, fp_role, fp_controller]

    def make_result(scalar=None, scalars_all=None):
        r = MagicMock()
        items = scalars_all or []
        r.scalar_one_or_none.return_value = scalar
        r.scalars.return_value.all.return_value = items
        # api.py iterates ``Result.scalars()`` directly in the batched
        # prefetch paths; MagicMock needs explicit __iter__ for that.
        r.scalars.return_value.__iter__ = lambda s: iter(items)
        return r

    # Calls 0-6: proxy's own relational queries; 7-8: impl job + Contract;
    # 9+: impl's relational queries (EF eager-loads FP, then CV/CGN/CGE/PL).
    call_results = [
        make_result(scalar=proxy_job),  # 0: Job lookup by name
        make_result(scalar=proxy_contract),  # 1: Contract lookup for proxy
        make_result(scalars_all=[]),  # 2: EffectiveFunction for proxy (empty)
        make_result(scalars_all=[]),  # 3: PrincipalLabel for proxy (empty)
        make_result(scalars_all=[]),  # 4: ControllerValue for proxy (empty)
        make_result(scalars_all=[]),  # 5: ControlGraphNode for proxy (empty)
        make_result(scalars_all=[]),  # 6: ControlGraphEdge for proxy (empty)
        make_result(scalar=impl_job),  # 7: impl job lookup by address
        make_result(scalar=impl_contract),  # 8: impl Contract lookup
        make_result(scalars_all=[ef]),  # 9: EffectiveFunction for impl
        make_result(scalars_all=[cv]),  # 10: ControllerValue for impl
        make_result(scalars_all=[cgn]),  # 11: ControlGraphNode for impl
        make_result(scalars_all=[cge]),  # 12: ControlGraphEdge for impl
        make_result(scalars_all=[pl]),  # 13: PrincipalLabel for impl
    ]
    # Add extra fallback results
    for _ in range(10):
        call_results.append(make_result())

    mock_session.execute.side_effect = call_results

    # Proxy has no analysis artifacts
    mock_get_all_artifacts.side_effect = [
        {
            "dependency_graph_viz": {"nodes": [], "edges": []},
            "dependencies": {"deps": []},
        },
        # impl artifacts (empty, so relational tables are used)
        {},
    ]

    mock_get_artifact.return_value = None

    response = client.get("/api/analyses/ProxyRelTest")
    assert response.status_code == 200
    body = response.json()

    # Should have inherited effective_permissions from impl relational tables
    assert "effective_permissions" in body
    assert body["effective_permissions"]["functions"][0]["function"] == "transfer(address,uint256)"

    # Should have inherited control_snapshot from impl
    assert "control_snapshot" in body
    assert "admin" in body["control_snapshot"]["controller_values"]

    # Should have inherited resolved_control_graph from impl
    assert "resolved_control_graph" in body
    assert len(body["resolved_control_graph"]["nodes"]) >= 1

    # Should have inherited principal_labels from impl
    assert "principal_labels" in body
    assert body["principal_labels"]["principals"][0]["address"] == "0xowner"

    # Should have contract_name from impl
    assert body["contract_name"] == "ImplContract"

    # Summary from impl contract
    assert body["summary"]["control_model"] == "authority"

    # Proxy-specific fields
    assert body["implementation_address"] == impl_addr


# ============================================================================
# 17. GET /api/company - capabilities and roles
# ============================================================================


def test_company_overview_with_proxy_and_effects(db_session, api_client):
    """Proxy with capability/effect labels — real-DB integration.

    Replaces the previous positional-mock test (which tied test correctness
    to the exact SQL call order and broke when the API switched to batched
    prefetches). Builds a real protocol with one proxy + one impl, asserts
    the capability/role/balance derivation logic.
    """
    from db.models import (
        Contract,
        ContractBalance,
        ContractSummary,
        EffectiveFunction,
        FunctionPrincipal,
        Job,
        JobStage,
        JobStatus,
        Protocol,
        UpgradeEvent,
    )

    proxy_addr = "0x" + "a" * 40
    impl_addr = "0x" + "b" * 40

    protocol = Protocol(name="myproj_proxy_test", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()

    proxy_job = Job(
        id=uuid.uuid4(),
        address=proxy_addr,
        company="myproj_proxy_test",
        name="MyProxy",
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"chain": "ethereum"},
        protocol_id=protocol.id,
    )
    impl_job = Job(
        id=uuid.uuid4(),
        address=impl_addr,
        company="myproj_proxy_test",
        name="MyProxy: (impl)",
        status=JobStatus.completed,
        stage=JobStage.done,
        request={"chain": "ethereum", "proxy_address": proxy_addr, "parent_job_id": str(proxy_job.id)},
        protocol_id=protocol.id,
    )
    db_session.add_all([proxy_job, impl_job])
    db_session.flush()

    proxy_contract = Contract(
        job_id=proxy_job.id,
        protocol_id=protocol.id,
        address=proxy_addr,
        chain="ethereum",
        contract_name="MyProxy",
        is_proxy=True,
        proxy_type="eip1967",
        implementation=impl_addr,
        source_verified=True,
    )
    impl_contract = Contract(
        job_id=impl_job.id,
        protocol_id=protocol.id,
        address=impl_addr,
        chain="ethereum",
        contract_name="VaultImpl",
        is_proxy=False,
        source_verified=True,
    )
    db_session.add_all([proxy_contract, impl_contract])
    db_session.flush()

    db_session.add(
        ContractSummary(
            contract_id=impl_contract.id,
            control_model="authority",
            is_upgradeable=True,
            is_pausable=True,
            has_timelock=True,
            risk_level="high",
            is_factory=False,
            standards=[],
            source_verified=True,
        )
    )
    db_session.add(
        UpgradeEvent(
            contract_id=proxy_contract.id,
            proxy_address=proxy_addr,
            old_impl=None,
            new_impl=impl_addr,
            block_number=1000,
            tx_hash="0x" + "f" * 64,
        )
    )
    db_session.add(
        ContractBalance(
            contract_id=proxy_contract.id,
            token_address=None,
            token_symbol="ETH",
            token_name="Ether",
            decimals=18,
            raw_balance="1000000000000000000",
            usd_value=3000.50,
            price_usd=3000.50,
        )
    )

    ef = EffectiveFunction(
        contract_id=impl_contract.id,
        function_name="pause",
        selector="0x8456cb59",
        abi_signature="pause()",
        effect_labels=["pause_toggle", "asset_pull", "delegatecall_execution"],
        effect_targets=[],
        action_summary="Pauses",
        authority_public=False,
        authority_roles=[],
    )
    db_session.add(ef)
    db_session.flush()
    db_session.add_all(
        [
            FunctionPrincipal(
                function_id=ef.id,
                address="0x" + "1" * 40,
                resolved_type="eoa",
                origin="direct owner",
                principal_type="direct_owner",
                details={},
            ),
            FunctionPrincipal(
                function_id=ef.id,
                address="0x" + "2" * 40,
                resolved_type="safe",
                origin="role 1",
                principal_type="authority_role",
                details={"threshold": 2},
            ),
            FunctionPrincipal(
                function_id=ef.id,
                address="0x" + "3" * 40,
                resolved_type="contract",
                origin="roleRegistry",
                principal_type="controller",
                details={"authority_kind": "external_authority"},
            ),
        ]
    )
    db_session.commit()

    try:
        response = api_client.get("/api/company/myproj_proxy_test")
        assert response.status_code == 200
        body = response.json()

        assert body["company"] == "myproj_proxy_test"
        proxy_entries = [c for c in body["contracts"] if c["address"] == proxy_addr]
        assert len(proxy_entries) == 1
        c = proxy_entries[0]
        assert c["is_proxy"] is True
        assert "upgradeable" in c["capabilities"]
        assert "pause" in c["capabilities"]
        assert "fund-in" in c["capabilities"]  # asset_pull → shared "fund-in" tag (was "value-in")
        assert "delegatecall" in c["capabilities"]
        assert c["upgrade_count"] == 1
        assert c["has_timelock"] is True
        # Functions moved to /api/company/{name}/functions to shrink the
        # main payload; the entry itself no longer carries them.
        assert "functions" not in c
        functions_body = api_client.get("/api/company/myproj_proxy_test/functions").json()
        proxy_key = f"ethereum::{proxy_addr.lower()}"
        assert proxy_key in functions_body["functions"]
        fn_entries = functions_body["functions"][proxy_key]
        assert len(fn_entries) == 1
        fn = fn_entries[0]
        assert fn["direct_owner"]["address"] == ("0x" + "1" * 40)
        assert fn["authority_roles"] and fn["authority_roles"][0]["role"] == 1
        assert any(p["address"] == "0x" + "3" * 40 for ctrl in fn["controllers"] for p in ctrl["principals"])
        assert len(c["balances"]) >= 1
    finally:
        db_session.execute(text("DELETE FROM contracts WHERE protocol_id = :p"), {"p": protocol.id})
        db_session.execute(text("DELETE FROM jobs WHERE company = :c"), {"c": "myproj_proxy_test"})
        db_session.execute(text("DELETE FROM protocols WHERE id = :p"), {"p": protocol.id})
        db_session.commit()


# ============================================================================
# 18. GET /api/analyses - chain from inventory 'chain' field (not 'chains')
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_analyses_chain_populated_from_contracts_table(mock_session_cls):
    """Chain comes from the ``contracts`` table (same pass that sets
    rank_score) regardless of how the discovery worker wrote it —
    a row with ``chain='arbitrum'`` surfaces in the analyses listing."""
    client = _make_client()
    company_job = _fake_job(
        name="chain_disc",
        company="test_co",
        address=None,
    )
    child_job = _fake_job(
        name="chain_child",
        address="0xdddd",
    )

    from db.models import JobStatus

    company_job.status = JobStatus.completed
    child_job.status = JobStatus.completed
    # The job and its Contract row must agree on chain for the listing to pair
    # them: an arbitrum contract belongs to an arbitrum job.
    child_job.chain_id = 42161

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    contract_row = SimpleNamespace(
        address="0xdddd",
        chain="arbitrum",
        rank_score=5.0,
        contract_name="ChainTest",
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )
    artifacts = [
        SimpleNamespace(
            job_id=child_job.id,
            name="contract_analysis",
            storage_key=None,
            data={"subject": {"name": "ChainTest"}, "summary": {}},
            text_data=None,
            content_type=None,
        ),
    ]

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [company_job, child_job]
        elif call_count["n"] == 2:
            result.scalars.return_value = iter([contract_row])
        elif call_count["n"] == 3:
            result.scalars.return_value = iter(artifacts)
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/analyses")
    assert response.status_code == 200
    entries = response.json()
    child = next((e for e in entries if e.get("address") == "0xdddd"), None)
    assert child is not None
    assert child["chain"] == "arbitrum"


# ============================================================================
# 19. GET /api/analyses - entry without contract_analysis is not appended
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_analyses_entry_without_analysis_still_appears(mock_session_cls):
    """A job without contract_analysis artifact still appears in results, but
    without contract_name or summary fields from the analysis."""
    client = _make_client()
    job = _fake_job(name="no_analysis", address="0xeeee")

    from db.models import JobStatus

    job.status = JobStatus.completed

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [job]
        elif call_count["n"] == 2:
            result.all.return_value = []
        elif call_count["n"] == 3:
            result.scalars.return_value = iter([])
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/analyses")
    assert response.status_code == 200
    entries = response.json()
    entry = next((e for e in entries if e.get("address") == "0xeeee"), None)
    assert entry is not None
    # No contract_name since analysis was None
    assert "contract_name" not in entry
    assert "summary" not in entry


# ============================================================================
# 20. GET /api/analyses - proxy uses impl analysis when proxy has none
# ============================================================================


@patch("routers.deps.SessionLocal")
def test_analyses_proxy_uses_impl_analysis_when_proxy_has_none(mock_session_cls):
    """When proxy's Contract row has no name, the proxy entry inherits the
    impl's Contract.contract_name. Earlier code reached for the impl's
    contract_analysis artifact body to read subject.name, but the listing
    no longer fetches artifact bodies — names come from the prefetched
    Contract rows directly. This regression test now seeds both
    Contract rows and asserts the impl-name is what surfaces."""
    client = _make_client()

    proxy_job_id = uuid.uuid4()
    impl_job_id = uuid.uuid4()

    proxy_job = _fake_job(
        job_id=str(proxy_job_id),
        name="proxy_no_analysis",
        address="0xaaaa",
        is_proxy=True,
    )
    impl_job = _fake_job(
        job_id=str(impl_job_id),
        name="impl_has_analysis",
        address="0xbbbb",
    )

    from db.models import JobStatus

    proxy_job.status = JobStatus.completed
    impl_job.status = JobStatus.completed

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    proxy_contract = SimpleNamespace(
        address="0xaaaa",
        chain=None,
        rank_score=None,
        contract_name=None,  # missing — should inherit from impl
        is_proxy=True,
        proxy_type="ERC1967",
        implementation="0xbbbb",
    )
    impl_contract = SimpleNamespace(
        address="0xbbbb",
        chain=None,
        rank_score=None,
        contract_name="ImplName",
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            # Job listing
            result.scalars.return_value.all.return_value = [proxy_job, impl_job]
        elif call_count["n"] == 2:
            # Contracts prefetch — returns both rows now (was just proxy
            # before, since the old code didn't need impl's Contract row).
            result.scalars.return_value = iter([proxy_contract, impl_contract])
        elif call_count["n"] == 3:
            # Artifact name listing — empty is fine, the test only cares
            # about the contract_name fallback chain.
            result.all.return_value = []
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/analyses")
    assert response.status_code == 200
    entries = response.json()
    # The proxy should have picked up impl's analysis
    proxy_entry = next((e for e in entries if e.get("job_id") == str(proxy_job_id)), None)
    if proxy_entry is not None:
        assert proxy_entry.get("contract_name") == "ImplName"
