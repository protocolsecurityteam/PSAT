from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from tests.cache_helpers import requires_postgres  # noqa: E402


def _make_fake_job(
    job_id: str | None = None,
    address: str | None = "0xabc",
    name: str = "demo_run",
    status: str = "completed",
    stage: str = "done",
):
    """Build a mock Job object that looks like db.models.Job."""
    job = MagicMock()
    job.id = uuid.UUID(job_id) if job_id else uuid.uuid4()
    job.address = address
    job.company = None
    job.name = name
    job.status = MagicMock(value=status)
    job.stage = MagicMock(value=stage)
    job.detail = "Test detail"
    job.request = {"address": address}
    job.error = None
    job.worker_id = None
    job.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    job.updated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    job.to_dict.return_value = {
        "job_id": str(job.id),
        "address": address,
        "company": None,
        "name": name,
        "status": status,
        "stage": stage,
        "detail": "Test detail",
        "request": {"address": address},
        "error": None,
        "worker_id": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    return job


def make_client() -> TestClient:
    import api

    return TestClient(api.app)


def _admin_headers() -> dict[str, str]:
    """Header carrying the configured admin key, for now-gated internal reads."""
    from routers import deps

    return {"X-PSAT-Admin-Key": deps.ADMIN_KEY or ""}


def test_build_company_function_entry_filters_generic_authority_contract_when_specific_principals_exist() -> None:
    from services.governance.principals import _build_company_function_entry

    ef = SimpleNamespace(
        abi_signature="pauseContract()",
        function_name="pauseContract",
        selector="0x439766ce",
        effect_labels=["pause_toggle"],
        effect_targets=["paused"],
        action_summary="Changes the contract pause state.",
        authority_public=False,
        authority_roles=[],
    )
    principals = [
        SimpleNamespace(
            address="0xrole",
            resolved_type="contract",
            origin="roleRegistry",
            principal_type="controller",
            details={"authority_kind": "external_authority"},
        ),
        SimpleNamespace(
            address="0xsafe",
            resolved_type="safe",
            origin="PROTOCOL_PAUSER",
            principal_type="controller",
            details={"threshold": 4, "owners": ["0x1", "0x2", "0x3", "0x4"]},
        ),
        SimpleNamespace(
            address="0xeoa",
            resolved_type="eoa",
            origin="PROTOCOL_PAUSER",
            principal_type="controller",
            details={},
        ),
    ]

    result = _build_company_function_entry(cast(Any, ef), cast(Any, principals))

    assert result["controllers"] == [
        {
            "label": "PROTOCOL_PAUSER",
            "controller_id": "PROTOCOL_PAUSER",
            "source": "PROTOCOL_PAUSER",
            "principals": [
                {
                    "address": "0xsafe",
                    "resolved_type": "safe",
                    "source_controller_id": "PROTOCOL_PAUSER",
                    "principal_type": "controller",
                    "details": {"threshold": 4, "owners": ["0x1", "0x2", "0x3", "0x4"]},
                    "terminal": True,
                },
                {
                    "address": "0xeoa",
                    "resolved_type": "eoa",
                    "source_controller_id": "PROTOCOL_PAUSER",
                    "principal_type": "controller",
                    "details": {},
                    "terminal": True,
                },
            ],
        }
    ]


def test_build_company_function_entry_enriches_principal_type_from_company_lookup() -> None:
    from services.governance.principals import _build_company_function_entry

    timelock_addr = "0x" + "9" * 40
    ef = SimpleNamespace(
        abi_signature="transferOwnership(address)",
        function_name="transferOwnership",
        selector="0xf2fde38b",
        effect_labels=["ownership_transfer"],
        effect_targets=["owner"],
        action_summary="Transfers ownership.",
        authority_public=False,
        authority_roles=[],
    )
    principals = [
        SimpleNamespace(
            address=timelock_addr,
            resolved_type=None,
            origin="semantic_capability:finite_set",
            principal_type="controller",
            details={"membership_quality": "exact"},
        )
    ]

    result = _build_company_function_entry(
        cast(Any, ef),
        cast(Any, principals),
        principal_lookup={
            timelock_addr: {
                "resolved_type": "timelock",
                "label": "ProtocolTimelock",
                "details": {"delay": 864000},
            }
        },
    )

    principal = result["controllers"][0]["principals"][0]
    assert principal["resolved_type"] == "timelock"
    assert principal["label"] == "ProtocolTimelock"
    assert principal["principal_type"] == "controller"
    assert principal["details"] == {"delay": 864000, "membership_quality": "exact"}


def test_company_principal_lookup_promotes_delay_contract_to_timelock() -> None:
    from services.aggregations.company_overview import _build_principal_lookup

    timelock_addr = "0x" + "8" * 40
    contract = SimpleNamespace(
        id=1,
        address=timelock_addr,
        contract_name="ProtocolTimelock",
        summary=SimpleNamespace(has_timelock=False),
    )
    node = SimpleNamespace(
        address=timelock_addr,
        resolved_type="contract",
        contract_name=None,
        label="timelock controller",
        details={"delay": 864000},
    )

    lookup = _build_principal_lookup(
        {uuid.uuid4(): cast(Any, contract)},
        {},
        {1: [cast(Any, node)]},
    )

    assert lookup[timelock_addr]["resolved_type"] == "timelock"
    assert lookup[timelock_addr]["label"] == "ProtocolTimelock"
    assert lookup[timelock_addr]["details"]["delay"] == 864000


def test_index_serves_html(spa_index) -> None:
    client = make_client()
    response = client.get("/")
    assert response.status_code == 200
    assert "Run an address and inspect the control surface" in response.text


def test_spa_fallback_serves_html_for_deep_link(spa_index) -> None:
    client = make_client()
    response = client.get("/address/0x1234567890123456789012345678901234567890/graph")
    assert response.status_code == 200
    assert "Run an address and inspect the control surface" in response.text


@requires_postgres
def test_health_and_config_endpoints(api_client) -> None:
    health = api_client.get("/api/health")
    config = api_client.get("/api/config")

    assert health.status_code == 200
    payload = health.json()
    assert payload["status"] == "ok"
    assert payload["db"] == "ok"
    # conftest scrubs ARTIFACT_STORAGE_*, so this client sees the inline path.
    assert payload["storage"] == "inline"
    assert config.status_code == 200
    assert "default_rpc_url" in config.json()


def test_version_endpoint_returns_git_sha(api_client, monkeypatch) -> None:
    monkeypatch.setenv("GIT_SHA", "deadbeef")
    r = api_client.get("/api/version")
    assert r.status_code == 200
    assert r.json() == {"sha": "deadbeef"}

    monkeypatch.delenv("GIT_SHA", raising=False)
    r = api_client.get("/api/version")
    assert r.json() == {"sha": "unknown"}


def test_admin_key_required_for_non_get(monkeypatch) -> None:
    """Without a valid admin key, write endpoints must return 401."""
    import api
    from routers.deps import require_admin_key

    # Drop the conftest override for this test only and force a known key.
    api.app.dependency_overrides.pop(require_admin_key, None)
    monkeypatch.setattr("routers.deps.ADMIN_KEY", "real-key")

    client = TestClient(api.app)

    no_header = client.post(
        "/api/analyze",
        json={"address": "0x1234567890123456789012345678901234567890", "name": "demo"},
    )
    bad_header = client.post(
        "/api/analyze",
        json={"address": "0x1234567890123456789012345678901234567890", "name": "demo"},
        headers={"X-PSAT-Admin-Key": "wrong"},
    )
    assert no_header.status_code == 401
    assert bad_header.status_code == 401


@requires_postgres
def test_cors_allows_configured_origin(monkeypatch, db_session) -> None:
    """Configured origins should be reflected in CORS responses."""
    from tests.conftest import SessionFactory

    monkeypatch.setenv("PSAT_SITE_ORIGIN", "https://psat.example.com")
    import importlib

    import api

    importlib.reload(api)
    try:
        # Reload re-evaluated the CORS middleware against the new origin.
        # SessionLocal lives on routers.deps (every router reads it from
        # there) — point that at the test DB so /api/health works.
        from routers import deps
        from routers.deps import require_admin_key

        monkeypatch.setattr(deps, "SessionLocal", SessionFactory(db_session))
        api.app.dependency_overrides[require_admin_key] = lambda: None
        client = TestClient(api.app)

        response = client.get("/api/health", headers={"Origin": "https://psat.example.com"})
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "https://psat.example.com"
    finally:
        monkeypatch.delenv("PSAT_SITE_ORIGIN", raising=False)
        importlib.reload(api)


def test_analyze_endpoint_rejects_bad_address() -> None:
    client = make_client()
    response = client.post("/api/analyze", json={"address": "123", "name": "demo"})
    assert response.status_code == 422


def test_analyze_endpoint_requires_at_least_one_target() -> None:
    client = make_client()

    missing = client.post("/api/analyze", json={"name": "demo"})

    assert missing.status_code == 422


@patch("routers.deps.SessionLocal")
def test_get_job_and_missing_job(mock_session_cls) -> None:
    client = make_client()
    fake_job = _make_fake_job()

    mock_session = MagicMock()
    mock_session.get.side_effect = lambda cls, id: fake_job if id == str(fake_job.id) else None
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    existing = client.get(f"/api/jobs/{fake_job.id}")
    missing = client.get(f"/api/jobs/{uuid.uuid4()}")

    assert existing.status_code == 200
    assert existing.json()["status"] == "completed"
    assert missing.status_code == 404


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analyses_detail(mock_session_cls, mock_get_all_artifacts) -> None:
    client = make_client()
    fake_job = _make_fake_job(name="demo_run", address="0xabc")

    mock_session = MagicMock()
    mock_execute = MagicMock()
    mock_execute.scalar_one_or_none.return_value = fake_job
    mock_session.execute.return_value = mock_execute
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    mock_get_all_artifacts.return_value = {
        "contract_analysis": {"subject": {"name": "Demo"}, "summary": {"control_model": "ownable"}},
    }

    detail = client.get("/api/analyses/demo_run")

    assert detail.status_code == 200
    assert detail.json()["run_name"] == "demo_run"


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_missing_analysis_returns_404(mock_session_cls, mock_get_all_artifacts) -> None:
    client = make_client()

    mock_session = MagicMock()
    mock_execute = MagicMock()
    mock_execute.scalar_one_or_none.return_value = None
    mock_session.execute.return_value = mock_execute
    mock_session.get.return_value = None
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    response = client.get("/api/analyses/missing")
    assert response.status_code == 404


@patch("routers.deps.SessionLocal")
def test_artifact_endpoint_serves_json_and_text(mock_session_cls) -> None:
    """Inline-stored artifacts (no storage_key) are served directly."""
    client = make_client()
    fake_job = _make_fake_job(name="demo_run")

    fake_json_artifact = MagicMock()
    fake_json_artifact.storage_key = None
    fake_json_artifact.data = {"summary": {"control_model": "ownable"}}
    fake_json_artifact.text_data = None
    fake_json_artifact.content_type = "application/json"

    fake_text_artifact = MagicMock()
    fake_text_artifact.storage_key = None
    fake_text_artifact.data = None
    fake_text_artifact.text_data = "report body"
    fake_text_artifact.content_type = "text/plain"

    # Per-request the endpoint runs: Job lookup (1) → Artifact lookup (2).
    # Two endpoint calls back-to-back = four execute() invocations total.
    sequence = [fake_job, fake_json_artifact, fake_job, fake_text_artifact]

    def execute_side_effect(*_args, **_kwargs):
        result = MagicMock()
        result.scalar_one_or_none.return_value = sequence.pop(0) if sequence else None
        return result

    mock_session = MagicMock()
    mock_session.execute.side_effect = execute_side_effect
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    json_response = client.get("/api/analyses/demo_run/artifact/contract_analysis.json", headers=_admin_headers())
    txt_response = client.get("/api/analyses/demo_run/artifact/analysis_report.txt", headers=_admin_headers())

    assert json_response.status_code == 200, json_response.text
    assert json_response.json()["summary"]["control_model"] == "ownable"
    assert txt_response.status_code == 200, txt_response.text
    assert "report body" in txt_response.text


@patch("routers.deps.SessionLocal")
def test_protocol_tvl_caps_days(mock_session_cls) -> None:
    """days parameter should be capped to MAX_TVL_HISTORY_DAYS."""
    client = make_client()

    fake_protocol = MagicMock()
    fake_protocol.id = 1
    fake_protocol.name = "TestProto"

    mock_session = MagicMock()
    mock_session.get.return_value = fake_protocol

    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_execute_result = MagicMock()
    mock_execute_result.scalars.return_value = mock_scalars
    mock_session.execute.return_value = mock_execute_result

    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    response = client.get("/api/protocols/1/tvl?days=9999")
    assert response.status_code == 200

    from routers import deps

    assert deps.MAX_TVL_HISTORY_DAYS <= 365
    # The clamp is only proven by the window the query actually asked for: the
    # query param carries no ``le=``, so ``days = min(days, MAX)`` is the sole
    # bound on an unauthenticated 9999-day scan.
    stmt = mock_session.execute.call_args[0][0]
    cutoffs = [v for v in stmt.compile().params.values() if isinstance(v, datetime)]
    assert len(cutoffs) == 1
    assert (datetime.now(timezone.utc) - cutoffs[0]).days == deps.MAX_TVL_HISTORY_DAYS


# ---------------------------------------------------------------------------
# /api/jobs/{job_id}/stage_timings — bench harness consumer
# ---------------------------------------------------------------------------


@patch("routers.deps.SessionLocal")
def test_stage_timings_endpoint_returns_per_stage_artifacts(mock_session_cls) -> None:
    """Bench harness needs a reliable per-stage timing source. The endpoint
    must collect every ``stage_timing_<stage>`` artifact for the job and
    return them keyed by stage name (the suffix after ``stage_timing_``).
    Mirrors what the worker writes via ``_record_stage_timing``."""
    from routers import deps

    client = make_client()
    fake_job = _make_fake_job()

    # Use the inline path (data set, storage_key NULL) — exercises the same
    # response-assembly code as the storage path without needing a fake
    # boto3 client. SimpleNamespace stands in for an ORM Artifact row.
    art_discovery = SimpleNamespace(
        name="stage_timing_discovery",
        storage_key=None,
        content_type=None,
        data={
            "schema_version": "2",
            "stage": "discovery",
            "elapsed_s": 4.2,
            "started_at": "t0",
            "ended_at": "t1",
            "worker_id": "DiscoveryWorker-1-aaa",
            "status": "success",
        },
        text_data=None,
    )
    art_static = SimpleNamespace(
        name="stage_timing_static",
        storage_key=None,
        content_type=None,
        data={
            "schema_version": "2",
            "stage": "static",
            "elapsed_s": 28.7,
            "started_at": "t1",
            "ended_at": "t2",
            "worker_id": "StaticWorker-1-bbb",
            "status": "success",
        },
        text_data=None,
    )

    mock_session = MagicMock()
    mock_session.get.return_value = fake_job
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = [art_discovery, art_static]
    mock_execute_result = MagicMock()
    mock_execute_result.scalars.return_value = mock_scalars
    mock_session.execute.return_value = mock_execute_result
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    deps.ADMIN_KEY = "test-admin-key"
    resp = client.get(
        f"/api/jobs/{fake_job.id}/stage_timings",
        headers={"X-PSAT-Admin-Key": "test-admin-key"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["job_id"] == str(fake_job.id)
    assert set(body["stage_timings"].keys()) == {"discovery", "static"}
    assert body["stage_timings"]["discovery"]["elapsed_s"] == 4.2
    assert body["stage_timings"]["static"]["elapsed_s"] == 28.7
    assert body["stage_timings"]["discovery"]["status"] == "success"


@patch("routers.deps.SessionLocal")
def test_stage_timings_endpoint_404_for_unknown_job(mock_session_cls) -> None:
    from routers import deps

    client = make_client()
    mock_session = MagicMock()
    mock_session.get.return_value = None
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    deps.ADMIN_KEY = "test-admin-key"
    resp = client.get(
        f"/api/jobs/{uuid.uuid4()}/stage_timings",
        headers={"X-PSAT-Admin-Key": "test-admin-key"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Storage-failure degradation. Both endpoints used to 500 on a transport
# error or a missing storage client; we degrade per-row so a flaky bucket
# can't take down the whole response.
# ---------------------------------------------------------------------------


@patch("routers.deps.get_storage_client")
@patch("routers.deps.SessionLocal")
def test_stage_timings_degrades_when_storage_unconfigured(mock_session_cls, mock_get_client) -> None:
    """If storage is not configured but rows reference ``storage_key``, the
    endpoint must return what it can (inline rows, empty if none) instead of
    raising — env drift on a redeploy shouldn't 500 the SPA."""

    fake_job = _make_fake_job()
    storage_row = SimpleNamespace(
        name="stage_timing_static",
        storage_key="some/key",
        content_type="application/json",
        data=None,
        text_data=None,
    )
    inline_row = SimpleNamespace(
        name="stage_timing_discovery",
        storage_key=None,
        content_type=None,
        data={"stage": "discovery", "elapsed_s": 1.0},
        text_data=None,
    )

    mock_session = MagicMock()
    mock_session.get.return_value = fake_job
    mock_session.execute.return_value.scalars.return_value.all.return_value = [inline_row, storage_row]
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_get_client.return_value = None  # storage env stripped

    resp = make_client().get(f"/api/jobs/{fake_job.id}/stage_timings")
    assert resp.status_code == 200
    body = resp.json()
    # Inline row survives; storage row is silently skipped.
    assert set(body["stage_timings"].keys()) == {"discovery"}


@patch("routers.deps.get_storage_client")
@patch("routers.deps.SessionLocal")
def test_stage_timings_degrades_on_storage_transport_error(mock_session_cls, mock_get_client) -> None:
    """Transport error from the bucket (Tigris hiccup, signing failure, etc.)
    surfaces as ``None`` for the affected key (per ``get_many``'s contract,
    pinned in test_db_storage_unit.py). The endpoint must drop the affected
    stage and keep healthy ones, not 500."""
    fake_job = _make_fake_job()
    inline_row = SimpleNamespace(
        name="stage_timing_discovery",
        storage_key=None,
        content_type=None,
        data={"stage": "discovery", "elapsed_s": 1.0},
        text_data=None,
    )
    storage_row = SimpleNamespace(
        name="stage_timing_static",
        storage_key="some/key",
        content_type="application/json",
        data=None,
        text_data=None,
    )

    fake_client = MagicMock()
    fake_client.get_many.return_value = {"some/key": None}

    mock_session = MagicMock()
    mock_session.get.return_value = fake_job
    mock_session.execute.return_value.scalars.return_value.all.return_value = [inline_row, storage_row]
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)
    mock_get_client.return_value = fake_client

    resp = make_client().get(f"/api/jobs/{fake_job.id}/stage_timings")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "discovery" in body["stage_timings"]
    assert "static" not in body["stage_timings"]


@patch("routers.deps.SessionLocal")
def test_analyses_listing_does_not_touch_object_storage(mock_session_cls) -> None:
    """The listing endpoint must build entirely from DB rows now — no
    object-storage GETs. The previous ``get_many`` path was the dominant
    cost on production (Tigris RTT × N artifacts) and a transient
    storage outage could degrade every row's name/summary. The new path
    reads contract names from prefetched Contract rows and lists
    artifact NAMES only.

    Replaces the older ``test_analyses_degrades_per_row_on_partial_storage_failure``
    — that test was specifically asserting the per-key fallback behaviour
    of the old storage path, which no longer exists in this endpoint.
    """
    j_good = _make_fake_job(name="run_good", address="0xaaa")
    j_bad = _make_fake_job(name="run_bad", address="0xbbb")

    contract_good = SimpleNamespace(
        address="0xaaa",
        chain=None,
        rank_score=None,
        contract_name="Good",
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )
    contract_bad = SimpleNamespace(
        address="0xbbb",
        chain=None,
        rank_score=None,
        contract_name=None,  # no name available — should still appear
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )

    jobs_result = MagicMock()
    jobs_result.scalars.return_value.all.return_value = [j_good, j_bad]
    contracts_result = MagicMock()
    contracts_result.scalars.return_value = iter([contract_good, contract_bad])
    artifact_names_result = MagicMock()
    # Two artifact NAMES per job — proves the row goes through without
    # any storage fetch happening.
    artifact_names_result.all.return_value = [
        (j_good.id, "contract_analysis"),
        (j_good.id, "contract_flags"),
        (j_bad.id, "contract_analysis"),
        (j_bad.id, "contract_flags"),
    ]

    sess = MagicMock()
    sess.execute.side_effect = [jobs_result, contracts_result, artifact_names_result]
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=sess)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)

    # Patch get_storage_client so we can assert it was never called.
    with patch("routers.deps.get_storage_client") as mock_get_client:
        resp = make_client().get("/api/analyses")
        assert resp.status_code == 200, resp.text
        mock_get_client.assert_not_called()

    by_run = {e["run_name"]: e for e in resp.json()}
    assert by_run["run_good"].get("contract_name") == "Good"
    # No summary anywhere — that field is no longer emitted by the listing.
    assert "summary" not in by_run["run_good"]
    # The unnamed row still appears, just without contract_name.
    assert "run_bad" in by_run
    assert "contract_name" not in by_run["run_bad"]
    # Artifact names are still listed (no body fetch needed).
    assert sorted(by_run["run_good"]["available_artifacts"]) == ["contract_analysis", "contract_flags"]
