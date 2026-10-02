from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.support.api_helpers import _mock_session_ctx


def _fake_api_job(
    job_id: str | None = None,
    address: str | None = None,
    company: str | None = None,
    name: str | None = None,
    status: str = "queued",
    stage: str = "discovery",
    request: dict | None = None,
    is_proxy: bool = False,
):
    job = MagicMock()
    uid = uuid.UUID(job_id) if job_id else uuid.uuid4()
    job.id = uid
    job.address = address
    job.company = company
    job.name = name
    job.status = MagicMock(value=status)
    job.stage = MagicMock(value=stage)
    job.detail = "Test detail"
    job.request = request or {}
    job.error = None
    job.worker_id = None
    # A bare MagicMock attribute is truthy, and the listing reads Job.is_proxy directly.
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
        "detail": "Test detail",
        "request": request or {},
        "error": None,
        "worker_id": None,
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
    }
    return job


def _make_client() -> TestClient:
    import api

    return TestClient(api.app)


@patch("routers.deps.SessionLocal")
@patch("routers.deps.create_job")
def test_analyze_address_creates_job(mock_create_job, mock_session_cls):
    client = _make_client()
    addr = "0x1111111111111111111111111111111111111111"

    fake_job = _fake_api_job(
        address=addr,
        status="queued",
        stage="discovery",
        request={
            "address": addr,
            "name": None,
            "company": None,
            "chain": None,
            "analyze_limit": 5,
            "rpc_url": None,
        },
    )
    mock_create_job.return_value = fake_job

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    response = client.post("/api/analyze", json={"address": addr})

    assert response.status_code == 200
    body = response.json()
    assert body["address"] == addr
    assert body["company"] is None
    assert body["stage"] == "discovery"
    assert body["status"] == "queued"

    call_args = mock_create_job.call_args
    req_dict = call_args[0][1]
    assert req_dict["address"] == addr
    assert req_dict.get("company") is None


@patch("routers.deps.SessionLocal")
def test_analyses_list_proxy_flagging(mock_session_cls):
    """Proxy entries whose impl child hasn't completed are hidden, so both jobs must be present."""
    client = _make_client()
    proxy_job_id = uuid.uuid4()
    impl_job_id = uuid.uuid4()
    proxy_addr = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    impl_addr = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

    proxy_job = _fake_api_job(
        job_id=str(proxy_job_id),
        address=proxy_addr,
        name="proxy_contract",
        status="completed",
        stage="done",
        request={"address": proxy_addr},
        is_proxy=True,
    )
    impl_job = _fake_api_job(
        job_id=str(impl_job_id),
        address=impl_addr,
        name="proxy_contract: (impl)",
        status="completed",
        stage="done",
        request={"address": impl_addr, "proxy_address": proxy_addr, "parent_job_id": str(proxy_job_id)},
    )

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    from db.models import JobStatus

    impl_job.status = JobStatus.completed
    proxy_job.status = JobStatus.completed

    # The merge prefers the impl's name over generic proxy names, so both Contract rows are mocked.
    proxy_contract_row = SimpleNamespace(
        address=proxy_addr,
        chain=None,
        rank_score=None,
        contract_name="ProxyContract",
        is_proxy=True,
        proxy_type="ERC1967",
        implementation=impl_addr,
    )
    impl_contract_row = SimpleNamespace(
        address=impl_addr,
        chain=None,
        rank_score=None,
        contract_name="VaultImpl",
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )

    # Query order: jobs, contracts (.scalars()), artifact names (.all()).

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [proxy_job, impl_job]
        elif call_count["n"] == 2:
            result.scalars.return_value = iter([proxy_contract_row, impl_contract_row])
        elif call_count["n"] == 3:
            result.all.return_value = []
        else:
            result.scalars.return_value.all.return_value = []
            result.scalar_one_or_none.return_value = None
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/analyses")

    assert response.status_code == 200
    entries = response.json()
    assert len(entries) >= 1

    # Proxy info rides proxy_address_display/proxy_type_display; is_proxy comes from the impl entry.
    merged = entries[0]
    assert merged["proxy_address_display"] == proxy_addr
    assert merged["proxy_type_display"] == "ERC1967"
    assert merged["display_name"] == "VaultImpl"


@patch("routers.deps.get_artifact")
@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_falls_back_to_proxy_artifacts(mock_session_cls, mock_get_all_artifacts, mock_get_artifact):
    client = _make_client()

    proxy_address = "0x2222222222222222222222222222222222222222"
    impl_job_id = uuid.uuid4()
    proxy_job_id = uuid.uuid4()

    impl_job = _fake_api_job(
        job_id=str(impl_job_id),
        address="0x3333333333333333333333333333333333333333",
        name="impl_contract",
        status="completed",
        stage="done",
        request={"proxy_address": proxy_address},
    )

    proxy_job = _fake_api_job(
        job_id=str(proxy_job_id),
        address=proxy_address,
        name="proxy_contract",
        status="completed",
        stage="done",
        request={"address": proxy_address},
    )

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # Query order: impl job by name, then proxy job by address.
    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = impl_job
        else:
            result.scalar_one_or_none.return_value = proxy_job
        return result

    mock_session.execute.side_effect = route_execute

    impl_artifacts = {
        "contract_analysis": {
            "subject": {"name": "ImplContract"},
            "summary": {"control_model": "ownable"},
        },
    }

    proxy_dep_graph = {
        "nodes": [{"id": "0x111"}, {"id": "0x222"}],
        "edges": [{"from": "0x111", "to": "0x222"}],
    }
    proxy_dependencies = {
        "dependencies": ["0x4444444444444444444444444444444444444444"],
    }
    proxy_artifacts = {
        "dependency_graph_viz": proxy_dep_graph,
        "dependencies": proxy_dependencies,
    }

    def fake_get_all_artifacts(session, jid):
        if str(jid) == str(proxy_job_id):
            return proxy_artifacts
        return impl_artifacts

    mock_get_all_artifacts.side_effect = fake_get_all_artifacts
    mock_get_artifact.side_effect = lambda *a, **kw: None

    response = client.get("/api/analyses/impl_contract")

    assert response.status_code == 200
    body = response.json()
    assert body["run_name"] == "impl_contract"
    assert body["proxy_address"] == proxy_address
    assert body["dependency_graph_viz"] == proxy_dep_graph
    assert body["dependencies"] == proxy_dependencies


@patch("routers.deps.get_artifact")
@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_no_fallback_when_impl_has_artifacts(
    mock_session_cls, mock_get_all_artifacts, mock_get_artifact
):
    client = _make_client()

    proxy_address = "0x2222222222222222222222222222222222222222"
    impl_job_id = uuid.uuid4()

    impl_job = _fake_api_job(
        job_id=str(impl_job_id),
        address="0x3333333333333333333333333333333333333333",
        name="impl_with_deps",
        status="completed",
        stage="done",
        request={"proxy_address": proxy_address},
    )

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_exec = MagicMock()
    mock_exec.scalar_one_or_none.return_value = impl_job
    mock_session.execute.return_value = mock_exec

    impl_dep_graph = {"nodes": [{"id": "own"}], "edges": []}
    impl_dependencies = {"dependencies": ["0x5555555555555555555555555555555555555555"]}

    mock_get_all_artifacts.return_value = {
        "contract_analysis": {
            "subject": {"name": "ImplContract"},
            "summary": {},
        },
        "dependency_graph_viz": impl_dep_graph,
        "dependencies": impl_dependencies,
    }

    response = client.get("/api/analyses/impl_with_deps")

    assert response.status_code == 200
    body = response.json()
    assert body["dependency_graph_viz"] == impl_dep_graph
    assert body["dependencies"] == impl_dependencies
    # dependency_graph_viz and dependencies already exist on the impl, so they must not be fetched from the proxy.
    for call_args in mock_get_artifact.call_args_list:
        artifact_name = call_args[0][2] if len(call_args[0]) >= 3 else call_args[1].get("name")
        assert artifact_name not in ("dependency_graph_viz", "dependencies"), (
            f"Fallback should not fetch {artifact_name} when impl already has it"
        )


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_no_fallback_without_proxy_address(mock_session_cls, mock_get_all_artifacts):
    client = _make_client()
    job_id = uuid.uuid4()

    job = _fake_api_job(
        job_id=str(job_id),
        address="0x5555555555555555555555555555555555555555",
        name="standalone_job",
        status="completed",
        stage="done",
        request={"address": "0x5555555555555555555555555555555555555555"},
    )

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    # Query order: job by name, then Contract by job_id (none).
    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = job
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute

    mock_get_all_artifacts.return_value = {
        "contract_analysis": {
            "subject": {"name": "Standalone"},
            "summary": {},
        },
    }

    response = client.get("/api/analyses/standalone_job")

    assert response.status_code == 200
    body = response.json()
    assert body["proxy_address"] is None
    assert "dependency_graph_viz" not in body


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_proxy_inherits_impl_artifacts(mock_session_cls, mock_get_artifact, mock_get_all_artifacts):
    client = _make_client()

    proxy_addr = "0x1111111111111111111111111111111111111111"
    impl_addr = "0x2222222222222222222222222222222222222222"
    proxy_job_id = uuid.uuid4()
    impl_job_id = uuid.uuid4()

    proxy_job = _fake_api_job(
        job_id=str(proxy_job_id),
        address=proxy_addr,
        name="MyProxy",
        status="completed",
        stage="done",
        request={"address": proxy_addr},
    )
    impl_job = _fake_api_job(
        job_id=str(impl_job_id),
        address=impl_addr,
        name="MyProxy: (impl)",
        status="completed",
        stage="done",
        request={"address": impl_addr, "proxy_address": proxy_addr},
    )

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    proxy_contract = MagicMock()
    proxy_contract.id = uuid.uuid4()
    proxy_contract.is_proxy = True
    proxy_contract.implementation = impl_addr
    proxy_contract.contract_name = "MyProxy"
    proxy_contract.address = proxy_addr
    proxy_contract.summary = None

    impl_contract = MagicMock()
    impl_contract.id = uuid.uuid4()
    impl_contract.is_proxy = False
    impl_contract.implementation = None
    impl_contract.contract_name = "VaultImpl"
    impl_contract.address = impl_addr
    impl_contract.summary = None

    # Query order: proxy job by name, proxy Contract, five empty relational queries, impl job by address,
    # impl Contract. The impl's relational queries are skipped because its artifacts already filled them.
    call_count = 0

    def route_execute(stmt, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        result = MagicMock()
        if call_count == 1:
            result.scalar_one_or_none.return_value = proxy_job
        elif call_count == 2:
            result.scalar_one_or_none.return_value = proxy_contract
        elif call_count == 8:
            result.scalar_one_or_none.return_value = impl_job
        elif call_count == 9:
            result.scalar_one_or_none.return_value = impl_contract
        else:
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute
    mock_session.get.return_value = None

    proxy_artifacts = {
        "dependencies": {"address": proxy_addr, "dependencies": {}},
        "dependency_graph_viz": {"nodes": [], "edges": []},
    }

    impl_analysis = {
        "subject": {"name": "VaultImpl"},
        "summary": {"control_model": "authority"},
    }
    impl_permissions = {"functions": [{"function": "pause()", "selector": "0x12"}]}
    impl_all_artifacts = {
        "contract_analysis": impl_analysis,
        "effective_permissions": impl_permissions,
        "principal_labels": {"principals": []},
        "principal_history": {
            "schema_version": "principal_history.v1",
            "contract_address": impl_addr,
            "status": "ok",
            "function_permissions": [{"function": "pause()", "principal": "0xowner"}],
        },
        "resolved_control_graph": {"nodes": [], "edges": []},
        "control_snapshot": {"controller_values": {}},
    }

    def fake_get_artifact(session, jid, name):
        if str(jid) == str(proxy_job_id) and name == "contract_flags":
            return {"is_proxy": True, "proxy_type": "eip1967", "implementation": impl_addr}
        return None

    mock_get_artifact.side_effect = fake_get_artifact

    call_count_artifacts = 0

    def fake_get_all(session, jid):
        nonlocal call_count_artifacts
        call_count_artifacts += 1
        if call_count_artifacts == 1:
            return proxy_artifacts
        return impl_all_artifacts

    mock_get_all_artifacts.side_effect = fake_get_all

    response = client.get("/api/analyses/MyProxy")

    assert response.status_code == 200
    body = response.json()

    assert "dependencies" in body
    assert "dependency_graph_viz" in body

    assert body["contract_analysis"]["summary"]["control_model"] == "authority"
    assert body["effective_permissions"]["functions"][0]["function"] == "pause()"
    assert "principal_labels" in body
    assert body["principal_history"]["function_permissions"][0]["principal"] == "0xowner"
    assert "resolved_control_graph" in body
    assert body["contract_name"] == "VaultImpl"
    assert body["implementation_address"] == impl_addr


@pytest.mark.parametrize(
    ("method", "url"),
    [
        pytest.param("get", "/api/company/nonexistent/audits", id="company-audits"),
        pytest.param("delete", "/api/company/psat-unknown-xyz/queued-jobs", id="cancel-queued-jobs"),
    ],
)
@patch("routers.deps.SessionLocal")
def test_unknown_company_404(mock_session_cls, method, url):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)
    mock_session.execute.return_value.scalar_one_or_none.return_value = None

    response = getattr(client, method)(url)
    assert response.status_code == 404
    assert mock_session.commit.call_count == 0


@patch("routers.deps.SessionLocal")
def test_cancel_queued_company_jobs_returns_deleted_ids(mock_session_cls):
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    protocol = MagicMock()
    protocol.id = 7

    fake_ids = [uuid.uuid4(), uuid.uuid4(), uuid.uuid4()]

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = protocol
        else:
            result.__iter__ = lambda self: iter((i,) for i in fake_ids)
        return result

    mock_session.execute.side_effect = route_execute

    response = client.delete("/api/company/etherfi/queued-jobs")
    assert response.status_code == 200
    body = response.json()
    assert body["company"] == "etherfi"
    assert body["cancelled"] == 3
    assert set(body["job_ids"]) == {str(i) for i in fake_ids}
    mock_session.commit.assert_called_once()
