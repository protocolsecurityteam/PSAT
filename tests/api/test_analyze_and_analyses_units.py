"""Unit tests for the analyze / analyses endpoints — mocked sessions, no Postgres.

Covers:
- POST /api/analyze with company and address payloads, plus validation
- GET /api/analyses proxy flagging via contract_flags artifact
- GET /api/analyses/{run_name} impl-to-proxy artifact fallback
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


def _fake_artifact(job_id, name: str, data):
    """Inline ``Artifact`` row stand-in for the /api/analyses batched select."""
    return SimpleNamespace(
        job_id=job_id,
        name=name,
        storage_key=None,
        data=data,
        text_data=None,
        content_type=None,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    """Build a MagicMock that behaves like db.models.Job."""
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
    # Must be set explicitly — bare MagicMock attributes are truthy and
    # the analyses listing now reads Job.is_proxy directly (denormalized
    # from contract_flags by the static worker).
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


def _mock_session_ctx(mock_session_cls, mock_session):
    """Wire up a mock SessionLocal so `with SessionLocal() as session:` works."""
    mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
    mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)


def _make_client() -> TestClient:
    import api

    return TestClient(api.app)


# ---------------------------------------------------------------------------
# 1. POST /api/analyze — company payload
# ---------------------------------------------------------------------------


@patch("routers.deps.SessionLocal")
@patch("routers.deps.create_job")
def test_analyze_company_creates_job(mock_create_job, mock_session_cls):
    """Submitting {"company": "etherfi"} should create a job with company set,
    address null, stage=discovery, status=queued."""
    client = _make_client()

    fake_job = _fake_api_job(
        company="etherfi",
        status="queued",
        stage="discovery",
        request={
            "company": "etherfi",
            "name": None,
            "address": None,
            "chain": None,
            "analyze_limit": 5,
            "rpc_url": None,
        },
    )
    mock_create_job.return_value = fake_job

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    response = client.post("/api/analyze", json={"company": "etherfi"})

    assert response.status_code == 200
    body = response.json()
    assert body["company"] == "etherfi"
    assert body["address"] is None
    assert body["stage"] == "discovery"
    assert body["status"] == "queued"

    # Verify create_job was called with the model-dumped dict
    call_args = mock_create_job.call_args
    req_dict = call_args[0][1]  # positional arg: (session, request_dict)
    assert req_dict["company"] == "etherfi"
    assert req_dict.get("address") is None


# ---------------------------------------------------------------------------
# 1b. POST /api/analyze — mutual exclusion validation
# ---------------------------------------------------------------------------


@patch("routers.deps.SessionLocal")
@patch("routers.deps.create_job")
def test_analyze_accepts_address_with_company_context(mock_create_job, mock_session_cls):
    """address + company together is valid (address is target, company is context)."""
    client = _make_client()
    addr = "0x1111111111111111111111111111111111111111"
    fake_job = _fake_api_job(address=addr, company="etherfi", status="queued", stage="discovery")
    mock_create_job.return_value = fake_job
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    response = client.post(
        "/api/analyze",
        json={"address": addr, "company": "etherfi"},
    )
    assert response.status_code == 200
    req_dict = mock_create_job.call_args[0][1]
    assert req_dict["address"] == addr
    assert req_dict["company"] == "etherfi"


# ---------------------------------------------------------------------------
# 2. POST /api/analyze — address payload
# ---------------------------------------------------------------------------


@patch("routers.deps.SessionLocal")
@patch("routers.deps.create_job")
def test_analyze_address_creates_job(mock_create_job, mock_session_cls):
    """Submitting {"address": "0x1111..."} should create a job with address set
    and company null."""
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


# ---------------------------------------------------------------------------
# 3. GET /api/analyses — proxy flagging via contract_flags artifact
# ---------------------------------------------------------------------------


@patch("routers.deps.SessionLocal")
def test_analyses_list_proxy_flagging(mock_session_cls):
    """A completed proxy job + its impl job should merge into one entry
    that carries the is_proxy, proxy_type, and implementation_address
    fields from the contract_flags artifact.

    _merge_proxy_impl_entries hides standalone proxy entries whose impl
    child job hasn't completed — so we must include both the proxy job
    and its impl job for the merged entry to appear."""
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

    # proxy_type, implementation, AND contract_name now come from the
    # Contract rows. The /api/analyses listing no longer fetches artifact
    # bodies — that was the dominant cost in production. The merge layer
    # prefers the impl's name over the proxy's (proxy shells usually
    # carry generic names like "UUPSProxy"), so both rows must be mocked.
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

    # /api/analyses query order:
    #   1. select(Job)             → jobs list
    #   2. select(Contract...)     → contracts_by_address (returns .scalars())
    #   3. select(Artifact.job_id, Artifact.name) → name-only artifact rows (.all())

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [proxy_job, impl_job]
        elif call_count["n"] == 2:
            result.scalars.return_value = iter([proxy_contract_row, impl_contract_row])
        elif call_count["n"] == 3:
            # Artifact-name listing — empty is fine; this test only cares
            # about contract_name resolution from Contract rows.
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

    # The merged entry carries proxy info via proxy_address_display and
    # proxy_type_display (not is_proxy — that field comes from the impl
    # entry base in the merge, where it's False).
    merged = entries[0]
    assert merged["proxy_address_display"] == proxy_addr
    assert merged["proxy_type_display"] == "ERC1967"
    # The impl's contract_name is used as the display_name
    assert merged["display_name"] == "VaultImpl"


@patch("routers.deps.SessionLocal")
def test_analyses_list_non_proxy_has_is_proxy_false(mock_session_cls):
    """A completed job without contract_flags or with is_proxy=False should
    appear with is_proxy=False."""
    client = _make_client()
    job_id = uuid.uuid4()

    fake_job = _fake_api_job(
        job_id=str(job_id),
        address="0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        name="regular_contract",
        status="completed",
        stage="done",
        request={"address": "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
    )

    from db.models import JobStatus

    fake_job.status = JobStatus.completed

    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    artifacts = [
        _fake_artifact(fake_job.id, "contract_analysis", {"subject": {"name": "Regular"}, "summary": {}}),
    ]

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalars.return_value.all.return_value = [fake_job]
        elif call_count["n"] == 2:
            # contracts_by_address prefetch — empty (no Contract row)
            result.scalars.return_value = iter([])
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
    entry = next((e for e in entries if e.get("job_id") == str(job_id)), None)
    assert entry is not None
    assert entry["is_proxy"] is False


# ---------------------------------------------------------------------------
# 4. GET /api/analyses/{run_name} — impl-to-proxy artifact fallback
# ---------------------------------------------------------------------------


@patch("routers.deps.get_artifact")
@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_falls_back_to_proxy_artifacts(mock_session_cls, mock_get_all_artifacts, mock_get_artifact):
    """When an impl job has proxy_address in its request but lacks
    dependency_graph_viz, the detail endpoint should fall back to the proxy
    job's dependency_graph_viz and dependencies artifacts."""
    client = _make_client()

    proxy_address = "0x2222222222222222222222222222222222222222"
    impl_job_id = uuid.uuid4()
    proxy_job_id = uuid.uuid4()

    # Impl job: has proxy_address in request, no dependency_graph_viz
    impl_job = _fake_api_job(
        job_id=str(impl_job_id),
        address="0x3333333333333333333333333333333333333333",
        name="impl_contract",
        status="completed",
        stage="done",
        request={"proxy_address": proxy_address},
    )

    # Proxy job: has the dependency_graph_viz and dependencies artifacts
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

    # The detail endpoint does:
    # 1. select(Job).where(Job.name == run_name) -> returns impl_job
    # 2. select(Job).where(Job.address == proxy_address) -> returns proxy_job
    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        # First execute: lookup impl job by name
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = impl_job
        # Second execute: lookup proxy job by address
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

    # get_all_artifacts is called once per job — return impl's artifacts for
    # the impl job's job.id and proxy's artifacts for the proxy job's job.id
    # (matches the batched proxy-fallback in analysis_detail).
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
    # Should have inherited dependency_graph_viz from proxy job
    assert body["dependency_graph_viz"] == proxy_dep_graph
    # Should have inherited dependencies from proxy job
    assert body["dependencies"] == proxy_dependencies


@patch("routers.deps.get_artifact")
@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_no_fallback_when_impl_has_artifacts(
    mock_session_cls, mock_get_all_artifacts, mock_get_artifact
):
    """When the impl job already has dependency_graph_viz, the detail endpoint
    should NOT fall back to the proxy job's artifacts."""
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

    # Impl job already has dependency_graph_viz and dependencies
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
    # Should use impl's own artifacts, not proxy's
    assert body["dependency_graph_viz"] == impl_dep_graph
    assert body["dependencies"] == impl_dependencies
    # get_artifact may still be called for upgrade_history (which the impl
    # doesn't have), but dependency_graph_viz and dependencies must NOT be
    # fetched from the proxy since they already exist on the impl.
    for call_args in mock_get_artifact.call_args_list:
        artifact_name = call_args[0][2] if len(call_args[0]) >= 3 else call_args[1].get("name")
        assert artifact_name not in ("dependency_graph_viz", "dependencies"), (
            f"Fallback should not fetch {artifact_name} when impl already has it"
        )


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_no_fallback_without_proxy_address(mock_session_cls, mock_get_all_artifacts):
    """When the job has no proxy_address in its request, no fallback should
    occur even if dependency_graph_viz is missing."""
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

    # The endpoint calls session.execute() multiple times:
    # 1. select(Job).where(name==...) -> returns job
    # 2. select(Contract).where(job_id==...) -> returns None (no Contract row)
    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            result.scalar_one_or_none.return_value = job
        else:
            # Contract query and any others: return None
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute

    # No dependency_graph_viz in artifacts
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


# ---------------------------------------------------------------------------
# 5. GET /api/analyses/{run_name} — proxy detail inherits impl artifacts
# ---------------------------------------------------------------------------


@patch("routers.deps.get_all_artifacts")
@patch("routers.deps.get_artifact")
@patch("routers.deps.SessionLocal")
def test_analysis_detail_proxy_inherits_impl_artifacts(mock_session_cls, mock_get_artifact, mock_get_all_artifacts):
    """When loading a proxy job's detail, analysis artifacts (contract_analysis,
    effective_permissions, etc.) should be inherited from the impl child job.
    This is the reverse of the impl->proxy fallback for dependency artifacts."""
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

    # Build Contract mocks for the relational-table queries
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

    # The endpoint calls session.execute() many times:
    # 1. select(Job) by name -> proxy_job
    # 2. select(Contract) by job_id (proxy) -> proxy_contract
    # 3-7. EffectiveFunction/PrincipalLabel/ControllerValue/CGN/CGE for proxy -> empty
    # 8. select(Job) by address==impl_addr -> impl_job
    #    (get_all_artifacts for impl is not an execute call)
    # 9. select(Contract) by job_id (impl) -> impl_contract
    #    (relational queries for impl are skipped since artifacts already filled them)
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
            # Relational queries for proxy/impl → empty
            result.scalar_one_or_none.return_value = None
            result.scalars.return_value.all.return_value = []
        return result

    mock_session.execute.side_effect = route_execute
    mock_session.get.return_value = None

    # Proxy job has only dependency artifacts (no analysis)
    proxy_artifacts = {
        "dependencies": {"address": proxy_addr, "dependencies": {}},
        "dependency_graph_viz": {"nodes": [], "edges": []},
    }

    # Impl artifacts (from get_all_artifacts)
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

    # get_all_artifacts: first call for proxy, second for impl
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

    # Should have proxy's own dependency artifacts
    assert "dependencies" in body
    assert "dependency_graph_viz" in body

    # Should have inherited impl's analysis artifacts
    assert body["contract_analysis"]["summary"]["control_model"] == "authority"
    assert body["effective_permissions"]["functions"][0]["function"] == "pause()"
    assert "principal_labels" in body
    assert body["principal_history"]["function_permissions"][0]["principal"] == "0xowner"
    assert "resolved_control_graph" in body
    assert body["contract_name"] == "VaultImpl"
    assert body["implementation_address"] == impl_addr


# ---------------------------------------------------------------------------
# Audit report endpoints
# ---------------------------------------------------------------------------


def _fake_audit_report(**overrides):
    """Build a MagicMock that behaves like db.models.AuditReport."""
    ar = MagicMock()
    ar.url = overrides.get("url", "https://blog.openzeppelin.com/aave-v3-audit")
    ar.pdf_url = overrides.get("pdf_url", "https://blog.openzeppelin.com/aave-v3-audit.pdf")
    ar.auditor = overrides.get("auditor", "OpenZeppelin")
    ar.title = overrides.get("title", "Aave V3 Security Audit")
    ar.date = overrides.get("date", "2023-06-15")
    ar.confidence = overrides.get("confidence", 0.95)
    return ar


@patch("routers.deps.SessionLocal")
def test_company_audits_endpoint(mock_session_cls):
    """GET /api/company/{name}/audits returns audit reports for a protocol."""
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    protocol = MagicMock()
    protocol.id = 1
    protocol.name = "aave"

    audit1 = _fake_audit_report()
    audit2 = _fake_audit_report(
        url="https://github.com/trailofbits/aave-audit",
        pdf_url=None,
        auditor="Trail of Bits",
        title="Aave V3 Review",
        date="2023-03-01",
        confidence=0.85,
    )

    call_count = {"n": 0}

    def route_execute(stmt, *args, **kwargs):
        call_count["n"] += 1
        result = MagicMock()
        if call_count["n"] == 1:
            # Protocol lookup
            result.scalar_one_or_none.return_value = protocol
        else:
            # AuditReport query
            result.scalars.return_value.all.return_value = [audit1, audit2]
        return result

    mock_session.execute.side_effect = route_execute

    response = client.get("/api/company/aave/audits")
    assert response.status_code == 200
    body = response.json()
    assert body["company"] == "aave"
    assert body["protocol_id"] == 1
    assert body["audit_count"] == 2
    assert len(body["audits"]) == 2

    oz = next(a for a in body["audits"] if a["auditor"] == "OpenZeppelin")
    assert oz["title"] == "Aave V3 Security Audit"
    assert oz["date"] == "2023-06-15"
    assert oz["pdf_url"] == "https://blog.openzeppelin.com/aave-v3-audit.pdf"
    assert oz["confidence"] == 0.95

    tob = next(a for a in body["audits"] if a["auditor"] == "Trail of Bits")
    assert tob["pdf_url"] is None
    assert tob["confidence"] == 0.85


@patch("routers.deps.SessionLocal")
def test_company_audits_not_found(mock_session_cls):
    """GET /api/company/{name}/audits returns 404 for unknown company."""
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)

    mock_session.execute.return_value.scalar_one_or_none.return_value = None

    response = client.get("/api/company/nonexistent/audits")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/company/{name}/queued-jobs — test-isolation teardown for
# analyze-remaining flood
# ---------------------------------------------------------------------------


@patch("routers.deps.SessionLocal")
def test_cancel_queued_company_jobs_unknown_company_404(mock_session_cls):
    """404 when the company has never been registered as a Protocol."""
    client = _make_client()
    mock_session = MagicMock()
    _mock_session_ctx(mock_session_cls, mock_session)
    mock_session.execute.return_value.scalar_one_or_none.return_value = None

    response = client.delete("/api/company/psat-unknown-xyz/queued-jobs")
    assert response.status_code == 404
    # Pure lookup: no DELETE should have run.
    assert mock_session.commit.call_count == 0


@patch("routers.deps.SessionLocal")
def test_cancel_queued_company_jobs_returns_deleted_ids(mock_session_cls):
    """DELETE returns the list of cancelled job UUIDs + a count."""
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
            # First call: SELECT Protocol
            result.scalar_one_or_none.return_value = protocol
        else:
            # Second call: DELETE ... RETURNING id — iterator yields single-col rows
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
