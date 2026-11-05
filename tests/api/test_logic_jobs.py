"""The actual HTTP/queue/artifact path, with external providers stubbed at their boundaries."""

from __future__ import annotations

import copy
import uuid
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from db.models import Job, JobStage, JobStatus
from db.queue import LeaseLost, claim_job, complete_job, get_artifact, store_artifact
from services.clients.jev import JevBudgetExceeded
from services.logic.model import ReadError
from services.logic_jobs import RESULT, publish, reserve_inference
from tests.cache_helpers import requires_postgres
from tests.logic.test_impact import Session as ModelSession
from tests.logic.test_impact import inputs
from tests.support.db_fixtures import test_session_local  # noqa: F401
from workers import logic_worker
from workers.retry_policy import classify

pytestmark = requires_postgres
ADDRESS = "0x" + "0" * 39 + "1"


@pytest.fixture
def runtime(monkeypatch, tmp_path, test_session_local):
    _, formulas, _ = inputs()
    wire = ModelSession()
    monkeypatch.setattr(logic_worker, "SessionLocal", test_session_local)
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-secret")
    monkeypatch.setenv("PSAT_LOGIC_JEV_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(logic_worker, "require_rpc_url", lambda **kw: "server-owned")
    monkeypatch.setattr(
        logic_worker, "rpc_request", lambda url, method, params, **kw: "0x1" if method == "eth_chainId" else "0x7b"
    )
    monkeypatch.setattr(logic_worker, "deployment_formulas", lambda *a, **kw: copy.deepcopy(formulas))

    @contextmanager
    def deployment_inputs(session, chain_id, url, block):
        assert chain_id == 1 and block == 123 and url == "server-owned"
        yield SimpleNamespace(block=123), {}

    monkeypatch.setattr(logic_worker, "_deployment_inputs", deployment_inputs)
    monkeypatch.setattr("services.logic.deployment._deployment_inputs", deployment_inputs)
    client = logic_worker.JobJev
    monkeypatch.setattr(logic_worker, "JobJev", lambda *a, **kw: client(*a, session=wire, **kw))
    return formulas, wire


def post(api, operation, data):
    response = api.post(f"/api/logic/{operation}", json=data)
    assert response.status_code == 202, response.text
    return response.json()["job_id"]


def run(session):
    worker = logic_worker.LogicWorker()
    job = claim_job(session, JobStage.logic, worker.worker_id)
    assert job is not None
    worker._execute_job(session, job)
    session.expire_all()
    return session.get(Job, job.id)


def generate(api, session):
    job_id = post(api, "generate", {"address": ADDRESS, "chain_id": 1})
    assert run(session).status == JobStatus.completed
    return job_id


def test_three_explicit_api_jobs_use_durable_queue_and_stored_results(api_client, db_session, runtime):
    formulas, wire = runtime
    generated = post(api_client, "generate", {"address": ADDRESS, "chain_id": 1})
    assert not wire.calls
    assert api_client.get(f"/api/logic/jobs/{generated}").json()["status"] == "queued"
    assert api_client.get(f"/api/logic/jobs/{generated}/result").status_code == 409
    assert api_client.post("/api/logic/assess", json={"formula_job_id": generated}).status_code == 409
    job = run(db_session)
    assert job.status == JobStatus.completed and job.address is None and job.protocol_id is None
    assert job.request["params"]["block"] == 123
    response = api_client.get(f"/api/logic/jobs/{generated}/result")
    assert response.json() == formulas
    assert response.headers["cache-control"] == "private, no-store"
    assert not wire.calls and len(db_session.scalars(select(Job)).all()) == 1
    assessed = post(api_client, "assess", {"formula_job_id": generated, "max_requests": 1})
    assert run(db_session).status == JobStatus.completed
    assessment = api_client.get(f"/api/logic/jobs/{assessed}/result").json()
    assert assessment["assessment"]["status"] == "assessed" and len(wire.calls) == 1
    state = api_client.get(f"/api/logic/jobs/{assessed}").json()
    assert state["jev_requests_reserved"] == 1 and state["result_state"] == "assessed" and state["block"] == 123
    assert len(db_session.scalars(select(Job)).all()) == 2
    expanded = post(api_client, "enumerate", {"assessment_job_id": assessed, "functions": ["change(uint256)"]})
    assert run(db_session).status == JobStatus.completed
    output = api_client.get(f"/api/logic/jobs/{expanded}/result").json()
    effect = output["functions"]["change(uint256)"]["expansion"]["value"]["effects"]["tuple"][0]
    assert effect["members"] == {"tuple": [7]} and effect["representation"] == "finite"
    assert len(wire.calls) == 1 and len(db_session.scalars(select(Job)).all()) == 3
    assert "test-secret" not in str(output)


def test_incomplete_assessment_is_a_completed_job_not_a_complete_answer(api_client, db_session, runtime):
    generated = generate(api_client, db_session)
    assessed = post(api_client, "assess", {"formula_job_id": generated, "max_requests": 0})
    assert run(db_session).status == JobStatus.completed
    state = api_client.get(f"/api/logic/jobs/{assessed}").json()
    assert state["status"] == "completed" and state["result_state"] == "incomplete"
    assert not runtime[1].calls
    assert (
        api_client.post(
            "/api/logic/enumerate", json={"assessment_job_id": assessed, "functions": ["change(uint256)"]}
        ).status_code
        == 409
    )


def test_durable_budget_survives_reclaim_and_old_lease_cannot_publish(api_client, db_session, runtime):
    generated = generate(api_client, db_session)
    assessed = post(api_client, "assess", {"formula_job_id": generated, "max_requests": 1})
    job = claim_job(db_session, JobStage.logic, "first")
    old_lease = job.lease_id
    reserve_inference(db_session, job.id, old_lease)
    job.status = JobStatus.queued
    job.lease_id = None
    db_session.commit()
    new = claim_job(db_session, JobStage.logic, "second")
    with pytest.raises(JevBudgetExceeded):
        reserve_inference(db_session, new.id, new.lease_id)
    with pytest.raises(LeaseLost):
        publish(db_session, new.id, old_lease, {"kind": "expansion_selection"})
    db_session.rollback()
    assert get_artifact(db_session, uuid.UUID(assessed), RESULT) is None
    assert api_client.get(f"/api/logic/jobs/{assessed}").json()["jev_requests_reserved"] == 1
    complete_job(db_session, new.id, lease_id=new.lease_id)


def test_changed_input_after_submission_fails_before_model(api_client, db_session, runtime):
    generated = generate(api_client, db_session)
    assessed = post(api_client, "assess", {"formula_job_id": generated})
    changed = copy.deepcopy(runtime[0])
    changed["source_scope"] = {"changed": True}
    store_artifact(db_session, uuid.UUID(generated), RESULT, changed)
    assert run(db_session).status == JobStatus.failed_terminal
    assert not runtime[1].calls
    assert api_client.get(f"/api/logic/jobs/{assessed}/result").status_code == 409


def test_rpc_failure_requeues_job_without_producing_verdict(api_client, db_session, runtime, monkeypatch):
    job_id = post(api_client, "generate", {"address": ADDRESS, "chain_id": 1})

    def fail(*a, **kw):
        raise ReadError("temporary unavailable state")

    monkeypatch.setattr(logic_worker, "execute_operation", fail)
    job = run(db_session)
    assert job.status == JobStatus.queued and job.retry_count == 1
    assert job.request["params"]["block"] == 123
    assert get_artifact(db_session, uuid.UUID(job_id), RESULT) is None
    assert classify(ReadError("unavailable")) == "transient"


@pytest.mark.parametrize(
    "operation,data",
    [
        ("generate", {"address": ADDRESS, "chain_id": True}),
        ("generate", {"address": "bad", "chain_id": 1}),
        ("generate", {"address": ADDRESS, "chain_id": 1, "rpc_url": "http://internal"}),
        ("assess", {"formula_job_id": str(uuid.uuid4()), "max_requests": 257}),
        ("assess", {"formula_job_id": str(uuid.uuid4()), "api_key": "forbidden"}),
        ("enumerate", {"assessment_job_id": str(uuid.uuid4()), "functions": []}),
    ],
)
def test_requests_reject_client_providers_credentials_and_unbounded_work(api_client, operation, data):
    assert api_client.post(f"/api/logic/{operation}", json=data).status_code == 422


def test_unknown_job_and_wrong_input_type_are_not_accepted(api_client, db_session, runtime):
    assert api_client.get(f"/api/logic/jobs/{uuid.uuid4()}").status_code == 404
    assert api_client.post("/api/logic/assess", json={"formula_job_id": str(uuid.uuid4())}).status_code == 404
    generated = generate(api_client, db_session)
    assert (
        api_client.post(
            "/api/logic/enumerate", json={"assessment_job_id": generated, "functions": ["change(uint256)"]}
        ).status_code
        == 409
    )


def test_routes_require_existing_admin_auth(api_client, monkeypatch):
    import api
    from routers import deps

    overrides = dict(api.app.dependency_overrides)
    api.app.dependency_overrides.pop(deps.require_admin, None)
    api.app.dependency_overrides.pop(deps.admin_actor, None)
    try:
        headers = {"X-PSAT-Admin-Key": "incorrect"}
        assert api_client.post(
            "/api/logic/generate", headers=headers, json={"address": ADDRESS, "chain_id": 1}
        ).status_code in (401, 403)
        assert api_client.get(f"/api/logic/jobs/{uuid.uuid4()}", headers=headers).status_code in (401, 403)
        assert api_client.get(f"/api/logic/jobs/{uuid.uuid4()}/result", headers=headers).status_code in (401, 403)
    finally:
        api.app.dependency_overrides.clear()
        api.app.dependency_overrides.update(overrides)


def test_disallowed_chain_cannot_enqueue_paid_work(api_client, db_session, monkeypatch):
    from utils.chains import UnsupportedChainError

    def reject(*a, **kw):
        raise UnsupportedChainError("chain disabled")

    monkeypatch.setattr("routers.logic.require_supported_chain", reject)
    response = api_client.post("/api/logic/generate", json={"address": ADDRESS, "chain_id": 1})
    assert response.status_code == 422
    assert not db_session.scalars(select(Job)).all()


def test_unverified_generation_remains_not_verified(api_client, db_session, runtime, monkeypatch):
    result = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": ADDRESS,
        "block": 123,
        "status": "not_verified",
        "functions": {},
    }
    monkeypatch.setattr(logic_worker, "deployment_formulas", lambda *a, **kw: result)
    generated = generate(api_client, db_session)
    assessed = post(api_client, "assess", {"formula_job_id": generated})
    assert run(db_session).status == JobStatus.completed
    assert api_client.get(f"/api/logic/jobs/{assessed}").json()["result_state"] == "not_verified"
    assert not runtime[1].calls


def test_long_context_flag_reaches_the_durable_assessment(api_client, db_session, runtime):
    _, wire = runtime
    generated = generate(api_client, db_session)
    assessed = post(api_client, "assess", {"formula_job_id": generated, "long_context": True, "max_requests": 1})
    assert run(db_session).status == JobStatus.completed
    assert wire.calls[0][1]["headers"]["TypeSafe-Danger-Zone-Long-Context"] == "true"
    assert api_client.get(f"/api/logic/jobs/{assessed}").json()["jev_requests_reserved"] == 1


def test_generate_resume_keeps_block_and_fences_checkpoint_artifact(api_client, db_session, runtime, monkeypatch):
    formulas, _ = runtime
    first = {
        **copy.deepcopy(formulas),
        "address": ADDRESS,
        "status": "incomplete",
        "pending_functions": {"f()": {"reason": "expansion_steps", "checkpoint": {}}},
    }
    monkeypatch.setattr(logic_worker, "deployment_formulas", lambda *a, **kw: copy.deepcopy(first))
    parent = generate(api_client, db_session)
    seen = []

    def resumed(*args, **kwargs):
        seen.append(kwargs)
        return copy.deepcopy(formulas)

    monkeypatch.setattr(logic_worker, "deployment_formulas", resumed)
    response = api_client.post(
        "/api/logic/generate", json={"address": ADDRESS, "chain_id": 1, "resume_job_id": parent, "block": 124}
    )
    assert response.status_code == 409
    child = post(
        api_client, "generate", {"address": ADDRESS, "chain_id": 1, "resume_job_id": parent, "expansion_steps": 100}
    )
    assert api_client.get(f"/api/logic/jobs/{child}").json()["block"] == 123
    assert run(db_session).status == JobStatus.completed
    assert seen[0]["block"] == 123 and seen[0]["resume"] == first and seen[0]["expansion_steps"] == 100
    assert api_client.get(f"/api/logic/jobs/{child}/result").json() == formulas


def test_storage_accounting_limit_reaches_expansion_worker(api_client, db_session, runtime, monkeypatch):
    generated = generate(api_client, db_session)
    assessed = post(api_client, "assess", {"formula_job_id": generated})
    assert run(db_session).status == JobStatus.completed
    captured = []
    original = logic_worker.deployment_expansions

    def expand(*args, **kwargs):
        captured.append(kwargs["limits"].storage_steps)
        return original(*args, **kwargs)

    monkeypatch.setattr(logic_worker, "deployment_expansions", expand)
    job_id = post(
        api_client,
        "enumerate",
        {"assessment_job_id": assessed, "functions": ["change(uint256)"], "storage_steps": 750000},
    )
    assert run(db_session).status == JobStatus.completed
    assert captured == [750000]
    assert db_session.get(Job, uuid.UUID(job_id)).request["params"]["storage_steps"] == 750000
    for invalid in (-1, True, "100000", 10000001):
        assert (
            api_client.post(
                "/api/logic/enumerate",
                json={"assessment_job_id": assessed, "functions": ["change(uint256)"], "storage_steps": invalid},
            ).status_code
            == 422
        )
