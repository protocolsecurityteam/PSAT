"""Operator endpoints enforce routing readiness and safe group recovery."""

import uuid

from db.models import Job, JobStatus
from db.queue import create_job


def test_local_submission_requires_gate_and_attestation(api_client, monkeypatch):
    body = {"address": "0x" + "a" * 40, "compute_target": "local"}
    monkeypatch.setenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "0")
    assert api_client.post("/api/analyze", json=body).status_code == 409
    assert api_client.get("/api/compute-capabilities").json() == {"local_enabled": False}
    monkeypatch.setenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "1")
    monkeypatch.setattr("services.compute.runtime.ready_contract", lambda _: {})
    assert api_client.get("/api/compute-capabilities").json() == {"local_enabled": True}
    response = api_client.post("/api/analyze", json=body)
    assert response.status_code == 200
    assert response.json()["compute_target"] == "local"
    assert response.json()["compute_group_id"] == response.json()["job_id"]


def test_recovery_refuses_live_lease_then_moves_entire_group(api_client, db_session, monkeypatch):
    monkeypatch.setenv("PSAT_LOCAL_COMPUTE_ROUTING_ENABLED", "1")
    first = create_job(db_session, {}, compute_target="local")
    second = create_job(db_session, {}, compute_target="local")
    second.compute_group_id = first.compute_group_id
    second.lease_id = uuid.uuid4()
    second.status = JobStatus.processing
    db_session.commit()
    path = f"/api/jobs/{first.id}/move-to-cloud"
    assert api_client.post(path).status_code == 409
    second.status = JobStatus.queued
    second.lease_id = None
    db_session.commit()
    assert api_client.post(path).json() == {"moved": 2, "compute_target": "cloud"}
    db_session.expire_all()
    assert all(db_session.get(Job, id).compute_target == "cloud" for id in (first.id, second.id))


def test_compute_endpoints_require_admin(api_client, monkeypatch):
    import api
    from routers.deps import require_admin_key

    previous = api.app.dependency_overrides.pop(require_admin_key)
    monkeypatch.setenv("PSAT_ADMIN_KEY", "test-admin")
    try:
        for method, path in [("get", "/api/compute-capabilities"), ("post", f"/api/jobs/{uuid.uuid4()}/move-to-cloud")]:
            assert getattr(api_client, method)(path).status_code in {401, 403, 503}
    finally:
        api.app.dependency_overrides[require_admin_key] = previous
