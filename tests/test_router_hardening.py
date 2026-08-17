"""Hardening for the public/admin routers: bounded pagination, guarded UUID
parsing, and no exception-string leakage to clients.

Covers routers/monitored.py, routers/protocols.py, routers/agent.py, and
routers/analyses.py.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [requires_postgres]


# --- Bounded pagination (FINDING 7) -----------------------------------------


def test_monitored_events_limit_over_cap_is_422(api_client):
    resp = api_client.get("/api/monitored-events", params={"limit": 1000})
    assert resp.status_code == 422


def test_monitored_events_limit_below_floor_is_422(api_client):
    resp = api_client.get("/api/monitored-events", params={"limit": 0})
    assert resp.status_code == 422


def test_monitored_events_limit_at_cap_ok(api_client):
    resp = api_client.get("/api/monitored-events", params={"limit": 500})
    assert resp.status_code == 200


def test_protocol_events_limit_over_cap_is_422(api_client):
    resp = api_client.get("/api/protocols/1/events", params={"limit": 1000})
    assert resp.status_code == 422


def test_protocol_events_limit_at_cap_ok(api_client):
    resp = api_client.get("/api/protocols/1/events", params={"limit": 500})
    assert resp.status_code == 200


# --- Guarded UUID parsing (FINDING 15) --------------------------------------


def test_patch_monitored_contract_bad_uuid_is_404_not_500(api_client):
    resp = api_client.patch("/api/monitored-contracts/not-a-uuid", json={"is_active": False})
    assert resp.status_code == 404


def test_delete_protocol_subscription_bad_uuid_is_404_not_500(api_client):
    resp = api_client.delete("/api/protocol-subscriptions/not-a-uuid")
    assert resp.status_code == 404


def test_patch_monitored_contract_valid_uuid_absent_is_404(api_client):
    resp = api_client.patch(f"/api/monitored-contracts/{uuid.uuid4()}", json={"is_active": False})
    assert resp.status_code == 404


def test_monitored_events_bad_contract_id_is_422_not_500(api_client):
    """``contract_id`` is a UUID column; a malformed value must be rejected
    before it reaches the DB (public endpoint)."""
    resp = api_client.get("/api/monitored-events", params={"contract_id": "not-a-uuid"})
    assert resp.status_code == 422


def test_monitored_events_valid_contract_id_absent_is_empty(api_client):
    resp = api_client.get("/api/monitored-events", params={"contract_id": str(uuid.uuid4())})
    assert resp.status_code == 200
    assert resp.json() == []


# --- No exception-string leakage (FINDING 14) -------------------------------


def test_agent_stream_error_is_generic(api_client, monkeypatch):
    """A raised agent stream returns a generic SSE error, never the raw
    exception text."""
    secret = "SECRET_DB_DSN=postgres://user:pw@host/db"

    def _boom(*a, **k):
        raise RuntimeError(secret)

    monkeypatch.setattr("routers.agent.run_agent_stream", _boom)
    resp = api_client.post(
        "/api/agent/chat",
        json={"company": "acme", "message": "hi"},
    )
    assert resp.status_code == 200
    body = resp.text
    assert "event: error" in body
    assert secret not in body


def test_analysis_artifact_not_determined_reason_is_generic(api_client, db_session, monkeypatch):
    """When the storage read is not-determined, the 503 body names the artifact
    but never carries the raw exception type+message."""
    from db.models import Job, JobStatus
    from db.storage import StorageKeyAbsent

    secret = "s3://internal-bucket/secret/path/object.bin"

    job = Job(
        id=uuid.uuid4(),
        name="__hardening_artifact_leak__",
        status=JobStatus.completed,
    )
    db_session.add(job)
    db_session.commit()

    def _boom(*a, **k):
        raise StorageKeyAbsent(secret)

    monkeypatch.setattr("routers.deps.get_artifact", _boom)
    try:
        resp = api_client.get(f"/api/analyses/{job.name}/artifact/dependencies")
        assert resp.status_code == 503
        body = resp.json()
        assert body["artifact"] == "dependencies"
        assert secret not in body["reason"]
        assert "StorageKeyAbsent" not in body["reason"]
    finally:
        db_session.delete(job)
        db_session.commit()


def test_upgrade_history_stage_raised_reason_omits_class_name(api_client, db_session, monkeypatch):
    """The upgrade-history absence reason for an unreadable ``stage_errors``
    read must not carry the raising exception's class name into the client."""
    from db.models import Contract, Job, JobStatus

    secret = "boto3.ClientError: connection to internal-bucket refused"

    job = Job(
        id=uuid.uuid4(),
        name="__hardening_upgrade_history_leak__",
        status=JobStatus.completed,
    )
    db_session.add(job)
    db_session.flush()
    # Non-proxy, self-consistent → the reason falls through to the
    # stage_errors read, which we force to raise.
    contract = Contract(
        job_id=job.id,
        address="0x" + "f0" * 20,
        is_proxy=False,
        proxy_type=None,
        implementation=None,
    )
    db_session.add(contract)
    db_session.commit()

    def _get_artifact(session, job_id, name):
        if name == "stage_errors":
            raise RuntimeError(secret)
        return None

    monkeypatch.setattr("routers.deps.get_artifact", _get_artifact)
    monkeypatch.setattr("services.discovery.upgrade_history.synthesize_from_events", lambda *a, **k: None)
    try:
        resp = api_client.get(f"/api/analyses/{job.name}/artifact/upgrade_history")
        assert resp.status_code == 503
        reason = resp.json()["reason"]
        assert reason == "stage_errors unreadable: cannot rule out a failed upgrade-history stage"
        assert "RuntimeError" not in reason
        assert secret not in reason
    finally:
        db_session.delete(contract)
        db_session.delete(job)
        db_session.commit()
