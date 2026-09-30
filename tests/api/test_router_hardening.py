
from __future__ import annotations

import uuid

import pytest
import requests

from tests.conftest import requires_postgres

pytestmark = [requires_postgres]


@pytest.mark.parametrize(
    ("path", "limit", "expected"),
    [
        pytest.param("/api/monitored-events", 1000, 422, id="monitored_over_cap"),
        pytest.param("/api/monitored-events", 0, 422, id="monitored_below_floor"),
        pytest.param("/api/monitored-events", 500, 200, id="monitored_at_cap"),
        pytest.param("/api/protocols/1/events", 1000, 422, id="protocol_over_cap"),
        pytest.param("/api/protocols/1/events", 500, 200, id="protocol_at_cap"),
    ],
)
def test_events_limit_bounds(api_client, path, limit, expected):
    resp = api_client.get(path, params={"limit": limit})
    assert resp.status_code == expected


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        pytest.param(
            "patch", "/api/monitored-contracts/not-a-uuid", {"json": {"is_active": False}}, id="patch_bad_uuid"
        ),
        pytest.param("delete", "/api/protocol-subscriptions/not-a-uuid", {}, id="delete_subscription_bad_uuid"),
        pytest.param(
            "patch",
            f"/api/monitored-contracts/{uuid.uuid4()}",
            {"json": {"is_active": False}},
            id="patch_valid_uuid_absent",
        ),
    ],
)
def test_unknown_or_malformed_uuid_is_404(api_client, method, path, kwargs):
    resp = getattr(api_client, method)(path, **kwargs)
    assert resp.status_code == 404


def test_monitored_events_bad_contract_id_is_422_not_500(api_client):
    resp = api_client.get("/api/monitored-events", params={"contract_id": "not-a-uuid"})
    assert resp.status_code == 422


def test_monitored_events_valid_contract_id_absent_is_empty(api_client):
    resp = api_client.get("/api/monitored-events", params={"contract_id": str(uuid.uuid4())})
    assert resp.status_code == 200
    assert resp.json() == []


def test_agent_stream_error_is_generic(api_client, monkeypatch):
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
    from db.models import Contract, Job, JobStatus

    secret = "boto3.ClientError: connection to internal-bucket refused"

    job = Job(
        id=uuid.uuid4(),
        name="__hardening_upgrade_history_leak__",
        status=JobStatus.completed,
    )
    db_session.add(job)
    db_session.flush()
    # Non-proxy and self-consistent, so the reason falls through to the forced stage_errors read.
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


# The public PDF route's ``url`` is crawler/LLM-sourced, so it must stream with a content-type gate and byte cap or a
# seeded URL could OOM the web VM.


class _FakeStreamResponse:
    """``consumed`` proves the route aborts an oversized body early."""

    def __init__(self, *, content_type, chunks, status=200):
        self.headers = {"content-type": content_type}
        self.status_code = status
        self._chunks = chunks
        self.closed = False
        self.consumed = 0

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=131_072):
        for chunk in self._chunks:
            self.consumed += 1
            yield chunk

    def close(self):
        self.closed = True


@pytest.fixture
def audit_pdf_row(db_session):
    from db.models import AuditReport, Protocol

    protocol = Protocol(name="__hardening_pdf_proxy__")
    db_session.add(protocol)
    db_session.flush()
    ar = AuditReport(
        protocol_id=protocol.id,
        url="https://example.com/report",
        pdf_url="https://example.com/report.pdf",
        auditor="ACME",
        title="Hardening PDF Proxy",
    )
    db_session.add(ar)
    db_session.commit()
    audit_id = ar.id
    try:
        yield audit_id
    finally:
        db_session.rollback()
        db_session.delete(ar)
        db_session.delete(protocol)
        db_session.commit()


def test_audit_pdf_small_pdf_is_served(api_client, audit_pdf_row, monkeypatch):
    pdf_body = b"%PDF-1.4\n" + b"content" * 10

    resp_obj = _FakeStreamResponse(content_type="application/pdf", chunks=[pdf_body])
    monkeypatch.setattr("utils.egress.safe_get", lambda *a, **k: resp_obj)

    resp = api_client.get(f"/api/audits/{audit_pdf_row}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content == pdf_body
    assert resp_obj.closed is True


def test_audit_pdf_non_pdf_content_type_is_rejected(api_client, audit_pdf_row, monkeypatch):
    html = b"<html><body>not a pdf</body></html>"
    resp_obj = _FakeStreamResponse(content_type="text/html", chunks=[html])
    monkeypatch.setattr("utils.egress.safe_get", lambda *a, **k: resp_obj)

    resp = api_client.get(f"/api/audits/{audit_pdf_row}/pdf")
    assert resp.status_code == 502
    assert html not in resp.content
    assert resp_obj.consumed == 0
    assert resp_obj.closed is True


def test_audit_pdf_oversized_body_is_capped_not_buffered(api_client, audit_pdf_row, monkeypatch):
    # The route reads the constant at call time, so patching the source module is enough.
    monkeypatch.setattr("services.audits.text_extraction._MAX_PDF_BYTES", 1000)

    chunk = b"x" * 400

    def _huge_chunks():
        for _ in range(100):
            yield chunk

    resp_obj = _FakeStreamResponse(content_type="application/pdf", chunks=_huge_chunks())
    monkeypatch.setattr("utils.egress.safe_get", lambda *a, **k: resp_obj)

    resp = api_client.get(f"/api/audits/{audit_pdf_row}/pdf")
    assert resp.status_code == 502
    assert len(resp.content) < 1000  # oversized body was not returned
    assert resp_obj.consumed <= 4
    assert resp_obj.closed is True


def test_audit_pdf_error_does_not_leak_upstream_url_or_error(api_client, audit_pdf_row, monkeypatch):
    from utils.egress import UnsafeUrlError

    secret_url = "https://example.com/report.pdf"

    def _boom(*a, **k):
        raise UnsafeUrlError(f"host resolves to non-public address for {secret_url}")

    monkeypatch.setattr("utils.egress.safe_get", _boom)

    resp = api_client.get(f"/api/audits/{audit_pdf_row}/pdf")
    assert resp.status_code == 502
    body = resp.text
    assert secret_url not in body
    assert "non-public" not in body
    assert resp.json()["detail"] == "Failed to fetch PDF"
