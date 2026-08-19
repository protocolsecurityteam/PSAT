"""Hardening for the public/admin routers: bounded pagination, guarded UUID
parsing, and no exception-string leakage to clients.

Covers routers/monitored.py, routers/protocols.py, routers/agent.py, and
routers/analyses.py.
"""

from __future__ import annotations

import uuid

import pytest
import requests

from tests.conftest import requires_postgres

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


# --- Unbounded PDF proxy response body (FINDING F4) -------------------------
#
# ``GET /api/audits/{audit_id}/pdf`` is a PUBLIC route whose upstream ``url`` is
# crawler/LLM-sourced. It must stream with a content-type gate and a hard byte
# cap so a seeded URL at a large or non-PDF public file can't OOM the web VM.


class _FakeStreamResponse:
    """Minimal stand-in for a streamed ``requests.Response``.

    ``iter_content`` yields from a caller-supplied generator/iterable and
    records how many chunks were actually consumed, so a test can prove the
    route aborts a too-large body early instead of buffering the whole thing.
    """

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
    """A committed ``AuditReport`` (+ owning ``Protocol``) with a public pdf_url.

    Yields the audit id; deletes both rows on teardown so the route test is
    hermetic and leaves no cross-test residue.
    """
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
    """A well-behaved small PDF returns 200 with ``application/pdf`` body."""
    pdf_body = b"%PDF-1.4\n" + b"content" * 10

    resp_obj = _FakeStreamResponse(content_type="application/pdf", chunks=[pdf_body])
    monkeypatch.setattr("utils.egress.safe_get", lambda *a, **k: resp_obj)

    resp = api_client.get(f"/api/audits/{audit_pdf_row}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content == pdf_body
    assert resp_obj.closed is True


def test_audit_pdf_non_pdf_content_type_is_rejected(api_client, audit_pdf_row, monkeypatch):
    """A present-but-wrong content-type (HTML error page) is refused, and the
    body is never returned to the client."""
    html = b"<html><body>not a pdf</body></html>"
    resp_obj = _FakeStreamResponse(content_type="text/html", chunks=[html])
    monkeypatch.setattr("utils.egress.safe_get", lambda *a, **k: resp_obj)

    resp = api_client.get(f"/api/audits/{audit_pdf_row}/pdf")
    assert resp.status_code == 502
    assert html not in resp.content
    # Never streamed the body, and the connection was released.
    assert resp_obj.consumed == 0
    assert resp_obj.closed is True


def test_audit_pdf_oversized_body_is_capped_not_buffered(api_client, audit_pdf_row, monkeypatch):
    """A body exceeding the cap is aborted mid-stream: the route errors and does
    NOT buffer/return the oversized content."""
    # Shrink the shared cap so the test stays light; the route imports the
    # constant at call time, so patching the source module is enough.
    monkeypatch.setattr("services.audits.text_extraction._MAX_PDF_BYTES", 1000)

    chunk = b"x" * 400

    def _huge_chunks():
        # Would yield 40KB if fully consumed; the route must stop well before.
        for _ in range(100):
            yield chunk

    resp_obj = _FakeStreamResponse(content_type="application/pdf", chunks=_huge_chunks())
    monkeypatch.setattr("utils.egress.safe_get", lambda *a, **k: resp_obj)

    resp = api_client.get(f"/api/audits/{audit_pdf_row}/pdf")
    assert resp.status_code == 502
    assert len(resp.content) < 1000  # oversized body was not returned
    # Aborted after crossing the cap (1000 / 400 -> 3 chunks), not after all 100.
    assert resp_obj.consumed <= 4
    assert resp_obj.closed is True


def test_audit_pdf_error_does_not_leak_upstream_url_or_error(api_client, audit_pdf_row, monkeypatch):
    """No error path echoes the upstream URL or raw exception text into the
    response body (witness discipline / findings #14-15)."""
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
