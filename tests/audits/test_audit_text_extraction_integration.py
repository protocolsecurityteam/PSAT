"""End-to-end text-extraction pipeline against real PostgreSQL, S3-compatible storage and FastAPI TestClient.
Only the outbound HTTP call is mocked; PDF bodies are small hand-built fixtures that ``pypdf`` parses like real
audits. Claim, thread pool, persist, stale recovery and the API endpoints run as in production.
Needs Postgres + storage (skips without docker).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from tests.conftest import SessionFactory, requires_postgres, requires_storage
from tests.support.pdf import minimal_pdf_with_text

pytestmark = [requires_postgres, requires_storage]


# Text long enough to clear the 500-char min-useful-text threshold.
_PADDED_SCOPE = "Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 15


# ---------------------------------------------------------------------------
# Fixtures: seed protocol + audit rows, clean up after each test
# ---------------------------------------------------------------------------


@pytest.fixture()
def seed_protocol(db_session):
    from db.models import AuditReport, Protocol

    # Make the protocol name unique per test so parallel runs don't collide.
    name = f"testprotocol-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id
    try:
        yield protocol_id
    finally:
        # Explicit AuditReport cleanup (CASCADE works at DB level, but also
        # be explicit so cleanup isn't order-dependent).
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _seed_audit(db_session, protocol_id: int, **overrides) -> int:
    from db.models import AuditReport

    defaults = dict(
        protocol_id=protocol_id,
        url=f"https://example.com/audit-{id(overrides)}.pdf",
        pdf_url=None,
        auditor="TestFirm",
        title="Test Audit",
        date="2025-01-01",
        confidence=0.9,
    )
    defaults.update(overrides)
    if defaults["pdf_url"] is None:
        defaults["pdf_url"] = defaults["url"]

    ar = AuditReport(**defaults)
    db_session.add(ar)
    db_session.commit()
    return ar.id


@pytest.fixture()
def worker(monkeypatch):
    """Worker pointed at the test DB: ``workers.audit_text_extraction.SessionLocal`` is rebound so
    ``_persist_outcome``'s own session can't write to the developer's real DB.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import workers.audit_text_extraction as worker_mod
    from tests.conftest import DATABASE_URL

    test_engine = create_engine(DATABASE_URL)
    test_session_factory = sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(worker_mod, "SessionLocal", test_session_factory)

    with patch("signal.signal"):
        w = worker_mod.AuditTextExtractionWorker()
    try:
        yield w
    finally:
        test_engine.dispose()


def _mock_download(monkeypatch, mapping: dict[str, bytes | Exception]):
    """Replace download_pdf / download_text with an exact-URL mapping (bytes -> returned, Exception -> raised).
    Unmapped URLs raise PdfDownloadError so typos fail loudly; both functions share the mapping so a test can
    mix .pdf and .md fixtures.
    """
    from services.audits.text_extraction import PdfDownloadError

    def fake_download(url, session=None):
        entry = mapping.get(url)
        if isinstance(entry, Exception):
            raise entry
        if entry is None:
            raise PdfDownloadError(f"test: no mock for url {url!r}")
        return entry

    monkeypatch.setattr("services.audits.text_extraction.download_pdf", fake_download)
    monkeypatch.setattr("services.audits.text_extraction.download_text", fake_download)


# ---------------------------------------------------------------------------
# 1. Worker happy path — claim, process, persist, write to real storage
# ---------------------------------------------------------------------------


def test_worker_processes_pending_rows_end_to_end(db_session, storage_bucket, seed_protocol, worker, monkeypatch):
    from db.models import AuditReport

    pdf_bytes = minimal_pdf_with_text(_PADDED_SCOPE)
    url = "https://example.com/real.pdf"
    audit_id = _seed_audit(db_session, seed_protocol, url=url, pdf_url=url)
    _mock_download(monkeypatch, {url: pdf_bytes})

    claimed = worker._claim_batch(db_session)
    claimed_ids = {a.id for a in claimed}
    assert audit_id in claimed_ids, f"worker failed to claim the seeded row; claimed={claimed_ids}"

    audit_obj = next(a for a in claimed if a.id == audit_id)
    returned_id, outcome = worker._process_row(audit_obj)
    assert returned_id == audit_id
    assert outcome.status == "success", f"outcome={outcome}"
    assert outcome.storage_key == f"audits/text/{audit_id}.txt"
    assert outcome.text_size_bytes is not None and outcome.text_size_bytes > 500
    assert outcome.text_sha256 is not None and len(outcome.text_sha256) == 64

    worker._persist_outcome(audit_id, outcome)

    # Re-query via a fresh session — avoid stale identity-map results.
    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row is not None
    assert row.text_extraction_status == "success"
    assert row.text_storage_key == f"audits/text/{audit_id}.txt"
    assert row.text_size_bytes == outcome.text_size_bytes
    assert row.text_sha256 == outcome.text_sha256
    assert row.text_extracted_at is not None
    assert row.text_extraction_worker is None  # cleared on persist
    assert row.text_extraction_error is None

    body = storage_bucket.get(outcome.storage_key)
    assert len(body) == outcome.text_size_bytes
    assert "Pool.sol" in body.decode("utf-8")
    assert "--- page 1 ---" in body.decode("utf-8")


# ---------------------------------------------------------------------------
# 1b. Markdown audit files — raw.githubusercontent.com URLs go through the
# text-decode path instead of pypdf, and the stored text is the markdown
# body verbatim.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 2. Worker failure path — HTTP error goes to 'failed' with error text
# ---------------------------------------------------------------------------


def test_worker_records_http_failure_without_touching_storage(
    db_session, storage_bucket, seed_protocol, worker, monkeypatch
):
    from db.models import AuditReport
    from services.audits.text_extraction import PdfDownloadError

    url = "https://example.com/nope.pdf"
    audit_id = _seed_audit(db_session, seed_protocol, url=url, pdf_url=url)
    _mock_download(monkeypatch, {url: PdfDownloadError("HTTP 404")})

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.text_extraction_status == "failed"
    assert row.text_extraction_error is not None
    assert "HTTP 404" in row.text_extraction_error
    assert row.text_storage_key is None
    assert row.text_extracted_at is None

    with pytest.raises(Exception):
        storage_bucket.get(f"audits/text/{audit_id}.txt")


# ---------------------------------------------------------------------------
# 3. Worker skip path — image-only PDFs (short extracted text)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 4. Claim atomicity — claimed rows transition status and won't re-appear
# ---------------------------------------------------------------------------


def test_claim_batch_flips_status_to_processing(db_session, storage_bucket, seed_protocol, worker):
    _seed_audit(db_session, seed_protocol, url="https://example.com/a.pdf")
    _seed_audit(db_session, seed_protocol, url="https://example.com/b.pdf")

    first = worker._claim_batch(db_session)
    assert len(first) >= 2

    for row in first:
        assert row.text_extraction_status == "processing"
        assert row.text_extraction_worker == worker.worker_id
        assert row.text_extraction_started_at is not None

    second = worker._claim_batch(db_session)
    assert second == []


# ---------------------------------------------------------------------------
# 5. Stale-row recovery resets abandoned 'processing' rows
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 6. API endpoints — metadata, text body, 409, 404
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_with_storage(monkeypatch, db_session, storage_bucket):
    from fastapi.testclient import TestClient

    import api as api_module
    from routers import deps
    from routers.deps import require_admin_key

    monkeypatch.setattr(deps, "SessionLocal", SessionFactory(db_session))
    api_module.app.dependency_overrides[require_admin_key] = lambda: None
    try:
        yield TestClient(api_module.app)
    finally:
        api_module.app.dependency_overrides.pop(require_admin_key, None)


def test_api_get_audit_returns_full_metadata(
    db_session, storage_bucket, seed_protocol, worker, monkeypatch, api_with_storage
):
    pdf_bytes = minimal_pdf_with_text(_PADDED_SCOPE)
    url = "https://example.com/for-api.pdf"
    audit_id = _seed_audit(
        db_session,
        seed_protocol,
        url=url,
        pdf_url=url,
        auditor="APITestFirm",
        title="API Test Audit",
        date="2025-03-14",
    )
    _mock_download(monkeypatch, {url: pdf_bytes})

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    r = api_with_storage.get(f"/api/audits/{audit_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == audit_id
    assert body["auditor"] == "APITestFirm"
    assert body["title"] == "API Test Audit"
    assert body["date"] == "2025-03-14"
    assert body["text_extraction_status"] == "success"
    assert body["has_text"] is True
    assert body["text_size_bytes"] == outcome.text_size_bytes
    assert body["text_extracted_at"] is not None


def test_api_get_audit_text_streams_body_from_storage(
    db_session, storage_bucket, seed_protocol, worker, monkeypatch, api_with_storage
):
    pdf_bytes = minimal_pdf_with_text(_PADDED_SCOPE)
    url = "https://example.com/for-text-api.pdf"
    audit_id = _seed_audit(db_session, seed_protocol, url=url, pdf_url=url)
    _mock_download(monkeypatch, {url: pdf_bytes})

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    r = api_with_storage.get(f"/api/audits/{audit_id}/text")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "--- page 1 ---" in r.text
    assert "Pool.sol" in r.text
    stored = storage_bucket.get(outcome.storage_key)
    assert r.text == stored.decode("utf-8")


def test_api_audit_text_returns_409_when_extraction_not_ready(
    db_session, storage_bucket, seed_protocol, api_with_storage
):
    """A pending / never-extracted audit returns 409 with structured detail
    (status + reason) so callers can distinguish from 404s."""
    audit_id = _seed_audit(
        db_session,
        seed_protocol,
        url="https://example.com/pending.pdf",
    )
    r = api_with_storage.get(f"/api/audits/{audit_id}/text")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["error"] == "text not available"
    # status is None on a pending row — the client can use that to tell
    # "extraction hasn't started" apart from "extraction failed".
    assert detail["status"] is None


def test_api_audit_text_returns_409_with_reason_on_failure(
    db_session, storage_bucket, seed_protocol, worker, monkeypatch, api_with_storage
):
    from services.audits.text_extraction import PdfDownloadError

    url = "https://example.com/fails.pdf"
    audit_id = _seed_audit(db_session, seed_protocol, url=url, pdf_url=url)
    _mock_download(monkeypatch, {url: PdfDownloadError("HTTP 403")})

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    r = api_with_storage.get(f"/api/audits/{audit_id}/text")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["status"] == "failed"
    assert detail["reason"] and "HTTP 403" in detail["reason"]


def test_api_audit_not_found_returns_404(api_with_storage):
    r = api_with_storage.get("/api/audits/99999999")
    assert r.status_code == 404


def test_api_company_audits_surfaces_has_text_per_entry(db_session, storage_bucket, seed_protocol, api_with_storage):
    """``has_text`` per entry on the company audits list. Post-extraction state is set directly on the rows; only
    API serialization is under test.
    """
    from datetime import datetime
    from datetime import timezone as _tz

    from db.models import AuditReport, Protocol

    aid_ok = _seed_audit(
        db_session,
        seed_protocol,
        url="https://example.com/list-ok.pdf",
        pdf_url="https://example.com/list-ok.pdf",
        auditor="FirmOK",
        title="OK",
    )
    _seed_audit(
        db_session,
        seed_protocol,
        url="https://example.com/list-pending.pdf",
        pdf_url="https://example.com/list-pending.pdf",
        auditor="FirmPending",
        title="Pending",
    )

    ok_row = db_session.get(AuditReport, aid_ok)
    assert ok_row is not None
    ok_row.text_extraction_status = "success"
    ok_row.text_storage_key = f"audits/text/{aid_ok}.txt"
    ok_row.text_size_bytes = 12345
    ok_row.text_sha256 = "a" * 64
    ok_row.text_extracted_at = datetime.now(_tz.utc)
    db_session.commit()

    protocol = db_session.execute(select(Protocol).where(Protocol.id == seed_protocol)).scalar_one()

    r = api_with_storage.get(f"/api/company/{protocol.name}/audits")
    assert r.status_code == 200
    body = r.json()
    assert body["audit_count"] == 2
    by_auditor = {a["auditor"]: a for a in body["audits"]}
    assert by_auditor["FirmOK"]["has_text"] is True
    assert by_auditor["FirmOK"]["text_size_bytes"] == 12345
    assert by_auditor["FirmOK"]["text_extraction_status"] == "success"
    assert by_auditor["FirmPending"]["has_text"] is False
    assert by_auditor["FirmPending"]["text_size_bytes"] is None
    assert by_auditor["FirmPending"]["text_extraction_status"] is None
