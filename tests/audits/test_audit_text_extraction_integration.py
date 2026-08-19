"""End-to-end integration tests for the audit text-extraction pipeline.

Exercises the full stack against live infrastructure:
    - real PostgreSQL (TEST_DATABASE_URL)
    - real S3-compatible object storage (TEST_ARTIFACT_STORAGE_*)
    - FastAPI via TestClient

Only the outbound HTTP call is mocked — every PDF body is a small hand-built
fixture that ``pypdf`` parses exactly like a real audit. The worker's claim,
thread-pool, persist, stale-recovery, and every API endpoint run as they
would in production.

Gated by ``requires_postgres`` + ``requires_storage`` so these skip cleanly
on a dev machine without docker running. CI brings both services up, so the
suite runs there unconditionally.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from tests.conftest import SessionFactory, requires_postgres, requires_storage  # noqa: E402
from tests.support.pdf import minimal_pdf_with_text  # noqa: E402

pytestmark = [requires_postgres, requires_storage]


# Text long enough to clear the 500-char min-useful-text threshold.
_PADDED_SCOPE = "Audits covering Pool.sol Vault.sol Strategy.sol Registry.sol. " * 15


# ---------------------------------------------------------------------------
# Fixtures: seed protocol + audit rows, clean up after each test
# ---------------------------------------------------------------------------


@pytest.fixture()
def seed_protocol(db_session):
    """Insert a fresh Protocol row; cascades to audit_reports cleanup on teardown."""
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
    """Insert a single AuditReport row and return its id."""
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
    """Construct an AuditTextExtractionWorker pointed at the test DB.

    ``workers.audit_text_extraction.SessionLocal`` is rebound to a factory
    that uses ``TEST_DATABASE_URL`` so ``_persist_outcome``'s internal
    session doesn't accidentally write to the developer's real DB.
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
    """Replace services.audits.text_extraction.download_pdf / download_text.

    The key is the exact URL. Values: bytes → returned; Exception → raised.
    Unmapped URLs raise PdfDownloadError so tests fail loudly on typos.
    Both ``download_pdf`` and ``download_text`` consult the same mapping so
    a test can mix .pdf and .md fixtures in one stub.
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
    """A pending row is claimed, downloaded, extracted, stored, and persisted
    with every text-extraction column populated correctly."""
    from db.models import AuditReport

    pdf_bytes = minimal_pdf_with_text(_PADDED_SCOPE)
    url = "https://example.com/real.pdf"
    audit_id = _seed_audit(db_session, seed_protocol, url=url, pdf_url=url)
    _mock_download(monkeypatch, {url: pdf_bytes})

    # Drive the worker's main steps manually so the test doesn't hang on
    # an infinite poll loop.
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

    # Object really exists with matching bytes.
    body = storage_bucket.get(outcome.storage_key)
    assert len(body) == outcome.text_size_bytes
    assert "Pool.sol" in body.decode("utf-8")
    assert "--- page 1 ---" in body.decode("utf-8")


# ---------------------------------------------------------------------------
# 1b. Markdown audit files — raw.githubusercontent.com URLs go through the
# text-decode path instead of pypdf, and the stored text is the markdown
# body verbatim.
# ---------------------------------------------------------------------------


def test_worker_processes_markdown_audit_rows_end_to_end(
    db_session, storage_bucket, seed_protocol, worker, monkeypatch
):
    """A .md URL is claimed, downloaded as text, decoded (no pypdf), and the
    markdown body is stored verbatim. No --- page N --- markers — those come
    from pypdf and must not appear for markdown inputs."""
    from db.models import AuditReport

    md_body = (
        "# Hats Finance — EtherFi Audit\n\n"
        "## Scope\n\n"
        "The following contracts were reviewed:\n\n"
        "- Pool.sol\n- Vault.sol\n- Strategy.sol\n- Registry.sol\n\n"
        + ("Finding N: description that pads the body above the 500-char gate. " * 20)
    )
    url = "https://raw.githubusercontent.com/etherfi-protocol/smart-contracts/master/audits/Hats.md"
    audit_id = _seed_audit(db_session, seed_protocol, url=url, pdf_url=None)
    _mock_download(monkeypatch, {url: md_body.encode("utf-8")})

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    assert outcome.status == "success", f"outcome={outcome}"
    worker._persist_outcome(audit_id, outcome)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.text_extraction_status == "success"
    assert row.text_storage_key == f"audits/text/{audit_id}.txt"

    body = storage_bucket.get(outcome.storage_key)
    stored = body.decode("utf-8")
    assert stored == md_body
    # Sanity: pypdf markers are a pdf-only artifact; they must not appear.
    assert "--- page 1 ---" not in stored


# ---------------------------------------------------------------------------
# 2. Worker failure path — HTTP error goes to 'failed' with error text
# ---------------------------------------------------------------------------


def test_worker_records_http_failure_without_touching_storage(
    db_session, storage_bucket, seed_protocol, worker, monkeypatch
):
    """A 404 URL results in status=failed with the error captured, and
    nothing gets written to object storage for that row."""
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

    # Nothing in storage for this row.
    with pytest.raises(Exception):
        storage_bucket.get(f"audits/text/{audit_id}.txt")


# ---------------------------------------------------------------------------
# 3. Worker skip path — image-only PDFs (short extracted text)
# ---------------------------------------------------------------------------


def test_worker_skips_short_text_pdfs(db_session, storage_bucket, seed_protocol, worker, monkeypatch):
    """PDFs that yield less than the min-useful-text threshold are marked
    skipped (OCR required) rather than stored as empty text."""
    from db.models import AuditReport

    pdf_bytes = minimal_pdf_with_text("tiny")  # far below 500 char threshold
    url = "https://example.com/image-only.pdf"
    audit_id = _seed_audit(db_session, seed_protocol, url=url, pdf_url=url)
    _mock_download(monkeypatch, {url: pdf_bytes})

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.text_extraction_status == "skipped"
    assert row.text_extraction_error is not None
    assert "image-only" in row.text_extraction_error
    assert row.text_storage_key is None


# ---------------------------------------------------------------------------
# 4. Claim atomicity — claimed rows transition status and won't re-appear
# ---------------------------------------------------------------------------


def test_claim_batch_flips_status_to_processing(db_session, storage_bucket, seed_protocol, worker):
    """Once claimed, a row is tagged with ``processing`` + this worker's id
    + a started_at timestamp — a second claim sees no eligible rows."""
    _seed_audit(db_session, seed_protocol, url="https://example.com/a.pdf")
    _seed_audit(db_session, seed_protocol, url="https://example.com/b.pdf")

    first = worker._claim_batch(db_session)
    assert len(first) >= 2

    for row in first:
        assert row.text_extraction_status == "processing"
        assert row.text_extraction_worker == worker.worker_id
        assert row.text_extraction_started_at is not None

    # Second claim should return nothing — both rows are held.
    second = worker._claim_batch(db_session)
    assert second == []


# ---------------------------------------------------------------------------
# 5. Stale-row recovery resets abandoned 'processing' rows
# ---------------------------------------------------------------------------


def test_stale_processing_rows_are_recovered(db_session, storage_bucket, seed_protocol, worker, monkeypatch):
    """A row stuck in ``processing`` past the stale timeout is reset to
    NULL so a fresh claim can pick it up, and its processing metadata is
    cleared so error state doesn't leak across workers."""
    from db.models import AuditReport

    audit_id = _seed_audit(db_session, seed_protocol, url="https://example.com/stale.pdf")

    # Manually park the row in 'processing' with a timestamp older than the
    # stale-recovery threshold (default 600s).
    row = db_session.get(AuditReport, audit_id)
    assert row is not None
    row.text_extraction_status = "processing"
    row.text_extraction_worker = "ghost-worker-that-died"
    row.text_extraction_started_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    worker._recover_stale_rows(db_session)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.text_extraction_status is None
    assert row.text_extraction_worker is None
    assert row.text_extraction_started_at is None

    # And the next claim now includes it.
    claimed = worker._claim_batch(db_session)
    assert audit_id in {a.id for a in claimed}


# ---------------------------------------------------------------------------
# 6. API endpoints — metadata, text body, 409, 404
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_with_storage(monkeypatch, db_session, storage_bucket):
    """TestClient wired to the test DB session + storage bucket."""
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
    """After successful extraction, GET /api/audits/{id} returns every
    stored metadata field including has_text + text_size_bytes."""
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
    """GET /api/audits/{id}/text returns the full extracted text body,
    served from object storage with the right content-type."""
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
    # Body matches the stored object verbatim.
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
    """For a row in ``failed`` state the 409 detail carries the original
    error string so the UI can show it."""
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
    """Unknown audit id surfaces as 404, not 500 or 409."""
    r = api_with_storage.get("/api/audits/99999999")
    assert r.status_code == 404


def test_api_company_audits_surfaces_has_text_per_entry(db_session, storage_bucket, seed_protocol, api_with_storage):
    """The existing /api/company/{name}/audits list endpoint now includes
    ``has_text`` per entry so the UI can tag processed vs. pending audits.

    Simulates post-extraction state directly on the rows — the worker code
    paths are covered by the earlier tests; here we're verifying the
    API-layer serialization only.
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

    # Mark the OK row as successfully extracted.
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
