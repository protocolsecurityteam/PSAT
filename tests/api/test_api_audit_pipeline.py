"""Integration tests for ``GET /api/audits/pipeline`` against real PostgreSQL (``requires_postgres``).

Each test seeds ``audit_reports`` rows in the states the endpoint slices on (NULL / processing /
success / failed); no workers or object storage involved.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from tests.conftest import requires_postgres

pytestmark = [requires_postgres]


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def seed_protocol(db_session):
    from db.models import AuditReport, Protocol

    name = f"pipe-{uuid.uuid4().hex[:10]}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    pid = p.id
    try:
        yield pid, name
    finally:
        db_session.query(AuditReport).filter_by(protocol_id=pid).delete()
        db_session.query(Protocol).filter_by(id=pid).delete()
        db_session.commit()


def _insert_audit(
    db_session,
    protocol_id: int,
    *,
    text_status: str | None = None,
    text_started_at: datetime | None = None,
    text_extracted_at: datetime | None = None,
    text_error: str | None = None,
    text_worker: str | None = None,
    text_size_bytes: int | None = None,
    scope_status: str | None = None,
    scope_started_at: datetime | None = None,
    scope_extracted_at: datetime | None = None,
    scope_error: str | None = None,
    scope_worker: str | None = None,
    scope_contracts: list[str] | None = None,
    reviewed_commits: list[str] | None = None,
    referenced_repos: list[str] | None = None,
    scope_entries: list[dict[str, object]] | None = None,
    classified_commits: list[dict[str, object]] | None = None,
    auditor: str = "Spearbit",
    title: str = "Test Audit",
    discovered_at: datetime | None = None,
) -> int:
    from db.models import AuditReport

    ar = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        pdf_url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor=auditor,
        title=title,
        date="2025-01-01",
        confidence=0.9,
        text_extraction_status=text_status,
        text_extraction_started_at=text_started_at,
        text_extracted_at=text_extracted_at,
        text_extraction_error=text_error,
        text_extraction_worker=text_worker,
        text_size_bytes=text_size_bytes,
        text_storage_key=(f"audits/text/placeholder-{uuid.uuid4().hex[:8]}.txt" if text_status == "success" else None),
        scope_extraction_status=scope_status,
        scope_extraction_started_at=scope_started_at,
        scope_extracted_at=scope_extracted_at,
        scope_extraction_error=scope_error,
        scope_extraction_worker=scope_worker,
        scope_contracts=scope_contracts,
        reviewed_commits=reviewed_commits,
        referenced_repos=referenced_repos,
        scope_entries=scope_entries,
        classified_commits=classified_commits,
    )
    if discovered_at is not None:
        ar.discovered_at = discovered_at
    db_session.add(ar)
    db_session.commit()
    return ar.id


# ---------------------------------------------------------------------------
# 1. Empty pipeline
# ---------------------------------------------------------------------------


def test_pipeline_empty_when_no_audits(api_client):
    r = api_client.get("/api/audits/pipeline")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"text_extraction", "scope_extraction", "generated_at"}
    for worker in ("text_extraction", "scope_extraction"):
        assert body[worker] == {"processing": [], "pending": [], "failed": []}


# ---------------------------------------------------------------------------
# 2. Bucket routing — rows land in the right column
# ---------------------------------------------------------------------------


def test_pipeline_places_rows_in_correct_buckets(db_session, api_client, seed_protocol):
    pid, _ = seed_protocol
    now = datetime.now(timezone.utc)

    pending_tid = _insert_audit(db_session, pid, text_status=None, auditor="Pending")
    proc_tid = _insert_audit(
        db_session,
        pid,
        text_status="processing",
        text_started_at=now - timedelta(seconds=30),
        text_worker="worker-a",
        auditor="Processing",
    )
    _insert_audit(db_session, pid, text_status="success", text_extracted_at=now, auditor="Ignored")
    failed_tid = _insert_audit(
        db_session,
        pid,
        text_status="failed",
        text_extracted_at=now - timedelta(hours=2),
        text_error="HTTP 404",
        auditor="Failed",
    )

    r = api_client.get("/api/audits/pipeline")
    assert r.status_code == 200
    te = r.json()["text_extraction"]

    assert {a["audit_id"] for a in te["pending"]} == {pending_tid}
    assert {a["audit_id"] for a in te["processing"]} == {proc_tid}
    assert {a["audit_id"] for a in te["failed"]} == {failed_tid}

    proc = next(a for a in te["processing"] if a["audit_id"] == proc_tid)
    assert proc["company"] == seed_protocol[1]
    assert proc["auditor"] == "Processing"
    assert proc["worker_id"] == "worker-a"
    assert proc["started_at"] is not None
    assert isinstance(proc["elapsed_seconds"], int) and proc["elapsed_seconds"] >= 30
    assert proc["text_extraction_status"] == "processing"
    assert proc["scope_extraction_status"] is None
    assert proc["text_extracted_at"] is None
    assert proc["text_size_bytes"] is None
    assert proc["scope_contract_count"] == 0
    assert proc["reviewed_commit_count"] == 0
    assert proc["referenced_repo_count"] == 0
    assert proc["scope_entry_count"] == 0
    assert proc["classified_commit_count"] == 0

    failed = next(a for a in te["failed"] if a["audit_id"] == failed_tid)
    assert failed["error"] == "HTTP 404"


# ---------------------------------------------------------------------------
# 3. Scope pending is gated on text success
# ---------------------------------------------------------------------------


def test_scope_pending_excludes_unclaimable_rows(db_session, api_client, seed_protocol):
    """A scope row is only ``pending`` when text has already succeeded —
    otherwise the worker can't do anything with it and showing it in the
    monitor would misrepresent the work the scope worker actually has."""
    pid, _ = seed_protocol
    now = datetime.now(timezone.utc)

    # Text failed → scope unreachable; must NOT show up in scope pending.
    text_failed_id = _insert_audit(
        db_session,
        pid,
        text_status="failed",
        text_extracted_at=now - timedelta(hours=1),
        text_error="HTTP 500",
    )
    assert text_failed_id  # row exists, just not claimable for scope

    _insert_audit(db_session, pid, text_status=None)

    claimable_id = _insert_audit(
        db_session,
        pid,
        text_status="success",
        text_extracted_at=now - timedelta(minutes=5),
    )

    r = api_client.get("/api/audits/pipeline")
    scope = r.json()["scope_extraction"]
    assert [a["audit_id"] for a in scope["pending"]] == [claimable_id]


# ---------------------------------------------------------------------------
# 4. Failed lookback window — stale failures drop out
# ---------------------------------------------------------------------------


def test_pipeline_excludes_failures_older_than_lookback(db_session, api_client, seed_protocol):
    """Only failures within the last 24h appear — older ones fade so the
    panel doesn't grow unbounded across weeks of accumulated misses."""
    pid, _ = seed_protocol
    now = datetime.now(timezone.utc)

    recent_id = _insert_audit(
        db_session,
        pid,
        text_status="failed",
        text_extracted_at=now - timedelta(hours=3),
        text_error="recent",
    )
    _insert_audit(  # >24h old — must not appear
        db_session,
        pid,
        text_status="failed",
        text_extracted_at=now - timedelta(days=3),
        text_error="stale",
    )

    r = api_client.get("/api/audits/pipeline")
    failed_ids = {a["audit_id"] for a in r.json()["text_extraction"]["failed"]}
    assert failed_ids == {recent_id}


# ---------------------------------------------------------------------------
# 5. Scope-stage state machine — pending → processing → failed / success
# ---------------------------------------------------------------------------


def test_scope_bucket_routing(db_session, api_client, seed_protocol):
    pid, _ = seed_protocol
    now = datetime.now(timezone.utc)

    pending = _insert_audit(
        db_session,
        pid,
        text_status="success",
        text_extracted_at=now,
        scope_status=None,
    )
    processing = _insert_audit(
        db_session,
        pid,
        text_status="success",
        text_extracted_at=now,
        scope_status="processing",
        scope_started_at=now - timedelta(minutes=2),
        scope_worker="scope-worker-b",
    )
    failed = _insert_audit(
        db_session,
        pid,
        text_status="success",
        text_extracted_at=now,
        scope_status="failed",
        scope_extracted_at=now - timedelta(hours=4),
        scope_error="LLM timeout",
    )
    _insert_audit(  # success — terminal, excluded
        db_session,
        pid,
        text_status="success",
        text_extracted_at=now,
        scope_status="success",
        scope_extracted_at=now,
    )

    r = api_client.get("/api/audits/pipeline")
    scope = r.json()["scope_extraction"]

    assert {a["audit_id"] for a in scope["pending"]} == {pending}
    assert {a["audit_id"] for a in scope["processing"]} == {processing}
    assert {a["audit_id"] for a in scope["failed"]} == {failed}

    # Processing row's worker_id is the SCOPE worker, not text — the
    # frontend shows "who's working on this right now".
    proc = next(a for a in scope["processing"] if a["audit_id"] == processing)
    assert proc["worker_id"] == "scope-worker-b"
    assert proc["error"] is None

    fail = next(a for a in scope["failed"] if a["audit_id"] == failed)
    assert fail["error"] == "LLM timeout"


# ---------------------------------------------------------------------------
# 6. Bucket cap — the endpoint never returns more than _PIPELINE_BUCKET_LIMIT
#    entries, protecting the monitor page from pathological backlogs
# ---------------------------------------------------------------------------


def test_pipeline_caps_buckets_at_limit(db_session, api_client, seed_protocol):
    """Seeding more rows than the cap still yields a bounded response (one stuck worker can't brick the monitor)."""
    from services.aggregations import audits_pipeline as pipeline_module

    cap = pipeline_module._PIPELINE_BUCKET_LIMIT
    pid, _ = seed_protocol

    for _ in range(cap + 10):
        _insert_audit(db_session, pid, text_status=None)

    r = api_client.get("/api/audits/pipeline")
    pending = r.json()["text_extraction"]["pending"]
    assert len(pending) == cap


# ---------------------------------------------------------------------------
# 8. Pending ordering — oldest discovered first so FIFO matches worker claim
# ---------------------------------------------------------------------------


def test_text_pending_ordered_oldest_first(db_session, api_client, seed_protocol):
    """Pending follows worker claim order (``discovered_at`` ascending); otherwise the top entry
    could be the newest audit, misleading anyone watching a stuck queue."""
    pid, _ = seed_protocol
    now = datetime.now(timezone.utc)

    # Insert newest first so we're sure ordering isn't just insertion order.
    newer = _insert_audit(db_session, pid, text_status=None, discovered_at=now - timedelta(hours=1))
    older = _insert_audit(db_session, pid, text_status=None, discovered_at=now - timedelta(hours=5))
    middle = _insert_audit(db_session, pid, text_status=None, discovered_at=now - timedelta(hours=3))

    r = api_client.get("/api/audits/pipeline")
    ids_in_order = [a["audit_id"] for a in r.json()["text_extraction"]["pending"]]
    assert ids_in_order == [older, middle, newer]
