"""Smoke test walking one fixture PDF through discovery sync, text extraction, scope extraction (stub returns
Pool/Vault/Strategy/Registry) and coverage population. Per-phase behaviour lives in the focused files; this
catches regressions in the *handoffs* (a status column no longer advanced, a storage key changing shape,
scope/coverage worker mismatch). Needs Postgres + object storage (skips without docker).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from tests.conftest import DATABASE_URL, requires_postgres, requires_storage
from tests.support.pdf import minimal_pdf_with_text

pytestmark = [
    requires_postgres,
    requires_storage,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "scope_extraction"
STUB_DIR = FIXTURE_DIR / "llm_responses"
AUDIT_FIXTURE = FIXTURE_DIR / "audits" / "spearbit_table.txt"


# ---------------------------------------------------------------------------
# LLM stub — scope-worker fixture stub expects a dir, not an individual file
# ---------------------------------------------------------------------------


@pytest.fixture()
def llm_stub_dir(monkeypatch, tmp_path):
    """Committed ``_default.json`` stub returns Pool/Vault/Strategy/Registry, all present in the Spearbit fixture
    body so the scope validator drops nothing as hallucinated.
    """
    committed = STUB_DIR / "_default.json"
    assert committed.exists()
    (tmp_path / "_default.json").write_text(committed.read_text())
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))
    return tmp_path


# ---------------------------------------------------------------------------
# Worker bindings — SessionLocal swapped to the test DB engine
# ---------------------------------------------------------------------------


@pytest.fixture()
def text_worker(monkeypatch):
    import workers.audit_text_extraction as worker_mod

    engine = create_engine(DATABASE_URL)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(worker_mod, "SessionLocal", factory)
    with patch("signal.signal"):
        w = worker_mod.AuditTextExtractionWorker()
    try:
        yield w
    finally:
        engine.dispose()


@pytest.fixture()
def scope_worker(monkeypatch):
    import workers.audit_scope_extraction as worker_mod

    engine = create_engine(DATABASE_URL)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(worker_mod, "SessionLocal", factory)
    with patch("signal.signal"):
        w = worker_mod.AuditScopeExtractionWorker()
    try:
        yield w
    finally:
        engine.dispose()


def _drive_batch(worker, db_session) -> None:
    for ar in worker._claim_batch(db_session):
        _, outcome = worker._process_row(ar)
        worker._persist_outcome(ar.id, outcome)


# ---------------------------------------------------------------------------
# Seed: protocol + one Pool Contract, to be matched by scope extraction
# ---------------------------------------------------------------------------


@pytest.fixture()
def seeded_protocol(db_session):
    from db.models import (
        AuditContractCoverage,
        AuditReport,
        Contract,
        Protocol,
    )

    name = f"e2e-{uuid.uuid4().hex[:10]}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id

    contract = Contract(
        protocol_id=protocol_id,
        address="0x" + "e" * 40,
        contract_name="Pool",
        chain="ethereum",
    )
    db_session.add(contract)
    db_session.commit()

    try:
        yield {"protocol_id": protocol_id, "protocol_name": name, "contract": contract}
    finally:
        db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def test_full_audit_pipeline_from_discovery_row_to_coverage(
    db_session,
    storage_bucket,
    seeded_protocol,
    text_worker,
    scope_worker,
    llm_stub_dir,
    monkeypatch,
):
    from db.models import AuditContractCoverage, AuditReport
    from workers.discovery import _sync_audit_reports_to_db

    protocol_id = seeded_protocol["protocol_id"]
    contract = seeded_protocol["contract"]

    # --- Phase 1: discovery syncs a report into audit_reports ---
    url = "https://example.com/e2e-spearbit.pdf"
    reports = [
        {
            "url": url,
            "pdf_url": url,
            "auditor": "Spearbit",
            "title": "Example Protocol Security Review",
            "date": "2024-12-19",
            "confidence": 0.9,
            "source_url": "https://example.com/",
        }
    ]
    _sync_audit_reports_to_db(db_session, protocol_id, reports)

    audit_row = db_session.query(AuditReport).filter_by(protocol_id=protocol_id).one()
    audit_id = audit_row.id
    assert audit_row.text_extraction_status is None
    assert audit_row.scope_extraction_status is None

    # --- Phase 2: text extraction worker ---
    # Stub ``download_pdf`` with a real PDF body carrying the Spearbit scope text; pypdf, MinIO and DB run for real.
    pdf_body = minimal_pdf_with_text(AUDIT_FIXTURE.read_text())
    monkeypatch.setattr(
        "services.audits.text_extraction.download_pdf",
        lambda url, session=None: pdf_body,
    )

    _drive_batch(text_worker, db_session)

    db_session.expire_all()
    audit_row = db_session.get(AuditReport, audit_id)
    assert audit_row.text_extraction_status == "success", (
        f"text extraction didn't complete: error={audit_row.text_extraction_error!r}"
    )
    assert audit_row.text_storage_key == f"audits/text/{audit_id}.txt"
    assert audit_row.text_size_bytes and audit_row.text_size_bytes > 0
    assert audit_row.text_sha256 and len(audit_row.text_sha256) == 64

    stored_text = storage_bucket.get(audit_row.text_storage_key).decode("utf-8")
    assert "Pool" in stored_text
    assert "Vault" in stored_text

    # --- Phase 3: scope extraction worker ---
    _drive_batch(scope_worker, db_session)

    db_session.expire_all()
    audit_row = db_session.get(AuditReport, audit_id)
    assert audit_row.scope_extraction_status == "success", (
        f"scope extraction didn't complete: error={audit_row.scope_extraction_error!r}"
    )
    assert audit_row.scope_storage_key == f"audits/scope/{audit_id}.json"
    assert audit_row.scope_contracts is not None
    assert "Pool" in audit_row.scope_contracts
    # The Spearbit fixture mentions ``abc123def456`` as the reviewed commit.
    assert audit_row.reviewed_commits and "abc123def456" in audit_row.reviewed_commits

    # --- Phase 4: coverage written by the scope worker's inline refresh ---
    # The scope worker calls ``upsert_coverage_for_audit`` in the same
    # persist transaction; by the time we see scope_status=success, the
    # audit_contract_coverage row is already durable.
    coverage_rows = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit_id).all()
    assert len(coverage_rows) >= 1, "no coverage written after scope extraction"
    pool_row = next((r for r in coverage_rows if r.contract_id == contract.id), None)
    assert pool_row is not None, (
        f"expected coverage row for Pool (contract_id={contract.id}); "
        f"got {[(r.contract_id, r.matched_name) for r in coverage_rows]}"
    )
    assert pool_row.matched_name == "Pool"
    assert pool_row.match_type in {"direct", "impl_era"}
    assert pool_row.match_confidence in {"high", "medium", "low"}


def test_e2e_pipeline_is_idempotent_on_reextract(
    db_session,
    storage_bucket,
    seeded_protocol,
    text_worker,
    scope_worker,
    llm_stub_dir,
    monkeypatch,
):
    """Re-driving the scope worker after a state reset must not duplicate coverage rows (upsert_coverage_for_audit
    must delete stale rows first, else a unique violation or creeping row count).
    """
    from db.models import AuditContractCoverage, AuditReport
    from workers.discovery import _sync_audit_reports_to_db

    protocol_id = seeded_protocol["protocol_id"]
    contract = seeded_protocol["contract"]

    _sync_audit_reports_to_db(
        db_session,
        protocol_id,
        [
            {
                "url": "https://example.com/e2e-reextract.pdf",
                "pdf_url": "https://example.com/e2e-reextract.pdf",
                "auditor": "Spearbit",
                "title": "Reextract Test",
                "date": "2024-12-19",
                "confidence": 0.9,
                "source_url": "https://example.com/",
            }
        ],
    )
    audit_id = db_session.query(AuditReport).filter_by(protocol_id=protocol_id).one().id

    monkeypatch.setattr(
        "services.audits.text_extraction.download_pdf",
        lambda url, session=None: minimal_pdf_with_text(AUDIT_FIXTURE.read_text()),
    )

    _drive_batch(text_worker, db_session)
    _drive_batch(scope_worker, db_session)

    db_session.expire_all()
    first = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit_id, contract_id=contract.id).all()
    assert len(first) == 1, f"expected 1 coverage row after first pass, got {len(first)}"

    audit_row = db_session.get(AuditReport, audit_id)
    audit_row.scope_extraction_status = None
    audit_row.scope_contracts = None
    audit_row.scope_storage_key = None
    audit_row.reviewed_commits = None
    db_session.commit()

    _drive_batch(scope_worker, db_session)

    db_session.expire_all()
    second = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit_id, contract_id=contract.id).all()
    assert len(second) == 1, (
        f"expected 1 coverage row after reextract, got {len(second)} (stale-row cleanup probably regressed)"
    )
