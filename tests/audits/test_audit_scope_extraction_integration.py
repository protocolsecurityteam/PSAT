"""The scope worker is driven directly, not through the poll loop."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.conftest import requires_postgres, requires_storage
from tests.support.audit_fixtures import (
    api_with_storage,  # noqa: F401  (fixture, registered by import)
    worker,  # noqa: F401  (fixture, registered by import)
)

pytestmark = [
    requires_postgres,
    requires_storage,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "scope_extraction"
AUDITS_DIR = FIXTURE_DIR / "audits"
STUB_DIR = FIXTURE_DIR / "llm_responses"


@pytest.fixture()
def llm_stub_dir(monkeypatch, tmp_path):
    """``_default.json`` names contracts every committed fixture mentions, so no per-test prompt digest is needed."""
    committed = STUB_DIR / "_default.json"
    assert committed.exists(), f"missing fixture: {committed}"
    (tmp_path / "_default.json").write_text(committed.read_text())
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))
    return tmp_path


def _fixture_text(name: str) -> str:
    path = AUDITS_DIR / name
    assert path.exists(), f"missing audit fixture: {path}"
    return path.read_text()


@pytest.fixture()
def seed_protocol(db_session):
    from db.models import AuditReport, Contract, Protocol

    name = f"scope-test-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id
    try:
        yield protocol_id, name
    finally:
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _seed_scoped_row(
    db_session,
    storage_bucket,
    protocol_id: int,
    *,
    fixture: str,
    text_sha256: str | None = None,
    url: str | None = None,
    **overrides,
) -> int:
    from db.models import AuditReport
    from services.audits.text_extraction import audit_text_key

    body = _fixture_text(fixture).encode("utf-8")
    ar = AuditReport(
        protocol_id=protocol_id,
        url=url or f"https://example.com/{fixture}",
        pdf_url=url or f"https://example.com/{fixture}",
        auditor=overrides.get("auditor", "TestFirm"),
        title=overrides.get("title", f"Test Audit — {fixture}"),
        date=overrides.get("date"),
        confidence=0.9,
        text_extraction_status="success",
        text_size_bytes=len(body),
        text_sha256=text_sha256 or f"sha-{fixture}",
        text_extracted_at=datetime.now(timezone.utc),
    )
    db_session.add(ar)
    db_session.commit()
    audit_id = ar.id
    ar.text_storage_key = audit_text_key(audit_id)
    db_session.commit()
    storage_bucket.put(
        audit_text_key(audit_id),
        body,
        "text/plain; charset=utf-8",
    )
    return audit_id


def test_worker_extracts_scope_for_spearbit_fixture(db_session, storage_bucket, seed_protocol, worker, llm_stub_dir):
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        auditor="Spearbit",
        title="Example Protocol Security Review",
        text_sha256="sha-spearbit-fixture",
    )

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.scope_extraction_status == "success"
    assert row.scope_contracts is not None
    assert sorted(row.scope_contracts) == ["Pool", "Registry", "Strategy", "Vault"]
    assert row.scope_storage_key == f"audits/scope/{audit_id}.json"
    assert row.scope_extracted_at is not None
    assert row.scope_extraction_worker is None
    # The discovery-time date was null; the worker backfills it from the fixture title.
    assert row.date == "2024-12-19"

    import json as _json

    body = storage_bucket.get(row.scope_storage_key)
    payload = _json.loads(body)
    assert payload["contracts"] == list(row.scope_contracts)
    assert payload["method"] == "llm"
    assert payload["prompt_version"]


def test_worker_skips_body_without_scope_header(db_session, storage_bucket, seed_protocol, worker, llm_stub_dir):
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="no_scope_section.txt",
        text_sha256="sha-degenerate",
    )

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.scope_extraction_status == "skipped"
    assert row.scope_extraction_error is not None
    assert "no scope section found" in row.scope_extraction_error
    assert row.scope_contracts is None or row.scope_contracts == []
    assert row.scope_storage_key is None


def test_worker_falls_back_to_regex_when_llm_fails(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
    monkeypatch,
    tmp_path,
):
    from db.models import AuditReport

    empty = tmp_path / "empty_stubs"
    empty.mkdir()
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(empty))

    protocol_id, _ = seed_protocol
    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-fallback",
    )

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.scope_extraction_status == "success"
    assert sorted(row.scope_contracts) == ["Pool", "Registry", "Strategy", "Vault"]

    import json as _json

    payload = _json.loads(storage_bucket.get(row.scope_storage_key))
    assert payload["method"] == "regex_fallback"


def test_stale_scope_rows_are_recovered(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
):
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-stale",
    )

    row = db_session.get(AuditReport, audit_id)
    assert row is not None
    row.scope_extraction_status = "processing"
    row.scope_extraction_worker = "ghost-worker"
    row.scope_extraction_started_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    worker._recover_stale_rows(db_session)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.scope_extraction_status is None
    assert row.scope_extraction_worker is None
    assert row.scope_extraction_started_at is None

    claimed = worker._claim_batch(db_session)
    assert audit_id in {a.id for a in claimed}


def test_api_audit_scope_returns_contracts_after_extraction(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    protocol_id, _ = seed_protocol
    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="cantina_urls.txt",
        auditor="Cantina",
        title="Example Protocol Cantina",
        text_sha256="sha-cantina",
    )

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    r = api_with_storage.get(f"/api/audits/{audit_id}/scope")
    assert r.status_code == 200
    body = r.json()
    assert body["audit_id"] == audit_id
    assert body["auditor"] == "Cantina"
    assert sorted(body["contracts"]) == ["Pool", "Registry", "Strategy", "Vault"]
    assert body["scope_extracted_at"] is not None


def test_api_audit_scope_returns_409_when_not_extracted(
    db_session,
    storage_bucket,
    seed_protocol,
    api_with_storage,
):
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    ar = AuditReport(
        protocol_id=protocol_id,
        url="https://example.com/pending.pdf",
        pdf_url="https://example.com/pending.pdf",
        auditor="X",
        title="Pending",
        confidence=0.9,
    )
    db_session.add(ar)
    db_session.commit()

    r = api_with_storage.get(f"/api/audits/{ar.id}/scope")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["error"] == "scope not available"
    assert detail["status"] is None


def test_api_audit_coverage_joins_inventory_to_audits(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    from db.models import Contract

    protocol_id, protocol_name = seed_protocol

    db_session.add_all(
        [
            Contract(
                protocol_id=protocol_id,
                address="0x" + "1" * 40,
                contract_name="Pool",
                chain="ethereum",
            ),
            Contract(
                protocol_id=protocol_id,
                address="0x" + "2" * 40,
                contract_name="Vault",
                chain="ethereum",
            ),
            Contract(
                protocol_id=protocol_id,
                address="0x" + "3" * 40,
                contract_name="NotAudited",
                chain="ethereum",
            ),
        ]
    )
    db_session.commit()

    # The most recent audit wins last_audit.
    old_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        auditor="OldFirm",
        title="Old Review",
        date="2023-06-01",
        text_sha256="sha-old",
    )
    new_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="cantina_urls.txt",
        auditor="NewFirm",
        title="New Review",
        date="2024-12-01",
        text_sha256="sha-new",
    )

    for _ in range(2):
        claimed = worker._claim_batch(db_session)
        for ar in claimed:
            _, outcome = worker._process_row(ar)
            worker._persist_outcome(ar.id, outcome)

    from db.models import AuditReport as _AR

    db_session.expire_all()
    for aid in (old_id, new_id):
        row = db_session.get(_AR, aid)
        assert row.scope_extraction_status == "success", (
            f"row {aid} status={row.scope_extraction_status} err={row.scope_extraction_error}"
        )

    r = api_with_storage.get(f"/api/company/{protocol_name}/audit_coverage")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["contract_count"] == 3
    assert body["audit_count"] == 2

    by_name = {c["contract_name"]: c for c in body["coverage"]}
    assert set(by_name) == {"Pool", "Vault", "NotAudited"}

    assert by_name["Pool"]["audit_count"] == 2
    assert by_name["Pool"]["last_audit"]["auditor"] == "NewFirm"
    assert by_name["Pool"]["last_audit"]["date"] == "2024-12-01"
    assert by_name["Vault"]["audit_count"] == 2
    assert by_name["Vault"]["last_audit"]["auditor"] == "NewFirm"

    assert by_name["NotAudited"]["audit_count"] == 0
    assert by_name["NotAudited"]["last_audit"] is None


@pytest.fixture()
def make_fresh_worker(monkeypatch):
    """The caching contract must rely on DB state, not worker-local caches."""
    from unittest.mock import patch

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import workers.audit_scope_extraction as worker_mod
    from tests.conftest import DATABASE_URL

    test_engine = create_engine(DATABASE_URL)
    test_session_factory = sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(worker_mod, "SessionLocal", test_session_factory)

    made: list = []

    def _make():
        with patch("signal.signal"):
            w = worker_mod.AuditScopeExtractionWorker()
        made.append(w)
        return w

    try:
        yield _make
    finally:
        test_engine.dispose()


@pytest.fixture()
def llm_call_counter(monkeypatch):
    counter = {"calls": 0}
    # Patching the package re-export wouldn't intercept calls from inside ``_llm``.
    import services.audits.scope_extraction._llm as llm_mod

    real = llm_mod._call_llm

    def counting_call(prompt):
        counter["calls"] += 1
        return real(prompt)

    monkeypatch.setattr(llm_mod, "_call_llm", counting_call)
    return counter


def _drive(worker, db_session) -> list[int]:
    claimed = worker._claim_batch(db_session)
    processed: list[int] = []
    for ar in claimed:
        _, outcome = worker._process_row(ar)
        worker._persist_outcome(ar.id, outcome)
        processed.append(ar.id)
    return processed


def test_terminal_status_rows_not_reclaimed_across_worker_restart(
    db_session,
    storage_bucket,
    seed_protocol,
    make_fresh_worker,
    llm_stub_dir,
):
    """DB status is the primary cache."""
    from db.models import AuditReport

    protocol_id, _ = seed_protocol

    success_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-success",
        url="https://example.com/already-success.pdf",
    )
    failed_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-failed",
        url="https://example.com/already-failed.pdf",
    )
    skipped_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-skipped",
        url="https://example.com/already-skipped.pdf",
    )
    pending_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-pending",
        url="https://example.com/pending-row.pdf",
    )

    for aid, status in (
        (success_id, "success"),
        (failed_id, "failed"),
        (skipped_id, "skipped"),
    ):
        row = db_session.get(AuditReport, aid)
        assert row is not None
        row.scope_extraction_status = status
        row.scope_contracts = ["Preset"] if status == "success" else None
        if status == "success":
            row.scope_storage_key = f"audits/scope/{aid}.json"
        elif status == "failed":
            row.scope_extraction_error = "preset failure"
    db_session.commit()

    w1 = make_fresh_worker()
    w2 = make_fresh_worker()
    assert w1.worker_id != w2.worker_id, "fresh workers should have distinct ids"

    processed_w1 = _drive(w1, db_session)
    processed_w2 = _drive(w2, db_session)

    all_processed = processed_w1 + processed_w2
    assert all_processed == [pending_id], f"only the pending row should be processed, got {all_processed}"

    db_session.expire_all()
    assert db_session.get(AuditReport, success_id).scope_extraction_status == "success"
    assert db_session.get(AuditReport, success_id).scope_contracts == ["Preset"]
    assert db_session.get(AuditReport, failed_id).scope_extraction_status == "failed"
    assert db_session.get(AuditReport, failed_id).scope_extraction_error == "preset failure"
    assert db_session.get(AuditReport, skipped_id).scope_extraction_status == "skipped"


def test_llm_not_called_again_for_already_scoped_row(
    db_session,
    storage_bucket,
    seed_protocol,
    make_fresh_worker,
    llm_stub_dir,
    llm_call_counter,
):
    """Guards against a loosened claim predicate."""
    protocol_id, _ = seed_protocol

    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-one-shot",
    )

    w1 = make_fresh_worker()
    assert _drive(w1, db_session) == [audit_id]
    assert llm_call_counter["calls"] == 1

    w2 = make_fresh_worker()
    assert _drive(w2, db_session) == []
    assert llm_call_counter["calls"] == 1, "LLM was called a second time on an already-scoped row"


def test_content_hash_cache_survives_worker_restart(
    db_session,
    storage_bucket,
    seed_protocol,
    make_fresh_worker,
    llm_stub_dir,
    llm_call_counter,
):
    from db.models import AuditReport
    from workers.audit_scope_extraction import _CacheCopyOutcome

    protocol_id, _ = seed_protocol
    shared_sha = "sha-shared-across-workers"

    id_a = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256=shared_sha,
        url="https://example.com/a.pdf",
    )
    w1 = make_fresh_worker()
    assert _drive(w1, db_session) == [id_a]
    assert llm_call_counter["calls"] == 1

    id_b = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256=shared_sha,
        url="https://example.com/b.pdf",
    )
    w2 = make_fresh_worker()
    claimed = w2._claim_batch(db_session)
    assert {a.id for a in claimed} == {id_b}, f"W2 should claim only the new row; got {[a.id for a in claimed]}"
    b_row = next(a for a in claimed if a.id == id_b)
    _, result_b = w2._process_row(b_row)
    assert isinstance(result_b, _CacheCopyOutcome), "Expected cache-copy outcome when a sibling's sha matches"
    assert result_b.sibling_id == id_a
    w2._persist_outcome(id_b, result_b)

    assert llm_call_counter["calls"] == 1, "Cache-copy should not trigger an LLM call"

    db_session.expire_all()
    row_a = db_session.get(AuditReport, id_a)
    row_b = db_session.get(AuditReport, id_b)
    assert row_b.scope_extraction_status == "success"
    assert row_b.scope_contracts == row_a.scope_contracts
    assert row_b.scope_storage_key == row_a.scope_storage_key


def test_reextract_endpoint_makes_row_eligible_again(
    db_session,
    storage_bucket,
    seed_protocol,
    make_fresh_worker,
    llm_stub_dir,
    llm_call_counter,
    api_with_storage,
):
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-reextract",
    )

    w1 = make_fresh_worker()
    _drive(w1, db_session)
    assert llm_call_counter["calls"] == 1
    db_session.expire_all()
    assert db_session.get(AuditReport, audit_id).scope_extraction_status == "success"

    r = api_with_storage.post(f"/api/audits/{audit_id}/reextract_scope")
    assert r.status_code == 200, r.text
    assert r.json()["reset"] is True

    db_session.expire_all()
    reset_row = db_session.get(AuditReport, audit_id)
    assert reset_row.scope_extraction_status is None
    assert reset_row.scope_extraction_error is None

    w2 = make_fresh_worker()
    assert _drive(w2, db_session) == [audit_id]
    assert llm_call_counter["calls"] == 2, "Re-extract should trigger a fresh LLM call"
    db_session.expire_all()
    assert db_session.get(AuditReport, audit_id).scope_extraction_status == "success"


def test_scope_worker_refresh_coverage_writes_pending_for_verify_worker(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
    llm_stub_dir,
    monkeypatch,
):
    """Inline verify caused Etherscan rate-limit cascades (#82), so the scope worker only writes 'pending'.

    The deferred half is in ``test_coverage_verify_worker.py``.
    """
    from db.models import AuditContractCoverage, AuditReport, Contract

    protocol_id, _ = seed_protocol

    impl = Contract(
        protocol_id=protocol_id,
        address="0x" + "d" * 40,
        contract_name="Pool",
        chain="ethereum",
        is_proxy=False,
    )
    db_session.add(impl)
    db_session.commit()

    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        auditor="Spearbit",
        title="Pre-Deployment Review",
        date="2026-02-01",
        text_sha256="sha-scope-se",
    )

    audit = db_session.get(AuditReport, audit_id)
    audit.reviewed_commits = ["abc123def456"]
    audit.source_repo = "example/protocol"
    db_session.commit()

    # The verify worker does the network; any HTTP here is loud.
    import services.audits.source_equivalence as se_mod

    def boom_etherscan(_addr):
        raise AssertionError("scope worker called etherscan inline (#82 regression)")

    def boom_github(*_a, **_k):
        raise AssertionError("scope worker called github inline (#82 regression)")

    monkeypatch.setattr(se_mod, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(se_mod, "fetch_github_source_hash", boom_github)

    claimed = worker._claim_batch(db_session)
    audit_obj = next(a for a in claimed if a.id == audit_id)
    _, outcome = worker._process_row(audit_obj)
    worker._persist_outcome(audit_id, outcome)

    db_session.expire_all()
    row = db_session.get(AuditReport, audit_id)
    assert row.scope_extraction_status == "success", (
        f"scope extraction didn't complete: err={row.scope_extraction_error!r}"
    )

    cov = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit_id, contract_id=impl.id).one()
    assert cov.match_type == "direct"
    assert cov.equivalence_status == "pending"
