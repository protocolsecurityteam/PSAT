"""End-to-end integration tests for the audit scope-extraction pipeline.

Drives the full stack against real infrastructure:
    - real PostgreSQL (TEST_DATABASE_URL)
    - real S3-compatible object storage (TEST_ARTIFACT_STORAGE_*)
    - FastAPI via TestClient
    - LLM responses stubbed via ``PSAT_LLM_STUB_DIR`` → fixture files

Each test seeds an ``AuditReport`` row with ``text_extraction_status='success'``
and manually uploads a per-auditor text fixture to the same storage key
the text-extraction worker would use. The scope worker's
``_claim_batch`` / ``_process_row`` / ``_persist_outcome`` are driven
directly rather than through the infinite poll loop so tests finish
quickly and deterministically.

Gated by ``requires_postgres + requires_storage`` so a dev box without
docker running will skip cleanly.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import SessionFactory, requires_postgres, requires_storage  # noqa: E402

pytestmark = [
    requires_postgres,
    requires_storage,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


# ---------------------------------------------------------------------------
# Fixture paths + LLM stub wiring
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "scope_extraction"
AUDITS_DIR = FIXTURE_DIR / "audits"
STUB_DIR = FIXTURE_DIR / "llm_responses"


@pytest.fixture()
def llm_stub_dir(monkeypatch, tmp_path):
    """Copy the committed stub fixtures into a tmp dir and point the env at it.

    The ``_default.json`` response resolves to
    ``["Pool","Vault","Strategy","Registry"]`` — every committed audit
    fixture mentions all four, so validation passes for the happy path
    without having to precompute a prompt digest per test.
    """
    committed = STUB_DIR / "_default.json"
    assert committed.exists(), f"missing fixture: {committed}"
    (tmp_path / "_default.json").write_text(committed.read_text())
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))
    return tmp_path


def _fixture_text(name: str) -> str:
    path = AUDITS_DIR / name
    assert path.exists(), f"missing audit fixture: {path}"
    return path.read_text()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


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
    """Insert an AuditReport with text_extraction='success' + fixture body in storage."""
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
    # Write the text blob under the deterministic key the worker reads from.
    ar.text_storage_key = audit_text_key(audit_id)
    db_session.commit()
    storage_bucket.put(
        audit_text_key(audit_id),
        body,
        "text/plain; charset=utf-8",
    )
    return audit_id


@pytest.fixture()
def worker(monkeypatch):
    """Construct the scope worker with SessionLocal rebound to the test DB."""
    from unittest.mock import patch

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import workers.audit_scope_extraction as worker_mod
    from tests.conftest import DATABASE_URL

    test_engine = create_engine(DATABASE_URL)
    test_session_factory = sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(worker_mod, "SessionLocal", test_session_factory)

    with patch("signal.signal"):
        w = worker_mod.AuditScopeExtractionWorker()
    try:
        yield w
    finally:
        test_engine.dispose()


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


# ---------------------------------------------------------------------------
# 1. Happy path — Spearbit markdown-table fixture
# ---------------------------------------------------------------------------


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
    # Discovery-time date was null — worker should have backfilled from the
    # fixture's "Delivered: 19 December 2024" title line.
    assert row.date == "2024-12-19"

    # Artifact really exists in storage, parses as valid JSON.
    import json as _json

    body = storage_bucket.get(row.scope_storage_key)
    payload = _json.loads(body)
    assert payload["contracts"] == list(row.scope_contracts)
    assert payload["method"] == "llm"
    assert payload["prompt_version"]


# ---------------------------------------------------------------------------
# 2. Content-hash cache hit — second row clones without an LLM call
# ---------------------------------------------------------------------------


def test_content_hash_cache_copies_scope_to_sibling(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
    llm_stub_dir,
):
    from db.models import AuditReport

    protocol_id, _ = seed_protocol

    # Same PDF, two mirrors. Seed A first and let it finish extraction
    # *before* B even exists — that's the realistic ordering (Solodit
    # discovers first, a GitHub mirror surfaces later) and also keeps the
    # first ``_claim_batch`` from scooping both rows into 'processing'
    # before we can drive them one at a time.
    sha = "sha-identical-mirror"
    id_a = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256=sha,
        url="https://example.com/solodit-copy.pdf",
    )

    claimed = worker._claim_batch(db_session)
    assert {a.id for a in claimed} == {id_a}
    a_row = next(a for a in claimed if a.id == id_a)
    _, outcome_a = worker._process_row(a_row)
    worker._persist_outcome(id_a, outcome_a)

    # A is 'success'. Now seed B with the same text_sha256 and break the
    # LLM stub — if B doesn't hit the content-hash cache the extraction
    # would raise, so a successful cache-copy is the only path.
    id_b = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256=sha,
        url="https://example.com/github-copy.pdf",
    )
    (llm_stub_dir / "_default.json").unlink()

    from workers.audit_scope_extraction import _CacheCopyOutcome

    claimed = worker._claim_batch(db_session)
    assert {a.id for a in claimed} == {id_b}
    b_row = next(a for a in claimed if a.id == id_b)
    _, result_b = worker._process_row(b_row)
    assert isinstance(result_b, _CacheCopyOutcome), f"expected cache copy, got {result_b!r}"
    assert result_b.sibling_id == id_a
    worker._persist_outcome(id_b, result_b)

    db_session.expire_all()
    row_b = db_session.get(AuditReport, id_b)
    row_a = db_session.get(AuditReport, id_a)
    assert row_b.scope_extraction_status == "success"
    assert row_b.scope_contracts == row_a.scope_contracts
    assert row_b.scope_storage_key == row_a.scope_storage_key


# ---------------------------------------------------------------------------
# 3. Degenerate fixture — no scope section header → skipped
# ---------------------------------------------------------------------------


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
    # With the header + content-pattern + chunk-scan pipeline the error
    # surface changed; all three layers having to come up empty is the
    # right signal that no scope could be extracted.
    assert "no scope section found" in row.scope_extraction_error
    assert row.scope_contracts is None or row.scope_contracts == []
    assert row.scope_storage_key is None


# ---------------------------------------------------------------------------
# 4. LLM failure → regex fallback still populates scope_contracts
# ---------------------------------------------------------------------------


def test_worker_falls_back_to_regex_when_llm_fails(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
    monkeypatch,
    tmp_path,
):
    from db.models import AuditReport

    # Point PSAT_LLM_STUB_DIR at an EMPTY dir — every lookup raises.
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
    # Regex picks up Pool, Vault, Strategy, Registry from the *.sol refs.
    assert sorted(row.scope_contracts) == ["Pool", "Registry", "Strategy", "Vault"]

    import json as _json

    payload = _json.loads(storage_bucket.get(row.scope_storage_key))
    assert payload["method"] == "regex_fallback"


# ---------------------------------------------------------------------------
# 5. Stale-row recovery
# ---------------------------------------------------------------------------


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

    # Park in processing with an old timestamp.
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


# ---------------------------------------------------------------------------
# 6. API — GET /api/audits/{id}/scope
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 7. API — GET /api/company/{name}/audit_coverage (the headline query)
# ---------------------------------------------------------------------------


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

    # Seed inventory contracts.
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

    # Seed two audits — both cover Pool + Vault via the default stub
    # response, with different dates. The most recent should win
    # last_audit.
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

    # Drive both through the worker.
    for _ in range(2):
        claimed = worker._claim_batch(db_session)
        for ar in claimed:
            _, outcome = worker._process_row(ar)
            worker._persist_outcome(ar.id, outcome)

    # Verify both extractions succeeded before hitting the endpoint.
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

    # Pool + Vault are in both audits → audit_count=2; last_audit is the
    # newest one (NewFirm, 2024-12-01).
    assert by_name["Pool"]["audit_count"] == 2
    assert by_name["Pool"]["last_audit"]["auditor"] == "NewFirm"
    assert by_name["Pool"]["last_audit"]["date"] == "2024-12-01"
    assert by_name["Vault"]["audit_count"] == 2
    assert by_name["Vault"]["last_audit"]["auditor"] == "NewFirm"

    # NotAudited → no matches.
    assert by_name["NotAudited"]["audit_count"] == 0
    assert by_name["NotAudited"]["last_audit"] is None


# ---------------------------------------------------------------------------
# 8. Idempotency across worker restarts — the caching contract
# ---------------------------------------------------------------------------


@pytest.fixture()
def make_fresh_worker(monkeypatch):
    """Factory that builds independent worker instances.

    Simulates a process restart: each call produces a brand-new
    AuditScopeExtractionWorker with its own worker_id and (importantly)
    no in-memory state from a prior run. The caching contract should
    rely entirely on DB state, not worker-local caches.
    """
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
    """Wrap services.audits.scope_extraction._llm._call_llm with a counter.

    Lets tests assert exactly how many LLM calls happened across a
    sequence of worker runs — the surest way to prove the cache
    short-circuited re-processing.
    """
    counter = {"calls": 0}
    # Patch ``_call_llm`` at its source (``_llm`` submodule) — patching the
    # package-level re-export wouldn't intercept calls from inside ``_llm``.
    import services.audits.scope_extraction._llm as llm_mod

    real = llm_mod._call_llm

    def counting_call(prompt):
        counter["calls"] += 1
        return real(prompt)

    monkeypatch.setattr(llm_mod, "_call_llm", counting_call)
    return counter


def _drive(worker, db_session) -> list[int]:
    """Claim + process + persist one batch; return the ids that got processed."""
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
    """Rows in any terminal state (success / failed / skipped) stay out of
    the claim query across worker restarts. The DB row-level status *is*
    the primary cache; no worker should ever re-touch a finished audit
    unless someone explicitly resets it."""
    from db.models import AuditReport

    protocol_id, _ = seed_protocol

    # Pre-populate three rows in distinct terminal states + one pending.
    # Distinct URLs per row so the (protocol_id, url) unique key isn't
    # violated.
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

    # Mark three as terminal with explicit state, as if a prior worker run
    # had already processed them.
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

    # Spawn two independent workers (simulating restarts) and let each
    # claim once. Only the pending row should ever get claimed — and only
    # once, across both workers combined.
    w1 = make_fresh_worker()
    w2 = make_fresh_worker()
    assert w1.worker_id != w2.worker_id, "fresh workers should have distinct ids"

    processed_w1 = _drive(w1, db_session)
    processed_w2 = _drive(w2, db_session)

    all_processed = processed_w1 + processed_w2
    assert all_processed == [pending_id], f"only the pending row should be processed, got {all_processed}"

    # Confirm the terminal rows were not touched.
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
    """An end-to-end idempotency assertion: after a row completes, restart
    the worker and confirm the LLM is not invoked a second time on the
    same audit. Guards against regressions where someone accidentally
    loosens the claim predicate."""
    protocol_id, _ = seed_protocol

    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-one-shot",
    )

    # Run 1: row is NULL, worker claims + processes. Expect exactly 1 LLM call.
    w1 = make_fresh_worker()
    assert _drive(w1, db_session) == [audit_id]
    assert llm_call_counter["calls"] == 1

    # Run 2: fresh worker, no other pending rows. Should claim nothing
    # and make no LLM calls.
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
    """Cache hit via text_sha256 works even when the sibling was processed
    by a different worker instance. The cache is pure DB state — no
    in-memory worker caching — so restart should be a no-op."""
    from db.models import AuditReport
    from workers.audit_scope_extraction import _CacheCopyOutcome

    protocol_id, _ = seed_protocol
    shared_sha = "sha-shared-across-workers"

    # Process audit A with worker W1.
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

    # Seed audit B with matching text_sha256 only NOW — after A has
    # finished. Spin up a brand-new worker W2, claim B. The content-hash
    # cache should short-circuit the LLM.
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

    # LLM count unchanged — cache did its job across the restart.
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
    """The admin re-extract endpoint is the designed way to force a
    re-run. Confirm it resets the row back to NULL and that a subsequent
    worker cycle picks it up and calls the LLM again."""
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    audit_id = _seed_scoped_row(
        db_session,
        storage_bucket,
        protocol_id,
        fixture="spearbit_table.txt",
        text_sha256="sha-reextract",
    )

    # Initial processing — 1 LLM call.
    w1 = make_fresh_worker()
    _drive(w1, db_session)
    assert llm_call_counter["calls"] == 1
    db_session.expire_all()
    assert db_session.get(AuditReport, audit_id).scope_extraction_status == "success"

    # Hit the admin endpoint to reset.
    r = api_with_storage.post(f"/api/audits/{audit_id}/reextract_scope")
    assert r.status_code == 200, r.text
    assert r.json()["reset"] is True

    # The row is now NULL again. A fresh worker should re-claim and
    # re-run the LLM.
    db_session.expire_all()
    reset_row = db_session.get(AuditReport, audit_id)
    assert reset_row.scope_extraction_status is None
    assert reset_row.scope_extraction_error is None

    w2 = make_fresh_worker()
    assert _drive(w2, db_session) == [audit_id]
    assert llm_call_counter["calls"] == 2, "Re-extract should trigger a fresh LLM call"
    db_session.expire_all()
    assert db_session.get(AuditReport, audit_id).scope_extraction_status == "success"


# ---------------------------------------------------------------------------
# 9. Regression — scope worker's inline coverage refresh runs source-equivalence
# ---------------------------------------------------------------------------


def test_scope_worker_refresh_coverage_writes_pending_for_verify_worker(
    db_session,
    storage_bucket,
    seed_protocol,
    worker,
    llm_stub_dir,
    monkeypatch,
):
    """Regression follow-up: the scope worker no longer runs source-
    equivalence inline (#82 — inline verify caused Etherscan rate-limit
    cascades that blocked every other worker). Instead the worker writes
    coverage rows with ``equivalence_status='pending'`` so the
    ``CoverageVerifyWorker`` can drain them at a controlled rate.

    The end-state for "LiquidityPool shows no audit coverage" is still
    correct — once the verify worker drains the pending row, it lands
    at ``match_type='reviewed_commit'`` exactly like the inline path
    used to. This test pins the synchronous half (pending status,
    no inline HTTP); the deferred verify path is covered by
    ``test_coverage_verify_worker.py``.
    """
    from db.models import AuditContractCoverage, AuditReport, Contract

    protocol_id, _ = seed_protocol

    # Seed a concrete, non-proxy impl Contract whose name the fixture's
    # scope will match.
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

    # Pre-populate reviewed_commits + source_repo on the audit row.
    audit = db_session.get(AuditReport, audit_id)
    audit.reviewed_commits = ["abc123def456"]
    audit.source_repo = "example/protocol"
    db_session.commit()

    # The scope worker MUST NOT touch the network on its own — the
    # verify worker does that asynchronously. Make any HTTP call loud.
    import services.audits.source_equivalence as se_mod

    def boom_etherscan(_addr):
        raise AssertionError("scope worker called etherscan inline (#82 regression)")

    def boom_github(*_a, **_k):
        raise AssertionError("scope worker called github inline (#82 regression)")

    monkeypatch.setattr(se_mod, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(se_mod, "fetch_github_source_hash", boom_github)

    # Drive the scope worker the same way the existing tests do.
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
    # Heuristic match still emitted synchronously…
    assert cov.match_type == "direct"
    # …with verification deferred to the CoverageVerifyWorker.
    assert cov.equivalence_status == "pending"
