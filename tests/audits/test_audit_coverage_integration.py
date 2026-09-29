"""End-to-end audit-coverage pipeline against real infra: PostgreSQL (TEST_DATABASE_URL), S3-compatible
storage (TEST_ARTIFACT_STORAGE_*), LLM stubbed via PSAT_LLM_STUB_DIR. Seed: proxy with 3 impl eras
(A -> B -> A) plus a standalone contract; three audits straddle the upgrades. The scope worker is driven
directly (not the poll loop) for determinism. Skips cleanly when docker isn't running.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.conftest import SessionFactory, requires_postgres, requires_storage
from tests.support.audit_coverage_builders import (
    _add_audit,
    _add_contract,
    _stub_get_code,
    seed_protocol,  # noqa: F401  (fixture, registered by import)
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


# ---------------------------------------------------------------------------
# Re-use the scope-extraction fixtures + worker plumbing
# ---------------------------------------------------------------------------


@pytest.fixture()
def llm_stub_dir(monkeypatch, tmp_path):
    """Committed ``_default.json`` stub returns Pool/Vault/Strategy/Registry; every audit fixture mentions Pool +
    Vault.
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


@pytest.fixture()
def worker(monkeypatch):
    """Scope worker bound to the test DB (SessionLocal swapped so worker sessions see fixture data)."""
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
# Protocol + history seeding
# ---------------------------------------------------------------------------


def _ts(year: int, month: int = 1, day: int = 1) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


@pytest.fixture()
def seed_protocol_with_history(db_session):
    """Proxy (-> impl_a) with impl_a "Pool" active [100,200)+[300,None), impl_b "PoolV2" [200,300), standalone "Vault".
    Returns a dict of the pieces.
    """
    from db.models import AuditContractCoverage, AuditReport, Contract, Protocol, UpgradeEvent

    name = f"cov-int-{uuid.uuid4().hex[:12]}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id

    proxy = Contract(
        protocol_id=protocol_id,
        address="0x" + "1" * 40,
        contract_name="PoolProxy",
        is_proxy=True,
        implementation="0x" + "a" * 40,  # current: impl_a
        chain="ethereum",
    )
    impl_a = Contract(
        protocol_id=protocol_id,
        address="0x" + "a" * 40,
        contract_name="Pool",  # matches default stub scope
        chain="ethereum",
    )
    impl_b = Contract(
        protocol_id=protocol_id,
        address="0x" + "b" * 40,
        contract_name="PoolV2",
        chain="ethereum",
    )
    standalone = Contract(
        protocol_id=protocol_id,
        address="0x" + "2" * 40,
        contract_name="Vault",  # also in default stub scope
        chain="ethereum",
    )
    db_session.add_all([proxy, impl_a, impl_b, standalone])
    db_session.commit()

    # Three events -> impl_a windows [100,200) + [300,None), impl_b [200,300).
    for ts, block, new_impl, old_impl in [
        (_ts(2023, 6, 1), 100, impl_a.address, None),
        (_ts(2024, 3, 1), 200, impl_b.address, impl_a.address),
        (_ts(2024, 9, 1), 300, impl_a.address, impl_b.address),
    ]:
        db_session.add(
            UpgradeEvent(
                contract_id=proxy.id,
                proxy_address=proxy.address,
                old_impl=old_impl,
                new_impl=new_impl,
                block_number=block,
                timestamp=ts,
                tx_hash=f"0x{uuid.uuid4().hex[:64]}",
            )
        )
    db_session.commit()

    try:
        yield {
            "proxy": proxy,
            "impl_a": impl_a,
            "impl_b": impl_b,
            "standalone": standalone,
            "protocol_id": protocol_id,
            "protocol_name": name,
        }
    finally:
        db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
        contract_ids = [c.id for c in db_session.query(Contract).filter_by(protocol_id=protocol_id).all()]
        if contract_ids:
            db_session.query(UpgradeEvent).filter(UpgradeEvent.contract_id.in_(contract_ids)).delete(
                synchronize_session=False
            )
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _seed_scoped_audit(
    db_session,
    storage_bucket,
    protocol_id: int,
    *,
    fixture: str,
    auditor: str,
    title: str,
    date: str | None,
    text_sha256: str | None = None,
) -> int:
    """Insert an AuditReport with text_extraction='success' + fixture body in storage."""
    from db.models import AuditReport
    from services.audits.text_extraction import audit_text_key

    body = _fixture_text(fixture).encode("utf-8")
    ar = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        pdf_url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor=auditor,
        title=title,
        date=date,
        confidence=0.9,
        text_extraction_status="success",
        text_size_bytes=len(body),
        text_sha256=text_sha256 or f"sha-{fixture}-{uuid.uuid4().hex[:8]}",
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


def _drive_worker(worker, db_session) -> None:
    claimed = worker._claim_batch(db_session)
    for ar in claimed:
        _, outcome = worker._process_row(ar)
        worker._persist_outcome(ar.id, outcome)


# ---------------------------------------------------------------------------
# 1. Scope worker triggers coverage population
# ---------------------------------------------------------------------------


def test_scope_worker_populates_coverage_for_proxy_and_standalone(
    db_session, storage_bucket, seed_protocol_with_history, worker, llm_stub_dir
):
    """An audit inside impl_a's [300,None) window yields an impl_era row on Pool and a direct row on Vault, populated
    by the worker's _persist_outcome (no manual upsert).
    """
    from db.models import AuditContractCoverage

    proto = seed_protocol_with_history
    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="Spearbit",
        title="Post-upgrade audit",
        date="2024-10-15",
    )

    _drive_worker(worker, db_session)

    db_session.expire_all()
    rows = (
        db_session.query(AuditContractCoverage)
        .filter_by(protocol_id=proto["protocol_id"])
        .order_by(AuditContractCoverage.contract_id)
        .all()
    )
    # The default LLM stub returns ['Pool','Vault','Strategy','Registry'].
    # Only Pool (impl_a) + Vault (standalone) are in the inventory.
    by_contract = {r.contract_id: r for r in rows}
    assert set(by_contract) == {proto["impl_a"].id, proto["standalone"].id}

    pool_row = by_contract[proto["impl_a"].id]
    assert pool_row.match_type == "impl_era"
    assert pool_row.match_confidence == "high"
    assert pool_row.covered_from_block == 300
    assert pool_row.covered_to_block is None
    assert pool_row.matched_name == "Pool"

    vault_row = by_contract[proto["standalone"].id]
    assert vault_row.match_type == "direct"
    assert vault_row.match_confidence == "high"
    assert vault_row.covered_from_block is None


def test_audits_straddling_upgrades_map_to_distinct_windows(
    db_session, storage_bucket, seed_protocol_with_history, worker, llm_stub_dir
):
    """Per-audit window selection for impl_a. The LLM stub always says Pool + Vault regardless of date, so the middle
    audit names Pool too.
    """
    from db.models import AuditContractCoverage

    proto = seed_protocol_with_history

    a1 = _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="Early",
        title="Era A1",
        date="2023-09-01",
        text_sha256=f"sha-a1-{uuid.uuid4().hex[:8]}",
    )
    a2 = _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="cantina_urls.txt",
        auditor="Middle",
        title="Era B",
        date="2024-05-01",
        text_sha256=f"sha-a2-{uuid.uuid4().hex[:8]}",
    )
    a3 = _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="certora_lines.txt",
        auditor="Late",
        title="Era A2",
        date="2025-01-01",
        text_sha256=f"sha-a3-{uuid.uuid4().hex[:8]}",
    )

    for _ in range(3):
        _drive_worker(worker, db_session)

    db_session.expire_all()
    rows_by_audit = {}
    for r in db_session.query(AuditContractCoverage).filter_by(contract_id=proto["impl_a"].id).all():
        rows_by_audit.setdefault(r.audit_report_id, r)

    assert set(rows_by_audit) == {a1, a2, a3}

    early = rows_by_audit[a1]
    middle = rows_by_audit[a2]
    late = rows_by_audit[a3]

    assert (early.covered_from_block, early.covered_to_block) == (100, 200)
    # Middle — 2024-05-01, falls in impl_b's [200,300) window. On
    # impl_a it's outside every window → confidence 'low', nearest
    # window is [100,200) (closer) or [300,None) (further).
    assert middle.match_confidence == "low"
    assert (late.covered_from_block, late.covered_to_block) == (300, None)
    assert late.match_confidence == "high"


def test_reextraction_updates_coverage(db_session, storage_bucket, seed_protocol_with_history, worker, llm_stub_dir):
    """Re-extraction changing scope_contracts pivots coverage rows (no live /reextract_scope call)."""
    from db.models import AuditContractCoverage, AuditReport

    proto = seed_protocol_with_history
    audit_id = _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="Spearbit",
        title="Original",
        date="2024-10-15",
    )
    _drive_worker(worker, db_session)

    db_session.expire_all()
    initial = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit_id).all()
    assert {r.contract_id for r in initial} == {
        proto["impl_a"].id,
        proto["standalone"].id,
    }

    from services.audits.coverage import upsert_coverage_for_audit

    ar = db_session.get(AuditReport, audit_id)
    ar.scope_contracts = ["Vault"]
    db_session.commit()
    upsert_coverage_for_audit(db_session, audit_id)
    db_session.commit()

    db_session.expire_all()
    after = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit_id).all()
    assert {r.contract_id for r in after} == {proto["standalone"].id}


# ---------------------------------------------------------------------------
# 2. refresh_coverage admin endpoint
# ---------------------------------------------------------------------------


def test_refresh_coverage_endpoint_backfills(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    """Wipe coverage, hit the admin refresh endpoint: rows reappear (backfill path)."""
    from db.models import AuditContractCoverage

    proto = seed_protocol_with_history
    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="X",
        title="T",
        date="2024-10-01",
    )
    _drive_worker(worker, db_session)

    db_session.query(AuditContractCoverage).filter_by(protocol_id=proto["protocol_id"]).delete()
    db_session.commit()

    r = api_with_storage.post(f"/api/company/{proto['protocol_name']}/refresh_coverage")
    assert r.status_code == 200
    body = r.json()
    assert body["company"] == proto["protocol_name"]
    assert body["coverage_rows"] == 2  # Pool + Vault

    rows = db_session.query(AuditContractCoverage).filter_by(protocol_id=proto["protocol_id"]).all()
    assert len(rows) == 2


def test_refresh_coverage_unknown_company_404(db_session, storage_bucket, api_with_storage):
    r = api_with_storage.post("/api/company/nonexistent/refresh_coverage")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# 3. API — GET /api/company/{name}/audit_coverage reads the new table
# ---------------------------------------------------------------------------


def test_audit_coverage_endpoint_uses_coverage_table(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    """Surfaces match_type, match_confidence, covered_from/to_block; an unrelated contract has audit_count=0."""
    from db.models import Contract

    proto = seed_protocol_with_history

    db_session.add(
        Contract(
            protocol_id=proto["protocol_id"],
            address="0x" + "f" * 40,
            contract_name="NotAudited",
            chain="ethereum",
        )
    )
    # Inventory-only entry: discovered but never analyzed, no Etherscan
    # name, no audits. Should NOT appear in the response.
    db_session.add(
        Contract(
            protocol_id=proto["protocol_id"],
            address="0x" + "e" * 40,
            contract_name=None,
            chain="ethereum",
        )
    )
    db_session.commit()

    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="Spearbit",
        title="Covers Pool + Vault",
        date="2024-10-15",
    )
    _drive_worker(worker, db_session)

    r = api_with_storage.get(f"/api/company/{proto['protocol_name']}/audit_coverage")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["audit_count"] == 1

    by_name = {c["contract_name"]: c for c in body["coverage"]}
    pool = by_name["Pool"]
    assert pool["audit_count"] == 1
    la = pool["last_audit"]
    assert la["auditor"] == "Spearbit"
    assert la["match_type"] == "impl_era"
    assert la["match_confidence"] == "high"
    assert la["covered_from_block"] == 300
    assert la["covered_to_block"] is None

    vault = by_name["Vault"]
    assert vault["audit_count"] == 1
    assert vault["last_audit"]["match_type"] == "direct"

    assert by_name["NotAudited"]["audit_count"] == 0
    assert by_name["NotAudited"]["last_audit"] is None

    # Inventory-only entry is filtered out, matching company_overview (never analyzed).
    addresses = {row["address"] for row in body["coverage"]}
    assert "0x" + "e" * 40 not in addresses
    assert body["contract_count"] == len(body["coverage"])

    # Proxy inherits its current impl's coverage: the company view asks "is the code this address runs
    # audited?", driven by Contract.implementation -> impl_a (Pool), not the generic proxy name.
    proxy_row = by_name["PoolProxy"]
    assert proxy_row["audit_count"] == 1
    assert proxy_row["last_audit"]["auditor"] == "Spearbit"
    assert proxy_row["last_audit"]["match_type"] == "impl_era"


def test_audit_coverage_endpoint_reuses_verified_dependency_coverage(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    api_with_storage,
):
    """A contract shared with another protocol inherits only strict verified coverage."""
    from db.models import AuditContractCoverage, AuditReport, Protocol

    proto = seed_protocol_with_history
    dep_protocol = Protocol(name=f"lido-dep-{uuid.uuid4().hex[:8]}")
    db_session.add(dep_protocol)
    db_session.commit()

    dep_contract = proto["standalone"]
    dep_audit = AuditReport(
        protocol_id=dep_protocol.id,
        url=f"https://example.com/lido-{uuid.uuid4().hex}.pdf",
        auditor="LidoAuditor",
        title="Lido Token Review",
        date="2024-11-01",
        confidence=1.0,
        scope_extraction_status="success",
        scope_extracted_at=datetime.now(timezone.utc),
        scope_contracts=["Vault"],
    )
    noisy_audit = AuditReport(
        protocol_id=dep_protocol.id,
        url=f"https://example.com/lido-noisy-{uuid.uuid4().hex}.pdf",
        auditor="NoisyAuditor",
        title="Cited Only Review",
        date="2024-12-01",
        confidence=1.0,
        scope_extraction_status="success",
        scope_extracted_at=datetime.now(timezone.utc),
        scope_contracts=["Vault"],
    )
    db_session.add_all([dep_audit, noisy_audit])
    db_session.commit()

    db_session.add_all(
        [
            AuditContractCoverage(
                contract_id=dep_contract.id,
                audit_report_id=dep_audit.id,
                protocol_id=dep_protocol.id,
                matched_name="Vault",
                match_type="reviewed_commit",
                match_confidence="high",
                equivalence_status="proven",
                proof_kind="clean",
                matched_commit_sha="a" * 40,
            ),
            AuditContractCoverage(
                contract_id=dep_contract.id,
                audit_report_id=noisy_audit.id,
                protocol_id=dep_protocol.id,
                matched_name="Vault",
                match_type="reviewed_commit",
                match_confidence="high",
                equivalence_status="proven",
                proof_kind="cited_only",
                matched_commit_sha="b" * 40,
            ),
        ]
    )
    db_session.commit()

    r = api_with_storage.get(f"/api/company/{proto['protocol_name']}/audit_coverage")
    assert r.status_code == 200, r.text
    body = r.json()

    by_name = {c["contract_name"]: c for c in body["coverage"]}
    vault = by_name["Vault"]
    assert body["audit_count"] == 0  # inherited coverage is not a local audit report.
    assert vault["audit_count"] == 1
    audit = vault["last_audit"]
    assert audit["auditor"] == "LidoAuditor"
    assert audit["match_type"] == "reviewed_commit"
    assert audit["equivalence_status"] == "proven"
    assert audit["coverage_source"] == "inherited"
    assert audit["inherited_from_protocol"] == dep_protocol.name
    assert audit["inherited_contract_address"] == dep_contract.address


# ---------------------------------------------------------------------------
# 4. API — GET /api/contracts/{id}/audit_timeline
# ---------------------------------------------------------------------------


def test_audit_timeline_for_proxy_with_audited_current_impl(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    """Proxy currently points at impl_a; an audit dated inside impl_a's
    open-ended window covers it → current_status='audited'."""
    proto = seed_protocol_with_history
    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="X",
        title="T",
        date="2025-01-01",  # in [300, None)
    )
    _drive_worker(worker, db_session)

    r = api_with_storage.get(f"/api/contracts/{proto['proxy'].id}/audit_timeline")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["contract"]["is_proxy"] is True
    assert body["contract"]["current_implementation"] == proto["impl_a"].address
    assert len(body["impl_windows"]) == 3
    blocks = [(w["from_block"], w["to_block"]) for w in body["impl_windows"]]
    assert blocks == [(100, 200), (200, 300), (300, None)]
    assert body["current_status"] == "audited"
    # Coverage must union in the proxy's historical impls, not just name matches on the proxy
    # (a bare-proxy query once came back empty).
    assert len(body["coverage"]) == 1
    entry = body["coverage"][0]
    assert entry["match_type"] == "impl_era"
    assert entry["covered_from_block"] == 300
    assert entry["covered_to_block"] is None


def test_audit_timeline_flags_unaudited_since_upgrade(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    """Audit covers only impl_a's first window ([100,200)); the proxy has since upgraded away and back, so the
    current-impl check (covered_to_block IS NULL) fails -> unaudited_since_upgrade.
    """
    proto = seed_protocol_with_history

    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="Early",
        title="Era A1 only",
        date="2023-09-01",
    )
    _drive_worker(worker, db_session)

    # current_status reflects the current impl: impl_a's coverage has covered_to_block=200 (not NULL),
    # so the "covered current era?" test fails.
    r = api_with_storage.get(f"/api/contracts/{proto['proxy'].id}/audit_timeline")
    assert r.status_code == 200, r.text
    assert r.json()["current_status"] == "unaudited_since_upgrade"


def test_audit_timeline_grace_match_is_not_audited(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    """A medium-confidence grace-zone match (audit 10 days before the impl went live) must not count as
    'audited'; the timeline reports unaudited_since_upgrade. Mirrors ether.fi LiquidityPool (impl live
    2026-03-16, nearest audit 2026-03-05).
    """
    proto = seed_protocol_with_history
    # Current impl (impl_a) went live at block 300, timestamp 2024-09-01.
    # Audit dated 2024-08-22 → 10 days before → grace → medium.
    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="JustBeforeUpgrade",
        title="T",
        date="2024-08-22",
    )
    _drive_worker(worker, db_session)

    r = api_with_storage.get(f"/api/contracts/{proto['proxy'].id}/audit_timeline")
    assert r.status_code == 200
    body = r.json()

    # Row stays present and 'medium' so the UI can show it, just not counted as "audited".
    cov = body["coverage"]
    assert len(cov) == 1
    entry = cov[0]
    assert entry["match_confidence"] == "medium"
    assert entry["match_type"] == "impl_era"
    assert body["current_status"] == "unaudited_since_upgrade"


def test_audit_timeline_cited_only_proof_is_not_audited(
    db_session,
    seed_protocol_with_history,
    api_with_storage,
):
    """A proven row with proof_kind='cited_only' is too weak to make the
    proxy's current impl count as audited."""
    from db.models import AuditContractCoverage, AuditReport

    proto = seed_protocol_with_history
    audit = AuditReport(
        protocol_id=proto["protocol_id"],
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        pdf_url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor="WeakProof",
        title="Context-only commit mention",
        date="2025-01-01",
        confidence=0.9,
        scope_extraction_status="success",
        scope_contracts=["Pool"],
    )
    db_session.add(audit)
    db_session.commit()

    db_session.add(
        AuditContractCoverage(
            contract_id=proto["impl_a"].id,
            audit_report_id=audit.id,
            protocol_id=proto["protocol_id"],
            matched_name="Pool",
            match_type="reviewed_commit",
            match_confidence="high",
            covered_from_block=300,
            covered_to_block=None,
            equivalence_status="proven",
            equivalence_reason="matched only a cited commit",
            proof_kind="cited_only",
        )
    )
    db_session.commit()

    r = api_with_storage.get(f"/api/contracts/{proto['proxy'].id}/audit_timeline")
    assert r.status_code == 200
    body = r.json()
    assert len(body["coverage"]) == 1
    assert body["coverage"][0]["proof_kind"] == "cited_only"
    assert body["current_status"] == "unaudited_since_upgrade"


def test_audit_timeline_for_non_proxy(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    """Non-proxy audited + non-proxy unaudited should both have
    impl_windows=[] and a non_proxy_* status."""
    proto = seed_protocol_with_history
    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="X",
        title="T",
        date="2024-10-15",
    )
    _drive_worker(worker, db_session)

    r = api_with_storage.get(f"/api/contracts/{proto['standalone'].id}/audit_timeline")
    assert r.status_code == 200
    body = r.json()
    assert body["contract"]["is_proxy"] is False
    assert body["impl_windows"] == []
    assert body["current_status"] == "non_proxy_audited"


def test_audit_timeline_non_proxy_unaudited(
    db_session, storage_bucket, seed_protocol_with_history, worker, api_with_storage
):
    proto = seed_protocol_with_history
    r = api_with_storage.get(f"/api/contracts/{proto['standalone'].id}/audit_timeline")
    assert r.status_code == 200
    body = r.json()
    assert body["current_status"] == "non_proxy_unaudited"
    assert body["coverage"] == []


def test_audit_timeline_for_impl_contract_queried_directly(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
    """Timeline on an IMPL Contract row (is_proxy=False, in UpgradeEvent history) returns non_proxy_audited +
    covering audits without walking a proxy lineage (ether.fi verification script drilling into a historical impl).
    """
    proto = seed_protocol_with_history
    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="X",
        title="T",
        date="2024-10-15",  # inside impl_a's [300, None) window
    )
    _drive_worker(worker, db_session)

    r = api_with_storage.get(f"/api/contracts/{proto['impl_a'].id}/audit_timeline")
    assert r.status_code == 200
    body = r.json()
    assert body["contract"]["is_proxy"] is False
    assert body["impl_windows"] == []
    assert len(body["coverage"]) == 1
    entry = body["coverage"][0]
    assert entry["match_type"] == "impl_era"
    assert entry["match_confidence"] == "high"
    assert entry["covered_from_block"] == 300
    assert body["current_status"] == "non_proxy_audited"


def test_audit_timeline_404_for_unknown_contract(db_session, api_with_storage):
    r = api_with_storage.get("/api/contracts/999999/audit_timeline")
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# 5. The "upgrade after most recent audit" unaudited_since_upgrade signal,
#     exercised via the unified-watcher live trigger
# ---------------------------------------------------------------------------


def test_unified_watcher_upgrade_refreshes_coverage_windows(
    db_session, storage_bucket, seed_protocol_with_history, worker, llm_stub_dir
):
    """A new upgrade event via unified_watcher's sync path closes impl_a's current window; the coverage row
    picks up the new upper bound.
    """
    from db.models import AuditContractCoverage, Contract, UpgradeEvent
    from services.monitoring.unified_watcher import _sync_relational_tables

    proto = seed_protocol_with_history

    _seed_scoped_audit(
        db_session,
        storage_bucket,
        proto["protocol_id"],
        fixture="spearbit_table.txt",
        auditor="X",
        title="T",
        date="2025-01-01",
    )
    _drive_worker(worker, db_session)

    db_session.expire_all()
    pool_row = db_session.query(AuditContractCoverage).filter_by(contract_id=proto["impl_a"].id).one()
    assert pool_row.covered_to_block is None

    # _sync_relational_tables needs a MonitoredContract with a linked contract_id; wire a lightweight one.
    from db.models import MonitoredContract

    mc = MonitoredContract(
        address=proto["proxy"].address,
        chain="ethereum",
        protocol_id=proto["protocol_id"],
        contract_id=proto["proxy"].id,
        contract_type="proxy",
    )
    db_session.add(mc)
    db_session.commit()

    _sync_relational_tables(
        db_session,
        mc,
        {
            "event_type": "upgraded",
            "implementation": "0x" + "c" * 40,
            "block_number": 400,
            "tx_hash": f"0x{uuid.uuid4().hex[:64]}",
        },
    )
    db_session.commit()

    db_session.expire_all()
    new_events = db_session.query(UpgradeEvent).filter_by(contract_id=proto["proxy"].id).count()
    assert new_events == 4

    refreshed = db_session.query(AuditContractCoverage).filter_by(contract_id=proto["impl_a"].id).one()
    assert refreshed.covered_to_block == 400

    db_session.query(MonitoredContract).filter_by(id=mc.id).delete()
    # Defensive: fixture teardown already sweeps UpgradeEvent for the protocol's contracts.
    db_session.query(UpgradeEvent).filter_by(contract_id=proto["proxy"].id, block_number=400).delete()
    db_session.query(Contract).filter_by(address=("0x" + "c" * 40).lower()).delete()
    db_session.commit()


# ---------------------------------------------------------------------------
# audit_timeline dedupe + findings filter — TestClient against the same rows
# ---------------------------------------------------------------------------


def test_audit_timeline_dedupe_prefers_reviewed_commit_over_impl_era(db_session, seed_protocol):
    """best_by_audit must prefer a reviewed_commit row over impl_era at equal confidence (cryptographic proof
    beats temporal heuristic).

    Regression: dedupe ranked only on match_confidence, so ties fell to first-iterated-wins; on EtherFi's
    LiquidityPool that dropped Certora "Priority Queue" off the current impl in the UI while the top banner
    said "audited".
    """
    from fastapi.testclient import TestClient

    import api as api_module
    from db.models import AuditContractCoverage, UpgradeEvent
    from tests.conftest import SessionFactory

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "1" * 40,
        name="Proxy",
        is_proxy=True,
        implementation="0x" + "a" * 40,
    )
    impl_a = _add_contract(db_session, protocol_id, address="0x" + "a" * 40, name="Pool")
    impl_b = _add_contract(db_session, protocol_id, address="0x" + "b" * 40, name="Pool")
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=None,
            new_impl=impl_b.address,
            block_number=100,
            timestamp=_ts(2024, 1, 1),
            tx_hash="0x" + "1" * 64,
        )
    )
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=impl_b.address,
            new_impl=impl_a.address,
            block_number=200,
            timestamp=_ts(2024, 6, 1),
            tx_hash="0x" + "2" * 64,
        )
    )
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-08-01")

    # Same confidence on both rows; impl_b's impl_era row goes FIRST so the old first-wins ranker pins the
    # chip to impl_b.
    db_session.add(
        AuditContractCoverage(
            contract_id=impl_b.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="impl_era",
            match_confidence="high",
            covered_from_block=100,
            covered_to_block=200,
        )
    )
    db_session.add(
        AuditContractCoverage(
            contract_id=impl_a.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="reviewed_commit",
            match_confidence="high",
        )
    )
    db_session.commit()

    from routers import deps as routers_deps

    SessionLocal_orig = routers_deps.SessionLocal
    routers_deps.SessionLocal = SessionFactory(db_session)
    try:
        client = TestClient(api_module.app)
        r = client.get(f"/api/contracts/{proxy.id}/audit_timeline")
    finally:
        routers_deps.SessionLocal = SessionLocal_orig

    assert r.status_code == 200, r.text
    body = r.json()
    rows_for_audit = [c for c in body["coverage"] if c["audit_id"] == audit.id]
    assert len(rows_for_audit) == 1, f"audit must dedupe to one row, got {rows_for_audit}"
    chosen = rows_for_audit[0]
    assert chosen["match_type"] == "reviewed_commit", (
        f"Source-equivalence proof must beat impl_era at equal confidence; got {chosen['match_type']!r}. "
        f"Full row: {chosen!r}"
    )
    assert chosen["impl_address"].lower() == impl_a.address.lower(), (
        f"Chip must point to current impl (reviewed_commit target), got {chosen['impl_address']!r}"
    )


def test_audit_timeline_dedupe_prefers_impl_era_over_direct(db_session, seed_protocol):
    """At equal confidence impl_era beats direct (carries more information); keeps the ranker consistent across match
    types.
    """
    from fastapi.testclient import TestClient

    import api as api_module
    from db.models import AuditContractCoverage, UpgradeEvent
    from tests.conftest import SessionFactory

    protocol_id, _ = seed_protocol
    proxy = _add_contract(
        db_session,
        protocol_id,
        address="0x" + "3" * 40,
        name="Proxy2",
        is_proxy=True,
        implementation="0x" + "c" * 40,
    )
    impl_c = _add_contract(db_session, protocol_id, address="0x" + "c" * 40, name="Pool")
    impl_d = _add_contract(db_session, protocol_id, address="0x" + "d" * 40, name="Pool")
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=None,
            new_impl=impl_d.address,
            block_number=300,
            timestamp=_ts(2024, 1, 1),
            tx_hash="0x" + "3" * 64,
        )
    )
    db_session.add(
        UpgradeEvent(
            contract_id=proxy.id,
            proxy_address=proxy.address,
            old_impl=impl_d.address,
            new_impl=impl_c.address,
            block_number=400,
            timestamp=_ts(2024, 6, 1),
            tx_hash="0x" + "4" * 64,
        )
    )
    audit = _add_audit(db_session, protocol_id, scope=["Pool"], date="2024-04-01")

    db_session.add(
        AuditContractCoverage(
            contract_id=impl_c.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="direct",
            match_confidence="high",
        )
    )
    db_session.add(
        AuditContractCoverage(
            contract_id=impl_d.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Pool",
            match_type="impl_era",
            match_confidence="high",
            covered_from_block=300,
            covered_to_block=400,
        )
    )
    db_session.commit()

    from routers import deps as routers_deps

    SessionLocal_orig = routers_deps.SessionLocal
    routers_deps.SessionLocal = SessionFactory(db_session)
    try:
        client = TestClient(api_module.app)
        r = client.get(f"/api/contracts/{proxy.id}/audit_timeline")
    finally:
        routers_deps.SessionLocal = SessionLocal_orig

    assert r.status_code == 200, r.text
    rows_for_audit = [c for c in r.json()["coverage"] if c["audit_id"] == audit.id]
    assert len(rows_for_audit) == 1
    assert rows_for_audit[0]["match_type"] == "impl_era"


def test_findings_filter_excludes_fixed_status(db_session, api_client, seed_protocol, monkeypatch):
    from db.models import AuditReport

    protocol_id, _ = seed_protocol
    addr = "0x" + "cc" * 20
    contract = _add_contract(db_session, protocol_id, address=addr, name="Vault")
    audit = _add_audit(db_session, protocol_id, date="2024-06-15", scope=["Vault"])

    # Write a coverage row directly (bypass upsert to keep this test
    # focused on the findings filter rather than the whole match path).
    from db.models import AuditContractCoverage

    db_session.add(
        AuditContractCoverage(
            contract_id=contract.id,
            audit_report_id=audit.id,
            protocol_id=protocol_id,
            matched_name="Vault",
            match_type="direct",
            match_confidence="high",
        )
    )
    # Set findings on the audit row — must update via SQLAlchemy so the
    # JSONB serialization path runs.
    audit_row = db_session.query(AuditReport).filter_by(id=audit.id).one()
    audit_row.findings = [
        {"title": "Fixed issue", "severity": "medium", "status": "fixed", "contract_hint": "Vault"},
        {"title": "Acknowledged issue", "severity": "high", "status": "acknowledged", "contract_hint": "Vault"},
        {"title": "Still mitigating", "severity": "low", "status": "mitigated", "contract_hint": "Vault"},
    ]
    db_session.commit()

    from services.clients import rpc

    monkeypatch.setattr(rpc, "get_code", _stub_get_code({addr: "0xbeef"}))

    resp = api_client.get(f"/api/contracts/{contract.id}/audit_timeline")
    assert resp.status_code == 200
    payload = resp.json()

    assert len(payload["coverage"]) == 1
    live = payload["coverage"][0]["live_findings"]
    titles = {f["title"] for f in live}
    assert "Fixed issue" not in titles
    assert "Acknowledged issue" in titles
    assert "Still mitigating" in titles
