"""End-to-end tests for the audit-coverage pipeline.

Exercises both population triggers and the new API endpoints against
real infrastructure:
  - PostgreSQL (TEST_DATABASE_URL) for the relational tables
  - S3-compatible object storage (TEST_ARTIFACT_STORAGE_*) for scope
    artifact round-trips through ``process_audit_scope``
  - LLM calls stubbed via ``PSAT_LLM_STUB_DIR`` → fixture files

Seed pattern: a 2-contract protocol with a proxy that has 3 impl eras
(A → B → A again), plus a standalone non-proxy contract. Three audits
dated straddle the upgrades so each audit should land in a distinct
window. The scope worker is driven directly (not via the poll loop)
for determinism.

Gated by ``requires_postgres + requires_storage`` — skips cleanly when
docker isn't running.
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
    """Committed ``_default.json`` stub returns ['Pool','Vault','Strategy','Registry'].
    All audit fixtures in this suite mention Pool + Vault, so the default
    response lines up with the seeded inventory.
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
    """Scope worker bound to the test DB — SessionLocal swapped so the
    worker's own sessions see the test data the fixtures wrote."""
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
    """A protocol with 2 inventory contracts, 2 historical impls, and
    proxy upgrade events A → B → A.

    Returns a dict so tests can name the pieces:
        proxy: Contract row of the proxy (currently pointing at impl_a)
        impl_a: Contract row named "Pool" (active [100,200) and [300,None))
        impl_b: Contract row named "PoolV2" (active [200,300))
        standalone: non-proxy Contract row named "Vault"
        protocol_id, protocol_name
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

    # Upgrade events on the proxy. Three events creates two historical
    # windows for impl_a: [100,200) + [300,None), plus one for impl_b:
    # [200,300).
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
    """Claim + process + persist one batch."""
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
    """A single audit dated inside impl_a's [300,None) window should
    produce:
      - 1 impl_era row on impl_a (Pool) with covered_from=300, to=None
      - 1 direct row on standalone (Vault, no impl history)
    The worker's _persist_outcome path fires the coverage refresh, so we
    shouldn't need to call upsert_coverage_for_protocol manually.
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
    """Three audits on the same contract (Pool), dated inside each of
    impl_a's eras and impl_b's era. The first two should both attach
    to impl_a with DIFFERENT windows; the middle to impl_b... wait —
    the LLM stub always says Pool + Vault regardless of date, so the
    middle audit names Pool too. Verify impl_a's window selection picks
    the right era per audit date.
    """
    from db.models import AuditContractCoverage

    proto = seed_protocol_with_history

    # Three audits, all scoping Pool (via the stub), dated inside each
    # era of the proxy: first window, impl_b's window, second window.
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

    # Drive; worker may claim in multiple batches depending on batch size.
    for _ in range(3):
        _drive_worker(worker, db_session)

    db_session.expire_all()
    rows_by_audit = {}
    for r in db_session.query(AuditContractCoverage).filter_by(contract_id=proto["impl_a"].id).all():
        rows_by_audit.setdefault(r.audit_report_id, r)

    # All three stubs return Pool in their scope → all three audits
    # coverage-link to impl_a, but with DIFFERENT windows.
    assert set(rows_by_audit) == {a1, a2, a3}

    early = rows_by_audit[a1]
    middle = rows_by_audit[a2]
    late = rows_by_audit[a3]

    # Early — 2023-09-01, in [100,200): first impl_a window.
    assert (early.covered_from_block, early.covered_to_block) == (100, 200)
    # Middle — 2024-05-01, falls in impl_b's [200,300) window. On
    # impl_a it's outside every window → confidence 'low', nearest
    # window is [100,200) (closer) or [300,None) (further).
    assert middle.match_confidence == "low"
    # Late — 2025-01-01, in [300, None): open-ended second impl_a window.
    assert (late.covered_from_block, late.covered_to_block) == (300, None)
    assert late.match_confidence == "high"


def test_reextraction_updates_coverage(db_session, storage_bucket, seed_protocol_with_history, worker, llm_stub_dir):
    """When scope_contracts changes post-re-extraction, coverage rows
    pivot accordingly. Simulates the end-to-end lifecycle without a
    live /reextract_scope API call.
    """
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
    # Pool + Vault covered initially.
    assert {r.contract_id for r in initial} == {
        proto["impl_a"].id,
        proto["standalone"].id,
    }

    # Simulate re-extraction shrinking the scope to just Vault.
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
    """Drive scope extraction, then wipe coverage, then hit the refresh
    endpoint. Rows should reappear. Verifies the admin backfill path."""
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

    # Wipe coverage rows (emulating a forgotten-to-populate state).
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
    """The endpoint should surface match_type + match_confidence +
    covered_from_block / covered_to_block. Proxy and standalone contracts
    both show up; an unrelated contract has audit_count=0.
    """
    from db.models import Contract

    proto = seed_protocol_with_history

    # Add an unrelated contract (so the endpoint shows a zero-cov case too).
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
    # Pool = impl_a
    pool = by_name["Pool"]
    assert pool["audit_count"] == 1
    la = pool["last_audit"]
    assert la["auditor"] == "Spearbit"
    assert la["match_type"] == "impl_era"
    assert la["match_confidence"] == "high"
    assert la["covered_from_block"] == 300
    assert la["covered_to_block"] is None

    # Vault = standalone
    vault = by_name["Vault"]
    assert vault["audit_count"] == 1
    assert vault["last_audit"]["match_type"] == "direct"

    # Unrelated contract — has a name but no audits, should still surface.
    assert by_name["NotAudited"]["audit_count"] == 0
    assert by_name["NotAudited"]["last_audit"] is None

    # Inventory-only entry (no name, no audits) is filtered out — the
    # company_overview endpoint excludes these contracts because they
    # were never analyzed, and the audit_coverage view should match.
    addresses = {row["address"] for row in body["coverage"]}
    assert "0x" + "e" * 40 not in addresses
    assert body["contract_count"] == len(body["coverage"])

    # Proxy row inherits its current implementation's coverage — the
    # company view is "is the code this address runs audited?", so a
    # proxy whose impl's name matched the audit's scope reports as
    # covered. The generic proxy name ("PoolProxy") isn't what drives
    # this; it's Contract.implementation pointing at impl_a (Pool).
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
    # 3 upgrade events → 3 impl_windows.
    assert len(body["impl_windows"]) == 3
    # Windows are ordered by block; check boundaries.
    blocks = [(w["from_block"], w["to_block"]) for w in body["impl_windows"]]
    assert blocks == [(100, 200), (200, 300), (300, None)]
    assert body["current_status"] == "audited"
    # The endpoint must surface coverage from the proxy's historical
    # impls, not just direct name matches against the proxy itself. The
    # one seeded audit links via impl_era on impl_a — so the proxy's
    # timeline should carry it. Before this union-in-impl-coverage fix,
    # `coverage` came back empty on a bare proxy query.
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
    """Audit covers impl_a during its FIRST window only (2023-09); the
    proxy has since upgraded away from impl_a and back. The current
    impl_a window has no covering audit → unaudited_since_upgrade.

    We have to be careful here: the default stub has Pool in the scope,
    so the audit DOES link to impl_a. But its covered range is [100,200)
    — the old window — so the current-impl check (covered_to_block IS
    NULL) evaluates false for that audit. That's exactly the 'upgrade
    happened after the most recent audit' signal.
    """
    proto = seed_protocol_with_history

    # Only one audit, dated in impl_a's FIRST (closed) window.
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

    # Query on the PROXY — current_status reflects the current impl's audit
    # state. The current impl is impl_a, and though it has coverage, that
    # coverage's covered_to_block is 200 (not NULL), so the endpoint's
    # "covered current era?" test fails and we report unaudited_since_upgrade.
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
    """An audit dated 10 days BEFORE the current impl went live lands in
    the grace zone → ``medium`` match on the impl's open-ended window.
    But ``current_status='audited'`` is a strong claim that should only
    fire on HIGH-confidence matches — the timeline must still report
    ``unaudited_since_upgrade`` and let the UI surface the medium match
    as "possibly covers this impl" separately.

    This is the headline case from the real ether.fi data: LiquidityPool's
    latest impl went live on 2026-03-16 and the nearest scoped audit is
    dated 2026-03-05 (11 days earlier). The fixture here reproduces that
    shape at synthetic scale.
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

    # Coverage row must be present and tagged 'medium' so the UI can still
    # show it — just not count it toward "audited".
    cov = body["coverage"]
    assert len(cov) == 1
    entry = cov[0]
    assert entry["match_confidence"] == "medium"
    assert entry["match_type"] == "impl_era"
    # The flag itself — tightened semantics.
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
    # No audit scoping "Vault" → standalone uncovered.
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
    """Hit the timeline endpoint on an IMPL Contract row (is_proxy=False
    but referenced in UpgradeEvent history). The impl has its own coverage
    (via impl_era) — endpoint should return ``non_proxy_audited`` + the
    covering audits without walking a proxy lineage.

    This covers the "ether.fi verification script drills into a specific
    historical-impl Contract row" use case: an audit reviewing "Pool"
    links to the impl row, and the user clicks through to that impl's
    timeline expecting to see what covered it.
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
    # impl_a itself is not a proxy — no impl_windows.
    assert body["contract"]["is_proxy"] is False
    assert body["impl_windows"] == []
    # Has impl_era coverage from the audit.
    assert len(body["coverage"]) == 1
    entry = body["coverage"][0]
    assert entry["match_type"] == "impl_era"
    assert entry["match_confidence"] == "high"
    assert entry["covered_from_block"] == 300
    # Non-proxy branch: any coverage → non_proxy_audited.
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
    """Audit + scope runs → impl_a's current window closes when a NEW
    upgrade event is written via unified_watcher's sync path. Coverage
    row for that audit should pick up the new upper bound automatically.
    """
    from db.models import AuditContractCoverage, Contract, UpgradeEvent
    from services.monitoring.unified_watcher import _sync_relational_tables

    proto = seed_protocol_with_history

    # Audit dated inside impl_a's still-current window.
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

    # Pre-check: pool coverage points at impl_a with NULL upper bound.
    db_session.expire_all()
    pool_row = db_session.query(AuditContractCoverage).filter_by(contract_id=proto["impl_a"].id).one()
    assert pool_row.covered_to_block is None

    # Simulate the unified watcher detecting a new upgrade (A → C).
    # _sync_relational_tables expects a MonitoredContract with a linked
    # contract_id, so we wire a lightweight one.
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

    # Post-check: there's a new UpgradeEvent at 400, and the audit's
    # coverage row now has covered_to_block=400 (impl_a's window closed).
    db_session.expire_all()
    new_events = db_session.query(UpgradeEvent).filter_by(contract_id=proto["proxy"].id).count()
    assert new_events == 4

    refreshed = db_session.query(AuditContractCoverage).filter_by(contract_id=proto["impl_a"].id).one()
    assert refreshed.covered_to_block == 400

    # Cleanup the MonitoredContract we added manually.
    db_session.query(MonitoredContract).filter_by(id=mc.id).delete()
    # Clean up the extra UpgradeEvent we synthesized so fixture teardown
    # doesn't hit a FK issue via cascades — the fixture already sweeps
    # UpgradeEvent for contract_ids in the protocol, so this is defensive.
    db_session.query(UpgradeEvent).filter_by(contract_id=proto["proxy"].id, block_number=400).delete()
    db_session.query(Contract).filter_by(address=("0x" + "c" * 40).lower()).delete()
    db_session.commit()


# ---------------------------------------------------------------------------
# audit_timeline dedupe + findings filter — TestClient against the same rows
# ---------------------------------------------------------------------------


def test_audit_timeline_dedupe_prefers_reviewed_commit_over_impl_era(db_session, seed_protocol):
    """``best_by_audit`` in api.contract_audit_timeline must prefer a
    ``reviewed_commit`` row over an ``impl_era`` row when the audit
    matched both at the same confidence. Source-equivalence is
    cryptographic proof; impl_era is a temporal heuristic — the proof
    should always win.

    Regression: pre-fix, the dedupe ranked only on ``match_confidence``,
    so two rows tied at 'high' fell through to first-iterated-wins (no
    SQL ORDER BY). On EtherFi's LiquidityPool that flipped audits like
    Certora "Priority Queue" off the current impl in the UI even though
    the DB had a reviewed_commit row pinning it there — top banner said
    "audited", per-impl chip said "no audit coverage" for the current
    impl.
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
    # Two upgrade events: impl_b first, then upgraded to impl_a (current).
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

    # Two coverage rows at SAME confidence. With the buggy ranker, whichever
    # row hits the cov_rows iteration first wins. We insert impl_b's
    # impl_era row FIRST so the bug pins the chip to impl_b — the fix must
    # still pick impl_a's reviewed_commit despite iteration order.
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

    # Hit the API on the proxy — it unions coverage from proxy + impls.
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
    """At equal confidence, ``impl_era`` (temporal window) beats
    ``direct`` (pure name match) — impl_era carries strictly more
    information. Defense-in-depth so the type-aware ranker remains
    consistent across all three match types.
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

    # direct on current impl (no temporal info), impl_era on past impl
    # (window match). impl_era should win.
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
    """Timeline endpoint exposes non-'fixed' findings, hides 'fixed' ones."""
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

    from utils import rpc

    monkeypatch.setattr(rpc, "get_code", _stub_get_code({addr: "0xbeef"}))

    resp = api_client.get(f"/api/contracts/{contract.id}/audit_timeline")
    assert resp.status_code == 200
    payload = resp.json()

    assert len(payload["coverage"]) == 1
    live = payload["coverage"][0]["live_findings"]
    # 'fixed' dropped, the other two survive.
    titles = {f["title"] for f in live}
    assert "Fixed issue" not in titles
    assert "Acknowledged issue" in titles
    assert "Still mitigating" in titles
