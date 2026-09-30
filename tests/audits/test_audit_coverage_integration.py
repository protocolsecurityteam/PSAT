"""Seed: a proxy with impl eras A -> B -> A plus a standalone contract, with audits straddling the upgrades.

The scope worker is driven directly for determinism.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.conftest import requires_postgres, requires_storage
from tests.support.audit_coverage_builders import (
    _add_audit,
    _add_contract,
    _stub_get_code,
    seed_protocol,  # noqa: F401  (fixture, registered by import)
)
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
    committed = STUB_DIR / "_default.json"
    assert committed.exists(), f"missing fixture: {committed}"
    (tmp_path / "_default.json").write_text(committed.read_text())
    monkeypatch.setenv("PSAT_LLM_STUB_DIR", str(tmp_path))
    return tmp_path


def _fixture_text(name: str) -> str:
    path = AUDITS_DIR / name
    assert path.exists(), f"missing audit fixture: {path}"
    return path.read_text()


def _ts(year: int, month: int = 1, day: int = 1) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


@pytest.fixture()
def seed_protocol_with_history(db_session):
    """impl_a "Pool" active [100,200)+[300,None), impl_b "PoolV2" [200,300), standalone "Vault"."""
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


def test_scope_worker_populates_coverage_for_proxy_and_standalone(
    db_session, storage_bucket, seed_protocol_with_history, worker, llm_stub_dir
):
    """Populated by the worker's _persist_outcome, not a manual upsert."""
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
    # The stub names Pool/Vault/Strategy/Registry; only Pool and Vault are in the inventory.
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
    """The stub names Pool regardless of date, so the middle audit matches too."""
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
    # 2024-05-01 is inside impl_b's window, outside every impl_a window.
    assert middle.match_confidence == "low"
    assert (late.covered_from_block, late.covered_to_block) == (300, None)
    assert late.match_confidence == "high"


def test_refresh_coverage_endpoint_backfills(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
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


def test_audit_coverage_endpoint_uses_coverage_table(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
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
    # Never analyzed, so it must not appear.
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

    addresses = {row["address"] for row in body["coverage"]}
    assert "0x" + "e" * 40 not in addresses
    assert body["contract_count"] == len(body["coverage"])

    # The company view asks whether the code this address runs is audited, via Contract.implementation.
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


def test_audit_timeline_for_proxy_with_audited_current_impl(
    db_session,
    storage_bucket,
    seed_protocol_with_history,
    worker,
    llm_stub_dir,
    api_with_storage,
):
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
    # A bare-proxy query once came back empty; coverage must union the historical impls.
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
    """Mirrors ether.fi LiquidityPool: impl live 2026-03-16, nearest audit 2026-03-05."""
    proto = seed_protocol_with_history
    # Audit 10 days before the impl went live: grace, medium.
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

    # The UI shows it, but it doesn't count as audited.
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
    """No proxy lineage walk (the ether.fi verification script drills into historical impls)."""
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


def test_unified_watcher_upgrade_refreshes_coverage_windows(
    db_session, storage_bucket, seed_protocol_with_history, worker, llm_stub_dir
):
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
    db_session.query(UpgradeEvent).filter_by(contract_id=proto["proxy"].id, block_number=400).delete()
    db_session.query(Contract).filter_by(address=("0x" + "c" * 40).lower()).delete()
    db_session.commit()


def test_audit_timeline_dedupe_prefers_reviewed_commit_over_impl_era(db_session, seed_protocol):
    """Cryptographic proof beats the temporal heuristic; ties used to fall to first-iterated, dropping an audit on
    EtherFi's LiquidityPool.
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

    # impl_b's row goes first so the old first-wins ranker would pick it.
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

    # Bypasses upsert to focus on the findings filter.
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
    # Update via SQLAlchemy so the JSONB serialization runs.
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
