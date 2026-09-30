"""Source-equivalence network helpers are stubbed at module scope, so no GitHub/Etherscan traffic."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from tests.conftest import requires_postgres

pytestmark = [
    requires_postgres,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


@pytest.fixture(autouse=True)
def _stub_source_equivalence_network(monkeypatch):
    """No match is proven, so the temporal matcher's answer stands."""
    from services.audits import source_equivalence

    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", lambda *a, **k: None)
    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", lambda *a, **k: None)


@pytest.fixture()
def worker():
    """``run_loop`` is never exercised; tests call the claim and process methods directly."""
    from unittest.mock import patch

    from workers.coverage_worker import CoverageWorker

    with patch("signal.signal"):
        yield CoverageWorker()


@pytest.fixture()
def seed_protocol(db_session):
    from db.models import AuditContractCoverage, AuditReport, Contract, Job, Protocol, UpgradeEvent

    name = f"cov-worker-{uuid.uuid4().hex[:10]}"
    p = Protocol(name=name)
    db_session.add(p)
    db_session.commit()
    protocol_id = p.id
    try:
        yield protocol_id, name
    finally:
        db_session.rollback()
        db_session.query(AuditContractCoverage).filter_by(protocol_id=protocol_id).delete()
        contract_ids = [c.id for c in db_session.query(Contract).filter_by(protocol_id=protocol_id).all()]
        if contract_ids:
            db_session.query(UpgradeEvent).filter(UpgradeEvent.contract_id.in_(contract_ids)).delete(
                synchronize_session=False
            )
        # Jobs are SET NULL on protocol deletion.
        job_ids = {c.job_id for c in db_session.query(Contract).filter_by(protocol_id=protocol_id).all() if c.job_id}
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        if job_ids:
            db_session.query(Job).filter(Job.id.in_(job_ids)).delete(synchronize_session=False)
        db_session.query(Job).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _add_contract(session, *, protocol_id: int, name: str, address: str, job_id=None):
    from db.models import Contract

    c = Contract(
        protocol_id=protocol_id,
        address=address.lower(),
        chain="ethereum",
        contract_name=name,
        job_id=job_id,
    )
    session.add(c)
    session.commit()
    return c


def _add_job(
    session,
    *,
    protocol_id: int | None,
    stage,
    status,
    address: str = "0x" + "e" * 40,
    updated_at: datetime | None = None,
):
    from db.models import Job

    j = Job(
        address=address.lower(),
        protocol_id=protocol_id,
        stage=stage,
        status=status,
        request={"address": address.lower()},
    )
    session.add(j)
    session.commit()
    if updated_at is not None:
        # onupdate would stamp NOW() and defeat the stuck-job test.
        from sqlalchemy import update as sa_update

        from db.models import Job as _Job

        session.execute(sa_update(_Job).where(_Job.id == j.id).values(updated_at=updated_at))
        session.commit()
        session.refresh(j)
    return j


def _add_audit(
    session,
    *,
    protocol_id: int,
    text_status: str | None,
    scope_status: str | None,
    scope: list[str] | None = None,
    date: str | None = "2024-06-01",
):
    from db.models import AuditReport

    ar = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor="T",
        title="T",
        date=date,
        confidence=0.9,
        text_extraction_status=text_status,
        scope_extraction_status=scope_status,
        scope_contracts=scope,
    )
    session.add(ar)
    session.commit()
    return ar


def test_coverage_worker_claims_and_writes_when_ready(db_session, seed_protocol, worker):
    from db.models import AuditContractCoverage, JobStage, JobStatus

    protocol_id, _ = seed_protocol
    job = _add_job(
        db_session,
        protocol_id=protocol_id,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )
    contract = _add_contract(
        db_session,
        protocol_id=protocol_id,
        name="Pool",
        address="0x" + "a" * 40,
        job_id=job.id,
    )
    _add_audit(
        db_session,
        protocol_id=protocol_id,
        text_status="success",
        scope_status="success",
        scope=["Pool"],
    )

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == JobStatus.processing

    worker.process(db_session, claimed)
    db_session.commit()
    db_session.expire_all()

    rows = (
        db_session.execute(select(AuditContractCoverage).where(AuditContractCoverage.contract_id == contract.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].matched_name == "Pool"
    assert rows[0].match_type == "direct"


def test_coverage_worker_writes_pending_when_audit_is_verifiable(db_session, seed_protocol, worker, monkeypatch):
    """The deferred-verify split (#82) keeps the coverage worker off the network."""
    from db.models import AuditContractCoverage, JobStage, JobStatus
    from services.audits import source_equivalence

    protocol_id, _ = seed_protocol
    job = _add_job(
        db_session,
        protocol_id=protocol_id,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )
    contract = _add_contract(
        db_session,
        protocol_id=protocol_id,
        name="Pool",
        address="0x" + "a" * 40,
        job_id=job.id,
    )
    audit = _add_audit(
        db_session,
        protocol_id=protocol_id,
        text_status="success",
        scope_status="success",
        scope=["Pool"],
    )
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "some/repo"
    db_session.commit()

    calls = {"github": 0, "etherscan": 0}

    def boom_etherscan(_addr, **_kw):
        calls["etherscan"] += 1
        raise AssertionError("coverage worker must not call etherscan")

    def boom_github(*_a, **_k):
        calls["github"] += 1
        raise AssertionError("coverage worker must not call github")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", boom_github)

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None
    worker.process(db_session, claimed)
    db_session.commit()
    db_session.expire_all()

    rows = (
        db_session.execute(select(AuditContractCoverage).where(AuditContractCoverage.contract_id == contract.id))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].match_type == "direct"
    assert rows[0].equivalence_status == "pending"
    assert calls == {"github": 0, "etherscan": 0}


def test_coverage_worker_waits_for_text_extraction(db_session, seed_protocol, worker):
    from db.models import AuditReport, JobStage, JobStatus

    protocol_id, _ = seed_protocol
    job = _add_job(
        db_session,
        protocol_id=protocol_id,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        name="Pool",
        address="0x" + "a" * 40,
        job_id=job.id,
    )
    audit = _add_audit(
        db_session,
        protocol_id=protocol_id,
        text_status="processing",
        scope_status=None,
    )

    assert worker._claim_next_job(db_session) is None

    ar = db_session.get(AuditReport, audit.id)
    ar.text_extraction_status = "success"
    db_session.commit()
    assert worker._claim_next_job(db_session) is None

    ar = db_session.get(AuditReport, audit.id)
    ar.scope_extraction_status = "success"
    ar.scope_contracts = ["SomethingElse"]
    db_session.commit()

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id


def test_coverage_worker_unblocks_on_text_extraction_failure(db_session, seed_protocol, worker):
    """Otherwise one bad PDF wedges every coverage job until the stuck-job timeout."""
    from db.models import JobStage, JobStatus

    protocol_id, _ = seed_protocol
    job = _add_job(
        db_session,
        protocol_id=protocol_id,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        name="Pool",
        address="0x" + "a" * 40,
        job_id=job.id,
    )
    _add_audit(
        db_session,
        protocol_id=protocol_id,
        text_status="failed",
        scope_status=None,
    )

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id


def test_coverage_worker_claims_stuck_job_past_timeout(db_session, seed_protocol, worker, monkeypatch):
    import workers.coverage_worker as worker_mod
    from db.models import JobStage, JobStatus

    monkeypatch.setattr(worker_mod, "_STUCK_COVERAGE_TIMEOUT", 60)

    protocol_id, _ = seed_protocol
    _add_audit(
        db_session,
        protocol_id=protocol_id,
        text_status="processing",
        scope_status=None,
    )
    past = datetime.now(timezone.utc) - timedelta(seconds=600)
    job = _add_job(
        db_session,
        protocol_id=protocol_id,
        stage=JobStage.coverage,
        status=JobStatus.queued,
        updated_at=past,
    )
    _add_contract(
        db_session,
        protocol_id=protocol_id,
        name="Pool",
        address="0x" + "a" * 40,
        job_id=job.id,
    )

    assert worker._claim_next_job(db_session) is None

    claimed = worker._claim_stuck_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == JobStatus.processing


def test_coverage_worker_claims_job_with_null_protocol(db_session, worker):
    """No audits to wait on, so the NOT EXISTS is vacuously true."""
    from db.models import AuditContractCoverage, Contract, JobStage, JobStatus

    job = _add_job(
        db_session,
        protocol_id=None,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )
    # No scope name can match, so the upsert is a no-op.
    contract = Contract(
        protocol_id=None,
        address="0x" + "c" * 40,
        chain="ethereum",
        contract_name="SomeContract",
        job_id=job.id,
    )
    db_session.add(contract)
    db_session.commit()

    try:
        claimed = worker._claim_next_job(db_session)
        assert claimed is not None
        assert claimed.id == job.id

        worker.process(db_session, claimed)
        db_session.commit()

        rows = (
            db_session.execute(select(AuditContractCoverage).where(AuditContractCoverage.contract_id == contract.id))
            .scalars()
            .all()
        )
        assert rows == []
    finally:
        db_session.query(Contract).filter_by(id=contract.id).delete()
        db_session.query(type(job)).filter_by(id=job.id).delete()
        db_session.commit()


def test_coverage_worker_handles_job_without_contract(db_session, seed_protocol, worker):
    from db.models import JobStage, JobStatus

    protocol_id, _ = seed_protocol
    _add_job(
        db_session,
        protocol_id=protocol_id,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None

    worker.process(db_session, claimed)
    db_session.commit()
