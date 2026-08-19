"""Unit tests for the end-of-pipeline ``CoverageWorker``.

Exercises the readiness-gated claim, the stuck-job escape hatch, and the
source-equivalence-enabled refresh path. Network calls into
``services.audits.source_equivalence`` are stubbed at module scope so
the real coverage code runs end-to-end without GitHub / Etherscan
traffic — per the test-hygiene rule: never rely on env-var-controlled
divergence; stub the network helpers directly.
"""

from __future__ import annotations

import hashlib
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.conftest import requires_postgres  # noqa: E402

pytestmark = [
    requires_postgres,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


# ---------------------------------------------------------------------------
# Network-stubbing fixture — every test in this module gets it.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _stub_source_equivalence_network(monkeypatch):
    """Replace GitHub + Etherscan helpers with deterministic no-ops.

    Tests that need a positive equivalence result override these with a
    local monkeypatch; by default both return None so no match is proven
    and the temporal matcher's answer stands.
    """
    from services.audits import source_equivalence

    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", lambda *a, **k: None)
    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", lambda *a, **k: None)


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def worker():
    """CoverageWorker with signals patched so pytest's handlers aren't touched.

    Tests call ``_claim_next_job``, ``_claim_stuck_job``, and ``process``
    directly against ``db_session``; the inherited ``run_loop`` (which
    opens its own ``SessionLocal``) is never exercised here.
    """
    from unittest.mock import patch

    from workers.coverage_worker import CoverageWorker

    with patch("signal.signal"):
        yield CoverageWorker()


@pytest.fixture()
def seed_protocol(db_session):
    """Bare protocol with cleanup of cascading rows + lingering Jobs."""
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
        # Jobs have ON DELETE SET NULL on protocol_id; clean them up by
        # (protocol_id + jobs whose contract we just deleted).
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
    """Insert a Job at the given stage/status, optionally backdated."""
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
        # Force the updated_at column — server_default/onupdate would
        # otherwise stamp NOW(), which defeats the stuck-job test.
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
    """Create an AuditReport in a specific (text, scope) state pair."""
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


# ---------------------------------------------------------------------------
# 1. Happy path — claim + process + write coverage rows
# ---------------------------------------------------------------------------


def test_coverage_worker_claims_and_writes_when_ready(db_session, seed_protocol, worker):
    """Audit is fully scoped, job is queued at stage=coverage → claim
    succeeds, process() writes one coverage row for the contract whose
    name matches scope, and advance_job routes it to done.
    """
    from db.models import AuditContractCoverage, JobStage, JobStatus

    protocol_id, _ = seed_protocol
    # Contract linked via job_id so the worker's Contract-by-job lookup succeeds.
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
    # Audit scoping "Pool" — settled via text+scope success.
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
    """A scope-completed audit with reviewed_commits + source_repo populated
    must produce a row with ``equivalence_status='pending'`` after
    ``process()`` — the verify worker takes it from there. The coverage
    worker itself MUST NOT make any GitHub / Etherscan HTTP calls; that's
    the whole point of the deferred-verify split (#82).
    """
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

    # Make any HTTP attempt loud — the coverage worker mustn't reach
    # network on the deferred-verify path.
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
    # Heuristic match still emitted synchronously…
    assert rows[0].match_type == "direct"
    # …but cryptographic verification is deferred.
    assert rows[0].equivalence_status == "pending"
    # And the worker stayed off the network.
    assert calls == {"github": 0, "etherscan": 0}


def test_coverage_worker_then_verify_worker_upgrades_to_reviewed_commit(db_session, seed_protocol, worker, monkeypatch):
    """End-to-end deferred path: coverage worker writes a pending row, then
    ``verify_one_coverage_row`` (the per-row entry point the verify worker
    calls) upgrades it to ``reviewed_commit/high`` once the source-
    equivalence proof goes through.
    """
    from db.models import AuditContractCoverage, JobStage, JobStatus
    from services.audits import source_equivalence
    from services.audits.coverage import verify_one_coverage_row

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

    content = "contract Pool {}"
    h = hashlib.sha256(content.encode()).hexdigest()
    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr, **_kw: source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name="Pool",
                compiler_version="0.8",
                files={"src/Pool.sol": h},
            ),
            status="ok",
            detail="",
        ),
    )
    monkeypatch.setattr(
        source_equivalence,
        "fetch_github_source_hash",
        lambda _repo, _commit, path, token=None: source_equivalence.GithubHashResult(
            sha256=h if path == "src/Pool.sol" else None,
            status="ok" if path == "src/Pool.sol" else "http_404",
            detail="",
        ),
    )

    # Phase 1: coverage worker lands a pending row.
    claimed = worker._claim_next_job(db_session)
    assert claimed is not None
    worker.process(db_session, claimed)
    db_session.commit()

    db_session.expire_all()
    row = (
        db_session.execute(select(AuditContractCoverage).where(AuditContractCoverage.contract_id == contract.id))
        .scalars()
        .one()
    )
    assert row.match_type == "direct"
    assert row.equivalence_status == "pending"

    # Phase 2: drive the per-row verify entry point. The verify worker
    # calls this from its thread pool; testing it directly keeps the
    # assertions focused on the row-level behavior.
    status = verify_one_coverage_row(db_session, row.id)
    db_session.commit()
    assert status == "proven"

    db_session.expire_all()
    row = db_session.get(AuditContractCoverage, row.id)
    assert row is not None
    assert row.match_type == "reviewed_commit"
    assert row.match_confidence == "high"
    assert row.equivalence_status == "proven"


# ---------------------------------------------------------------------------
# 2. Readiness blocking — an unsettled audit prevents claim
# ---------------------------------------------------------------------------


def test_coverage_worker_waits_for_text_extraction(db_session, seed_protocol, worker):
    """An audit whose text_extraction_status='processing' keeps readiness
    false → claim returns None. Once it's flipped to success + scope
    success, the next claim picks the job up.
    """
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

    # Readiness predicate is false — claim returns nothing.
    assert worker._claim_next_job(db_session) is None

    # Flip text → success but leave scope NULL. Still blocked (scope mid-flight).
    ar = db_session.get(AuditReport, audit.id)
    ar.text_extraction_status = "success"
    db_session.commit()
    assert worker._claim_next_job(db_session) is None

    # Now mark scope success with a non-matching scope. Settled → claim succeeds.
    ar = db_session.get(AuditReport, audit.id)
    ar.scope_extraction_status = "success"
    ar.scope_contracts = ["SomethingElse"]
    db_session.commit()

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id


def test_coverage_worker_unblocks_on_text_extraction_failure(db_session, seed_protocol, worker):
    """An audit whose text extraction ``failed`` leaves scope_extraction_status
    NULL forever. The readiness predicate must treat that as settled — NOT
    blocked — otherwise a single bad PDF would wedge every coverage job in
    the protocol until the stuck-job timeout kicked in.
    """
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


# ---------------------------------------------------------------------------
# 3. Stuck-audit timeout — bypass readiness after cutoff
# ---------------------------------------------------------------------------


def test_coverage_worker_claims_stuck_job_past_timeout(db_session, seed_protocol, worker, monkeypatch):
    """Job has been at stage=coverage, status=queued for > timeout AND
    an audit is still mid-flight (readiness predicate false). The stuck
    claim path bypasses readiness so the job doesn't hang forever.
    """
    import workers.coverage_worker as worker_mod
    from db.models import JobStage, JobStatus

    # Collapse the timeout so we don't have to actually backdate by an hour.
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

    # Readiness-gated claim still blocked by the processing audit.
    assert worker._claim_next_job(db_session) is None

    # Stuck path picks it up.
    claimed = worker._claim_stuck_job(db_session)
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == JobStatus.processing


# ---------------------------------------------------------------------------
# 4. Edge — job.protocol_id is NULL (direct address submission)
# ---------------------------------------------------------------------------


def test_coverage_worker_claims_job_with_null_protocol(db_session, worker):
    """A direct address job (no parent company → protocol_id NULL) has
    no audits to wait on. The NOT EXISTS subquery is vacuously true, so
    claim fires immediately and process() runs a no-op coverage refresh.
    """
    from db.models import AuditContractCoverage, Contract, JobStage, JobStatus

    job = _add_job(
        db_session,
        protocol_id=None,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )
    # Contract linked to the job but with protocol_id NULL — no scope
    # name can match (match_audits_for_contract short-circuits), so the
    # upsert is a zero-row no-op.
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
    """If discovery/static never produced a Contract row for the job (e.g.
    a cached-path reassignment edge case), process() should log and
    return without crashing — the outer run_loop will then advance to done.
    """
    from db.models import JobStage, JobStatus

    protocol_id, _ = seed_protocol
    _add_job(
        db_session,
        protocol_id=protocol_id,
        stage=JobStage.coverage,
        status=JobStatus.queued,
    )
    # No Contract row for this job_id.

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None

    # Should not raise.
    worker.process(db_session, claimed)
    db_session.commit()


# ---------------------------------------------------------------------------
# 5. Perf: HTTP calls must not run inside an open DB transaction
# ---------------------------------------------------------------------------


def test_coverage_worker_makes_zero_http_calls_on_deferred_path(db_session, seed_protocol, worker, monkeypatch):
    """The coverage worker MUST NOT touch GitHub / Etherscan even when the
    audit looks ripe for source-equivalence verification. The whole
    point of moving verify to a dedicated worker is that the synchronous
    coverage write sees zero rate-limit-able traffic — that's how we
    avoid the 4-way Etherscan burst that used to cascade-block other
    workers behind the shared backoff sleep (#82).
    """
    from db.models import JobStage, JobStatus
    from services.audits import source_equivalence

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
        text_status="success",
        scope_status="success",
        scope=["Pool"],
    )
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "some/repo"
    db_session.commit()

    calls = {"github": 0, "etherscan": 0}

    def record_github(*_a, **_k):
        calls["github"] += 1
        raise AssertionError("github fetch reached on deferred path")

    def record_etherscan(_addr, **_kw):
        calls["etherscan"] += 1
        raise AssertionError("etherscan fetch reached on deferred path")

    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", record_github)
    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", record_etherscan)

    claimed = worker._claim_next_job(db_session)
    assert claimed is not None
    worker.process(db_session, claimed)
    db_session.commit()

    assert calls == {"github": 0, "etherscan": 0}
