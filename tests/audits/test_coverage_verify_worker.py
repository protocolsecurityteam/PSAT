"""The deferred half of the source-equivalence split (#82); network calls are stubbed at module scope."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from tests.conftest import requires_postgres

pytestmark = [
    requires_postgres,
    # offline: no RPC for the coverage upsert's eth_getCode bytecode-drift anchor
    pytest.mark.usefixtures("_stub_rpc_bytecode"),
]


@pytest.fixture(autouse=True)
def _stub_source_equivalence_network(monkeypatch):
    from services.audits import source_equivalence

    monkeypatch.setattr(
        source_equivalence,
        "fetch_github_source_hash",
        lambda *_a, **_k: source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="default stub"),
    )
    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr, **_kw: source_equivalence.EtherscanFetch(
            source=None, status="fetch_failed", detail="default stub"
        ),
    )


@pytest.fixture()
def worker(monkeypatch):
    """``_process_row`` opens its own session per row."""
    from unittest.mock import patch

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import workers.coverage_verify as worker_mod
    from tests.conftest import DATABASE_URL

    test_engine = create_engine(DATABASE_URL)
    test_session_factory = sessionmaker(bind=test_engine, expire_on_commit=False)
    monkeypatch.setattr(worker_mod, "SessionLocal", test_session_factory)

    with patch("signal.signal"):
        w = worker_mod.CoverageVerifyWorker()
    try:
        yield w
    finally:
        test_engine.dispose()


@pytest.fixture()
def seed_protocol(db_session):
    from db.models import AuditContractCoverage, AuditReport, Contract, Protocol, UpgradeEvent

    name = f"cov-verify-{uuid.uuid4().hex[:10]}"
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
        db_session.query(Contract).filter_by(protocol_id=protocol_id).delete()
        db_session.query(AuditReport).filter_by(protocol_id=protocol_id).delete()
        db_session.query(Protocol).filter_by(id=protocol_id).delete()
        db_session.commit()


def _add_contract(session, *, protocol_id: int, name: str, address: str):
    from db.models import Contract

    c = Contract(
        protocol_id=protocol_id,
        address=address.lower(),
        chain="ethereum",
        contract_name=name,
    )
    session.add(c)
    session.commit()
    return c


def _add_audit(session, *, protocol_id: int, scope: list[str]):
    from db.models import AuditReport

    ar = AuditReport(
        protocol_id=protocol_id,
        url=f"https://example.com/{uuid.uuid4().hex}.pdf",
        auditor="T",
        title="T",
        date="2024-06-01",
        confidence=0.9,
        scope_extraction_status="success",
        scope_contracts=scope,
    )
    session.add(ar)
    session.commit()
    return ar


def _seed_pending_row(db_session, *, protocol_id: int, name: str = "MyPool", address: str = "0x" + "a" * 40):
    from services.audits.coverage import upsert_coverage_for_audit

    contract = _add_contract(db_session, protocol_id=protocol_id, name=name, address=address)
    audit = _add_audit(db_session, protocol_id=protocol_id, scope=[name])
    audit.reviewed_commits = ["abc1234"]
    audit.source_repo = "etherfi-protocol/smart-contracts"
    db_session.commit()
    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()
    return contract, audit


def _stub_proven_match(monkeypatch, *, content: str = "contract MyPool {}", name: str = "MyPool"):
    from services.audits import source_equivalence

    h = hashlib.sha256(content.encode()).hexdigest()
    src_path = f"src/{name}.sol"
    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr, **_kw: source_equivalence.EtherscanFetch(
            source=source_equivalence.VerifiedSource(
                contract_name=name,
                compiler_version="0.8",
                files={src_path: h},
            ),
            status="ok",
            detail="",
        ),
    )
    monkeypatch.setattr(
        source_equivalence,
        "fetch_github_source_hash",
        lambda _repo, _commit, path, token=None: source_equivalence.GithubHashResult(
            sha256=h if path == src_path else None,
            status="ok" if path == src_path else "http_404",
            detail="",
        ),
    )


def test_claim_batch_picks_pending_rows_and_marks_them_verifying(db_session, worker, seed_protocol):
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)

    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 1

    db_session.expire_all()
    row = db_session.query(AuditContractCoverage).filter_by(id=claimed[0]).one()
    assert row.equivalence_status == "verifying"
    assert row.equivalence_checked_at is not None


def test_claim_batch_skips_terminal_rows(db_session, worker, seed_protocol):
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    contract, audit = _seed_pending_row(db_session, protocol_id=protocol_id)

    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    row.equivalence_status = "proven"
    db_session.commit()

    claimed = worker._claim_batch(db_session)
    assert claimed == []


def test_idle_queue_makes_no_http_calls_and_no_writes(db_session, worker, seed_protocol, monkeypatch):
    """An empty queue is the common state and must make zero HTTP calls and writes, or the rate-limit cascade
    returns.
    """
    from services.audits import source_equivalence

    protocol_id, _ = seed_protocol

    contract, audit = _seed_pending_row(db_session, protocol_id=protocol_id)
    db_session.execute(
        text("UPDATE audit_contract_coverage SET equivalence_status = 'proven' WHERE audit_report_id = :a"),
        {"a": audit.id},
    )
    db_session.commit()

    rows_before = db_session.execute(
        text(
            "SELECT id, equivalence_status, equivalence_checked_at, match_type "
            "FROM audit_contract_coverage WHERE protocol_id = :p ORDER BY id"
        ),
        {"p": protocol_id},
    ).all()

    calls = {"github": 0, "etherscan": 0}

    def boom_etherscan(_addr, **_kw):
        calls["etherscan"] += 1
        raise AssertionError("etherscan called on idle tick (queue should be empty)")

    def boom_github(*_a, **_k):
        calls["github"] += 1
        raise AssertionError("github called on idle tick (queue should be empty)")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", boom_github)

    claimed = worker._claim_batch(db_session)
    assert claimed == []
    worker._recover_stale(db_session)

    assert calls == {"github": 0, "etherscan": 0}

    # A bumped ``equivalence_checked_at`` would mean a stray UPDATE.
    db_session.expire_all()
    rows_after = db_session.execute(
        text(
            "SELECT id, equivalence_status, equivalence_checked_at, match_type "
            "FROM audit_contract_coverage WHERE protocol_id = :p ORDER BY id"
        ),
        {"p": protocol_id},
    ).all()
    assert rows_after == rows_before


def test_claim_batch_respects_batch_size(db_session, worker, seed_protocol, monkeypatch):
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    for i in range(6):
        _seed_pending_row(
            db_session,
            protocol_id=protocol_id,
            name=f"Pool{i}",
            address="0x" + format(i, "040x"),
        )

    monkeypatch.setattr(worker, "batch_size", 2)
    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 2

    remaining = db_session.query(AuditContractCoverage).filter_by(equivalence_status="pending").count()
    assert remaining == 4


def test_claim_batch_skips_rows_whose_contract_was_reclassified_as_proxy(db_session, worker, seed_protocol):
    """A contract reclassified as a proxy made the ``_reject_proxy_coverage`` trigger raise on claim, which exited the
    worker and took the VM down via ``wait -n`` (2026-05-09). The claim CTE now filters ``is_proxy=FALSE``.
    """
    from db.models import AuditContractCoverage, Contract

    protocol_id, _ = seed_protocol

    contract_ok, _audit_ok = _seed_pending_row(
        db_session,
        protocol_id=protocol_id,
        name="GoodImpl",
        address="0x" + "1" * 40,
    )
    contract_bad, _audit_bad = _seed_pending_row(
        db_session,
        protocol_id=protocol_id,
        name="BecomesProxy",
        address="0x" + "2" * 40,
    )
    # The trigger fires only on coverage writes, so this update itself is fine.
    db_session.query(Contract).filter_by(id=contract_bad.id).update({"is_proxy": True})
    db_session.commit()

    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 1

    db_session.expire_all()
    good_row = db_session.query(AuditContractCoverage).filter_by(contract_id=contract_ok.id).one()
    bad_row = db_session.query(AuditContractCoverage).filter_by(contract_id=contract_bad.id).one()
    assert good_row.equivalence_status == "verifying"
    assert good_row.id == claimed[0]
    assert bad_row.equivalence_status == "pending"


def test_run_loop_survives_claim_batch_exception(db_session, worker, seed_protocol, monkeypatch):
    """A SQL failure in claim/recover used to exit the worker and end the VM."""
    import threading

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)

    calls = []

    def boom(_session):
        calls.append("called")
        worker._running = False
        raise RuntimeError("simulated SQL failure")

    monkeypatch.setattr(worker, "_claim_batch", boom)
    monkeypatch.setattr(worker, "idle_poll_interval", 0.01)

    # A thread keeps a hang from deadlocking the test.
    t = threading.Thread(target=worker.run_loop, daemon=True)
    t.start()
    t.join(timeout=5.0)
    assert not t.is_alive(), "run_loop did not exit — likely re-raised"
    assert calls == ["called"]


def test_process_row_proves_pending_to_proven(db_session, worker, seed_protocol, monkeypatch):
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)
    _stub_proven_match(monkeypatch)

    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 1
    row_id, status, exc, ctx = worker._process_row(claimed[0])
    assert exc is None
    assert status == "proven"
    # The keys ops greps for in a verdict log.
    assert ctx["audit_id"] is not None
    assert ctx["contract_id"] is not None
    assert ctx["matched_name"] == "MyPool"

    db_session.expire_all()
    row = db_session.query(AuditContractCoverage).filter_by(id=row_id).one()
    assert row.equivalence_status == "proven"
    assert row.match_type == "reviewed_commit"
    assert row.match_confidence == "high"


def test_process_row_records_crash_via_handle_crash(db_session, worker, seed_protocol, monkeypatch):
    """``github_fetch_failed`` keeps the result from being dropped."""
    from db.models import AuditContractCoverage
    from services.audits import coverage as coverage_mod

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)

    def boom(*_a, **_k):
        raise RuntimeError("synthetic verify crash")

    monkeypatch.setattr(coverage_mod, "verify_one_coverage_row", boom)

    claimed = worker._claim_batch(db_session)
    row_id, status, exc, _ctx = worker._process_row(claimed[0])
    assert status is None
    assert isinstance(exc, RuntimeError)

    worker._handle_crash(row_id, exc)
    db_session.expire_all()
    row = db_session.query(AuditContractCoverage).filter_by(id=row_id).one()
    assert row.equivalence_status == "github_fetch_failed"
    assert "synthetic verify crash" in (row.equivalence_reason or "")
    assert row.proof_kind is None
    assert row.matched_commit_sha is None


def test_recover_stale_resets_old_verifying_rows_to_pending(db_session, worker, seed_protocol):
    """Otherwise a crashed worker strands its claimed rows."""
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)

    row = db_session.query(AuditContractCoverage).filter_by(equivalence_status="pending").one()
    backdated = datetime.now(timezone.utc) - timedelta(seconds=worker.stale_seconds + 60)
    db_session.execute(
        text(
            """
            UPDATE audit_contract_coverage
            SET equivalence_status = 'verifying',
                equivalence_checked_at = :ts
            WHERE id = :id
            """
        ),
        {"id": row.id, "ts": backdated},
    )
    db_session.commit()

    worker._recover_stale(db_session)

    db_session.expire_all()
    row = db_session.query(AuditContractCoverage).filter_by(id=row.id).one()
    assert row.equivalence_status == "pending"
    assert row.equivalence_checked_at is None


def test_in_flight_verify_survives_coverage_rebuild_race(db_session, worker, seed_protocol, monkeypatch):
    """A rebuild deletes and reinserts coverage under a claimed row; the stale UPDATE must no-op."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _, audit = _seed_pending_row(db_session, protocol_id=protocol_id)

    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 1
    claimed_id = claimed[0]

    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    assert db_session.get(AuditContractCoverage, claimed_id) is None

    pending_rows = db_session.query(AuditContractCoverage).filter_by(equivalence_status="pending").all()
    assert len(pending_rows) == 1
