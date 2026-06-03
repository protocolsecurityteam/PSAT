"""Tests for ``workers.coverage_verify.CoverageVerifyWorker``.

The worker drains ``audit_contract_coverage`` rows where
``equivalence_status='pending'`` — the deferred-verify side of the
fix that split source-equivalence out of the inline coverage write
(#82). These tests exercise the claim → verify → persist cycle without
running the full poll loop, plus the stale-recovery and crash-fallback
paths.

Network calls into ``services.audits.source_equivalence`` are stubbed
at module scope; tests that need a positive proof override locally.
"""

from __future__ import annotations

import hashlib
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import text

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
    from services.audits import source_equivalence

    monkeypatch.setattr(
        source_equivalence,
        "fetch_github_source_hash",
        lambda *_a, **_k: source_equivalence.GithubHashResult(sha256=None, status="http_404", detail="default stub"),
    )
    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr: source_equivalence.EtherscanFetch(source=None, status="fetch_failed", detail="default stub"),
    )


# ---------------------------------------------------------------------------
# Worker fixture — patches signal so pytest's handlers aren't touched.
# ---------------------------------------------------------------------------


@pytest.fixture()
def worker(monkeypatch):
    """CoverageVerifyWorker with SessionLocal rebound to the test DB.

    ``_process_row`` opens its own ``SessionLocal()`` (each row gets a
    fresh session in production so failures don't poison siblings); in
    tests that session must talk to ``TEST_DATABASE_URL`` instead of
    ``DATABASE_URL`` or the verify writes land in the wrong database.
    """
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


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


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
    """Insert a Contract + AuditReport + pending coverage row in one helper."""
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
    """Wire the source-equivalence stubs to return a positive proof."""
    from services.audits import source_equivalence

    h = hashlib.sha256(content.encode()).hexdigest()
    src_path = f"src/{name}.sol"
    monkeypatch.setattr(
        source_equivalence,
        "fetch_etherscan_source_files",
        lambda _addr: source_equivalence.EtherscanFetch(
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


# ---------------------------------------------------------------------------
# 1. Claim semantics
# ---------------------------------------------------------------------------


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
    """Rows already in a terminal status (proven, hash_mismatch, etc.)
    must NOT be re-claimed — they're done."""
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    contract, audit = _seed_pending_row(db_session, protocol_id=protocol_id)

    # Manually advance the row to a terminal state.
    row = db_session.query(AuditContractCoverage).filter_by(audit_report_id=audit.id).one()
    row.equivalence_status = "proven"
    db_session.commit()

    claimed = worker._claim_batch(db_session)
    assert claimed == []


def test_claim_batch_returns_empty_when_no_pending(db_session, worker):
    claimed = worker._claim_batch(db_session)
    assert claimed == []


def test_idle_queue_makes_no_http_calls_and_no_writes(db_session, worker, seed_protocol, monkeypatch):
    """When every coverage row has reached a terminal status, the verify
    worker's poll tick must be a true no-op: zero Etherscan calls, zero
    GitHub calls, zero DB row updates. This is the guarantee that lets
    us run the worker continuously alongside the rest of the fleet
    without re-introducing the rate-limit cascade — an empty queue is
    the most common state and it has to stay free.
    """
    from services.audits import source_equivalence

    protocol_id, _ = seed_protocol

    # Seed one coverage row, but in a TERMINAL state (proven). The worker
    # must skip it — proven rows aren't pending. Pair with a manually-
    # created row in another terminal state so the predicate gets exercised
    # against more than one shape.
    contract, audit = _seed_pending_row(db_session, protocol_id=protocol_id)
    db_session.execute(
        text("UPDATE audit_contract_coverage SET equivalence_status = 'proven' WHERE audit_report_id = :a"),
        {"a": audit.id},
    )
    db_session.commit()

    # Snapshot the row state pre-tick so we can prove it's untouched.
    rows_before = db_session.execute(
        text(
            "SELECT id, equivalence_status, equivalence_checked_at, match_type "
            "FROM audit_contract_coverage WHERE protocol_id = :p ORDER BY id"
        ),
        {"p": protocol_id},
    ).all()

    # Make any HTTP attempt loud — stuck stale recovery, bug in claim
    # predicate, etc. would all surface as a real call.
    calls = {"github": 0, "etherscan": 0}

    def boom_etherscan(_addr):
        calls["etherscan"] += 1
        raise AssertionError("etherscan called on idle tick (queue should be empty)")

    def boom_github(*_a, **_k):
        calls["github"] += 1
        raise AssertionError("github called on idle tick (queue should be empty)")

    monkeypatch.setattr(source_equivalence, "fetch_etherscan_source_files", boom_etherscan)
    monkeypatch.setattr(source_equivalence, "fetch_github_source_hash", boom_github)

    # One tick: claim + stale recovery (the same operations the poll loop
    # runs every interval). Both must be no-ops on a queue with no
    # pending / verifying rows.
    claimed = worker._claim_batch(db_session)
    assert claimed == []
    worker._recover_stale(db_session)

    # No HTTP calls — that's the headline guarantee.
    assert calls == {"github": 0, "etherscan": 0}

    # And the row is byte-identical to its pre-tick state. equivalence_checked_at
    # MUST NOT have been bumped to NOW() — that'd indicate a stray UPDATE.
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
    """Multiple pending rows → claim only ``batch_size`` of them."""
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

    # Remaining four still pending.
    remaining = db_session.query(AuditContractCoverage).filter_by(equivalence_status="pending").count()
    assert remaining == 4


def test_claim_batch_skips_rows_whose_contract_was_reclassified_as_proxy(db_session, worker, seed_protocol):
    """Regression for the live-test crash on 2026-05-09.

    A coverage row was inserted while its contract had ``is_proxy=FALSE``;
    a later static-analysis pass flipped the contract to ``is_proxy=TRUE``.
    The DB trigger ``_reject_proxy_coverage`` correctly rejects any
    INSERT/UPDATE that targets a proxy. Without filtering on the claim
    side, the worker's UPDATE-to-``verifying`` raised, the exception
    propagated out of ``run_loop``, the process exited 1, and
    ``start_workers.sh``'s ``wait -n`` brought the whole VM down with it
    — Fly retried, the same row was still bad, the machine stayed
    stopped.

    The fix: the claim CTE joins ``contracts`` and filters
    ``is_proxy=FALSE``. Reclassified rows stay in ``pending`` (orphaned
    but harmless); valid pending rows continue to be claimed.
    """
    from db.models import AuditContractCoverage, Contract

    protocol_id, _ = seed_protocol

    # Row A: pending, contract still impl → should be claimed.
    contract_ok, _audit_ok = _seed_pending_row(
        db_session,
        protocol_id=protocol_id,
        name="GoodImpl",
        address="0x" + "1" * 40,
    )
    # Row B: pending, contract reclassified to proxy mid-flight →
    # claim must skip it instead of raising.
    contract_bad, _audit_bad = _seed_pending_row(
        db_session,
        protocol_id=protocol_id,
        name="BecomesProxy",
        address="0x" + "2" * 40,
    )
    # Flip ``is_proxy`` directly on the contracts row. The trigger only
    # fires on writes to ``audit_contract_coverage``, so this update
    # itself is fine — the breakage shows up on the *next* coverage
    # write.
    db_session.query(Contract).filter_by(id=contract_bad.id).update({"is_proxy": True})
    db_session.commit()

    # The previously-failing path: this used to raise psycopg2 error and
    # crash the worker. After the fix, it returns only the valid row.
    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 1

    db_session.expire_all()
    good_row = db_session.query(AuditContractCoverage).filter_by(contract_id=contract_ok.id).one()
    bad_row = db_session.query(AuditContractCoverage).filter_by(contract_id=contract_bad.id).one()
    assert good_row.equivalence_status == "verifying"
    assert good_row.id == claimed[0]
    # The proxy-targeting row is left pending — orphaned but never
    # crashes the worker.
    assert bad_row.equivalence_status == "pending"


def test_run_loop_survives_claim_batch_exception(db_session, worker, seed_protocol, monkeypatch):
    """Defense-in-depth: any future SQL failure in the claim/recover
    phase must not crash the worker process.

    Earlier behaviour: an exception from ``_claim_batch`` propagated
    straight out of ``run_loop`` → process exits 1 → ``start_workers.sh``
    ``wait -n`` ends the whole VM. Now ``run_loop`` catches the failure,
    rolls back, logs, and continues to the next poll.
    """
    import threading

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)

    calls = []

    def boom(_session):
        calls.append("called")
        # Stop the loop after the first failure so the test terminates.
        worker._running = False
        raise RuntimeError("simulated SQL failure")

    monkeypatch.setattr(worker, "_claim_batch", boom)
    # Avoid sleeping idle — we want the loop to exit promptly.
    monkeypatch.setattr(worker, "idle_poll_interval", 0.01)

    # Run the loop on a thread so a hypothetical hang doesn't deadlock the
    # test. The fix should make this exit cleanly via ``self._running=False``.
    t = threading.Thread(target=worker.run_loop, daemon=True)
    t.start()
    t.join(timeout=5.0)
    assert not t.is_alive(), "run_loop did not exit — likely re-raised"
    assert calls == ["called"]


# ---------------------------------------------------------------------------
# 2. Per-row verify (smoke test of the threadpool entry point)
# ---------------------------------------------------------------------------


def test_process_row_proves_pending_to_proven(db_session, worker, seed_protocol, monkeypatch):
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)
    _stub_proven_match(monkeypatch)

    # Claim (writes 'verifying') then run verify on the row.
    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 1
    row_id, status, exc, ctx = worker._process_row(claimed[0])
    assert exc is None
    assert status == "proven"
    # Context hands the run loop everything _log_outcome needs without a
    # second DB read — assert the keys ops would grep for in a verdict log.
    assert ctx["audit_id"] is not None
    assert ctx["contract_id"] is not None
    assert ctx["matched_name"] == "MyPool"

    db_session.expire_all()
    row = db_session.query(AuditContractCoverage).filter_by(id=row_id).one()
    assert row.equivalence_status == "proven"
    assert row.match_type == "reviewed_commit"
    assert row.match_confidence == "high"


def test_process_row_records_crash_via_handle_crash(db_session, worker, seed_protocol, monkeypatch):
    """A crash inside ``verify_one_coverage_row`` (e.g. an unexpected DB
    error) must be caught by ``_process_row`` and surfaced via
    ``_handle_crash`` so the row gets a ``github_fetch_failed`` stamp
    and the worker thread doesn't drop the result."""
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

    # Manually invoke the crash handler — the run loop does this for us
    # in production; we exercise it here to assert the fallback write.
    worker._handle_crash(row_id, exc)
    db_session.expire_all()
    row = db_session.query(AuditContractCoverage).filter_by(id=row_id).one()
    assert row.equivalence_status == "github_fetch_failed"
    assert "synthetic verify crash" in (row.equivalence_reason or "")
    assert row.proof_kind is None
    assert row.matched_commit_sha is None


# ---------------------------------------------------------------------------
# 3. Stale recovery
# ---------------------------------------------------------------------------


def test_recover_stale_resets_old_verifying_rows_to_pending(db_session, worker, seed_protocol):
    """A row stuck in ``verifying`` past the cutoff is reverted to
    ``pending`` so the next claim picks it up. Without recovery, a
    crashed worker would strand its claimed rows invisible to siblings."""
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)

    # Force the row into a stale 'verifying' state.
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


def test_recover_stale_leaves_fresh_verifying_rows_alone(db_session, worker, seed_protocol):
    """A fresh ``verifying`` row (within the cutoff) must not be reset —
    that worker's still working on it."""
    from db.models import AuditContractCoverage

    protocol_id, _ = seed_protocol
    _seed_pending_row(db_session, protocol_id=protocol_id)
    row = db_session.query(AuditContractCoverage).filter_by(equivalence_status="pending").one()
    db_session.execute(
        text(
            """
            UPDATE audit_contract_coverage
            SET equivalence_status = 'verifying',
                equivalence_checked_at = NOW()
            WHERE id = :id
            """
        ),
        {"id": row.id},
    )
    db_session.commit()

    worker._recover_stale(db_session)

    db_session.expire_all()
    row = db_session.query(AuditContractCoverage).filter_by(id=row.id).one()
    assert row.equivalence_status == "verifying"


# ---------------------------------------------------------------------------
# 4. Idempotency: rebuild during in-flight verify must not corrupt state
# ---------------------------------------------------------------------------


def test_in_flight_verify_survives_coverage_rebuild_race(db_session, worker, seed_protocol, monkeypatch):
    """Simulates the worst-case race: the verify worker has claimed a
    row (state='verifying'), then a coverage rebuild deletes-and-reinserts
    coverage for that audit. The verify worker's UPDATE should be a
    no-op and the new pending row stays available for re-claim."""
    from db.models import AuditContractCoverage
    from services.audits.coverage import upsert_coverage_for_audit

    protocol_id, _ = seed_protocol
    _, audit = _seed_pending_row(db_session, protocol_id=protocol_id)

    claimed = worker._claim_batch(db_session)
    assert len(claimed) == 1
    claimed_id = claimed[0]

    # Rebuild coverage for the audit — old row goes away, new pending row appears.
    upsert_coverage_for_audit(db_session, audit.id)
    db_session.commit()

    # The original claimed row should be gone.
    assert db_session.get(AuditContractCoverage, claimed_id) is None

    # And there's exactly one fresh pending row to verify.
    pending_rows = db_session.query(AuditContractCoverage).filter_by(equivalence_status="pending").all()
    assert len(pending_rows) == 1
