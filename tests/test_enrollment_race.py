"""Regression tests for the whole-protocol enrollment race (PR #139 live errors).

Two independent failures combined to mark a *completed* policy job
``failed_terminal`` when several policy workers enrolled the same protocol
concurrently:

1. ``enroll_protocol_contracts`` did a check-then-insert per contract, so two
   workers that both passed the existence check raced to ``flush()`` and the
   loser hit ``uq_monitored_contract_address_chain`` — a ``UniqueViolation``
   that poisoned the SQLAlchemy session.

2. ``PolicyWorker.process`` swallowed that ``IntegrityError`` but never rolled
   the session back, so the poisoned session escaped ``process()`` and the
   worker's success path (advance/complete job) re-raised
   ``PendingRollbackError`` → terminal failure.

The fixes: a race-safe ``ON CONFLICT DO NOTHING`` insert (so a concurrent
loser is a no-op, never a violation), and a ``session.rollback()`` in the
auto-enroll failure handler (so any benign enroll hiccup degrades instead of
killing the job). Both are exercised against a real Postgres — the race lives
in the unique index and the session-poisoning semantics, which SQLite can't
reproduce.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import Select, create_engine, func, select
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStage, JobStatus, MonitoredContract, Protocol
from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = requires_postgres

PROTO_NAME = "__test_enrollment_race__"
DUP_POISON_ADDR = "0x" + "ab" * 20


@pytest.fixture()
def race_session():
    """Real Postgres session matching the production ``SessionLocal`` shape
    (``expire_on_commit=False``); cleans up only this test's rows."""
    engine = create_engine(DATABASE_URL)
    session = Session(engine, expire_on_commit=False)
    try:
        yield session
    finally:
        session.rollback()
        proto = session.execute(select(Protocol).where(Protocol.name == PROTO_NAME)).scalar_one_or_none()
        if proto is not None:
            session.query(MonitoredContract).filter(MonitoredContract.protocol_id == proto.id).delete()
            session.query(Job).filter(Job.protocol_id == proto.id).delete()
            session.query(Contract).filter(Contract.protocol_id == proto.id).delete()
            session.delete(proto)
        session.query(MonitoredContract).filter(MonitoredContract.address == DUP_POISON_ADDR).delete()
        session.commit()
        session.close()
        engine.dispose()


def _is_monitored_contract_select(statement: object) -> bool:
    """True for the per-contract existence-check SELECT (the TOCTOU read)."""
    return isinstance(statement, Select) and "monitored_contracts" in str(statement).lower()


def _commit_conflicting_monitored_contract(protocol_id: int, address: str) -> None:
    """Insert + commit a clashing ``(address, ethereum)`` row from a SEPARATE
    connection — the concurrent winner the enrolling session can't see until
    after its own existence check has already returned empty."""
    engine = create_engine(DATABASE_URL)
    other = Session(engine, expire_on_commit=False)
    try:
        other.add(
            MonitoredContract(
                id=uuid.uuid4(),
                address=address,
                chain="ethereum",
                protocol_id=protocol_id,
                contract_type="regular",
                monitoring_config={},
                last_known_state={},
                last_scanned_block=0,
                needs_polling=False,
                is_active=True,
                enrollment_source="auto",
            )
        )
        other.commit()
    finally:
        other.close()
        engine.dispose()


def _poisoning_enroll(session, protocol_id, *args, **kwargs):
    """Stand-in for ``maybe_enroll_protocol`` that reproduces the benign race's
    effect: a duplicate ``(address, chain)`` flush raises ``IntegrityError`` and
    leaves the session pending-rollback, exactly as the concurrent
    uq_monitored_contract_address_chain loser did. Two adds so the flush — not
    the second add — is what raises."""
    for _ in range(2):
        session.add(
            MonitoredContract(id=uuid.uuid4(), address=DUP_POISON_ADDR, chain="ethereum", contract_type="regular")
        )
    session.flush()


def _seed_policy_job(session):
    """A committed processing policy job with a protocol but no Contract row, so
    ``process`` skips every DB-write branch and reaches the auto-enroll block."""
    proto = Protocol(name=PROTO_NAME)
    session.add(proto)
    session.flush()
    job = Job(
        address="0x" + "b7" * 20,
        name="TestContract",
        protocol_id=proto.id,
        status=JobStatus.processing,
        stage=JobStage.policy,
        request={"rpc_url": "https://rpc.example"},
    )
    session.add(job)
    session.commit()
    return job


def _stub_policy_internals(monkeypatch, job_address):
    """Stub the heavy / RPC policy internals so ``process`` runs offline, and
    wire ``maybe_enroll_protocol`` to the session-poisoning stand-in."""
    from workers.policy_worker import PolicyWorker

    artifacts = {
        "contract_analysis": {"contract_address": job_address, "contract_name": "TestContract", "functions": []},
        "control_snapshot": {"contract_address": job_address, "controller_values": {}},
        "resolved_control_graph": {"nodes": [], "edges": []},
        "control_tracking_plan": {"schema_version": "0.1", "contract_address": job_address},
    }
    monkeypatch.setattr("workers.policy_worker.get_artifact", lambda _s, _j, name: artifacts.get(name))
    monkeypatch.setattr("workers.policy_worker.store_artifact", lambda *a, **kw: None)
    monkeypatch.setattr("workers.policy_worker._load_nested_artifacts", lambda *a, **kw: {})
    monkeypatch.setattr(
        "workers.policy_worker.build_effective_permissions",
        lambda *a, **kw: {"schema_version": "1", "functions": []},
    )
    monkeypatch.setattr("workers.policy_worker.resolve_control_graph", lambda **kw: ({}, {}))
    monkeypatch.setattr("workers.policy_worker.build_principal_labels", lambda *a, **kw: {"principals": []})
    monkeypatch.setattr(
        PolicyWorker,
        "_resolve_authority",
        lambda self, *a, **kw: {"principal_resolution": {"status": "no_authority"}, "authority_snapshot": None},
    )
    monkeypatch.setattr(PolicyWorker, "_enrich_cross_contract", lambda self, *a, **kw: {})
    monkeypatch.setattr("services.monitoring.enrollment.maybe_enroll_protocol", _poisoning_enroll)


def test_concurrent_enroll_insert_is_race_safe(race_session):
    """A concurrent enroll of the same ``(address, chain)`` landing in the
    window between the existence check and the insert must be a no-op, not a
    session-poisoning ``UniqueViolation``.

    Pre-fix (``session.add`` + ``flush``) this raised ``IntegrityError`` out of
    ``enroll_protocol_contracts``; post-fix ``ON CONFLICT DO NOTHING`` swallows
    only the unique conflict and the run completes with exactly one row.
    """
    from services.monitoring.enrollment import maybe_enroll_protocol

    proto = Protocol(name=PROTO_NAME)
    race_session.add(proto)
    race_session.flush()
    addr = "0x" + "a7" * 20
    race_session.add(
        Contract(address=addr, chain="ethereum", protocol_id=proto.id, contract_name="RaceContract", is_proxy=False)
    )
    race_session.add(Job(address=addr, protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    race_session.commit()

    # Inject the concurrent winner right after enroll's existence-check SELECT
    # returns (its snapshot already taken → still sees nothing → takes the
    # insert path), so the insert collides with a committed row.
    injected = {"done": False}
    orig_execute = race_session.execute

    def execute_then_inject(statement, *args, **kwargs):
        result = orig_execute(statement, *args, **kwargs)
        if not injected["done"] and _is_monitored_contract_select(statement):
            injected["done"] = True
            _commit_conflicting_monitored_contract(proto.id, addr)
        return result

    race_session.execute = execute_then_inject  # type: ignore[method-assign]
    try:
        with patch("services.monitoring.enrollment.rpc_request", return_value="0x100"):
            # No PendingRollbackError / IntegrityError may escape.
            fired = maybe_enroll_protocol(race_session, proto.id, "http://rpc")
    finally:
        del race_session.execute  # restore the bound method

    assert injected["done"], "TOCTOU injection never fired — the test would be vacuous"
    assert fired is True

    rows = race_session.execute(select(MonitoredContract).where(MonitoredContract.address == addr)).scalars().all()
    assert len(rows) == 1, f"expected exactly one row for {addr}, got {len(rows)}"
    # Session survived the benign race and is still usable.
    assert race_session.execute(select(func.count()).select_from(MonitoredContract)).scalar() >= 1


def test_benign_enroll_race_does_not_poison_policy_job(race_session, monkeypatch):
    """A failed auto-enroll (here the same unique-violation that poisons the
    session) must be rolled back inside ``PolicyWorker.process`` so the worker's
    success path can still complete the job.

    Pre-fix the poisoned session escaped ``process()`` and the next statement
    raised ``PendingRollbackError`` → ``failed_terminal``. Post-fix the handler
    rolls back, so the session is usable again afterwards. The live SELECT below
    is the assertion that fails without the rollback.
    """
    from workers.policy_worker import PolicyWorker

    job = _seed_policy_job(race_session)
    _stub_policy_internals(monkeypatch, job.address)

    PolicyWorker().process(race_session, job)  # must not raise

    # The poisoned session was rolled back inside the handler, so it is usable
    # for the post-process success path. Without the fix this SELECT raises
    # PendingRollbackError.
    assert race_session.execute(select(func.count()).select_from(Job)).scalar() >= 1
    # And the doomed enroll rows were discarded — nothing leaked.
    leaked = race_session.execute(
        select(func.count()).select_from(MonitoredContract).where(MonitoredContract.address == DUP_POISON_ADDR)
    ).scalar()
    assert leaked == 0
