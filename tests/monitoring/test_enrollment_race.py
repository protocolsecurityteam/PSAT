"""Concurrent enrolls raced on ``uq_monitored_contract_address_chain`` and poisoned the session, failing a completed
policy job (PR #139). Needs real Postgres for the unique-index race.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from db.models import Contract, Job, JobStage, JobStatus, MonitoredContract, Protocol
from tests.conftest import DATABASE_URL, requires_postgres

pytestmark = requires_postgres

PROTO_NAME = "__test_enrollment_race__"
DUP_POISON_ADDR = "0x" + "ab" * 20


@pytest.fixture()
def race_session():
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


def _poisoning_enroll(session, protocol_id, *args, **kwargs):
    """Two adds, so the flush, not the second add, raises."""
    for _ in range(2):
        session.add(
            MonitoredContract(id=uuid.uuid4(), address=DUP_POISON_ADDR, chain="ethereum", contract_type="regular")
        )
    session.flush()


def _seed_policy_job(session):
    """No Contract row, so ``process`` reaches the auto-enroll block."""
    proto = Protocol(name=PROTO_NAME)
    session.add(proto)
    session.flush()
    job = Job(
        address="0x" + "b7" * 20,
        name="TestContract",
        protocol_id=proto.id,
        chain_id=1,
        status=JobStatus.processing,
        stage=JobStage.policy,
        request={"rpc_url": "https://rpc.example", "chain": "ethereum"},
    )
    session.add(job)
    session.commit()
    return job


def _stub_policy_internals(monkeypatch, job_address):
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


def test_benign_enroll_race_does_not_poison_policy_job(race_session, monkeypatch):
    """The live SELECT fails without the rollback."""
    from workers.policy_worker import PolicyWorker

    job = _seed_policy_job(race_session)
    _stub_policy_internals(monkeypatch, job.address)

    PolicyWorker().process(race_session, job)  # must not raise

    assert race_session.execute(select(func.count()).select_from(Job)).scalar() >= 1
    leaked = race_session.execute(
        select(func.count()).select_from(MonitoredContract).where(MonitoredContract.address == DUP_POISON_ADDR)
    ).scalar()
    assert leaked == 0
