"""The reconciler that keeps invariant 8 true across a schema bump — at a price
somebody decided (invariant 11).

A bump to ``ANALYSIS_SCHEMA_VERSION`` makes every existing row read as a miss at
once, and without this the whole monitored fleet quietly falls back to
baseline-only watching. The backlog is published while it is still small (F9c),
and the rebuild work is capped, counted, and reported rather than emitted.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from db.contract_materializations import ANALYSIS_SCHEMA_VERSION
from db.models import ContractMaterialization, Job, JobStage, JobStatus, MonitoredContract
from services.monitoring.materialization_reconciler import (
    REASON_FAILED,
    REASON_IN_PROGRESS,
    REASON_NO_ROW,
    REASON_SUPERSEDED_VERSION,
    REBUILD_REQUEST_KEY,
    materialization_backlog,
    plan_rebuilds,
)
from tests.conftest import requires_postgres


@pytest.fixture()
def cm_db(db_session, monkeypatch):
    """Route the module's own sessions at the test DB, storage off (inline JSONB)."""
    import os

    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.skip("TEST_DATABASE_URL not set")
    engine = create_engine(test_url)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    monkeypatch.setattr("db.contract_materializations.SessionLocal", factory)
    monkeypatch.setattr("db.contract_materializations.get_storage_client", lambda: None)
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    yield db_session
    db_session.query(ContractMaterialization).delete()
    db_session.commit()
    engine.dispose()


def _monitored(session, address: str, *, chain: str = "ethereum") -> MonitoredContract:
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=address.lower(),
        chain=chain,
        contract_type="regular",
        monitoring_config={},
        last_known_state={},
        last_scanned_block=0,
        needs_polling=False,
        is_active=True,
    )
    session.add(mc)
    session.commit()
    return mc


def _queue_rebuild_jobs(
    session,
    addresses: list[str],
    *,
    created_at: datetime | None = None,
    chain_id: int = 1,
) -> None:
    for address in addresses:
        session.add(
            Job(
                id=uuid.uuid4(),
                address=address,
                status=JobStatus.queued,
                stage=JobStage.discovery,
                chain_id=chain_id,
                request={"address": address, "force": True, REBUILD_REQUEST_KEY: True},
                created_at=created_at or datetime.now(timezone.utc),
            )
        )
    session.commit()


def _materialization(
    session,
    address: str,
    keccak: str,
    *,
    status: str,
    version: int,
    builder_started_at: datetime | None = None,
) -> None:
    session.add(
        ContractMaterialization(
            chain="1",
            bytecode_keccak=keccak,
            address=address.lower(),
            status=status,
            builder_started_at=builder_started_at,
            analysis_schema_version=version,
        )
    )
    session.commit()


@requires_postgres
def test_backlog_names_the_reason_per_contract(cm_db):
    addrs = ["0x" + f"{n:02x}" * 20 for n in range(1, 6)]
    for addr in addrs:
        _monitored(cm_db, addr)
    _materialization(cm_db, addrs[0], "0x" + "01" * 32, status="ready", version=ANALYSIS_SCHEMA_VERSION)
    _materialization(cm_db, addrs[1], "0x" + "02" * 32, status="ready", version=ANALYSIS_SCHEMA_VERSION - 1)
    _materialization(cm_db, addrs[2], "0x" + "03" * 32, status="failed", version=ANALYSIS_SCHEMA_VERSION)
    _materialization(
        cm_db,
        addrs[3],
        "0x" + "04" * 32,
        status="building",
        version=ANALYSIS_SCHEMA_VERSION,
        builder_started_at=datetime.now(timezone.utc),
    )

    backlog = materialization_backlog(cm_db)
    assert backlog["contracts"] == 4
    assert backlog["by_reason"] == {
        REASON_SUPERSEDED_VERSION: 1,
        REASON_FAILED: 1,
        REASON_IN_PROGRESS: 1,
        REASON_NO_ROW: 1,
    }
    assert sum(backlog["by_reason"].values()) == backlog["contracts"]


@requires_postgres
def test_rebuild_plan_is_capped_and_excludes_in_flight_builds(cm_db, monkeypatch):
    addrs = ["0x" + f"{n:02x}" * 20 for n in range(10, 16)]
    for addr in addrs:
        _monitored(cm_db, addr)
    _materialization(
        cm_db,
        addrs[0],
        "0x" + "10" * 32,
        status="building",
        version=ANALYSIS_SCHEMA_VERSION,
        builder_started_at=datetime.now(timezone.utc),
    )

    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "2")
    candidates, backlog = plan_rebuilds(cm_db)
    assert backlog["budget_per_day"] == 2
    assert len(candidates) == 2
    assert all(c.reason != REASON_IN_PROGRESS for c in candidates)
    # Stable order, so a repeated dry run proposes the same work.
    assert [c.address for c in candidates] == [c.address for c in plan_rebuilds(cm_db)[0]]


@requires_postgres
def test_budget_counts_what_it_already_spent(cm_db, monkeypatch):
    for addr in ["0x" + f"{n:02x}" * 20 for n in range(20, 25)]:
        _monitored(cm_db, addr)
    now = datetime.now(timezone.utc)
    cm_db.add(
        Job(
            id=uuid.uuid4(),
            address="0x" + "20" * 20,
            status=JobStatus.queued,
            stage=JobStage.discovery,
            request={REBUILD_REQUEST_KEY: True, "address": "0x" + "20" * 20},
            created_at=now - timedelta(hours=2),
        )
    )
    # Older than the window, and an unrelated job — neither is this budget.
    cm_db.add(
        Job(
            id=uuid.uuid4(),
            address="0x" + "21" * 20,
            status=JobStatus.queued,
            stage=JobStage.discovery,
            request={REBUILD_REQUEST_KEY: True},
            created_at=now - timedelta(days=3),
        )
    )
    cm_db.add(
        Job(
            id=uuid.uuid4(),
            address="0x" + "22" * 20,
            status=JobStatus.queued,
            stage=JobStage.discovery,
            request={"reanalysis_trigger": "owner"},
            created_at=now,
        )
    )
    cm_db.commit()

    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "3")
    backlog = materialization_backlog(cm_db, now=now)
    assert backlog["queued_last_24h"] == 1
    assert backlog["queueable_now"] == 2
    assert len(plan_rebuilds(cm_db, now=now)[0]) == 2


@requires_postgres
def test_a_second_pass_moves_down_the_list_instead_of_re_proposing_the_head(cm_db, monkeypatch):
    """The 24h counter bounds how MANY jobs are issued, not WHICH. Without an
    identity exclusion every pass re-proposes the head, and a contract that
    keeps failing to rebuild starves the tail forever."""
    addrs = ["0x" + f"{n:02x}" * 20 for n in range(40, 45)]
    for addr in addrs:
        _monitored(cm_db, addr)
    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "2")

    first, _ = plan_rebuilds(cm_db)
    assert len(first) == 2
    _queue_rebuild_jobs(cm_db, [c.address for c in first])

    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "4")
    second, backlog = plan_rebuilds(cm_db)
    assert {c.address for c in second}.isdisjoint({c.address for c in first})
    assert backlog["attempted_not_yet_resolved"] == 2


@requires_postgres
def test_an_in_flight_rebuild_is_not_re_queued_even_when_it_is_old(cm_db, monkeypatch):
    addr = "0x" + "50" * 20
    _monitored(cm_db, addr)
    _queue_rebuild_jobs(cm_db, [addr], created_at=datetime.now(timezone.utc) - timedelta(days=9))
    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "5")
    candidates, backlog = plan_rebuilds(cm_db)
    assert candidates == []
    # Outside the 24h window, so it is not budget already spent — but it is
    # still an attempt outstanding, and those are different facts.
    assert backlog["queued_last_24h"] == 0
    assert backlog["attempted_not_yet_resolved"] == 1


@requires_postgres
def test_a_rebuild_on_one_chain_does_not_suppress_the_same_address_on_another(cm_db, monkeypatch):
    """The same address on two chains is two deployments with two
    materializations; keying the exclusion on the address alone would leave the
    twin permanently unattempted."""
    addr = "0x" + "80" * 20
    _monitored(cm_db, addr, chain="ethereum")
    _monitored(cm_db, addr, chain="base")
    _queue_rebuild_jobs(cm_db, [addr], chain_id=1)

    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "5")
    candidates, backlog = plan_rebuilds(cm_db)
    assert [(c.chain, c.address) for c in candidates] == [("base", addr)]
    assert backlog["attempted_not_yet_resolved"] == 1


@requires_postgres
def test_a_resolved_attempt_is_not_outstanding_work(cm_db, monkeypatch):
    """The count answers "how much issued work has not landed yet"; an attempt
    whose contract now has its row has landed."""
    resolved, outstanding = "0x" + "90" * 20, "0x" + "91" * 20
    _monitored(cm_db, resolved)
    _monitored(cm_db, outstanding)
    _materialization(cm_db, resolved, "0x" + "90" * 32, status="ready", version=ANALYSIS_SCHEMA_VERSION)
    _queue_rebuild_jobs(cm_db, [resolved, outstanding])

    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "5")
    backlog = materialization_backlog(cm_db)
    assert backlog["queued_last_24h"] == 2
    assert backlog["attempted_not_yet_resolved"] == 1


@requires_postgres
def test_a_stale_builder_claim_is_rebuildable_not_in_flight(cm_db, monkeypatch):
    """A crashed worker's leftover claim would otherwise read as "a builder is
    running" forever and exempt the contract from every rebuild pass."""
    fresh, stale = "0x" + "60" * 20, "0x" + "61" * 20
    _monitored(cm_db, fresh)
    _monitored(cm_db, stale)
    now = datetime.now(timezone.utc)
    for addr, keccak, started in ((fresh, "0x" + "60" * 32, now), (stale, "0x" + "61" * 32, now - timedelta(hours=6))):
        cm_db.add(
            ContractMaterialization(
                chain="1",
                bytecode_keccak=keccak,
                address=addr,
                status="building",
                builder_started_at=started,
                analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
            )
        )
    cm_db.commit()

    backlog = materialization_backlog(cm_db)
    assert backlog["by_reason"] == {REASON_IN_PROGRESS: 1, REASON_NO_ROW: 1}
    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "5")
    assert [c.address for c in plan_rebuilds(cm_db)[0]] == [stale]


@requires_postgres
def test_queued_rebuilds_force_past_the_static_cache(cm_db, monkeypatch):
    """Discovery's same-address static cache is not version-gated, so a rebuild
    issued after a schema bump would copy the superseded era's artifacts, skip
    analysis, and clear the backlog without re-analyzing anything."""
    from scripts.reconcile_materializations import queue_rebuilds

    addr = "0x" + "70" * 20
    _monitored(cm_db, addr)
    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "1")
    candidates, _ = plan_rebuilds(cm_db)
    assert queue_rebuilds(cm_db, candidates)["queued"] == 1

    job = cm_db.execute(select(Job).where(Job.address == addr)).scalar_one()
    assert job.request["force"] is True
    assert job.request[REBUILD_REQUEST_KEY] is True


@requires_postgres
def test_zero_budget_queues_nothing_but_still_reports_the_backlog(cm_db, monkeypatch):
    for addr in ["0x" + f"{n:02x}" * 20 for n in range(30, 33)]:
        _monitored(cm_db, addr)
    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "0")
    candidates, backlog = plan_rebuilds(cm_db)
    assert candidates == []
    assert backlog["contracts"] == 3
    assert backlog["queueable_now"] == 0


@requires_postgres
def test_fleet_status_publishes_the_backlog(cm_db):
    """F9c rides the F9a surface: the counts are published unconditionally, with
    no invented alert threshold (see ``ops_alerts.collect_materialization_backlog``)."""
    from services.aggregations import build_fleet_status

    _monitored(cm_db, "0x" + "40" * 20)
    backlog = build_fleet_status(cm_db)["watchers"]["materialization_backlog"]
    assert backlog["contracts"] == 1
    assert backlog["by_reason"] == {REASON_NO_ROW: 1}
    assert "budget_per_day" in backlog and "basis" in backlog
