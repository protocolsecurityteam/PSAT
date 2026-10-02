"""The reconciler that restores current materializations across a schema bump
with an explicit rebuild budget.

A bump to ``ANALYSIS_SCHEMA_VERSION`` makes every existing row read as a miss at
once, and without this the whole monitored fleet quietly falls back to
baseline-only watching. The backlog is published while it is still small,
and the rebuild work is capped, counted, and reported rather than emitted.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

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
from tests.support.materializations import cm_db  # noqa: F401  (fixture, registered by import)


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
def test_an_in_flight_rebuild_is_not_re_queued_even_when_it_is_old(cm_db, monkeypatch):
    addr = "0x" + "50" * 20
    _monitored(cm_db, addr)
    _queue_rebuild_jobs(cm_db, [addr], created_at=datetime.now(timezone.utc) - timedelta(days=9))
    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "5")
    candidates, backlog = plan_rebuilds(cm_db)
    assert candidates == []
    # Outside the budget window but still outstanding.
    assert backlog["queued_last_24h"] == 0
    assert backlog["attempted_not_yet_resolved"] == 1


@requires_postgres
def test_a_rebuild_on_one_chain_does_not_suppress_the_same_address_on_another(cm_db, monkeypatch):
    """Keying on the address alone would leave the twin unattempted."""
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
    """Otherwise a crashed worker's claim exempts the contract forever."""
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
def test_zero_budget_queues_nothing_but_still_reports_the_backlog(cm_db, monkeypatch):
    for addr in ["0x" + f"{n:02x}" * 20 for n in range(30, 33)]:
        _monitored(cm_db, addr)
    monkeypatch.setenv("PSAT_MATERIALIZATION_REBUILD_BUDGET_PER_DAY", "0")
    candidates, backlog = plan_rebuilds(cm_db)
    assert candidates == []
    assert backlog["contracts"] == 3
    assert backlog["queueable_now"] == 0
