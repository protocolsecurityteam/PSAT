"""Coverage states must be visible to an operator.

136 of 183 monitored contracts were watching on the hand-rolled baseline
registry alone, and the monitor page rendered them exactly like the 21 watching
a full analyzer-derived plan: quiet. "Quiet because nothing happened" and "quiet
because nothing is being watched" are different facts, and the census is what
keeps them apart on ``/api/fleet`` and in the ops watchdog.
"""

from __future__ import annotations

import logging
import uuid

import pytest
from sqlalchemy import select

from db.models import ContractMaterialization, MonitoredContract
from services.aggregations import build_fleet_status
from services.monitoring.tracking_plan_state import (
    CONFIG_SUPPLIED_BY_CALLER,
    CONTRACT_NOT_ANALYZED,
    NO_CURRENT_MATERIALIZATION,
    NOT_DETERMINED_KEY,
    READY_FRESH_PROVEN_EMPTY,
    READY_FRESH_WITH_TOPICS,
    READY_STALE,
    TRACKED_TOPICS_KEY,
    TRACKED_TOPICS_STALE_SINCE_KEY,
    UNCLASSIFIED,
    plan_coverage_counts,
)
from services.monitoring.verify_status import (
    CENSUS_BASIS,
    CONTROLLER_STATUS_PREFIX,
    VERIFY_ERROR,
    VERIFY_NO_READ_BINDING,
    VERIFY_OVER_BUDGET,
)

_TOPICS = [{"topic0": "0x" + "ab" * 32, "event_type": "authority_updated"}]


def _addr(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


def _mk(session, n: int, config, *, chain: str = "ethereum", is_active: bool = True):
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=_addr(n),
        chain=chain,
        contract_type="regular",
        monitoring_config=config,
        last_known_state={},
        last_scanned_block=0,
        needs_polling=False,
        is_active=is_active,
    )
    session.add(mc)
    session.commit()
    return mc


@pytest.fixture()
def fleet(db_session):
    _mk(db_session, 1, {TRACKED_TOPICS_KEY: _TOPICS})
    _mk(db_session, 2, {TRACKED_TOPICS_KEY: []})
    _mk(
        db_session,
        3,
        {
            TRACKED_TOPICS_KEY: _TOPICS,
            NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION,
            TRACKED_TOPICS_STALE_SINCE_KEY: "2026-08-04T01:42:00+00:00",
        },
    )
    _mk(db_session, 4, {NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION})
    _mk(db_session, 5, {NOT_DETERMINED_KEY: CONTRACT_NOT_ANALYZED})
    _mk(db_session, 6, {NOT_DETERMINED_KEY: CONFIG_SUPPLIED_BY_CALLER})
    _mk(db_session, 7, {"watch_ownership": True})  # pre-discriminant row
    _mk(db_session, 8, None)  # no config at all
    _mk(db_session, 9, {TRACKED_TOPICS_KEY: _TOPICS}, is_active=False)  # not watched at all
    return db_session


def test_census_partitions_the_active_fleet(fleet):
    counts = plan_coverage_counts(fleet)

    assert counts["contracts"] == 8  # the inactive row is not being watched
    assert counts[READY_FRESH_WITH_TOPICS] == 1
    assert counts[READY_FRESH_PROVEN_EMPTY] == 1
    assert counts[READY_STALE] == 1
    assert counts["not_determined"] == {
        NO_CURRENT_MATERIALIZATION: 1,
        CONTRACT_NOT_ANALYZED: 1,
        CONFIG_SUPPLIED_BY_CALLER: 1,
    }
    assert counts["not_determined_total"] == 3
    assert counts[UNCLASSIFIED] == 2

    partition = (
        counts[READY_FRESH_WITH_TOPICS]
        + counts[READY_FRESH_PROVEN_EMPTY]
        + counts[READY_STALE]
        + counts["not_determined_total"]
        + counts[UNCLASSIFIED]
    )
    assert partition == counts["contracts"]


def test_ready_stale_row_needs_its_staleness_stamp(fleet, db_session):
    """The census reads the same witness the classifier does."""
    row = db_session.execute(select(MonitoredContract).where(MonitoredContract.address == _addr(3))).scalar_one()
    config = dict(row.monitoring_config or {})
    del config[TRACKED_TOPICS_STALE_SINCE_KEY]
    row.monitoring_config = config
    db_session.commit()

    counts = plan_coverage_counts(db_session)
    assert counts[READY_STALE] == 0
    assert counts["not_determined"][NO_CURRENT_MATERIALIZATION] == 2
    assert counts["contracts"] == 8  # still a partition


def test_failed_analysis_is_reported_as_an_overlay(db_session):
    """The reason is reported as an overlay without double-counting."""
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    _mk(db_session, 1, {NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION})
    row = ContractMaterialization(
        chain="1",
        bytecode_keccak=("0x" + uuid.uuid4().hex * 2)[:66],
        address=_addr(1),
        status="failed",
        analysis_schema_version=ANALYSIS_SCHEMA_VERSION,
    )
    db_session.add(row)
    db_session.commit()
    try:
        counts = plan_coverage_counts(db_session)
        assert counts["analysis_failed"] == 1
        assert counts["not_determined"][NO_CURRENT_MATERIALIZATION] == 1
        assert counts["contracts"] == 1
    finally:
        db_session.delete(row)
        db_session.commit()


def test_census_is_empty_and_total_free_of_a_none_config(db_session):
    counts = plan_coverage_counts(db_session)
    assert counts["contracts"] == 0
    assert counts["not_determined"] == {}
    assert counts["analysis_failed"] == 0


def test_coverage_alarm_is_silent_until_a_threshold_is_set(fleet, monkeypatch):
    """An acceptable shortfall is operator policy; inventing one would page on a long-standing state."""
    from services.monitoring import ops_alerts

    monkeypatch.delenv("PSAT_PLAN_COVERAGE_ALERT", raising=False)
    assert ops_alerts._coverage_alert_threshold() == 0
    assert "tracking_plan_coverage" not in ops_alerts._current_problems({}, _now(), None)


def test_coverage_alarm_fires_over_the_threshold(fleet, monkeypatch):
    from services.monitoring import ops_alerts

    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "2")
    coverage = ops_alerts.collect_plan_coverage(fleet)
    # Caller-supplied rows are an operator's choice and not paged on.
    problems = ops_alerts._current_problems({}, _now(), coverage)
    assert coverage["not_determined"][CONFIG_SUPPLIED_BY_CALLER] == 1
    assert problems["tracking_plan_coverage"]["uncovered"] == 3
    assert problems["tracking_plan_coverage"]["kind"] == "coverage"

    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "3")
    assert "tracking_plan_coverage" not in ops_alerts._current_problems({}, _now(), coverage)


@pytest.fixture()
def _clean_heartbeats(db_session):
    """Teardown doesn't sweep ``worker_heartbeats``, so a leftover row would read as a live daemon."""
    from db.models import WorkerHeartbeat

    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()
    yield
    db_session.rollback()
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()


# ---------------------------------------------------------------------------
# Verification-read gaps (the verification-gap counter, wired onto this surface)
# ---------------------------------------------------------------------------


def _marked(session, n: int):
    mc = _mk(session, n, {TRACKED_TOPICS_KEY: _TOPICS})
    mc.last_poll_status = {
        "rate": VERIFY_ERROR,
        "fee": VERIFY_OVER_BUDGET,
        f"{CONTROLLER_STATUS_PREFIX}state_variable:owner": VERIFY_NO_READ_BINDING,
    }
    session.commit()
    return mc


def test_fleet_publishes_the_verification_gap_census(db_session):
    """A current plan does not mean its hint controllers were verified."""
    _marked(db_session, 11)

    watchers = build_fleet_status(db_session)["watchers"]
    assert watchers["plan_coverage"][READY_FRESH_WITH_TOPICS] == 1
    gaps = watchers["verification_gaps"]
    assert gaps["read_failed"] == 1
    assert gaps["over_budget"] == 1
    assert gaps["no_read_binding"] == 1
    assert gaps["contracts_affected"] == 1


def test_the_gap_census_says_what_its_zeroes_mean(api_client, fleet):
    """The poller erases markers, so this is a point-in-time census."""
    gaps = api_client.get("/api/fleet").json()["watchers"]["verification_gaps"]
    assert gaps == {
        "read_failed": 0,
        "over_budget": 0,
        "no_read_binding": 0,
        "contracts_affected": 0,
        "basis": CENSUS_BASIS,
    }


def test_the_tick_records_the_census_only_when_something_is_marked(db_session, _clean_heartbeats, monkeypatch, caplog):
    """The timestamped log line survives erased markers."""
    from services.monitoring import ops_alerts

    monkeypatch.setattr(ops_alerts, "_webhook_url", lambda: None)
    mc = _mk(db_session, 13, {TRACKED_TOPICS_KEY: _TOPICS})

    with caplog.at_level(logging.INFO, logger="services.monitoring.ops_alerts"):
        ops_alerts.run_ops_alert_tick(db_session)
    assert not _gap_records(caplog)

    mc.last_poll_status = {"rate": VERIFY_ERROR}
    db_session.commit()
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="services.monitoring.ops_alerts"):
        ops_alerts.run_ops_alert_tick(db_session)
    record = _gap_records(caplog)[0]
    assert record.read_failed == 1
    assert record.basis == CENSUS_BASIS


def _gap_records(caplog):
    return [r for r in caplog.records if "verification read" in r.getMessage()]


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
