"""F9a — coverage states must be visible to an operator.

136 of 183 monitored contracts were watching on the hand-rolled baseline
registry alone, and the monitor page rendered them exactly like the 21 watching
a full analyzer-derived plan: quiet. "Quiet because nothing happened" and "quiet
because nothing is being watched" are different facts, and the census is what
keeps them apart on ``/api/fleet`` and in the ops watchdog.
"""

from __future__ import annotations

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
    """One row in each plan state, mirroring the audited census shape."""
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


def test_stale_is_neither_fresh_nor_ignorance(fleet):
    """The state F5 mints has to survive to the consumer as its own number:
    folding it into ready collapses "we cannot re-read this" and folding it into
    not-determined discards a watch list we do hold."""
    counts = plan_coverage_counts(fleet)
    assert counts[READY_STALE] == 1
    assert NO_CURRENT_MATERIALIZATION not in {READY_STALE}
    assert counts["not_determined"][NO_CURRENT_MATERIALIZATION] == 1  # the row with no topics only


def test_failed_analysis_is_reported_as_an_overlay(db_session):
    """A failed build reads as ``no_current_materialization`` at enrollment — the
    reader cannot see why. The census names the reason without double-counting:
    the row stays in its partition bucket and is additionally reported here."""
    from db.contract_materializations import ANALYSIS_SCHEMA_VERSION

    _mk(db_session, 1, {NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION})
    row = ContractMaterialization(
        # chain-id token, never the monitored_contracts chain NAME
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


def test_fleet_status_publishes_the_census(fleet):
    coverage = build_fleet_status(fleet)["watchers"]["plan_coverage"]
    assert coverage["contracts"] == 8
    assert coverage[READY_STALE] == 1
    assert coverage["not_determined"][CONTRACT_NOT_ANALYZED] == 1


def test_fleet_endpoint_exposes_the_census(api_client, fleet):
    body = api_client.get("/api/fleet").json()
    assert body["watchers"]["plan_coverage"]["not_determined_total"] == 3


# ---------------------------------------------------------------------------
# Ops watchdog
# ---------------------------------------------------------------------------


def test_coverage_alarm_is_silent_until_a_threshold_is_set(fleet, monkeypatch):
    """No default threshold: what counts as an acceptable shortfall is an
    operator policy, and inventing one here would page on a state the fleet has
    been in all along."""
    from services.monitoring import ops_alerts

    monkeypatch.delenv("PSAT_PLAN_COVERAGE_ALERT", raising=False)
    assert ops_alerts._coverage_alert_threshold() == 0
    assert "tracking_plan_coverage" not in ops_alerts._current_problems({}, _now(), None)


def test_coverage_alarm_fires_over_the_threshold(fleet, monkeypatch):
    from services.monitoring import ops_alerts

    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "3")
    coverage = ops_alerts.collect_plan_coverage(fleet)
    # 3 not-determined + 1 stale = 4 contracts watching without a current plan.
    problems = ops_alerts._current_problems({}, _now(), coverage)
    assert problems["tracking_plan_coverage"]["uncovered"] == 4
    assert problems["tracking_plan_coverage"]["kind"] == "coverage"

    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "4")
    assert "tracking_plan_coverage" not in ops_alerts._current_problems({}, _now(), coverage)


@pytest.fixture()
def _clean_heartbeats(db_session):
    """``run_ops_alert_tick`` persists its own ``ops_alerter`` heartbeat. The
    shared ``db_session`` teardown does not sweep ``worker_heartbeats``, so a row
    left here would be read as a live daemon by every later test on this
    worker's DB."""
    from db.models import WorkerHeartbeat

    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()
    yield
    db_session.rollback()
    db_session.query(WorkerHeartbeat).delete()
    db_session.commit()


def test_coverage_alarm_posts_and_recovers_through_the_tick(fleet, _clean_heartbeats, monkeypatch):
    """The alarm rides the existing dedupe/cooldown machinery, so it posts once
    on the transition and once on recovery."""
    from services.monitoring import ops_alerts

    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "3")
    monkeypatch.setattr(ops_alerts, "_webhook_url", lambda: None)
    first = ops_alerts.run_ops_alert_tick(fleet)
    assert first["posted_down"] >= 1

    second = ops_alerts.run_ops_alert_tick(fleet)
    assert second["posted_down"] == 0  # deduped inside the cooldown

    # Coverage repaired: every row now carries a read plan.
    for mc in fleet.execute(select(MonitoredContract)).scalars().all():
        mc.monitoring_config = {TRACKED_TOPICS_KEY: _TOPICS}
    fleet.commit()
    third = ops_alerts.run_ops_alert_tick(fleet)
    assert third["posted_recovery"] >= 1


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
