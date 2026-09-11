"""F9a — coverage states must be visible to an operator.

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
from services.monitoring.observation_plan_state import (
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


def test_ready_stale_row_needs_its_staleness_stamp(fleet, db_session):
    """Review finding 5: the census reads the same witness the classifier does.
    Strip the stamp and the row falls back to its token — it is no longer
    reported as watching on a dated plan."""
    row = db_session.execute(select(MonitoredContract).where(MonitoredContract.address == _addr(3))).scalar_one()
    config = dict(row.monitoring_config or {})
    del config[TRACKED_TOPICS_STALE_SINCE_KEY]
    row.monitoring_config = config
    db_session.commit()

    counts = plan_coverage_counts(db_session)
    assert counts[READY_STALE] == 0
    assert counts["not_determined"][NO_CURRENT_MATERIALIZATION] == 2
    assert counts["contracts"] == 8  # still a partition


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
    from db.contract_materializations import STATIC_FACTS_SCHEMA_VERSION

    _mk(db_session, 1, {NOT_DETERMINED_KEY: NO_CURRENT_MATERIALIZATION})
    row = ContractMaterialization(
        # chain-id token, never the monitored_contracts chain NAME
        chain="1",
        bytecode_keccak=("0x" + uuid.uuid4().hex * 2)[:66],
        address=_addr(1),
        status="failed",
        static_facts_schema_version=STATIC_FACTS_SCHEMA_VERSION,
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
    assert "observation_plan_coverage" not in ops_alerts._current_problems({}, _now(), None)


def test_coverage_alarm_fires_over_the_threshold(fleet, monkeypatch):
    from services.monitoring import ops_alerts

    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "2")
    coverage = ops_alerts.collect_plan_coverage(fleet)
    # Review finding 6: 2 not-determined (no_current_materialization,
    # contract_not_analyzed) + 1 stale. The caller-supplied row is an operator's
    # own choice and is NOT paged on, though it stays in the payload.
    problems = ops_alerts._current_problems({}, _now(), coverage)
    assert coverage["not_determined"][CONFIG_SUPPLIED_BY_CALLER] == 1
    assert problems["observation_plan_coverage"]["uncovered"] == 3
    assert problems["observation_plan_coverage"]["kind"] == "coverage"

    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "3")
    assert "observation_plan_coverage" not in ops_alerts._current_problems({}, _now(), coverage)


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

    # 3 pageable uncovered rows (the caller-supplied one is excluded), so a
    # threshold of 2 is crossed.
    monkeypatch.setenv("PSAT_PLAN_COVERAGE_ALERT", "2")
    monkeypatch.setattr(ops_alerts, "_webhook_url", lambda: None)
    first = ops_alerts.run_ops_alert_tick(fleet)
    assert first["posted_down"] >= 1
    assert any(k == "observation_plan_coverage" for k in _alert_keys(fleet))

    second = ops_alerts.run_ops_alert_tick(fleet)
    assert second["posted_down"] == 0  # deduped inside the cooldown

    # Coverage repaired: every row now carries a read plan.
    for mc in fleet.execute(select(MonitoredContract)).scalars().all():
        mc.monitoring_config = {TRACKED_TOPICS_KEY: _TOPICS}
    fleet.commit()
    third = ops_alerts.run_ops_alert_tick(fleet)
    assert third["posted_recovery"] >= 1


# ---------------------------------------------------------------------------
# Verification-read gaps (F9b's counter, wired onto this surface)
# ---------------------------------------------------------------------------


def _marked(session, n: int):
    """One contract on a current plan whose hint controllers went unverified."""
    mc = _mk(session, n, {TRACKED_TOPICS_KEY: _TOPICS})
    mc.last_poll_status = {
        "rate": VERIFY_ERROR,
        "fee": VERIFY_OVER_BUDGET,
        f"{CONTROLLER_STATUS_PREFIX}state_variable:owner": VERIFY_NO_READ_BINDING,
    }
    session.commit()
    return mc


def test_fleet_publishes_the_verification_gap_census(db_session):
    """A current plan does not mean its hint controllers were verified — the two
    censuses answer different questions, and both ride the fleet payload."""
    _marked(db_session, 11)

    watchers = build_fleet_status(db_session)["watchers"]
    assert watchers["plan_coverage"][READY_FRESH_WITH_TOPICS] == 1
    gaps = watchers["verification_gaps"]
    assert gaps["read_failed"] == 1
    assert gaps["over_budget"] == 1
    assert gaps["no_read_binding"] == 1
    assert gaps["contracts_affected"] == 1


def test_the_gap_census_says_what_its_zeroes_mean(api_client, fleet):
    """No marker anywhere. The payload names its own basis rather than letting
    four zeroes read as "no verification read has ever failed" — the poller
    erases markers, so this is a point-in-time census, not a tally."""
    gaps = api_client.get("/api/fleet").json()["watchers"]["verification_gaps"]
    assert gaps == {
        "read_failed": 0,
        "over_budget": 0,
        "no_read_binding": 0,
        "contracts_affected": 0,
        "basis": CENSUS_BASIS,
    }


def test_ops_collects_the_gap_census_without_a_new_alarm_family(db_session):
    """Published unconditionally, on G1's precedent — and no invented threshold:
    a marker census would page on when the poller last ran as much as on the
    reads."""
    from services.monitoring import ops_alerts

    _marked(db_session, 12)
    assert ops_alerts.collect_verification_gaps(db_session)["read_failed"] == 1
    problems = ops_alerts._current_problems({}, _now(), None)
    assert not [key for key in problems if "verification" in key]


def test_the_tick_records_the_census_only_when_something_is_marked(db_session, _clean_heartbeats, monkeypatch, caplog):
    """The log line is what survives the markers: it is timestamped, so an
    erased marker still leaves a record that the gap existed."""
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


def _alert_keys(session) -> list[str]:
    """Dedupe keys the alerter currently holds in its own heartbeat detail."""
    from db.models import WorkerHeartbeat
    from db.queue import HEARTBEAT_OPS_ALERTER

    session.expire_all()
    hb = session.execute(select(WorkerHeartbeat).where(WorkerHeartbeat.process == HEARTBEAT_OPS_ALERTER)).scalar_one()
    return list((hb.detail or {}).get("alerts", {}))
