"""F6 — cursor hygiene: no monitored row starts life with a manufactured
scan cursor, and the rows that already have one can be repaired.

Two halves:

* **the guard** — a chain-head read that fails is not-determined. Block 0 is not
  its stand-in: a row seeded there claims the whole chain as backlog (the
  scanner serves it first on every pass, forever) and declares an enrollment
  floor of 0, which lets every historical event it eventually finds publish as a
  live change. Both enrollment entry points defer the row instead.
* **the clamp** — the repair for rows that already carry such a cursor (the
  audited ``0xe2acf9f8…``: floor 0, cursor 9,400,000, ~16M behind). Dry run is
  the default; the mutating path is operator-run.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from db.models import Contract, Job, JobStage, JobStatus, MonitoredContract, Protocol
from scripts.clamp_monitoring_cursors import (
    BELOW_FLOOR,
    UNFLOORED_RUNAWAY,
    apply_clamps,
    main,
    plan_clamps,
)
from tests.conftest import SessionFactory

PROTO_NAME = "__test_cursor_hygiene__"
ADDRESS = "0x" + "e2" * 20
HEAD = 25_662_000


def _mk(session, address: str, cursor: int, floor: int | None, *, chain: str = "ethereum", config=None):
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=address.lower(),
        chain=chain,
        contract_type="regular",
        monitoring_config=config if config is not None else {},
        last_known_state={},
        last_scanned_block=cursor,
        enrollment_block=floor,
        needs_polling=False,
        is_active=True,
        enrollment_source="auto",
    )
    session.add(mc)
    session.commit()
    return mc


def _row(session, address: str) -> MonitoredContract:
    session.expire_all()
    return session.execute(select(MonitoredContract).where(MonitoredContract.address == address.lower())).scalar_one()


# ---------------------------------------------------------------------------
# The enrollment guard
# ---------------------------------------------------------------------------


@pytest.fixture()
def analyzed_protocol(db_session):
    proto = Protocol(name=PROTO_NAME)
    db_session.add(proto)
    db_session.flush()
    db_session.add(Contract(address=ADDRESS, chain="ethereum", protocol_id=proto.id, contract_name="Teller"))
    db_session.add(Job(address=ADDRESS, protocol_id=proto.id, status=JobStatus.completed, stage=JobStage.done))
    db_session.commit()
    return proto


def _enroll(session, protocol_id: int, head: str | Exception):
    from services.monitoring.enrollment import enroll_protocol_contracts

    def _rpc(*_a, **_kw):
        if isinstance(head, Exception):
            raise head
        return head

    with patch("services.monitoring.enrollment.rpc_request", side_effect=_rpc):
        return enroll_protocol_contracts(session, protocol_id, "http://rpc", "ethereum", enroll_controllers=False)


def test_new_row_is_deferred_when_the_chain_head_is_not_determined(db_session, analyzed_protocol):
    """No head, no row. The next pass creates it — enrollment is idempotent and
    the reconciler re-runs it — where the old fallback would have persisted a
    genesis-cursor row that outlives the outage."""
    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))

    assert db_session.execute(select(MonitoredContract).where(MonitoredContract.address == ADDRESS)).all() == []

    _enroll(db_session, analyzed_protocol.id, hex(HEAD))
    row = _row(db_session, ADDRESS)
    assert row.last_scanned_block == HEAD
    assert row.enrollment_block == HEAD


def test_deferred_enrollment_is_requeued_not_reported_as_reconciled(db_session, analyzed_protocol):
    """Review finding 1: a pass that could not create every row it should have
    is not a completed reconcile.

    Without the re-mark, ``enroll_protocol_contracts`` returns normally, the
    drain deletes the queue row and stamps ``last_enrollment_reconcile_at`` —
    the deferral survives only as a log line and the protocol goes to the BACK
    of the sweep queue. The re-mark advances ``dirty_at``, which is exactly the
    condition ``_finish_success``'s guarded delete treats as "re-dirtied during
    the build": the row stays queued and the next tick re-runs the build.
    """
    from db.models import MonitoringEnrollmentQueue
    from services.monitoring.reconciler import EnrollmentClaim, _finish_success
    from services.monitoring.tracking_plan_state import HEAD_NOT_DETERMINED_REASON

    claimed_at = datetime(2026, 8, 4, 1, 0, tzinfo=timezone.utc)
    lease_id = uuid.uuid4()
    db_session.add(
        MonitoringEnrollmentQueue(
            protocol_id=analyzed_protocol.id,
            reason="policy_complete",
            dirty_at=claimed_at,
            lease_id=lease_id,
        )
    )
    db_session.commit()
    claim = EnrollmentClaim(analyzed_protocol.id, claimed_at, 0, lease_id)

    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))

    row = db_session.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == analyzed_protocol.id)
    ).scalar_one()
    assert row.reason == HEAD_NOT_DETERMINED_REASON
    assert row.dirty_at > claimed_at
    # ...and not due immediately: the retry re-runs the whole build, and the
    # chain that just failed to answer will not answer a second later.
    assert row.dirty_at > datetime.now(timezone.utc)

    # The drain now runs its success bookkeeping: the delete must no-op.
    _finish_success(db_session, claim)
    db_session.expire_all()
    survivor = db_session.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == analyzed_protocol.id)
    ).scalar_one()
    assert survivor.lease_id is None  # lease released, row retained for the next tick


def test_deferred_enrollment_is_visible_in_the_coverage_census(db_session, analyzed_protocol):
    """A deferred contract has no ``monitored_contracts`` row, so a surface that
    counts rows can only see it through the queue."""
    from services.monitoring.tracking_plan_state import plan_coverage_counts

    assert plan_coverage_counts(db_session)["enrollment_deferred_protocols"] == 0
    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))
    assert plan_coverage_counts(db_session)["enrollment_deferred_protocols"] == 1


def test_existing_row_still_reconciles_when_the_head_is_not_determined(db_session, analyzed_protocol):
    """The guard suppresses only row creation. A row that already exists keeps
    converging (config, type, activation) — its cursor needs no head."""
    _mk(db_session, ADDRESS, cursor=HEAD - 5000, floor=HEAD - 5000)

    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))

    row = _row(db_session, ADDRESS)
    assert row.protocol_id == analyzed_protocol.id  # reconciled
    assert row.last_scanned_block == HEAD - 5000  # untouched
    assert row.is_active is True


def test_upsert_route_refuses_to_seed_a_floor_zero_row(api_client, db_session, monkeypatch):
    """The manual add is the other floor-0 door. It fails loudly rather than
    persisting a row whose cursor and floor were never witnessed."""
    from routers import monitored

    proto = Protocol(name=PROTO_NAME)
    db_session.add(proto)
    db_session.commit()

    def _boom(*_a, **_kw):
        raise RuntimeError("upstream down")

    monkeypatch.setattr(monitored, "rpc_request", _boom)
    resp = api_client.post(
        f"/api/protocols/{proto.id}/monitoring",
        json={
            "address": ADDRESS,
            "chain": "ethereum",
            "contract_type": "regular",
            "monitoring_config": {"watch_ownership": True},
            "needs_polling": False,
            "is_active": True,
        },
        headers={"X-PSAT-Admin-Key": "test-admin-key"},
    )

    assert resp.status_code == 503
    assert db_session.execute(select(MonitoredContract).where(MonitoredContract.address == ADDRESS)).all() == []


# ---------------------------------------------------------------------------
# The clamp
# ---------------------------------------------------------------------------


def test_cursor_below_its_own_floor_is_raised_to_it(db_session):
    """Pre-enrollment blocks were never this row's to scan, so nothing is
    skipped and no gap is recorded."""
    _mk(db_session, ADDRESS, cursor=100, floor=5000)

    clamps = plan_clamps(db_session, heads={"ethereum": HEAD})
    assert len(clamps) == 1
    assert (clamps[0].kind, clamps[0].new_cursor, clamps[0].new_floor) == (BELOW_FLOOR, 5000, 5000)
    assert clamps[0].skipped_from is None

    assert apply_clamps(db_session, clamps) == 1
    row = _row(db_session, ADDRESS)
    assert row.last_scanned_block == 5000
    assert "scan_gaps" not in (row.monitoring_config or {})


def test_unfloored_runaway_is_clamped_and_its_unscanned_interval_recorded(db_session):
    """The audited legacy row. The blocks the clamp jumps over were never
    scanned; the row says so afterwards instead of presenting continuous
    coverage."""
    _mk(db_session, ADDRESS, cursor=9_400_000, floor=0)

    clamps = plan_clamps(db_session, heads={"ethereum": HEAD})
    assert len(clamps) == 1
    assert clamps[0].kind == UNFLOORED_RUNAWAY
    assert (clamps[0].skipped_from, clamps[0].skipped_to) == (9_400_001, HEAD)

    apply_clamps(db_session, clamps)
    row = _row(db_session, ADDRESS)
    assert row.last_scanned_block == HEAD
    assert row.enrollment_block == HEAD  # events below it can no longer read as live
    gap = (row.monitoring_config or {})["scan_gaps"][0]
    assert (gap["from_block"], gap["to_block"], gap["reason"]) == (9_400_001, HEAD, UNFLOORED_RUNAWAY)
    assert gap["clamped_at"]


def test_healthy_rows_are_never_touched(db_session):
    _mk(db_session, ADDRESS, cursor=HEAD - 10, floor=HEAD - 1000)
    _mk(db_session, "0x" + "b3" * 20, cursor=HEAD - 500_000, floor=0)  # behind, but under the threshold
    assert plan_clamps(db_session, heads={"ethereum": HEAD}) == []


def test_a_head_that_did_not_answer_suppresses_the_runaway_class(db_session):
    """A clamp target nobody witnessed is not a target. The below-floor class
    needs no head and still applies."""
    _mk(db_session, ADDRESS, cursor=9_400_000, floor=0)
    _mk(db_session, "0x" + "b4" * 20, cursor=100, floor=5000)

    clamps = plan_clamps(db_session, heads={"ethereum": None})
    assert [c.kind for c in clamps] == [BELOW_FLOOR]


def test_apply_never_rewinds_a_cursor_that_advanced_since_planning(db_session):
    """A scan pass can commit between planning and applying; the clamp is a
    repair, never a rewind."""
    mc = _mk(db_session, ADDRESS, cursor=100, floor=5000)
    clamps = plan_clamps(db_session, heads={"ethereum": HEAD})

    mc.last_scanned_block = 9000
    db_session.commit()

    assert apply_clamps(db_session, clamps) == 0
    assert _row(db_session, ADDRESS).last_scanned_block == 9000


def test_clamp_record_survives_re_enrollment(db_session, analyzed_protocol):
    """Review finding 2: enrollment rebuilds ``monitoring_config`` wholesale, so
    without an explicit carry the clamp's own record of what was never scanned
    is erased on the next pass — and the row goes back to presenting continuous
    coverage over the interval, which is what the clamp exists to deny."""
    from services.monitoring.tracking_plan_state import SCAN_GAPS_KEY

    _mk(db_session, ADDRESS, cursor=9_400_000, floor=0)
    apply_clamps(db_session, plan_clamps(db_session, heads={"ethereum": HEAD}))
    gaps = (_row(db_session, ADDRESS).monitoring_config or {})[SCAN_GAPS_KEY]

    _enroll(db_session, analyzed_protocol.id, hex(HEAD))

    config = _row(db_session, ADDRESS).monitoring_config or {}
    assert config[SCAN_GAPS_KEY] == gaps
    # The plan-plane rebuild still happened (this is not a config that was left alone).
    assert "watch_ownership" in config


def test_clamp_record_survives_a_caller_supplied_overwrite(api_client, db_session, monkeypatch):
    """The route replaces the config wholesale too, and no caller authored the
    scan-plane record."""
    from routers import monitored
    from services.monitoring.tracking_plan_state import SCAN_GAPS_KEY

    proto = Protocol(name=PROTO_NAME)
    db_session.add(proto)
    db_session.commit()
    gaps = [{"from_block": 1, "to_block": 2, "reason": UNFLOORED_RUNAWAY}]
    mc = _mk(db_session, ADDRESS, cursor=HEAD, floor=HEAD, config={SCAN_GAPS_KEY: gaps})

    monkeypatch.setattr(monitored, "rpc_request", lambda *_a, **_kw: hex(HEAD))
    resp = api_client.patch(
        f"/api/monitored-contracts/{mc.id}",
        json={"monitoring_config": {"watch_ownership": True}},
        headers={"X-PSAT-Admin-Key": "test-admin-key"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["monitoring_config"][SCAN_GAPS_KEY] == gaps
    assert resp.json()["monitoring_config"]["tracking_plan_not_determined"] == "config_supplied_by_caller"


def test_target_block_refuses_to_span_chains(db_session, monkeypatch):
    """Review finding 4: a block number is a fact about one chain. Fleet-wide it
    would write a mainnet head as a Base row's cursor AND its enrollment floor —
    a floor nothing witnessed."""
    import scripts.clamp_monitoring_cursors as clamp

    _mk(db_session, ADDRESS, cursor=9_400_000, floor=0)
    _mk(db_session, ADDRESS, cursor=9_400_000, floor=0, chain="base")
    monkeypatch.setattr(clamp, "SessionLocal", SessionFactory(db_session))

    with pytest.raises(SystemExit):
        clamp.main(["--target-block", str(HEAD)])  # no scope at all
    with pytest.raises(SystemExit):
        clamp.main(["--target-block", str(HEAD), "--address", ADDRESS])  # twin on two chains

    assert _row_on(db_session, ADDRESS, "base").last_scanned_block == 9_400_000
    assert clamp.main(["--target-block", str(HEAD), "--chain", "ethereum"]) == 0


def _row_on(session, address: str, chain: str) -> MonitoredContract:
    session.expire_all()
    return session.execute(
        select(MonitoredContract).where(MonitoredContract.address == address.lower(), MonitoredContract.chain == chain)
    ).scalar_one()


def test_main_dry_run_is_the_default_and_writes_nothing(db_session, monkeypatch, capsys):
    """``--apply`` is the only path that writes. The operator runs it; a plain
    invocation reports."""
    import scripts.clamp_monitoring_cursors as clamp

    _mk(db_session, ADDRESS, cursor=9_400_000, floor=0)
    monkeypatch.setattr(clamp, "SessionLocal", SessionFactory(db_session))
    monkeypatch.setattr(clamp, "_head_for", lambda *_a, **_kw: HEAD)

    assert clamp.main([]) == 0

    out = capsys.readouterr().out
    assert UNFLOORED_RUNAWAY in out
    assert "dry run" in out
    row = _row(db_session, ADDRESS)
    assert row.last_scanned_block == 9_400_000
    assert row.enrollment_block == 0


def test_main_target_block_needs_no_rpc(db_session, monkeypatch, capsys):
    """``--target-block`` pins the clamp target so the script can run without
    touching a node at all."""
    import scripts.clamp_monitoring_cursors as clamp

    _mk(db_session, ADDRESS, cursor=9_400_000, floor=0)
    monkeypatch.setattr(clamp, "SessionLocal", SessionFactory(db_session))
    monkeypatch.setattr(
        clamp, "_head_for", lambda *_a, **_kw: pytest.fail("--target-block must not read a head over RPC")
    )

    assert main(["--target-block", str(HEAD), "--address", ADDRESS]) == 0
    assert str(HEAD) in capsys.readouterr().out
