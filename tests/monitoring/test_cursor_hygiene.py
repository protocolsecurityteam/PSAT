"""F6 — cursor hygiene: no monitored row starts life with a manufactured
scan cursor.

The guard: a chain-head read that fails is not-determined. Block 0 is not its
stand-in — a row seeded there claims the whole chain as backlog (the scanner
serves it first on every pass, forever) and declares an enrollment floor of 0,
which lets every historical event it eventually finds publish as a live change.
Both enrollment entry points defer the row instead. (Repair of legacy rows that
already carry such a cursor is operator tooling, kept outside the repo.)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from db.models import Contract, Job, JobStage, JobStatus, MonitoredContract, Protocol

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
    from services.monitoring.observation_plan_state import HEAD_NOT_DETERMINED_REASON
    from services.monitoring.reconciler import EnrollmentClaim, _finish_success

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
    from services.monitoring.observation_plan_state import plan_coverage_counts

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
