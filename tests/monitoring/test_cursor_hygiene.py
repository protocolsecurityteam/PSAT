"""F6: block 0 is not a stand-in for a failed head read.

A genesis cursor claims the whole chain as backlog and a floor of 0, so every historical event publishes as live.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
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
    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))

    assert db_session.execute(select(MonitoredContract).where(MonitoredContract.address == ADDRESS)).all() == []

    _enroll(db_session, analyzed_protocol.id, hex(HEAD))
    row = _row(db_session, ADDRESS)
    assert row.last_scanned_block == HEAD
    assert row.enrollment_block == HEAD


def test_deferred_enrollment_is_requeued_not_reported_as_reconciled(db_session, analyzed_protocol):
    """Otherwise the drain deletes the queue row and the deferral survives only as a log line."""
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
            lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=900),
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
    # The chain that just failed won't answer a second later.
    assert row.dirty_at > datetime.now(timezone.utc)

    _finish_success(db_session, claim)
    db_session.expire_all()
    survivor = db_session.execute(
        select(MonitoringEnrollmentQueue).where(MonitoringEnrollmentQueue.protocol_id == analyzed_protocol.id)
    ).scalar_one()
    assert survivor.lease_id is None  # lease released, row retained for the next tick


def test_deferred_enrollment_is_visible_in_the_coverage_census(db_session, analyzed_protocol):
    from services.monitoring.tracking_plan_state import plan_coverage_counts

    assert plan_coverage_counts(db_session)["enrollment_deferred_protocols"] == 0
    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))
    assert plan_coverage_counts(db_session)["enrollment_deferred_protocols"] == 1


def test_existing_row_still_reconciles_when_the_head_is_not_determined(db_session, analyzed_protocol):
    _mk(db_session, ADDRESS, cursor=HEAD - 5000, floor=HEAD - 5000)

    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))

    row = _row(db_session, ADDRESS)
    assert row.protocol_id == analyzed_protocol.id  # reconciled
    assert row.last_scanned_block == HEAD - 5000  # untouched
    assert row.is_active is True


def test_upsert_route_refuses_to_seed_a_floor_zero_row(api_client, db_session, monkeypatch):
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
