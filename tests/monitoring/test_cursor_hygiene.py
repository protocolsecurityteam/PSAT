"""F6: block 0 is not a stand-in for a failed head read.

A genesis cursor claims the whole chain as backlog and a floor of 0, so every historical event publishes as live.
"""

from __future__ import annotations

import uuid
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


def test_deferred_enrollment_is_visible_in_the_coverage_census(db_session, analyzed_protocol):
    from services.monitoring.tracking_plan_state import plan_coverage_counts

    assert plan_coverage_counts(db_session)["enrollment_deferred_protocols"] == 0
    _enroll(db_session, analyzed_protocol.id, RuntimeError("upstream down"))
    assert plan_coverage_counts(db_session)["enrollment_deferred_protocols"] == 1


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
