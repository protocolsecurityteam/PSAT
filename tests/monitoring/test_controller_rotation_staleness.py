"""A rotated controller used to keep the old address's classification, so a Timelock -> EOA rotation published the
EOA as a timelock with the old delay: a safety-inflating false credit.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from db.models import (
    CONTROLLER_OBSERVED_VIA_STORAGE_POLL,
    Contract,
    ControllerValue,
    MonitoredContract,
    Protocol,
)
from services.monitoring.unified_watcher import poll_for_state_changes

SUBJECT = "0x1111111111111111111111111111111111111111"
OLD_TIMELOCK = "0x2222222222222222222222222222222222222222"
NEW_EOA = "0x3333333333333333333333333333333333333333"
OLD_SAFE = "0x4444444444444444444444444444444444444444"

OWNER_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000"


def _word(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


@pytest.fixture()
def subject(db_session):
    protocol = Protocol(name=f"g1-5-{uuid.uuid4().hex[:10]}")
    db_session.add(protocol)
    db_session.commit()
    contract = Contract(
        protocol_id=protocol.id,
        address=SUBJECT,
        chain="ethereum",
        contract_name="Governed",
    )
    db_session.add(contract)
    db_session.commit()
    return contract


def _seed_controller(session, contract, controller_id, value, resolved_type, details):
    row = ControllerValue(
        contract_id=contract.id,
        controller_id=controller_id,
        value=value,
        resolved_type=resolved_type,
        source=controller_id.split(":")[-1],
        block_number=18_000_000,
        details=details,
        observed_via="eth_call",
    )
    session.add(row)
    session.commit()
    return row


def _reload(session, contract_id, controller_id) -> ControllerValue:
    return session.execute(
        select(ControllerValue).where(
            ControllerValue.contract_id == contract_id,
            ControllerValue.controller_id == controller_id,
        )
    ).scalar_one()


def _monitored(session, contract) -> MonitoredContract:
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=SUBJECT,
        chain="ethereum",
        contract_type="contract",
        contract_id=contract.id,
        protocol_id=contract.protocol_id,
        monitoring_config={
            "polling_plan": [{"field": "owner", "kind": "storage_slot", "slot": OWNER_SLOT, "type_kind": "address"}]
        },
        last_known_state={"owner": OLD_TIMELOCK},
        last_scanned_block=0,
        needs_polling=True,
        is_active=True,
        last_polled_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
    )
    session.add(mc)
    session.commit()
    return mc


def test_poll_rotation_records_no_block_rather_than_the_stale_one(db_session, subject, monkeypatch):
    monkeypatch.setenv("PSAT_POLL_CONTRACTS_PER_PASS", "5")
    _seed_controller(
        db_session,
        subject,
        "state_variable:owner",
        OLD_TIMELOCK,
        "timelock",
        {"address": OLD_TIMELOCK, "delay": 259200, "owner": OLD_SAFE},
    )
    _monitored(db_session, subject)

    with patch(
        "services.monitoring.unified_watcher.rpc_batch_request_classified",
        side_effect=lambda _url, calls: [(_word(NEW_EOA), "ok") for _ in calls],
    ):
        poll_for_state_changes(db_session, "http://rpc")
    db_session.commit()
    db_session.expire_all()

    row = _reload(db_session, subject.id, "state_variable:owner")
    assert (row.value or "").lower() == NEW_EOA
    assert row.resolved_type is None
    assert row.details is None
    assert row.observed_via == CONTROLLER_OBSERVED_VIA_STORAGE_POLL
    # A poll reads a slot, not a log; the old block would misdate the value.
    assert row.block_number is None
