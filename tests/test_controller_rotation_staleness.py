"""A rotated controller must not keep the OLD address's classification.

``_update_controller_value_rows`` wrote exactly one column — ``cv.value`` —
leaving ``resolved_type``, ``details``, ``block_number`` and ``observed_via``
describing the address that was just replaced. Both call sites are
unconditional (event-driven ``_sync_relational_tables``, poll-driven
``_sync_relational_from_poll``).

The consumer republishes that stale payload under the NEW address:
``company_overview._record_principal_lookup`` keys on ``cv.value`` while
merging ``cv.details``, and ``_principal_lookup_type`` promotes on ``details``
alone via ``_has_timelock_delay``. So the worse half is the TIMELOCK case —
a Timelock -> EOA rotation publishes a freshly-installed EOA as
``resolved_type="timelock"`` carrying the old ``delay`` — a credit-bearing
scoring input. That is a safety-inflating false credit, which ranks
worse than a false adverse, on top of a false statement about a named
individual's keys. The Safe -> Safe case (owners/threshold of the wrong Safe)
is the milder half and is covered too.

Armed population when this was written: 13 ``controller_values`` rows on
enrolled + active contracts under a ``_GOVERNANCE_ROTATION_WRITE_TARGETS``
controller_id — 8 ``safe`` + 5 ``timelock`` — and 23 enrolled+active rows
carrying an ``owners`` or ``delay`` key at all. Lower bound: one protocol.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import select

from db.jsonb import JSONB_UNSET, jsonb_state
from db.models import (
    CONTROLLER_OBSERVED_VIA_EVENT_LOG,
    CONTROLLER_OBSERVED_VIA_STORAGE_POLL,
    Contract,
    ControllerValue,
    MonitoredContract,
    Protocol,
)
from services.monitoring.unified_watcher import _sync_relational_tables, poll_for_state_changes

SUBJECT = "0x1111111111111111111111111111111111111111"
OLD_TIMELOCK = "0x2222222222222222222222222222222222222222"
NEW_EOA = "0x3333333333333333333333333333333333333333"
OLD_SAFE = "0x4444444444444444444444444444444444444444"
NEW_SAFE = "0x5555555555555555555555555555555555555555"

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


# --- the worse half: a timelock's delay must not follow the rotation ------


def test_event_rotation_from_timelock_to_eoa_drops_the_stale_delay(db_session, subject):
    _seed_controller(
        db_session,
        subject,
        "state_variable:owner",
        OLD_TIMELOCK,
        "timelock",
        {"address": OLD_TIMELOCK, "delay": 259200, "owner": OLD_SAFE},
    )
    mc = _monitored(db_session, subject)

    _sync_relational_tables(
        db_session,
        mc,
        {
            "event_type": "ownership_transferred",
            "new_owner": NEW_EOA,
            "effect_tags": {"writes": ["owner"]},
            "block_number": 25_619_159,
            "tx_hash": "0x" + "a" * 64,
        },
    )
    db_session.commit()
    db_session.expire_all()

    row = _reload(db_session, subject.id, "state_variable:owner")
    assert row.value == NEW_EOA
    # The classification described the OLD address. Nothing here can
    # re-classify, so NULL — not determined — is the only honest answer.
    assert row.resolved_type is None
    assert row.details is None
    # And it is SQL NULL, not the jsonb scalar ``null``. psycopg2 decodes both
    # to Python None, so the distinction is only visible from SQL — and it
    # matters because a written ``null`` is "the writer recorded an absence",
    # which is evidence, while unset is not (db/jsonb.py).
    state = db_session.execute(
        select(jsonb_state(ControllerValue.details)).where(ControllerValue.id == row.id)
    ).scalar_one()
    assert state == JSONB_UNSET
    # The read that produced the new value is identified and dated.
    assert row.observed_via == CONTROLLER_OBSERVED_VIA_EVENT_LOG
    assert row.block_number == 25_619_159


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
    # A poll reads a slot, not a log. Keeping 18,000,000 would date the new
    # value to a block at which it was not there.
    assert row.block_number is None


# --- the milder half: a Safe's owner set must not follow the rotation -----


def test_event_rotation_between_safes_drops_the_stale_owner_set(db_session, subject):
    _seed_controller(
        db_session,
        subject,
        "state_variable:owner",
        OLD_SAFE,
        "safe",
        {"address": OLD_SAFE, "owners": ["0x" + "aa" * 20, "0x" + "bb" * 20], "threshold": 2},
    )
    mc = _monitored(db_session, subject)

    _sync_relational_tables(
        db_session,
        mc,
        {
            "event_type": "ownership_transferred",
            "new_owner": NEW_SAFE,
            "effect_tags": {"writes": ["owner"]},
            "block_number": 25_619_159,
            "tx_hash": "0x" + "b" * 64,
        },
    )
    db_session.commit()
    db_session.expire_all()

    row = _reload(db_session, subject.id, "state_variable:owner")
    assert row.value == NEW_SAFE
    assert row.resolved_type is None
    # ``details["address"]`` used to stay the OLD Safe, and the consumer's
    # ``setdefault("address", addr)`` cannot correct a key that is present.
    assert row.details is None


# --- negative control: an unchanged value must not be disturbed -----------


def test_a_write_that_does_not_move_the_value_leaves_the_row_alone(db_session, subject):
    _seed_controller(
        db_session,
        subject,
        "state_variable:owner",
        OLD_TIMELOCK,
        "timelock",
        {"address": OLD_TIMELOCK, "delay": 259200},
    )
    mc = _monitored(db_session, subject)

    _sync_relational_tables(
        db_session,
        mc,
        {
            "event_type": "ownership_transferred",
            "new_owner": OLD_TIMELOCK,
            "effect_tags": {"writes": ["owner"]},
            "block_number": 25_619_159,
            "tx_hash": "0x" + "c" * 64,
        },
    )
    db_session.commit()
    db_session.expire_all()

    row = _reload(db_session, subject.id, "state_variable:owner")
    # Still describing the same address, so the classification is still valid.
    assert row.resolved_type == "timelock"
    assert row.details == {"address": OLD_TIMELOCK, "delay": 259200}
    assert row.block_number == 18_000_000
    assert row.observed_via == "eth_call"
