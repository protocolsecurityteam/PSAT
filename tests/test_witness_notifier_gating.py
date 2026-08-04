"""Side effects follow claim strength (invariant 5), plus the event-type
column the new vocabulary needs.

The scanner never hands a hint- or activity-tier row to the notifier — it
inserts no such row at all — so these tests exercise the notifier's own gate:
the second lock on the same door, for any caller that hands it one anyway.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from sqlalchemy import inspect, text

from db.models import Contract, MonitoredContract, MonitoredEvent, Protocol, ProtocolSubscription
from services.monitoring.event_topics import MAX_EVENT_TYPE_LENGTH, value_changed_event_type
from services.monitoring.notifier import _expand_allowed_event_types, notify_protocol_events


def ADDR(n: int) -> str:
    return "0x" + hex(n)[2:].zfill(40)


@pytest.fixture()
def notify_env(db_session):
    protocol = Protocol(name="notify-gating", chains=["ethereum"])
    db_session.add(protocol)
    db_session.flush()
    contract = Contract(protocol_id=protocol.id, address=ADDR(0x31), chain="ethereum")
    db_session.add(contract)
    db_session.flush()
    mc = MonitoredContract(
        id=uuid.uuid4(),
        address=ADDR(0x31),
        chain="ethereum",
        protocol_id=protocol.id,
        contract_id=contract.id,
        contract_type="regular",
        monitoring_config={},
        last_scanned_block=1,
        enrollment_block=1,
        is_active=True,
    )
    db_session.add(mc)
    db_session.add(
        ProtocolSubscription(
            id=uuid.uuid4(),
            protocol_id=protocol.id,
            discord_webhook_url="https://discord.invalid/hook",
        )
    )
    db_session.commit()

    def emit(event_type: str, data: dict | None) -> MonitoredEvent:
        event = MonitoredEvent(
            id=uuid.uuid4(),
            monitored_contract_id=mc.id,
            event_type=event_type,
            block_number=10,
            tx_hash="0x" + "aa" * 32,
            log_index=0,
            data=data,
        )
        db_session.add(event)
        db_session.commit()
        db_session.refresh(event)
        return event

    return emit


@pytest.mark.parametrize(
    "tier,expected_sends",
    [
        ("self_describing", 1),
        ("hint", 0),
        ("activity", 0),
        (None, 1),
    ],
)
def test_only_witnessed_claims_notify(db_session, notify_env, tier, expected_sends):
    data = {"witness_tier": tier} if tier else {"new_owner": ADDR(0x99)}
    event = notify_env("ownership_transferred", data)
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    assert send.call_count == expected_sends


def test_read_verified_change_notifies(db_session, notify_env):
    event = notify_env(
        "value_changed:state_variable:owner",
        {"field": "owner", "old": ADDR(1), "new": ADDR(2), "witness": "read_verified"},
    )
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    assert send.call_count == 1
    embed = send.call_args[0][1]
    labels = {f["name"]: f["value"] for f in embed["fields"]}
    assert labels["Old"] == f"`{ADDR(1)}`"
    assert labels["New"] == f"`{ADDR(2)}`"
    assert labels["Witness"] == "verification read"


# ---------------------------------------------------------------------------
# Legacy webhook filters must not be muted by the strengthened vocabulary
# ---------------------------------------------------------------------------


def test_filter_shim_carries_a_canonical_seed_onto_the_verified_form():
    expanded = _expand_allowed_event_types(["ownership_transferred"])
    assert "value_changed:state_variable:owner" in expanded
    assert "value_changed:owner" in expanded
    assert "value_changed:external_contract:owner" in expanded


def test_filter_shim_carries_a_neutral_seed_onto_the_verified_form():
    expanded = _expand_allowed_event_types(["state_changed:state_variable:rate"])
    assert "value_changed:state_variable:rate" in expanded
    expanded = _expand_allowed_event_types(["controller_changed:state_variable:rate"])
    assert "value_changed:state_variable:rate" in expanded


def test_filter_shim_invents_no_member_coverage():
    """No legacy filter ever covered a mapping's members, so expanding one
    onto ``member_changed`` would be a claim about the subscriber's intent."""
    expanded = _expand_allowed_event_types(["state_changed:state_variable:fromDenyList"])
    assert not any(t.startswith("member_changed") for t in expanded)


def test_filter_shim_keeps_the_historical_group_expansions():
    assert "safe_tx_executed" in _expand_allowed_event_types(["signer_added"])


def test_a_filtered_subscription_still_hears_the_verified_successor(db_session, notify_env):
    event = notify_env(
        "value_changed:state_variable:owner",
        {"field": "owner", "old": ADDR(1), "new": ADDR(2), "witness": "read_verified"},
    )
    sub = db_session.query(ProtocolSubscription).one()
    sub.event_filter = {"event_types": ["ownership_transferred"]}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    assert send.call_count == 1


# ---------------------------------------------------------------------------
# event_type column width
# ---------------------------------------------------------------------------


def test_event_type_column_is_wide_enough_for_the_vocabulary(db_session):
    column = inspect(db_session.get_bind()).get_columns("monitored_events")
    width = next(c["type"].length for c in column if c["name"] == "event_type")
    assert width == MAX_EVENT_TYPE_LENGTH == 100


def test_the_longest_mintable_type_fits(db_session, notify_env):
    """The worst real case on the audited fleet — a struct-member controller
    id under the read-verified stem — must store whole, not truncated."""
    longest = value_changed_event_type("state_variable:accountantState.payoutAddress")
    assert len(longest) == 58
    assert len(longest) <= MAX_EVENT_TYPE_LENGTH

    at_limit = "v" * MAX_EVENT_TYPE_LENGTH
    event = notify_env(at_limit, None)
    db_session.expire_all()
    assert db_session.get(MonitoredEvent, event.id).event_type == at_limit

    # One over is refused by the database rather than silently trimmed.
    with pytest.raises(Exception):
        db_session.execute(
            text(
                "INSERT INTO monitored_events (id, monitored_contract_id, event_type, block_number, tx_hash) "
                "SELECT gen_random_uuid(), monitored_contract_id, :et, 1, '' FROM monitored_events LIMIT 1"
            ),
            {"et": "v" * (MAX_EVENT_TYPE_LENGTH + 1)},
        )
    db_session.rollback()
