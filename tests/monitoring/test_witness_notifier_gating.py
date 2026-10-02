"""Side effects follow claim strength, plus the event-type column width.

The scanner never hands a hint- or activity-tier row to the notifier, so these exercise the
notifier's own gate: the second lock on the same door, for any caller that hands one anyway.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest

from db.models import Contract, MonitoredContract, MonitoredEvent, Protocol, ProtocolSubscription
from services.monitoring.notifier import _expand_allowed_event_types, _filter_allows, notify_protocol_events


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


_SIGNER_TYPES = ["signer_added", "signer_removed", "threshold_changed"]


@pytest.mark.parametrize("token", [None, [], "signers", ["signers", 3], 7, ["banana"], ["banana", "kiwi"]])
def test_an_unreadable_group_token_falls_back_to_no_mute(token):
    """An unreadable token would otherwise mute Safe executions over a word never defined."""
    from services.monitoring.notifier import _stated_filter_groups

    stated = _stated_filter_groups({"event_types": _SIGNER_TYPES, "groups": token})
    assert stated is None
    assert _filter_allows(_SIGNER_TYPES, "safe_tx_executed", filter_groups=stated)


def test_a_post_split_signers_only_subscription_does_not(db_session, notify_env):
    event = notify_env("safe_tx_executed", {"safe_tx_hash": "0x" + "ab" * 32, "payment": 0})
    sub = db_session.query(ProtocolSubscription).one()
    sub.event_filter = {"event_types": _SIGNER_TYPES, "groups": ["signers"]}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    assert send.call_count == 0


def test_state_polling_subscribers_hear_read_verified_changes(db_session, notify_env):
    """A verification read advances state one tick earlier, so the poll never fires."""
    assert _filter_allows(["state_changed_poll"], "value_changed:state_variable:owner")
    assert _filter_allows(["state_changed_poll"], "value_changed:state_variable:anythingElse")

    event = notify_env(
        "value_changed:state_variable:owner",
        {"field": "owner", "old": ADDR(1), "new": ADDR(2), "witness": "read_verified"},
    )
    sub = db_session.query(ProtocolSubscription).one()
    sub.event_filter = {"event_types": ["state_changed_poll"]}
    db_session.commit()
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    assert send.call_count == 1


def test_absent_filter_still_allows_everything(db_session):
    assert _filter_allows(None, "anything")
    assert _filter_allows([], "anything")


def test_stale_plan_provenance_reaches_the_recipient(db_session, notify_env):
    event = notify_env(
        "ownership_transferred",
        {"new_owner": ADDR(0x99), "plan_stale_since": "2026-08-01T00:00:00Z"},
    )
    with patch("services.monitoring.notifier._send_discord") as send:
        notify_protocol_events(db_session, [event])
    embed = send.call_args[0][1]
    watchlist = next(f for f in embed["fields"] if f["name"] == "Watch-list")
    assert "2026-08-01T00:00:00Z" in watchlist["value"]
    assert "coverage may be incomplete" in watchlist["value"]
