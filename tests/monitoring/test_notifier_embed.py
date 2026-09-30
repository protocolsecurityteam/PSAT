"""The renderer now drives off ``effect_tags.writes``; every event_type the old branches covered must produce the
same fields.
"""

from __future__ import annotations

import types
import uuid
from typing import Any, cast

import pytest
from sqlalchemy.orm import Session

from db.models import MonitoredEvent
from services.monitoring.notifier import _format_governance_embed as _format_embed_real


class _FakeSession:
    def get(self, _model, _id):
        return None


def _make_evt(event_type: str, data: dict, *, address: str = "0x" + "aa" * 20) -> MonitoredEvent:
    mc = types.SimpleNamespace(
        protocol_id=None,
        contract_id=None,
        address=address,
        chain="ethereum",
    )
    return cast(
        MonitoredEvent,
        types.SimpleNamespace(
            id=uuid.uuid4(),
            event_type=event_type,
            block_number=100,
            tx_hash="0x" + "ff" * 32,
            monitored_contract=mc,
            data=data,
        ),
    )


def _format_governance_embed(event: MonitoredEvent, session: Any) -> dict:
    return _format_embed_real(event, cast(Session, session))


def _fields(embed: dict) -> dict[str, dict]:
    return {f["name"]: f for f in embed["fields"]}


def _addr(byte: str) -> str:
    return "0x" + byte * 20


# An empty inline dict means the case doesn't pin layout.
@pytest.mark.parametrize(
    ("event_type", "data", "expected_values", "expected_inline"),
    [
        pytest.param(
            "ownership_transferred",
            {"old_owner": _addr("11"), "new_owner": _addr("22"), "effect_tags": {"writes": ["owner"]}},
            {"Old Owner": f"`{_addr('11')}`", "New Owner": f"`{_addr('22')}`"},
            {"Old Owner": False},
            id="ownership_transferred",
        ),
        pytest.param(
            "ownership_transfer_started",
            {"old_owner": _addr("11"), "new_owner": _addr("22"), "effect_tags": {"writes": ["pendingOwner"]}},
            {"Old Owner": f"`{_addr('11')}`", "New Owner": f"`{_addr('22')}`"},
            {},
            id="ownership_transfer_started",
        ),
        pytest.param(
            "authority_updated",
            {"old_authority": _addr("11"), "new_authority": _addr("22"), "effect_tags": {"writes": ["authority"]}},
            {"Old Authority": f"`{_addr('11')}`", "New Authority": f"`{_addr('22')}`"},
            {},
            id="authority_updated",
        ),
        pytest.param(
            "upgraded",
            {"implementation": _addr("cc"), "effect_tags": {"writes": ["implementation"], "delegates": True}},
            {"New Implementation": f"`{_addr('cc')}`"},
            {"New Implementation": False},
            id="upgraded",
        ),
        # Stored under ``implementation`` for the upgrade renderer.
        pytest.param(
            "changed_master_copy",
            {"implementation": _addr("cc"), "effect_tags": {"writes": ["implementation"], "delegates": True}},
            {"New Implementation": f"`{_addr('cc')}`"},
            {"New Implementation": False},
            id="changed_master_copy",
        ),
        pytest.param(
            "target_updated",
            {"implementation": _addr("cc"), "effect_tags": {"writes": ["implementation"], "delegates": True}},
            {"New Implementation": f"`{_addr('cc')}`"},
            {"New Implementation": False},
            id="target_updated",
        ),
        pytest.param(
            "diamond_cut",
            {
                "implementation": _addr("cc"),
                "facets": [_addr("cc"), _addr("dd")],
                "effect_tags": {"writes": ["facets"], "delegates": True},
            },
            {"New Implementation": f"`{_addr('cc')}`"},
            {},
            id="diamond_cut",
        ),
        pytest.param(
            "admin_changed",
            {"previous_admin": _addr("11"), "new_admin": _addr("22"), "effect_tags": {"writes": ["admin"]}},
            {"Old Admin": f"`{_addr('11')}`", "New Admin": f"`{_addr('22')}`"},
            {},
            id="admin_changed",
        ),
        pytest.param(
            "beacon_upgraded",
            {"beacon": _addr("dd"), "effect_tags": {"writes": ["beacon"], "delegates": True}},
            {"Beacon": f"`{_addr('dd')}`"},
            {},
            id="beacon_upgraded",
        ),
        pytest.param(
            "paused",
            {"account": _addr("ee"), "effect_tags": {"writes": ["paused"]}},
            {"Account": f"`{_addr('ee')}`"},
            {},
            id="paused",
        ),
        pytest.param(
            "unpaused",
            {"account": _addr("ee"), "effect_tags": {"writes": ["paused"]}},
            {"Account": f"`{_addr('ee')}`"},
            {},
            id="unpaused",
        ),
        *[
            pytest.param(
                event_type,
                {
                    "role": "0x" + "00" * 32,
                    "account": _addr("ee"),
                    "sender": _addr("ff"),
                    "effect_tags": {"writes": ["_roles"]},
                },
                {"Role": "`0x" + "00" * 32 + "`", "Account": f"`{_addr('ee')}`", "Sender": f"`{_addr('ff')}`"},
                {"Role": False, "Account": True, "Sender": True},
                id=event_type,
            )
            for event_type in ("role_granted", "role_revoked")
        ],
        *[
            pytest.param(
                event_type,
                {"owner": _addr("ee"), "effect_tags": {"writes": ["owners"]}},
                {"Signer": f"`{_addr('ee')}`"},
                {},
                id=event_type,
            )
            for event_type in ("signer_added", "signer_removed")
        ],
        pytest.param(
            "threshold_changed",
            {"threshold": 3, "effect_tags": {"writes": ["threshold"]}},
            {"New Threshold": "3"},
            {"New Threshold": True},
            id="threshold_changed",
        ),
        pytest.param(
            "delay_changed",
            {"old_delay": 3600, "new_delay": 7200, "effect_tags": {"writes": ["min_delay"]}},
            {"Old Delay": "3600", "New Delay": "7200"},
            {"Old Delay": True, "New Delay": True},
            id="delay_changed",
        ),
        pytest.param(
            "state_changed_poll",
            {"field": "implementation", "old_value": _addr("aa"), "new_value": _addr("bb")},
            {"Field": "implementation", "Old": f"`{_addr('aa')}`", "New": f"`{_addr('bb')}`"},
            {},
            id="state_changed_poll",
        ),
        # A slot outside the render table uses the generic name-match fallback.
        pytest.param(
            "controller_changed:state_variable:protocolAdmin",
            {"newProtocolAdmin": _addr("ee"), "effect_tags": {"writes": ["protocolAdmin"]}},
            {"New ProtocolAdmin": f"`{_addr('ee')}`"},
            {},
            id="custom_named_slot",
        ),
        pytest.param(
            "controller_changed:state_variable:guardian",
            {"guardian": _addr("ee"), "effect_tags": {"writes": ["guardian"]}},
            {"Guardian": f"`{_addr('ee')}`"},
            {},
            id="custom_slot_bare_name",
        ),
    ],
)
def test_governance_embed_renders_expected_fields(event_type, data, expected_values, expected_inline):
    fields = _fields(_format_governance_embed(_make_evt(event_type, data), _FakeSession()))
    assert {name: fields[name]["value"] for name in expected_values} == expected_values
    assert {name: fields[name]["inline"] for name in expected_inline} == expected_inline


def test_new_implementation_renders_via_synthesis_fallback():
    """It can land with no effect_tags."""
    evt = _make_evt("new_implementation", {"implementation": "0x" + "cc" * 20})
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["New Implementation"]["value"] == "`0x" + "cc" * 20 + "`"


def test_admin_changed_compound_single_new_admin():
    evt = _make_evt(
        "admin_changed",
        {
            "new_admin": "0x" + "22" * 20,
            "effect_tags": {"writes": ["admin"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert "New Admin" in fields
    assert fields["New Admin"]["value"] == "`0x" + "22" * 20 + "`"
    assert "Old Admin" not in fields


def test_legacy_event_without_tags_renders_via_synthesis_fallback():
    evt = _make_evt(
        "ownership_transferred",
        {
            "old_owner": "0x" + "11" * 20,
            "new_owner": "0x" + "22" * 20,
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["New Owner"]["value"] == "`0x" + "22" * 20 + "`"


def test_synthetic_write_target_no_extra_fields():
    """Underscore markers are activity markers, not slots."""
    evt = _make_evt(
        "safe_tx_executed",
        {
            "safe_tx_hash": "0x" + "11" * 32,
            "payment": 0,
            "effect_tags": {"writes": ["_safe_op"]},
        },
    )
    embed = _format_governance_embed(evt, _FakeSession())
    field_names = {f["name"] for f in embed["fields"]}
    assert "Contract" in field_names
    assert "Chain" in field_names
    assert "Event" in field_names
    assert "_safe_op" not in field_names
    assert "Safe_op" not in field_names


def test_unknown_event_type_with_no_tags_renders_only_envelope():
    evt = _make_evt(
        "totally_unknown_event_type",
        {"some_field": "value"},
    )
    embed = _format_governance_embed(evt, _FakeSession())
    field_names = {f["name"] for f in embed["fields"]}
    assert "Contract" in field_names
    assert "Chain" in field_names
    assert "Event" in field_names


@pytest.mark.parametrize(
    ("event_type", "data", "expected_color"),
    [
        # Tag-derived, so a custom ABI needs no per-event_type entry.
        pytest.param(
            "ownership_transferred", {"effect_tags": {"writes": ["owner"]}}, 0xFF0000, id="red_ownership_transferred"
        ),
        pytest.param(
            "authority_updated", {"effect_tags": {"writes": ["authority"]}}, 0xFF0000, id="red_authority_updated"
        ),
        pytest.param("paused", {"effect_tags": {"writes": ["paused"]}}, 0xFF0000, id="red_paused"),
        pytest.param("unpaused", {"effect_tags": {"writes": ["paused"]}}, 0xFF0000, id="red_unpaused"),
        pytest.param(
            "controller_changed:state_variable:protocolOwner",
            {"effect_tags": {"writes": ["owner"]}},
            0xFF0000,
            id="red_custom_owner_write",
        ),
        pytest.param(
            "ownership_transferred",
            {"effect_tags": {"writes": ["owner", "pendingOwner"]}},
            0xFF0000,
            id="red_multi_write_priority",
        ),
        pytest.param(
            "upgraded",
            {"effect_tags": {"writes": ["implementation"], "delegates": True}},
            0xFF9900,
            id="orange_upgraded",
        ),
        pytest.param("admin_changed", {"effect_tags": {"writes": ["admin"]}}, 0xFF9900, id="orange_admin_changed"),
        pytest.param(
            "beacon_upgraded",
            {"effect_tags": {"writes": ["beacon"], "delegates": True}},
            0xFF9900,
            id="orange_beacon_upgraded",
        ),
        pytest.param(
            "ownership_transfer_started",
            {"effect_tags": {"writes": ["pendingOwner"]}},
            0xFF9900,
            id="orange_ownership_transfer_started",
        ),
        pytest.param(
            "new_pending_implementation",
            {"effect_tags": {"writes": ["pendingImplementation"]}},
            0xFF9900,
            id="orange_new_pending_implementation",
        ),
        pytest.param("signer_added", {"effect_tags": {"writes": ["owners"]}}, 0x3498DB, id="blue_signer_added"),
        pytest.param("role_granted", {"effect_tags": {"writes": ["_roles"]}}, 0xF39C12, id="amber_role_granted"),
        pytest.param("role_revoked", {"effect_tags": {"writes": ["_roles"]}}, 0xF39C12, id="amber_role_revoked"),
        pytest.param(
            "threshold_changed", {"effect_tags": {"writes": ["threshold"]}}, 0xF39C12, id="amber_threshold_changed"
        ),
        pytest.param("delay_changed", {"effect_tags": {"writes": ["min_delay"]}}, 0xF39C12, id="amber_delay_changed"),
        # Both share writes=['_safe_op'], so the outcome is keyed on event_type.
        pytest.param(
            "safe_tx_executed", {"effect_tags": {"writes": ["_safe_op"]}}, 0x2ECC71, id="green_safe_tx_executed"
        ),
        pytest.param(
            "safe_module_executed", {"effect_tags": {"writes": ["_safe_op"]}}, 0x2ECC71, id="green_safe_module_executed"
        ),
        pytest.param("safe_tx_failed", {"effect_tags": {"writes": ["_safe_op"]}}, 0xE74C3C, id="red_safe_tx_failed"),
        pytest.param(
            "safe_module_failed", {"effect_tags": {"writes": ["_safe_op"]}}, 0xE74C3C, id="red_safe_module_failed"
        ),
        pytest.param(
            "timelock_scheduled", {"effect_tags": {"writes": ["_timelock_op"]}}, 0x3498DB, id="blue_timelock_scheduled"
        ),
        pytest.param(
            "timelock_executed", {"effect_tags": {"writes": ["_timelock_op"]}}, 0xFF9900, id="orange_timelock_executed"
        ),
        pytest.param("state_changed_poll", {"field": "owner"}, 0x9B59B6, id="purple_state_changed_poll"),
        pytest.param(
            "ownership_transferred", {"new_owner": "0x" + "11" * 20}, 0xFF0000, id="legacy_event_synthesis_fallback"
        ),
        pytest.param(
            "totally_unknown",
            {"effect_tags": {"writes": ["something_random"]}},
            0x95A5A6,
            id="unknown_event_falls_back_to_neutral",
        ),
    ],
)
def test_governance_embed_color(event_type, data, expected_color):
    embed = _format_governance_embed(_make_evt(event_type, data), _FakeSession())
    assert embed["color"] == expected_color, f"{event_type}: got {hex(embed['color'])}"
