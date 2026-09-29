"""Tag-driven Discord embed rendering: pin the field shape per write target.

``_format_governance_embed`` used to branch on event_type; after the PR-B refactor it drives
off ``effect_tags.writes``. Every event_type the old branches covered must produce the same
fields. Pure unit tests.
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
    """No-op session: only .get() is called, and None falls back to the address-only title."""

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
    """Casts the duck-typed fake session through Session so pyright accepts the call site."""
    return _format_embed_real(event, cast(Session, session))


def _fields(embed: dict) -> dict[str, dict]:
    return {f["name"]: f for f in embed["fields"]}


# ---------------------------------------------------------------------------
# Hand-rolled governance events — pin every old branch's field shape
# ---------------------------------------------------------------------------


def test_ownership_transferred_renders_old_and_new_owner():
    evt = _make_evt(
        "ownership_transferred",
        {
            "old_owner": "0x" + "11" * 20,
            "new_owner": "0x" + "22" * 20,
            "effect_tags": {"writes": ["owner"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Old Owner"]["value"] == "`0x" + "11" * 20 + "`"
    assert fields["New Owner"]["value"] == "`0x" + "22" * 20 + "`"
    assert fields["Old Owner"]["inline"] is False


def test_ownership_transfer_started_renders_via_pending_owner_write():
    """Ownable2Step intent phase: emitter writes ``pendingOwner``; decoder fills old/new owner."""
    evt = _make_evt(
        "ownership_transfer_started",
        {
            "old_owner": "0x" + "11" * 20,
            "new_owner": "0x" + "22" * 20,
            "effect_tags": {"writes": ["pendingOwner"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Old Owner"]["value"] == "`0x" + "11" * 20 + "`"
    assert fields["New Owner"]["value"] == "`0x" + "22" * 20 + "`"


def test_authority_updated_renders_old_and_new_authority():
    evt = _make_evt(
        "authority_updated",
        {
            "old_authority": "0x" + "11" * 20,
            "new_authority": "0x" + "22" * 20,
            "effect_tags": {"writes": ["authority"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Old Authority"]["value"] == "`0x" + "11" * 20 + "`"
    assert fields["New Authority"]["value"] == "`0x" + "22" * 20 + "`"


@pytest.mark.parametrize(
    "event_type",
    [
        "upgraded",
        # GnosisSafe ChangedMasterCopy stores the new master copy under
        # ``implementation`` for backward compat with the upgrade renderer.
        "changed_master_copy",
        # Synthetix TargetUpdated — same shape as Upgraded modulo the topic0.
        "target_updated",
    ],
)
def test_upgrade_family_renders_new_implementation(event_type):
    evt = _make_evt(
        event_type,
        {
            "implementation": "0x" + "cc" * 20,
            "effect_tags": {"writes": ["implementation"], "delegates": True},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["New Implementation"]["value"] == "`0x" + "cc" * 20 + "`"
    assert fields["New Implementation"]["inline"] is False


def test_new_implementation_renders_via_synthesis_fallback():
    """Compound NewImplementation can land with no effect_tags; the renderer must synthesize
    them from ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` rather than render an empty embed."""
    evt = _make_evt("new_implementation", {"implementation": "0x" + "cc" * 20})
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["New Implementation"]["value"] == "`0x" + "cc" * 20 + "`"


def test_diamond_cut_renders_first_facet_as_implementation():
    """EIP-2535 facet swap: the first new facet is stored under ``implementation`` so it
    renders as ``New Implementation``."""
    evt = _make_evt(
        "diamond_cut",
        {
            "implementation": "0x" + "cc" * 20,
            "facets": ["0x" + "cc" * 20, "0x" + "dd" * 20],
            "effect_tags": {"writes": ["facets"], "delegates": True},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["New Implementation"]["value"] == "`0x" + "cc" * 20 + "`"


def test_admin_changed_renders_old_and_new_admin():
    evt = _make_evt(
        "admin_changed",
        {
            "previous_admin": "0x" + "11" * 20,
            "new_admin": "0x" + "22" * 20,
            "effect_tags": {"writes": ["admin"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Old Admin"]["value"] == "`0x" + "11" * 20 + "`"
    assert fields["New Admin"]["value"] == "`0x" + "22" * 20 + "`"


def test_admin_changed_compound_single_new_admin():
    """Compound's NewAdmin carries only the new admin: no fabricated Old Admin."""
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


def test_beacon_upgraded_renders_beacon_address():
    evt = _make_evt(
        "beacon_upgraded",
        {
            "beacon": "0x" + "dd" * 20,
            "effect_tags": {"writes": ["beacon"], "delegates": True},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Beacon"]["value"] == "`0x" + "dd" * 20 + "`"


@pytest.mark.parametrize("event_type", ["paused", "unpaused"])
def test_pause_family_renders_account_field(event_type):
    evt = _make_evt(
        event_type,
        {
            "account": "0x" + "ee" * 20,
            "effect_tags": {"writes": ["paused"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Account"]["value"] == "`0x" + "ee" * 20 + "`"


@pytest.mark.parametrize("event_type", ["role_granted", "role_revoked"])
def test_role_family_renders_role_account_sender(event_type):
    evt = _make_evt(
        event_type,
        {
            "role": "0x" + "00" * 32,
            "account": "0x" + "ee" * 20,
            "sender": "0x" + "ff" * 20,
            "effect_tags": {"writes": ["_roles"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Role"]["value"] == "`0x" + "00" * 32 + "`"
    assert fields["Account"]["value"] == "`0x" + "ee" * 20 + "`"
    assert fields["Sender"]["value"] == "`0x" + "ff" * 20 + "`"
    assert fields["Role"]["inline"] is False
    assert fields["Account"]["inline"] is True
    assert fields["Sender"]["inline"] is True


@pytest.mark.parametrize("event_type", ["signer_added", "signer_removed"])
def test_signer_family_renders_signer_address(event_type):
    evt = _make_evt(
        event_type,
        {
            "owner": "0x" + "ee" * 20,
            "effect_tags": {"writes": ["owners"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Signer"]["value"] == "`0x" + "ee" * 20 + "`"


def test_threshold_changed_renders_integer_threshold_inline():
    evt = _make_evt(
        "threshold_changed",
        {
            "threshold": 3,
            "effect_tags": {"writes": ["threshold"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["New Threshold"]["value"] == "3"
    assert "`" not in fields["New Threshold"]["value"]
    assert fields["New Threshold"]["inline"] is True


def test_delay_changed_renders_old_and_new_delays_inline():
    evt = _make_evt(
        "delay_changed",
        {
            "old_delay": 3600,
            "new_delay": 7200,
            "effect_tags": {"writes": ["min_delay"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Old Delay"]["value"] == "3600"
    assert fields["New Delay"]["value"] == "7200"
    assert fields["Old Delay"]["inline"] is True
    assert fields["New Delay"]["inline"] is True


def test_state_changed_poll_keeps_synthetic_field_shape():
    """Poll events carry no decoder or tags; the renderer keeps the (Field, Old, New) shape."""
    evt = _make_evt(
        "state_changed_poll",
        {
            "field": "implementation",
            "old_value": "0x" + "aa" * 20,
            "new_value": "0x" + "bb" * 20,
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["Field"]["value"] == "implementation"
    assert fields["Old"]["value"] == "`0x" + "aa" * 20 + "`"
    assert fields["New"]["value"] == "`0x" + "bb" * 20 + "`"


# ---------------------------------------------------------------------------
# Tag-driven fallback paths
# ---------------------------------------------------------------------------


def test_legacy_event_without_tags_renders_via_synthesis_fallback():
    """A persisted event from before tag synthesis (no ``effect_tags``) still renders via
    synthesis from event_type."""
    evt = _make_evt(
        "ownership_transferred",
        {
            "old_owner": "0x" + "11" * 20,
            "new_owner": "0x" + "22" * 20,
            # NO effect_tags key
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert fields["New Owner"]["value"] == "`0x" + "22" * 20 + "`"


def test_custom_named_slot_renders_via_generic_fallback():
    """A custom slot ``protocolAdmin`` (not in the render table) renders via the generic
    name-match fallback: label from the write target, value from data["newProtocolAdmin"]."""
    evt = _make_evt(
        "controller_changed:state_variable:protocolAdmin",
        {
            "newProtocolAdmin": "0x" + "ee" * 20,
            "effect_tags": {"writes": ["protocolAdmin"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    assert "New ProtocolAdmin" in fields
    assert fields["New ProtocolAdmin"]["value"] == "`0x" + "ee" * 20 + "`"


def test_custom_slot_bare_name_falls_through_when_no_new_prefix():
    """Without a ``new<X>`` arg name the decoder stores the bare slot name; the fallback finds it."""
    evt = _make_evt(
        "controller_changed:state_variable:guardian",
        {
            "guardian": "0x" + "ee" * 20,
            "effect_tags": {"writes": ["guardian"]},
        },
    )
    fields = _fields(_format_governance_embed(evt, _FakeSession()))
    # Renders under the CamelCased bare-name label (not "New Guardian")
    # because there's no ``newGuardian`` arg.
    assert "Guardian" in fields
    assert fields["Guardian"]["value"] == "`0x" + "ee" * 20 + "`"


def test_synthetic_write_target_no_extra_fields():
    """Underscore-prefixed markers like ``_safe_op`` are activity markers, not slots, so the
    generic fallback doesn't render them; envelope fields still appear."""
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
    # No fabricated "Safe Op" field from the synthetic marker
    assert "_safe_op" not in field_names
    assert "Safe_op" not in field_names


def test_unknown_event_type_with_no_tags_renders_only_envelope():
    """Defense-in-depth: an unknown event_type with no tags renders the envelope without error."""
    evt = _make_evt(
        "totally_unknown_event_type",
        {"some_field": "value"},
    )
    embed = _format_governance_embed(evt, _FakeSession())
    field_names = {f["name"] for f in embed["fields"]}
    assert "Contract" in field_names
    assert "Chain" in field_names
    assert "Event" in field_names


# ---------------------------------------------------------------------------
# Color mapping preserved (regression guard on _EVENT_COLORS)
# ---------------------------------------------------------------------------


def test_color_critical_derives_from_write_target():
    """Red for critical control writes (owner / authority / paused), derived from tags, so a
    custom ABI classified as ownership_transferred gets red with no per-event_type entry."""
    cases = [
        ("ownership_transferred", {"writes": ["owner"]}),
        ("authority_updated", {"writes": ["authority"]}),
        ("paused", {"writes": ["paused"]}),
        ("unpaused", {"writes": ["paused"]}),
        # Custom event_type that happens to write ``owner`` — still red.
        ("controller_changed:state_variable:protocolOwner", {"writes": ["owner"]}),
    ]
    for et, tags in cases:
        evt = _make_evt(et, {"effect_tags": tags})
        embed = _format_governance_embed(evt, _FakeSession())
        assert embed["color"] == 0xFF0000, f"{et} should be red, got {hex(embed['color'])}"


def test_color_warning_derives_from_upgrade_write_targets():
    """Orange for upgrade-shape writes and intent-phase pendingOwner, all tag-derived."""
    cases = [
        ("upgraded", {"writes": ["implementation"], "delegates": True}),
        ("admin_changed", {"writes": ["admin"]}),
        ("beacon_upgraded", {"writes": ["beacon"], "delegates": True}),
        ("ownership_transfer_started", {"writes": ["pendingOwner"]}),
        ("new_pending_implementation", {"writes": ["pendingImplementation"]}),
    ]
    for et, tags in cases:
        evt = _make_evt(et, {"effect_tags": tags})
        embed = _format_governance_embed(evt, _FakeSession())
        assert embed["color"] == 0xFF9900, f"{et} should be orange, got {hex(embed['color'])}"


def test_color_blue_for_signer_changes():
    """Safe signer set mutations (writes=['owners']) → blue, tag-derived."""
    evt = _make_evt("signer_added", {"effect_tags": {"writes": ["owners"]}})
    assert _format_governance_embed(evt, _FakeSession())["color"] == 0x3498DB


def test_color_amber_for_operational_params():
    """Roles, threshold, and min_delay — operational params, amber."""
    for et, tags in (
        ("role_granted", {"writes": ["_roles"]}),
        ("role_revoked", {"writes": ["_roles"]}),
        ("threshold_changed", {"writes": ["threshold"]}),
        ("delay_changed", {"writes": ["min_delay"]}),
    ):
        evt = _make_evt(et, {"effect_tags": tags})
        embed = _format_governance_embed(evt, _FakeSession())
        assert embed["color"] == 0xF39C12, f"{et} should be amber, got {hex(embed['color'])}"


def test_color_success_failure_for_safe_execution_via_event_type_override():
    """Safe execution outcome: green success, red failure. Keyed on event_type via
    _EVENT_TYPE_COLOR_OVERRIDES since both share writes=['_safe_op'] with no outcome marker."""
    for et in ("safe_tx_executed", "safe_module_executed"):
        evt = _make_evt(et, {"effect_tags": {"writes": ["_safe_op"]}})
        assert _format_governance_embed(evt, _FakeSession())["color"] == 0x2ECC71, et

    for et in ("safe_tx_failed", "safe_module_failed"):
        evt = _make_evt(et, {"effect_tags": {"writes": ["_safe_op"]}})
        assert _format_governance_embed(evt, _FakeSession())["color"] == 0xE74C3C, et


def test_color_phase_split_for_timelock_via_event_type_override():
    """Timelock scheduled (blue) vs executed (orange): same writes, phase lives in
    _EVENT_TYPE_COLOR_OVERRIDES."""
    scheduled = _make_evt("timelock_scheduled", {"effect_tags": {"writes": ["_timelock_op"]}})
    assert _format_governance_embed(scheduled, _FakeSession())["color"] == 0x3498DB

    executed = _make_evt("timelock_executed", {"effect_tags": {"writes": ["_timelock_op"]}})
    assert _format_governance_embed(executed, _FakeSession())["color"] == 0xFF9900


def test_color_state_changed_poll_uses_override():
    """The synthetic poll event has no tags or decoder; color comes from the override map."""
    evt = _make_evt("state_changed_poll", {"field": "owner"})
    assert _format_governance_embed(evt, _FakeSession())["color"] == 0x9B59B6


def test_color_multi_write_priority_picks_most_critical():
    """Ownable2Step ``acceptOwnership`` writes owner AND pendingOwner: red (committed)
    outranks orange (intent)."""
    evt = _make_evt(
        "ownership_transferred",
        {"effect_tags": {"writes": ["owner", "pendingOwner"]}},
    )
    assert _format_governance_embed(evt, _FakeSession())["color"] == 0xFF0000


def test_color_legacy_event_synthesis_fallback():
    """A legacy event with no effect_tags resolves via _HANDROLLED_EVENT_TYPE_TO_TAGS."""
    evt = _make_evt("ownership_transferred", {"new_owner": "0x" + "11" * 20})
    assert _format_governance_embed(evt, _FakeSession())["color"] == 0xFF0000


def test_color_unknown_event_falls_back_to_neutral():
    """An event_type with no override and no recognizable writes gets
    the neutral default color — never raises."""
    evt = _make_evt("totally_unknown", {"effect_tags": {"writes": ["something_random"]}})
    assert _format_governance_embed(evt, _FakeSession())["color"] == 0x95A5A6
