"""Project the analyzer's tracking plan into a flat list of pollable slots.

Entries come from three sources: getter_call controllers in ``tracking_plan.tracked_controllers`` with a decodable type
(so custom slots like ``protocolAdmin`` need no code); vendored proxy storage slots keyed on ``proxy_type`` (proxy
shells often skip Slither); and vendored Safe/Timelock getters. Each entry's ``suppress_when_scan_event_types`` comes
from the contract's own tracked topics.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from typing import Any

from eth_utils.crypto import keccak

from schemas.contract_analysis import ControllerProvenance
from schemas.control_tracking import MonitoredContractType
from services.monitoring.event_topics import SIGNAL_CLASS_CONFIG, SIGNAL_CLASS_METRIC
from utils.evm import (
    EIP1822_LOGIC_SLOT,
    EIP1967_IMPL_SLOT,
    GNOSIS_MASTERCOPY_SLOT,
    OZ_LEGACY_IMPL_SLOT,
    SAFE_GUARD_SLOT,
    SAFE_MODULES_HEAD_SLOT,
)

logger = logging.getLogger(__name__)


# Write target -> hand-rolled event_types that mutate it, inverted lazily from ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` to
# avoid an import cycle.
_HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES: dict[str, list[str]] | None = None


def _handrolled_events_for_write_target(write_target: str) -> list[str]:
    """Hand-rolled event_types whose tags write *write_target*; ``[]`` for custom slots."""
    global _HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES
    if _HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES is None:
        from services.monitoring.event_topics import _HANDROLLED_EVENT_TYPE_TO_TAGS

        inverted: dict[str, list[str]] = {}
        for event_type, tags in _HANDROLLED_EVENT_TYPE_TO_TAGS.items():
            writes = tags.get("writes") or []
            for target in writes:
                if not isinstance(target, str):
                    continue
                bucket = inverted.setdefault(target, [])
                if event_type not in bucket:
                    bucket.append(event_type)
        _HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES = inverted
    return list(_HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES.get(write_target, ()))


# Safe module-list head (``modules[address(0x1)]``, slot 1) and guard slot; canonical in ``utils.evm``, re-exported for
# tests.

# proxy_type -> the poll entry resolving its implementation, mirroring ``proxy_watcher._RESOLVE_BY_TYPE``. Getter-based
# proxies emit ``getter_call`` entries.
_VENDORED_PROXY_ENTRIES: dict[str, dict[str, Any]] = {
    "eip1967": {
        "field": "implementation",
        "kind": "storage_slot",
        "slot": EIP1967_IMPL_SLOT,
        "type_kind": "address",
        "source": "vendored:eip1967",
    },
    "beacon_proxy": {
        "field": "implementation",
        "kind": "storage_slot",
        "slot": EIP1967_IMPL_SLOT,
        "type_kind": "address",
        "source": "vendored:eip1967",
    },
    "eip1822": {
        "field": "implementation",
        "kind": "storage_slot",
        "slot": EIP1822_LOGIC_SLOT,
        "type_kind": "address",
        "source": "vendored:eip1822",
    },
    "oz_legacy": {
        "field": "implementation",
        "kind": "storage_slot",
        "slot": OZ_LEGACY_IMPL_SLOT,
        "type_kind": "address",
        "source": "vendored:oz_legacy",
    },
    "gnosis_safe": {
        "field": "implementation",
        "kind": "storage_slot",
        "slot": GNOSIS_MASTERCOPY_SLOT,
        "type_kind": "address",
        "source": "vendored:gnosis_safe",
    },
    "custom": {
        "field": "implementation",
        "kind": "getter_call",
        "target": "implementation",
        "type_kind": "address",
        "source": "vendored:custom_proxy",
    },
    "compound": {
        "field": "implementation",
        "kind": "getter_call",
        "target": "comptrollerImplementation",
        "type_kind": "address",
        "source": "vendored:compound",
    },
    "synthetix": {
        "field": "implementation",
        "kind": "getter_call",
        "target": "target",
        "type_kind": "address",
        "source": "vendored:synthetix",
    },
}

# Standard event_types for the same mutation, so poll/scan dedupe survives projection.
_VENDORED_IMPL_SCAN_EVENTS = (
    "upgraded",
    "new_implementation",
    "changed_master_copy",
    "target_updated",
    "beacon_upgraded",
)

# Safe and Timelock ABIs are standard but their source isn't always analyzed, so the analyzer can't see these getters.
_VENDORED_CONTRACT_TYPE_ENTRIES: dict[str, list[dict[str, Any]]] = {
    "safe": [
        {
            "field": "threshold",
            "kind": "getter_call",
            "target": "getThreshold",
            "type_kind": "primitive",
            "type": "uint256",
            "source": "vendored:safe",
            "suppress_when_scan_event_types": ["threshold_changed"],
        },
        # The head only shows that the module set changed; it can't enumerate the list.
        {
            "field": "modules_head",
            "kind": "storage_slot",
            "slot": SAFE_MODULES_HEAD_SLOT,
            "type_kind": "address",
            "source": "vendored:safe",
            "suppress_when_scan_event_types": ["safe_module_enabled", "safe_module_disabled"],
        },
        {
            "field": "guard",
            "kind": "storage_slot",
            "slot": SAFE_GUARD_SLOT,
            "type_kind": "address",
            "source": "vendored:safe",
            "suppress_when_scan_event_types": ["safe_guard_changed"],
        },
    ],
    "timelock": [
        {
            "field": "min_delay",
            "kind": "getter_call",
            "target": "getMinDelay",
            "type_kind": "primitive",
            "type": "uint256",
            "source": "vendored:timelock",
            "suppress_when_scan_event_types": ["delay_changed"],
        },
    ],
}


def selector_for(target_name: str) -> str:
    """The 4-byte selector of a no-arg getter named *target_name*.

    Current plans only admit analyzer-resolved getters. Older plans may name a private var; the poll loop reports those
    as ``error`` or ``no_value`` rather than silence.
    """
    return "0x" + keccak(text=f"{target_name}()").hex()[:8]


def decode_poll_outcome(raw: str | None, type_kind: str | None, type_str: str | None) -> tuple[object | None, bool]:
    """Decode an answered return for *entry* as ``(value, parsed)``.

    ``parsed`` is whether the body parsed as the declared type. The zero address parses but yields ``value=None`` (the
    "None means first observation" convention), so an answered zero is ``(None, True)`` and never ``(None, False)``.
    Bools and ints store their zero values.
    """
    if raw is None:
        return None, False
    raw_str = raw if isinstance(raw, str) else ""
    if not raw_str or raw_str == "0x":
        return None, False

    kind = (type_kind or "").lower()
    if kind in ("address", "contract"):
        # Inlined ``parse_address_result`` to keep this module decoupled.
        body = raw_str[2:] if raw_str.startswith("0x") else raw_str
        if len(body) < 40:
            return None, False
        addr = "0x" + body[-40:]
        if addr == "0x" + "0" * 40:
            return None, True
        return addr.lower(), True

    if kind == "primitive":
        t = (type_str or "").lower().strip()
        body = raw_str[2:] if raw_str.startswith("0x") else raw_str
        if t == "bool":
            if not body:
                return None, False
            # Nonzero anywhere in the word is True, matching the poller.
            return any(c != "0" for c in body), True
        if t.startswith("uint") or t.startswith("int"):
            try:
                return int(raw_str, 16), True
            except (ValueError, TypeError):
                return None, False

    return None, False


# Single-value types the poller can decode. Structs are only reachable via member projection.
_DECODABLE_TYPE_KINDS = frozenset({"address", "contract", "primitive"})

# Vendored entries win these fields, so the EIP-1967 slot read isn't shadowed by an analyzer-found ``implementation()``
# getter.
_VENDORED_FIELD_WINS = frozenset({"implementation", "threshold", "min_delay"})


# One-word ABI types. A dynamic member puts an offset in the head, which would be published as an address.
_STATIC_WORD_ABI_TYPE = re.compile(
    r"^(address|bool"
    r"|u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128"
    r"|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
    r"|bytes([1-9]|[12][0-9]|3[0-2]))$"
)


def _member_word_index(read_spec: Mapping[str, Any]) -> int | None:
    """The word index holding this controller's member in a struct getter's return, or ``None`` unless provable.

    Requires every member to be one static word and no mapping or array members (the auto-getter omits those, shifting
    later indexes). Otherwise the controller stays unreadable.
    """
    member_path = read_spec.get("member_path")
    if not isinstance(member_path, list) or len(member_path) != 1:
        return None
    member = member_path[0]
    components = read_spec.get("components")
    if not isinstance(components, list) or not components:
        return None
    index: int | None = None
    for position, component in enumerate(components):
        if not isinstance(component, Mapping):
            return None
        abi_type = str(component.get("abi_type") or "")
        if not _STATIC_WORD_ABI_TYPE.match(abi_type):
            return None
        if component.get("name") == member:
            index = position
    return index


# What one diff on this entry means to an operator; stamped at enrollment, read by ``salience.assign_salience``. The
# basis rides along so a re-analysis can upgrade ``metric`` to ``config`` visibly.

# ``vendored:*`` bases are the entry's own ``source``.
SIGNAL_BASIS_CALLER_GATE: ControllerProvenance = "caller_gate"
SIGNAL_BASIS_NO_GATE_PROVENANCE = "no_gate_provenance"
SIGNAL_BASIS_TYPE_KIND_REFERENCE = "type_kind_reference"

# The one provenance that proves the controller gates callers.
_PROVEN_GATE_PROVENANCE: ControllerProvenance = "caller_gate"

# A moved reference is a control-plane fact regardless of its writers.
_REFERENCE_TYPE_KINDS = frozenset({"address", "contract"})


def _signal_class_for_vendored(entry: Mapping[str, Any]) -> tuple[str, str]:
    """Vendored entries are config by construction; the basis is their vendored provenance."""
    source = entry.get("source")
    basis = source if isinstance(source, str) and source.startswith("vendored:") else "vendored"
    return SIGNAL_CLASS_CONFIG, basis


def _signal_class_for_analyzer(type_kind: str, authority_provenance: str | None) -> tuple[str, str]:
    """Classify an analyzer-derived entry.

    References are config. Primitives are config only with proven caller-gate provenance, else ``metric`` with
    ``no_gate_provenance``: a positive basis from a completed derivation, which is what lets ``metric`` render as
    routine.
    """
    if type_kind in _REFERENCE_TYPE_KINDS:
        return SIGNAL_CLASS_CONFIG, SIGNAL_BASIS_TYPE_KIND_REFERENCE
    if authority_provenance == _PROVEN_GATE_PROVENANCE:
        return SIGNAL_CLASS_CONFIG, SIGNAL_BASIS_CALLER_GATE
    return SIGNAL_CLASS_METRIC, SIGNAL_BASIS_NO_GATE_PROVENANCE


def _is_poll_decodable(read_spec: Mapping[str, Any]) -> bool:
    """Pollable iff the getter is callable (getter_call) and the type decodable.

    Member-path controllers also need a proven word index.
    """
    if (read_spec.get("strategy") or "").lower() != "getter_call":
        return False
    type_kind = (read_spec.get("type_kind") or "").lower()
    if type_kind not in _DECODABLE_TYPE_KINDS:
        return False
    if read_spec.get("member_path") and _member_word_index(read_spec) is None:
        return False
    if not read_spec.get("target"):
        return False
    return True


def project_entry_return(raw: str | None, entry: Mapping[str, Any]) -> str | None:
    """The one ABI word *entry* reads from a getter's return; ``None`` if the body is too short to hold it."""
    index = entry.get("member_word_index")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        return raw
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:]
    if len(body) < (index + 1) * 64:
        return None
    return "0x" + body[index * 64 : (index + 1) * 64]


def _entry_field_name(read_spec: Mapping[str, Any], controller_id: str | None) -> str:
    """The ``last_known_state`` key for this entry: ``state_variable_name`` (matching the event side), else the
    getter name, else the controller id's var part.
    """
    name = read_spec.get("state_variable_name")
    if isinstance(name, str) and name:
        member_path = read_spec.get("member_path")
        if isinstance(member_path, list) and member_path:
            # A projected member is its own field; sharing the parent's name would collide.
            return ".".join([name, *(str(part) for part in member_path)])
        return name
    target = read_spec.get("target")
    if isinstance(target, str) and target:
        return target
    if controller_id and ":" in controller_id:
        return controller_id.split(":", 1)[1]
    return controller_id or ""


def _derive_suppress_event_types(field: str, tracked_topics: Iterable[Mapping[str, Any]] | None) -> list[str]:
    """Canonical event_types whose ``effect_tags.writes`` includes *field*.

    Both the hand-rolled registry (OZ/Safe/Timelock/proxy topics, which aren't in per-contract ``tracked_topics``) and
    the contract's own tracked topics (non-OZ ABIs).
    """
    out: list[str] = []
    seen: set[str] = set()
    for event_type in _handrolled_events_for_write_target(field):
        if event_type not in seen:
            seen.add(event_type)
            out.append(event_type)
    if tracked_topics:
        for spec in tracked_topics:
            if not isinstance(spec, Mapping):
                continue
            tags = spec.get("effect_tags")
            if not isinstance(tags, Mapping):
                continue
            writes = tags.get("writes") or []
            if not isinstance(writes, Iterable):
                continue
            if field not in writes:
                continue
            event_type = spec.get("event_type")
            if isinstance(event_type, str) and event_type and event_type not in seen:
                seen.add(event_type)
                out.append(event_type)
    return out


def build_polling_plan(
    *,
    contract_type: MonitoredContractType,
    proxy_type: str | None = None,
    tracking_plan: Mapping[str, Any] | None = None,
    tracked_topics: Iterable[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Project a contract's polling intent into the entries enrollment stores under
    ``monitoring_config["polling_plan"]``.

    Vendored entries beat analyzer duplicates for ``_VENDORED_FIELD_WINS`` fields.
    """
    from services.monitoring.event_topics import MAX_EVENT_TYPE_LENGTH, value_changed_event_type

    by_field: dict[str, dict[str, Any]] = {}

    if contract_type == "proxy" and proxy_type:
        vendored_proxy = _VENDORED_PROXY_ENTRIES.get((proxy_type or "").lower())
        if vendored_proxy:
            entry = dict(vendored_proxy)
            entry.setdefault("suppress_when_scan_event_types", list(_VENDORED_IMPL_SCAN_EVENTS))
            entry["signal_class"], entry["signal_class_basis"] = _signal_class_for_vendored(entry)
            by_field[entry["field"]] = entry

    for entry in _VENDORED_CONTRACT_TYPE_ENTRIES.get(contract_type, []):
        copy = dict(entry)
        copy.setdefault("suppress_when_scan_event_types", list(copy.get("suppress_when_scan_event_types") or []))
        copy["signal_class"], copy["signal_class_basis"] = _signal_class_for_vendored(copy)
        by_field.setdefault(copy["field"], copy)

    if isinstance(tracking_plan, Mapping):
        for tc in tracking_plan.get("tracked_controllers") or []:
            if not isinstance(tc, Mapping):
                continue
            read_spec = tc.get("read_spec")
            if not isinstance(read_spec, Mapping):
                continue
            if not _is_poll_decodable(read_spec):
                continue
            field = _entry_field_name(read_spec, tc.get("controller_id"))
            if not field:
                continue
            if field in by_field and field in _VENDORED_FIELD_WINS:
                continue
            target = read_spec.get("target") or field
            type_kind = (read_spec.get("type_kind") or "").lower()
            type_str = read_spec.get("type") or ""
            suppress = _derive_suppress_event_types(field, tracked_topics)
            # A hint on this controller resolves through a verification read of this same entry; suppress the duplicate.
            verified_type = value_changed_event_type(tc.get("controller_id"))
            if len(verified_type) <= MAX_EVENT_TYPE_LENGTH and verified_type not in suppress:
                suppress.append(verified_type)
            signal_class, signal_basis = _signal_class_for_analyzer(type_kind, tc.get("authority_provenance"))
            entry = {
                "field": field,
                "kind": "getter_call",
                "target": target,
                "type_kind": type_kind,
                "type": type_str,
                "source": f"analyzer:{tc.get('controller_id') or field}",
                "signal_class": signal_class,
                "signal_class_basis": signal_basis,
            }
            member_word_index = _member_word_index(read_spec)
            if member_word_index is not None:
                # The parent getter returns the whole struct; this names this controller's word.
                entry["member_word_index"] = member_word_index
                entry["member_path"] = list(read_spec.get("member_path") or [])
            if suppress:
                entry["suppress_when_scan_event_types"] = suppress
            # First write wins, so sorted plan order keeps results stable.
            by_field.setdefault(field, entry)

    # Pre-resolve selectors so the poll hot path skips per-tick keccak.
    plan: list[dict[str, Any]] = []
    for entry in by_field.values():
        if entry.get("kind") == "getter_call" and "selector" not in entry:
            target = entry.get("target")
            if isinstance(target, str) and target:
                entry["selector"] = selector_for(target)
            else:
                continue
        plan.append(entry)

    # Stable order so the persisted JSON diffs cleanly.
    plan.sort(key=lambda e: e.get("field") or "")
    return plan
