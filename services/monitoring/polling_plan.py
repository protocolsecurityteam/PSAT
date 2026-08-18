"""Polling-plan projection — turns the static analyzer's tracking plan
into a flat, watcher-shaped list of pollable slots.

The poller used to branch on ``contract_type`` and hardcode a handful of
function selectors (``owner()``, ``paused()``, ``getThreshold()``,
``getMinDelay()``) plus the EIP-1967 implementation slot. That left
custom-named slots (``protocolAdmin``, ``feeRecipient``) invisible to the
poll path even when the analyzer correctly identified them.

This module derives entries from three sources, mirroring how the event
side splits work between vendored standards and per-contract analyzer
output:

  1. **Per-contract entries** from ``tracking_plan.tracked_controllers``.
     Any controller whose ``read_spec.strategy == "getter_call"`` and
     whose ``type_kind`` is poll-decodable (``address``, ``contract``,
     or a ``primitive`` bool/uint) becomes a getter_call entry. This is
     the path that unlocks custom slots without code changes.
  2. **Vendored proxy storage-slot entries** keyed on ``proxy_type``
     (EIP-1967, EIP-1822, OZ legacy, Beacon, Gnosis Safe slot 0). Same
     justification as ``services/discovery/upgrade_history.py``'s
     vendored topic registry — the slot is a fixed standard and proxy
     shells often skip Slither, so the analyzer can't surface it.
  3. **Vendored contract-type templates** for Safe (``getThreshold()``)
     and Timelock (``getMinDelay()``) — same rationale; vendored
     bytecode whose ABI is standard but whose source isn't always
     re-analyzed per protocol.

Per-entry ``suppress_when_scan_event_types`` lists are derived from the
contract's per-contract ``tracked_topics`` so the poll-vs-scan dedupe is
self-describing instead of keyed off a global field→event_type table.
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


# ---------------------------------------------------------------------------
# Hand-rolled write-target → event_type fan-out
# ---------------------------------------------------------------------------

# Inverted view of ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` — for each write
# target the canonical hand-rolled registry covers, the canonical
# event_types that observe a mutation of that target. Used to seed
# ``suppress_when_scan_event_types`` for analyzer-derived poll entries
# whose field overlaps a hand-rolled tag.
#
# Lazily built on first access so a circular import between this module
# and event_topics is impossible at import time (event_topics doesn't
# import this one today, but the inversion lives here to keep the
# polling-plan module self-contained).
_HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES: dict[str, list[str]] | None = None


def _handrolled_events_for_write_target(write_target: str) -> list[str]:
    """Return canonical hand-rolled event_types whose effect_tags claim
    they write *write_target*.

    Returns ``[]`` for targets the hand-rolled registry doesn't know
    about — custom slots flow through the per-contract tracked_topics
    derivation instead.
    """
    global _HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES
    if _HANDROLLED_WRITE_TARGET_TO_EVENT_TYPES is None:
        # Local import to avoid event_topics → polling_plan cycles.
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


# ---------------------------------------------------------------------------
# Vendored standards
# ---------------------------------------------------------------------------


# Safe module linked list head — ``modules[SENTINEL_MODULES]`` with the mapping
# at storage slot 1 and ``SENTINEL_MODULES == address(0x1)`` — and the guard
# slot, ``keccak256("guard_manager.guard.address")``, the literal the 1.3.0 and
# 1.4.1 singletons carry. Canonical values live in ``utils.evm``
# (re-exported here for the monitoring tests that import them); the
# preimage-recompute drift test is tests/test_safe_module_guard_monitoring.py.

# proxy_type → polling entry that resolves the current implementation.
# Mirrors ``services/monitoring/proxy_watcher._RESOLVE_BY_TYPE`` but
# emits the unified poll_plan entry shape. ``custom`` / ``compound`` /
# ``synthetix`` proxies use an eth_call getter rather than a slot read;
# those are emitted with ``kind: "getter_call"`` so the poll loop's
# single dispatcher handles them.
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

# Standard event_types that signal the same underlying mutation a vendored
# poll entry observes. Used to seed ``suppress_when_scan_event_types`` so
# the poll/scan dedupe survives the projection.
_VENDORED_IMPL_SCAN_EVENTS = (
    "upgraded",
    "new_implementation",
    "changed_master_copy",
    "target_updated",
    "beacon_upgraded",
)

# contract_type → list of vendored polling entries. Safe and Timelock
# ship standard ABIs whose source isn't always re-analyzed per protocol;
# the analyzer-derived path can't see ``getThreshold`` / ``getMinDelay``
# unless Slither walked the vendored Safe / TimelockController source.
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
        # Head of the Safe module linked list. The poll observes CHANGE, not
        # membership: the head alone cannot enumerate the list (see the
        # resolution-plane probe), so a moved head means "the module set
        # changed", never "the module set is [head]".
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


# ---------------------------------------------------------------------------
# Decoding + selector helpers
# ---------------------------------------------------------------------------


def selector_for(target_name: str) -> str:
    """Return the 4-byte selector for a no-arg getter named *target_name*.

    ``read_spec``-derived poll entries are admitted only for
    ``strategy == "getter_call"`` specs (``_is_poll_decodable``), whose
    target the analyzer resolved to a compiled getter: a public state
    var's auto-getter or a discovered no-parameter view function
    (``_build_getter_index`` only keeps parameterless functions). A var
    with no getter carries ``strategy == "unknown"`` and never reaches
    here. ``keccak(name + "()")[:4]`` is therefore the selector of a
    real function for every entry built from a current-schema plan;
    plans persisted before the ``unknown`` strategy existed may still
    name a private var as a getter target, and the poll loop surfaces
    those as per-entry ``error`` (revert) or ``no_value`` (empty return
    from a permissive fallback) status rather than silence.
    """
    return "0x" + keccak(text=f"{target_name}()").hex()[:8]


def decode_poll_outcome(raw: str | None, type_kind: str | None, type_str: str | None) -> tuple[object | None, bool]:
    """Decode a raw answered-RPC return for a polling entry.

    Returns ``(value, parsed)``. ``parsed`` is True iff the response body
    parsed as the entry's declared type — the wire yielded an observation.
    ``value`` is what the value plane stores; it is ``None`` either when
    nothing parsed (``parsed=False``: absent / empty ``0x`` / short body /
    undecodable type) or when the parse produced the type's conventional
    empty — the zero address — which the poll loop's "old_value=None means
    first observation" rule keeps out of ``last_known_state`` by
    convention. An answered zero address is therefore ``(None, True)``, an
    observed outcome, never conflated with an unparseable answer's
    ``(None, False)``.

    Shapes handled:
      * ``address`` / ``contract`` — right-20-byte address; the zero
        address parses (``parsed=True``) but yields ``value=None``
        (matches ``parse_address_result``'s storage convention).
      * ``primitive`` + ``type="bool"`` — non-zero word → True, zero
        word → False (both parse and both store).
      * ``primitive`` + ``type`` starting with ``uint`` / ``int`` —
        decode as integer (zero stores as 0).
    """
    if raw is None:
        return None, False
    raw_str = raw if isinstance(raw, str) else ""
    if not raw_str or raw_str == "0x":
        return None, False

    kind = (type_kind or "").lower()
    if kind in ("address", "contract"):
        # parse_address_result lives in utils.rpc but its shape is
        # tiny — inlined here to keep this module decoupled.
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
            # bool encodes as 32-byte word — non-zero anywhere in the
            # word means True. Match the existing poller semantics.
            return any(c != "0" for c in body), True
        if t.startswith("uint") or t.startswith("int"):
            try:
                return int(raw_str, 16), True
            except (ValueError, TypeError):
                return None, False

    return None, False


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

# read_spec.type_kind values the poller knows how to decode. ``unknown`` /
# ``struct`` / ``mapping`` / ``array`` / ``enum`` are deliberately
# excluded — the first two would need struct-decoding (the analyzer
# already projects struct fields via member_path; we drop those because
# decoding a struct return is ABI-heavy and no current consumer needs
# it) and the others aren't single-value reads.
_DECODABLE_TYPE_KINDS = frozenset({"address", "contract", "primitive"})

# When the analyzer emits an entry whose type matches a vendored standard
# already in the polling plan, the vendored entry wins and the analyzer
# duplicate drops. Field-name overlap is the dedupe key. This keeps the
# storage-slot fast path (EIP-1967) from being shadowed by a slower
# ``implementation()`` getter the analyzer might have surfaced from the
# UUPS pattern's ``_getImplementation`` view.
_VENDORED_FIELD_WINS = frozenset({"implementation", "threshold", "min_delay"})


# ABI types that occupy exactly one 32-byte word in a return. A struct getter's
# return is projectable by word index only when EVERY member is one of these:
# a dynamic member (``string`` / ``bytes`` / an array / a nested struct) puts an
# offset in the head instead of the value, and the word at the member's index
# would then be a pointer published as an address.
_STATIC_WORD_ABI_TYPE = re.compile(
    r"^(address|bool"
    r"|u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128"
    r"|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?"
    r"|bytes([1-9]|[12][0-9]|3[0-2]))$"
)


def _member_word_index(read_spec: Mapping[str, Any]) -> int | None:
    """Index of the word a struct getter's return holds this controller's
    member in, or ``None`` when the projection is not provably that word.

    A public struct variable's compiler-generated getter returns the members as
    a flat tuple, so member *i* is word *i* — but only under two conditions the
    analyzer's ``components`` list lets us check:

      * every member is a single static word (see ``_STATIC_WORD_ABI_TYPE``),
        which also makes the flattened auto-getter and an explicit
        ``returns (S memory)`` getter encode identically; and
      * no member is a mapping or array — the auto-getter OMITS those, which
        shifts every later member's index and would publish a neighbouring
        member's value under this controller's name.

    Both are refusals to decode, not fallbacks: an unprojectable controller
    stays unreadable, which the taxonomy already has a state for.
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


# ---------------------------------------------------------------------------
# E5 — signal classification (§3.6)
# ---------------------------------------------------------------------------

# What ONE diff on this entry tells an operator. Stamped at enrollment, read
# at mint time by ``salience.assign_salience``. The split is total over the
# entries this builder emits — there is no third state here — but the BASIS
# rides along so a consumer can see why, and so a later re-analysis can
# upgrade ``metric`` → ``config`` without a silent behaviour change.

# Basis codes. ``vendored:*`` is the entry's own ``source`` verbatim (the
# provenance the plan already carried); the other three are stated here.
SIGNAL_BASIS_CALLER_GATE: ControllerProvenance = "caller_gate"
SIGNAL_BASIS_NO_GATE_PROVENANCE = "no_gate_provenance"
SIGNAL_BASIS_TYPE_KIND_REFERENCE = "type_kind_reference"

# The one ``authority_provenance`` value that PROVES the controller behind an
# entry gates callers; the annotation pins it inside the schema vocabulary.
_PROVEN_GATE_PROVENANCE: ControllerProvenance = "caller_gate"

# Reference-typed reads name a binding, not a quantity: a moved address or
# contract reference is a control-plane fact whatever the analyzer proved
# about its writers.
_REFERENCE_TYPE_KINDS = frozenset({"address", "contract"})


def _signal_class_for_vendored(entry: Mapping[str, Any]) -> tuple[str, str]:
    """Vendored entries are config by construction: every one of them is a
    proxy implementation slot, a Safe guard / module head / threshold, or a
    timelock delay. The basis is the vendored provenance the entry already
    carries (``vendored:safe``, ``vendored:eip1967``, …)."""
    source = entry.get("source")
    basis = source if isinstance(source, str) and source.startswith("vendored:") else "vendored"
    return SIGNAL_CLASS_CONFIG, basis


def _signal_class_for_analyzer(type_kind: str, authority_provenance: str | None) -> tuple[str, str]:
    """Classify an analyzer-derived entry.

    A reference-typed read is config. A primitive is config only when the
    plan PROVES its controller gates callers; otherwise it is ``metric`` with
    ``no_gate_provenance`` — the honest default, because an unclassified
    number is not presumed to be a control parameter.

    ``no_gate_provenance`` is a POSITIVE basis, not an absent input: the
    derivation completed for this entry (it has a target, a selector and a
    type) and carried no gate proof. That is a measured fact about a finished
    analysis, and it is what lets ``metric`` collapse to ``routine`` at render
    without suppressing anything on ignorance — a later re-analysis that
    attaches ``caller_gate`` upgrades the entry with the basis change on the
    record.
    """
    if type_kind in _REFERENCE_TYPE_KINDS:
        return SIGNAL_CLASS_CONFIG, SIGNAL_BASIS_TYPE_KIND_REFERENCE
    if authority_provenance == _PROVEN_GATE_PROVENANCE:
        return SIGNAL_CLASS_CONFIG, SIGNAL_BASIS_CALLER_GATE
    return SIGNAL_CLASS_METRIC, SIGNAL_BASIS_NO_GATE_PROVENANCE


def _is_poll_decodable(read_spec: Mapping[str, Any]) -> bool:
    """A controller becomes a polling entry only when we can both call its
    getter (strategy == getter_call) and decode the result (type_kind in the
    supported set).

    A member-path controller qualifies through the same door with one extra
    proof: the word its member occupies in the parent getter's return must be
    known (:func:`_member_word_index`). Without that the projection would be a
    guess at an offset, so the controller stays unreadable."""
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
    """The single ABI word *entry* reads, sliced out of a getter's return.

    A no-op for every entry without a member projection. For one with a
    projection, a body too short to hold that word yields ``None`` — the answer
    did not contain the member, which ``decode_poll_outcome`` reports as
    unparsed rather than as a value.
    """
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
    """Pick the ``field`` key the poller writes into ``last_known_state``.

    Prefer ``state_variable_name`` — matches what
    ``_update_state_from_event`` writes on the event side, so the event
    and poll paths converge on the same key per slot. Falls back to the
    bare ``target`` (getter name) and finally the controller_id's
    state-var portion if the read spec is sparse.
    """
    name = read_spec.get("state_variable_name")
    if isinstance(name, str) and name:
        member_path = read_spec.get("member_path")
        if isinstance(member_path, list) and member_path:
            # A projected member is its own field. Sharing the parent's name
            # would file one member's value under the whole struct — and
            # collide with any entry the parent variable itself produced.
            return ".".join([name, *(str(part) for part in member_path)])
        return name
    target = read_spec.get("target")
    if isinstance(target, str) and target:
        return target
    if controller_id and ":" in controller_id:
        return controller_id.split(":", 1)[1]
    return controller_id or ""


def _derive_suppress_event_types(field: str, tracked_topics: Iterable[Mapping[str, Any]] | None) -> list[str]:
    """Return canonical event_types whose ``effect_tags.writes`` includes
    *field*, drawn from both:

      * the hand-rolled registry (``_HANDROLLED_EVENT_TYPE_TO_TAGS``) —
        covers OZ/Safe/Timelock/proxy events whose topic0s are NOT
        included in per-contract ``tracked_topics`` (the global registry
        owns them, per ``extract_governance_topics``). Without this an
        analyzer-derived ``owner`` poll entry would never know that a
        scanner ``ownership_transferred`` event is the same mutation.
      * per-contract ``tracked_topics`` — covers non-OZ ABIs the global
        registry doesn't know about (Solmate OwnerUpdated, DSAuth,
        Compound NewAdmin, custom-named slots).

    Replaces the global ``_POLL_FIELD_TO_SCAN_EVENTS`` table the prior
    poller used.
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
    """Project per-contract polling intent into a flat list of entries.

    The returned list is what enrollment stores under
    ``monitoring_config["polling_plan"]`` and what
    ``poll_for_state_changes`` walks each tick.

    Vendored entries (proxy slot, safe/timelock getters) take precedence
    over analyzer-derived duplicates for fields in
    ``_VENDORED_FIELD_WINS`` — the storage-slot fast path beats an
    analyzer's ``implementation()`` getter discovery and the standard
    Safe/Timelock ABIs beat any local re-discovery.
    """
    # Local import for the same acyclicity reason as
    # ``_handrolled_events_for_write_target``.
    from services.monitoring.event_topics import MAX_EVENT_TYPE_LENGTH, value_changed_event_type

    by_field: dict[str, dict[str, Any]] = {}

    # Vendored proxy storage-slot or getter entry, keyed on proxy_type.
    if contract_type == "proxy" and proxy_type:
        vendored_proxy = _VENDORED_PROXY_ENTRIES.get((proxy_type or "").lower())
        if vendored_proxy:
            entry = dict(vendored_proxy)
            entry.setdefault("suppress_when_scan_event_types", list(_VENDORED_IMPL_SCAN_EVENTS))
            entry["signal_class"], entry["signal_class_basis"] = _signal_class_for_vendored(entry)
            by_field[entry["field"]] = entry

    # Vendored contract-type templates (safe.getThreshold, timelock.getMinDelay).
    for entry in _VENDORED_CONTRACT_TYPE_ENTRIES.get(contract_type, []):
        copy = dict(entry)
        copy.setdefault("suppress_when_scan_event_types", list(copy.get("suppress_when_scan_event_types") or []))
        copy["signal_class"], copy["signal_class_basis"] = _signal_class_for_vendored(copy)
        by_field.setdefault(copy["field"], copy)

    # Analyzer-derived entries from the tracking plan.
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
            # Vendored standards always win for their canonical fields.
            if field in by_field and field in _VENDORED_FIELD_WINS:
                continue
            target = read_spec.get("target") or field
            type_kind = (read_spec.get("type_kind") or "").lower()
            type_str = read_spec.get("type") or ""
            suppress = _derive_suppress_event_types(field, tracked_topics)
            # A hint occurrence on this controller resolves through a
            # verification read against this very entry, so the witnessed
            # ``value_changed`` it mints and this entry's own poll report the
            # same mutation from the same read. Suppress the duplicate.
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
                # The parent getter answers with the whole struct; this names
                # the one word that is this controller. ``member_path`` rides
                # along so a persisted entry says what it projects.
                entry["member_word_index"] = member_word_index
                entry["member_path"] = list(read_spec.get("member_path") or [])
            if suppress:
                entry["suppress_when_scan_event_types"] = suppress
            # First-write-wins for analyzer entries so the deterministic
            # tracking_plan iteration order (already sorted by label)
            # doesn't churn between runs.
            by_field.setdefault(field, entry)

    # Pre-resolve the selector for every getter_call entry so the poll
    # hot path is a flat dict lookup instead of a per-tick keccak.
    plan: list[dict[str, Any]] = []
    for entry in by_field.values():
        if entry.get("kind") == "getter_call" and "selector" not in entry:
            target = entry.get("target")
            if isinstance(target, str) and target:
                entry["selector"] = selector_for(target)
            else:
                # An entry without a target can't be polled — skip rather
                # than persist garbage.
                continue
        plan.append(entry)

    # Sort deterministically so the persisted JSON is stable across
    # re-enrollments and diffs cleanly in DB inspections.
    plan.sort(key=lambda e: e.get("field") or "")
    return plan
