"""Assemble the per-function effect records into the effects artifact."""

from __future__ import annotations

from typing import Any, cast

from ..record_ordering import attach_record_ordering
from ..summaries import _action_summary, _effect_labels
from ..token_slots import derive_token_slots
from .selectors import _function_full_name, _own_selector
from .sinks import _build_sink_records, _is_externally_observable, _is_state_changing_entry_point
from .state_writes import _state_write_facts
from .types import (
    _ERC20_PULL_SELECTORS,
    _SPECIFIC_EFFECT_LABELS,
    SCHEMA_VERSION,
    EffectInfo,
    EffectsArtifact,
    SinkRecord,
    TokenSlots,
    ValueFlow,
)
from .value_flow import _value_flow_facts

# ---------------------------------------------------------------------------
# Effects + labels + writer selectors per function.
# ---------------------------------------------------------------------------


def _effect_targets_from_sinks(sinks: list[SinkRecord]) -> list[str]:
    """Compatibility display targets sourced from the sink list.

    State writes and external-call dotted targets both remain here because
    API/UI consumers already render this field. Semantic consumers should
    read ``sinks`` and selectors directly.
    """
    seen: list[str] = []
    seen_set: set[str] = set()
    for sink in sinks:
        if sink["kind"] == "state_write" and sink["target"] not in seen_set:
            seen.append(sink["target"])
            seen_set.add(sink["target"])
        elif sink["kind"] == "external_call" and sink["target"] not in seen_set:
            # Kept for API/UI compatibility; label inference reads the
            # selector-bearing sink records instead.
            seen.append(sink["target"])
            seen_set.add(sink["target"])
    return seen


def _writer_selectors_for(function: Any, sinks: list[SinkRecord]) -> list[str]:
    """For a state-write function, its own selector is the relevant
    writer selector (HyperSync replays this function to attribute the
    write). Returns a list because some pipelines accumulate multiple
    selectors per logical writer (overloads)."""
    has_state_write = any(s["kind"] == "state_write" for s in sinks)
    if not has_state_write:
        return []
    selector = _own_selector(function)
    if selector is None:
        return []
    return [selector]


def _reconcile_value_flow_labels(
    labels: list[str], value_flows: list[ValueFlow], zero_value_sinks: set[str] | None = None
) -> list[str]:
    """Correct asset-direction labels from the value-flow facts. Native
    transfer/send is an outbound value sink Slither's low-level scan misses;
    a ``transferFrom`` whose ``from`` is ``address(this)`` was mis-read as a
    pull. Only body-origin flows count. ``value_router`` flows are excluded: they
    are a callee's move, not the entry's own asset direction, so they must not add
    ``asset_send``/``asset_pull`` to the router."""
    body = [vf for vf in value_flows if vf["origin"] != "guard"]
    body_flows = [vf for vf in body if vf["direction"] != "value_router"]

    def _is_erc20_pull(vf: ValueFlow) -> bool:
        return vf["kind"] == "callee_erc20_selector" and vf["selector"] in _ERC20_PULL_SELECTORS

    # Plane 0 maps a pull SELECTOR straight to ``asset_pull``, which reads the
    # call and not the destination. When every pull this function makes is one it
    # merely caused between two other parties, nothing arrived here and the label
    # has to come off — otherwise the row still says "fund-in" and the summary
    # still reads "Pulls assets into the contract" about a contract the funds
    # never touched. Removal only, and only on positive evidence: a routed flow
    # never ADDS a direction label, and a function with no flow facts keeps
    # whatever the selector scan said, because silence is not evidence.
    if any(_is_erc20_pull(vf) and vf["direction"] == "value_router" for vf in body) and not any(
        _is_erc20_pull(vf) for vf in body_flows
    ):
        labels = [lbl for lbl in labels if lbl != "asset_pull"]

    # Plane 0 mints ``asset_send`` from ANY ``.call{value: v}`` it can reach
    # through an internal call, without looking at v. OZ's
    # ``Address.functionCallWithValue(target, data, 0)`` sits at the bottom of
    # every SafeERC20 call, so a function whose only "value move" is an approval
    # published "sends assets out of the contract" — with no flow fact under it,
    # because the walk had already proved the same site moves nothing. That proof
    # is what retracts the label; it is available precisely because the walk
    # resolves the callee's ``value`` parameter through the caller's binding,
    # which the Plane-0 string scan cannot do. Only when no outbound flow
    # survives: a function that both approves and pays keeps the label from the
    # payment.
    if "low_level_value_call" in (zero_value_sinks or ()) and not any(vf["direction"] == "out" for vf in body_flows):
        labels = [lbl for lbl in labels if lbl != "asset_send"]

    if not body_flows:
        return labels

    if any(vf["kind"] == "native_transfer_send" for vf in body_flows):
        labels = [lbl for lbl in labels if lbl != "hook_update"]
        if "asset_send" not in labels:
            labels.append("asset_send")

    pull_from_self = any(_is_erc20_pull(vf) and vf["from_is_self"] for vf in body_flows)
    genuine_pull = any(_is_erc20_pull(vf) and not vf["from_is_self"] for vf in body_flows)
    if pull_from_self and not genuine_pull and "asset_pull" in labels:
        labels = [lbl for lbl in labels if lbl != "asset_pull"]
        if "asset_send" not in labels:
            labels.append("asset_send")
    return labels


def _effect_info_for_function(function: Any) -> EffectInfo:
    sinks = _build_sink_records(function)
    state_writes = _state_write_facts(function, sinks)
    zero_value_sinks: set[str] = set()
    value_flows = _value_flow_facts(function, zero_value_sinks=zero_value_sinks)
    assembly_state_access = any(
        s["kind"] in ("state_write", "delegatecall")
        and (s["target"].startswith("assembly_storage:") or s["target"].startswith("assembly_delegatecall:"))
        for s in sinks
    )
    attach_record_ordering(value_flows, function, assembly_state_access=assembly_state_access)
    effects: list[str] = []

    # Guard-origin sinks (a modifier's own auth call, a reentrancy latch) are
    # facts, not effects: they never drive a label, a display target, or a
    # summary. They stay in ``sinks`` with ``origin=guard``.
    body_sinks = [s for s in sinks if s["origin"] != "guard"]

    # ``effect_targets`` remains a compatibility display field. Semantic
    # consumers should read ``sinks`` and selectors instead.
    effect_targets = _effect_targets_from_sinks(body_sinks)

    # _effect_labels takes a synthetic graph-entry analog. Capability
    # reachability (delegatecall_execution, selfdestruct_capability,
    # contract_deployment) keys on ``sink_kinds`` over *all* sinks — a
    # delegatecall reachable only through a proxy's ``ifAdmin`` modifier is
    # still reachable. The external-call/asset layer reads the body-only sink
    # list, so a modifier's own auth call can't drive an effect label.
    sink_kinds = sorted({s["kind"] for s in sinks})
    effect_context = {
        "effects": list(effects),
        "effect_targets": list(effect_targets),
        "sink_kinds": sink_kinds,
        "sinks": list(body_sinks),
    }
    labels = _effect_labels(function, effect_context)
    labels = _reconcile_value_flow_labels(labels, value_flows, zero_value_sinks)
    # Functions with body external_call sinks but no specific (mint/burn/asset/etc)
    # label get ``external_contract_call`` directly from the sink shape. AFTER the
    # reconcile, so a function whose only specific label the flow facts just
    # disproved falls back to the generic sink fact rather than to nothing.
    has_external_call = any(s["kind"] == "external_call" for s in body_sinks)
    if has_external_call and not any(lbl in _SPECIFIC_EFFECT_LABELS for lbl in labels):
        labels.append("external_contract_call")
    summary = _action_summary(labels, list(effect_targets))

    signature = _function_full_name(function)
    # "" is the no-selector sentinel (fallback/receive), matching the
    # ``effect_verdicts`` identity key in ``db/effect_cache.py``.
    selector = _own_selector(function) or ""
    return {
        "function": signature,
        "selector": selector,
        "abi_signature": signature,
        "sinks": sinks,
        "state_writes": state_writes,
        "value_flows": value_flows,
        "effects": list(effects),
        "effect_labels": list(labels),
        # Includes both state-write var names and external-call dotted
        # targets for label/summary rendering. Tracking.py reads ``sinks``
        # directly to enumerate state_write writers.
        "effect_targets": list(effect_targets),
        "action_summary": summary,
        "writer_selectors": _writer_selectors_for(function, sinks),
        "state_changing": _is_state_changing_entry_point(function),
        "parameter_names": [str(getattr(p, "name", "") or "") for p in (getattr(function, "parameters", None) or [])],
        "payable": bool(getattr(function, "payable", False)),
        "assembly_state_access": assembly_state_access,
    }


# ---------------------------------------------------------------------------
# Top-level entry.
# ---------------------------------------------------------------------------


def _record_prefers(new_info: EffectInfo, new_fn: Any, old_info: EffectInfo, old_fn: Any) -> bool:
    """Should ``new_info`` replace ``old_info`` for the same signature?

    Two functions can share a ``full_name`` — a concrete implementation and
    an inherited interface/abstract re-declaration (0 nodes). Keying the dict
    by ``full_name`` alone lets the 0-node record clobber the real one and
    blank its sinks (EigenLayer StrategyManager ``pause``). Prefer the
    implemented body, then the one carrying more sinks."""
    new_impl = bool(getattr(new_fn, "is_implemented", False)) and bool(getattr(new_fn, "nodes", None))
    old_impl = bool(getattr(old_fn, "is_implemented", False)) and bool(getattr(old_fn, "nodes", None))
    if new_impl != old_impl:
        return new_impl
    return len(new_info["sinks"]) > len(old_info["sinks"])


def build_effects(contract: Any) -> EffectsArtifact:
    """Return the ``effects`` artifact for ``contract``: one
    ``EffectInfo`` per externally-observable function (external,
    public, fallback, receive)."""
    functions: dict[str, EffectInfo] = {}
    chosen_fn: dict[str, Any] = {}
    for fn in getattr(contract, "functions", []) or []:
        if not _is_externally_observable(fn):
            continue
        info = _effect_info_for_function(fn)
        signature = info["function"]
        existing = functions.get(signature)
        if existing is None or _record_prefers(info, fn, existing, chosen_fn[signature]):
            functions[signature] = info
            chosen_fn[signature] = fn

    artifact: EffectsArtifact = {
        "schema_version": SCHEMA_VERSION,
        "contract_name": getattr(contract, "name", None),
        "functions": functions,
    }
    token_slots = derive_token_slots(contract)
    if token_slots is not None:
        artifact["token_slots"] = cast("TokenSlots", token_slots)
    return artifact
