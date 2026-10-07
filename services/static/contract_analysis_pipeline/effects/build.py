"""Assemble the per-function effect records into the effects artifact."""

from __future__ import annotations

from typing import Any, cast

from ..record_ordering import attach_record_ordering
from ..summaries import _action_summary, _effect_labels
from ..token_slots import derive_token_slots
from .origins import _ENGINE_BUNDLE_SCOPE
from .selectors import _function_full_name, _is_fallback_or_receive, _own_abi_signature, _selector_for
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


def _effect_targets_from_sinks(sinks: list[SinkRecord]) -> list[str]:
    """Display targets from the sink list, kept for API/UI; semantic consumers read ``sinks`` and selectors."""
    seen: list[str] = []
    seen_set: set[str] = set()
    for sink in sinks:
        if sink["kind"] == "state_write" and sink["target"] not in seen_set:
            seen.append(sink["target"])
            seen_set.add(sink["target"])
        elif sink["kind"] == "external_call" and sink["target"] not in seen_set:
            seen.append(sink["target"])
            seen_set.add(sink["target"])
    return seen


def _writer_selectors_for(function: Any, sinks: list[SinkRecord], selector: str | None) -> list[str] | None:
    """A state-write function's own selector (HyperSync replays it to attribute the write); a list because overloads
    accumulate. ``None`` when the function writes but its selector is not determined.
    """
    has_state_write = any(s["kind"] == "state_write" for s in sinks)
    if not has_state_write or _is_fallback_or_receive(function):
        return []
    if selector is None:
        return None
    return [selector]


def _reconcile_value_flow_labels(
    labels: list[str], value_flows: list[ValueFlow], zero_value_sinks: set[str] | None = None
) -> list[str]:
    """Correct asset-direction labels from the value-flow facts: native ``transfer``/``send`` is an outbound sink
    Slither's scan misses, and a ``transferFrom`` from ``address(this)`` is not a pull. Body-origin only;
    ``value_router`` flows are a callee's move and never add direction labels.
    """
    body = [vf for vf in value_flows if vf["origin"] != "guard"]
    body_flows = [vf for vf in body if vf["direction"] != "value_router"]

    def _is_erc20_pull(vf: ValueFlow) -> bool:
        return vf["kind"] == "callee_erc20_selector" and vf["selector"] in _ERC20_PULL_SELECTORS

    # The selector scan labels any pull ``asset_pull``. When every pull is one this function merely caused between third
    # parties, nothing arrived here, so remove it. Only on positive evidence: no flow facts leaves the label alone.
    if any(_is_erc20_pull(vf) and vf["direction"] == "value_router" for vf in body) and not any(
        _is_erc20_pull(vf) for vf in body_flows
    ):
        labels = [lbl for lbl in labels if lbl != "asset_pull"]

    # Plane 0 mints ``asset_send`` from any reachable ``.call{value: v}`` without reading v, so OZ's
    # ``functionCallWithValue(target, data, 0)`` under every SafeERC20 call made approvals read as sends. The walk
    # proved the site moves nothing, which retracts it, unless an outbound flow survives.
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

    # Guard-origin sinks are facts, not effects: they stay in ``sinks`` but drive no label, target or summary.
    body_sinks = [s for s in sinks if s["origin"] != "guard"]

    effect_targets = _effect_targets_from_sinks(body_sinks)

    # Capability reachability (delegatecall, selfdestruct, deployment) uses all sinks (a delegatecall behind a proxy's
    # ``ifAdmin`` modifier is still reachable); the external-call/asset layer uses body sinks only.
    sink_kinds = sorted({s["kind"] for s in sinks})
    effect_context = {
        "effects": list(effects),
        "effect_targets": list(effect_targets),
        "sink_kinds": sink_kinds,
        "sinks": list(body_sinks),
    }
    labels = _effect_labels(function, effect_context)
    labels = _reconcile_value_flow_labels(labels, value_flows, zero_value_sinks)
    # After the reconcile, so a function whose only specific label was disproved falls back to the generic fact.
    has_external_call = any(s["kind"] == "external_call" for s in body_sinks)
    if has_external_call and not any(lbl in _SPECIFIC_EFFECT_LABELS for lbl in labels):
        labels.append("external_contract_call")
    summary = _action_summary(labels, list(effect_targets))

    signature = _function_full_name(function)
    # "" is the no-selector sentinel (fallback/receive), matching ``db/effect_cache.py``; ``None`` is not determined.
    abi_signature: str | None
    selector: str | None
    if _is_fallback_or_receive(function):
        abi_signature, selector = signature, ""
    else:
        abi_signature = _own_abi_signature(function)
        selector = _selector_for(abi_signature)
    return {
        "function": signature,
        "selector": selector,
        "abi_signature": abi_signature,
        "sinks": sinks,
        "state_writes": state_writes,
        "value_flows": value_flows,
        "effects": list(effects),
        "effect_labels": list(labels),
        "effect_targets": list(effect_targets),
        "action_summary": summary,
        "writer_selectors": _writer_selectors_for(function, sinks, selector),
        "state_changing": _is_state_changing_entry_point(function),
        "parameter_names": [str(getattr(p, "name", "") or "") for p in (getattr(function, "parameters", None) or [])],
        "payable": bool(getattr(function, "payable", False)),
        "assembly_state_access": assembly_state_access,
    }


def _record_prefers(new_info: EffectInfo, new_fn: Any, old_info: EffectInfo, old_fn: Any) -> bool:
    """Whether ``new_info`` should replace ``old_info`` for the same signature: prefer an implemented body over a
    0-node interface re-declaration (which blanked EigenLayer StrategyManager ``pause``), then more sinks.
    """
    new_impl = bool(getattr(new_fn, "is_implemented", False)) and bool(getattr(new_fn, "nodes", None))
    old_impl = bool(getattr(old_fn, "is_implemented", False)) and bool(getattr(old_fn, "nodes", None))
    if new_impl != old_impl:
        return new_impl
    return len(new_info["sinks"]) > len(old_info["sinks"])


def build_effects(contract: Any) -> EffectsArtifact:
    """The ``effects`` artifact for ``contract``: one ``EffectInfo`` per external, public, fallback and receive
    function.
    """
    cache_token = _ENGINE_BUNDLE_SCOPE.set({})
    try:
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
    finally:
        _ENGINE_BUNDLE_SCOPE.reset(cache_token)
