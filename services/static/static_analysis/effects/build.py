"""Assemble the per-function effect records into the effects artifact."""

from __future__ import annotations

from typing import Any, cast

from ..record_ordering import attach_record_ordering
from ..token_slots import derive_token_slots
from .selectors import _function_full_name, _own_selector
from .sinks import _build_sink_records, _is_externally_observable, _is_state_changing_entry_point
from .state_writes import _state_write_facts
from .types import (
    SCHEMA_VERSION,
    EffectInfo,
    EffectsArtifact,
    SinkRecord,
    TokenSlots,
)
from .value_flow import _value_flow_facts

# ---------------------------------------------------------------------------
# Effects + labels + writer selectors per function.
# ---------------------------------------------------------------------------


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


def _effect_info_for_function(function: Any) -> EffectInfo:
    sinks = _build_sink_records(function)
    state_writes = _state_write_facts(function, sinks)
    value_flows = _value_flow_facts(function)
    assembly_state_access = any(
        s["kind"] in ("state_write", "delegatecall")
        and (s["target"].startswith("assembly_storage:") or s["target"].startswith("assembly_delegatecall:"))
        for s in sinks
    )
    attach_record_ordering(value_flows, function, assembly_state_access=assembly_state_access)
    effects: list[str] = []

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
