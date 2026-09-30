"""Flow reads: payout shapes, destination shape, payability."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    from services.static.contract_analysis_pipeline.predicate_types import (
        StateVarTargetKind,
    )

from typing import TYPE_CHECKING

from eth_utils.crypto import keccak

from services.effects.config import (
    SHAPE_IMMUTABLE_FIXED,
    SHAPE_STORAGE_DETERMINED,
)
from services.resolution.differential_probe import (
    _is_address_type,
)

from .trees import _param_index_by_name

if TYPE_CHECKING:
    from .facts import FunctionFacts

logger = logging.getLogger("services.effects.calldata")


# Flows moving native ETH from the contract's own balance, the only shape a contract-balance seed can unblock.
_NATIVE_OUT_KINDS = frozenset({"native_transfer_send", "low_level_value_call"})


def has_native_payout(fn: "FunctionFacts") -> bool:
    """Does static say F sends native ETH out of the contract's own balance? Gates the contract-balance seed, the
    most synthetic override.
    """
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("direction")) in _OUT_DIRECTIONS and str(flow.get("kind")) in _NATIVE_OUT_KINDS:
            return True
    return False


# Kinds proving a fixed destination: baked into code, or storage with no repointing setter found.
_FIXED_TARGET_KINDS: frozenset[StateVarTargetKind] = frozenset({"immutable", "constant", "storage_no_setter"})
# Redirectable only by the setter holder (an admin fact). Type-only import of the static Literal so drift is a pyright
# error.
_ADMIN_TARGET_KIND: "StateVarTargetKind" = "storage_setter"


def _target_member_kinds(flow: Mapping[str, Any]) -> list[str]:
    """The destination kinds one flow asserts; ``several`` expands to members, unreadable gives ``[""]`` (accepted by
    no rule).
    """
    kind = flow.get("target_kind")
    name = kind.get("kind") if isinstance(kind, dict) else None
    if name != "several":
        return [name if isinstance(name, str) else ""]
    entries = flow.get("target_kinds") or []
    members = [k.get("kind") if isinstance(k, dict) else None for k in entries]
    # Unreadable entries count as ``""`` rather than being skipped, or a partly unreadable disjunction could fail open.
    return [str(m) if isinstance(m, str) else "" for m in members] or [""]


def static_destination_shape(fn: "FunctionFacts", directions: frozenset[str]) -> str | None:
    """The destination shape static proves for F, or ``None``.

    A universal over every out-flow: all fixed gives ``immutable_fixed``; all fixed-or-admin with at least one admin
    gives ``storage_determined``; anything else no claim. ``None`` is the common case. Over-claiming (calling a
    redirectable destination fixed) is the dangerous direction. A landed sentinel still outranks this
    (``_resolve_destination_shape``).
    """
    # Routed flows count: a router could otherwise publish ``immutable_fixed`` from a fee transfer while forwarding the
    # principal to a caller-chosen address via a callee, which the sentinel can't see either.
    considered = set(directions) | {"value_router"}
    kinds: list[str] = []
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("direction")) not in considered:
            continue
        kinds.extend(_target_member_kinds(flow))
    if not kinds:
        return None
    if all(k in _FIXED_TARGET_KINDS for k in kinds):
        return SHAPE_IMMUTABLE_FIXED
    if all(k in _FIXED_TARGET_KINDS or k == _ADMIN_TARGET_KIND for k in kinds):
        return SHAPE_STORAGE_DETERMINED
    return None


def function_payable(fn: "FunctionFacts") -> bool | None:
    """ABI payability, or ``None`` on older artifacts. Only a recorded ``False`` suppresses an attempt."""
    value = fn.effect_info.get("payable")
    return value if isinstance(value, bool) else None


def _selector_of(signature: str) -> str | None:
    """The 4-byte selector, or ``None`` if ``signature`` isn't fully lowered (a residual type name would call the
    wrong function).
    """
    from services.static.contract_analysis_pipeline.predicate_artifacts import is_canonical_abi_signature

    if not signature or not is_canonical_abi_signature(signature):
        return None
    return "0x" + keccak(text=signature)[:4].hex()


_OUT_DIRECTIONS = frozenset({"out", "eth_out"})


def _flow_directions(fn: FunctionFacts) -> set[str]:
    dirs = {str(f.get("direction")) for f in fn.legacy_value_flows if f.get("direction")}
    for flow in fn.effect_info.get("value_flows") or []:
        if isinstance(flow, dict) and flow.get("origin") != "guard" and flow.get("direction"):
            dirs.add(str(flow["direction"]))
    return dirs


def _lattice_taint_index(fn: FunctionFacts, types: Sequence[str], directions: frozenset[str]) -> int | None:
    """The recipient slot the flow lattice resolved (``target_kind == "param"``, agreed across sites).

    Disagreeing flows yield nothing.
    """
    found: set[int] = set()
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("direction")) not in directions:
            continue
        index = flow.get("target_param_index")
        kind = flow.get("target_kind")
        kind_name = kind.get("kind") if isinstance(kind, dict) else None
        if kind_name != "param" or not isinstance(index, int) or isinstance(index, bool):
            continue
        found.add(index)
    if len(found) != 1:
        return None
    index = next(iter(found))
    return index if 0 <= index < len(types) and _is_address_type(types[index]) else None


def _taint_index(fn: FunctionFacts, types: Sequence[str], directions: frozenset[str]) -> int | None:
    """Index of the address param taint says the caller controls, or ``None`` (no sentinel probe) when absent,
    unmappable, or not address-typed.
    """
    lattice_index = _lattice_taint_index(fn, types, directions)
    if lattice_index is not None:
        return lattice_index
    names = [
        str(f.get("token_var"))
        for f in fn.legacy_value_flows
        if f.get("is_parameter") and str(f.get("direction")) in directions and f.get("token_var")
    ]
    if not names:
        return None
    index_by_name = _param_index_by_name(fn.tree)
    for name in names:
        idx = index_by_name.get(name.lower())
        if idx is not None and 0 <= idx < len(types) and _is_address_type(types[idx]):
            return idx
    return None
