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

logger = logging.getLogger(__name__)


# Flow kinds that move NATIVE ETH out of the contract's OWN balance (as opposed
# to an ERC-20 selector call, which moves a token the contract holds). A function
# with one of these is the only shape a contract-balance seed could unblock.
_NATIVE_OUT_KINDS = frozenset({"native_transfer_send", "low_level_value_call"})


def has_native_payout(fn: "FunctionFacts") -> bool:
    """Does static say F sends native ETH out of the contract's own balance?

    Gates the contract-balance seeding attempt, which is the most synthetic
    override the stage makes: without this the attempt would fire on every
    reverting probe and buy nothing on the ones whose revert has no funding
    cause."""
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("direction")) in _OUT_DIRECTIONS and str(flow.get("kind")) in _NATIVE_OUT_KINDS:
            return True
    return False


# Destination kinds that PROVE a fixed destination: the value is baked into the
# code, or lives in storage the static plane completed a setter scan over and
# found nothing that could repoint it.
_FIXED_TARGET_KINDS: frozenset[StateVarTargetKind] = frozenset({"immutable", "constant", "storage_no_setter"})
# Redirectable, but only by whoever holds the setter — an admin fact, not a
# caller one. Annotated against the static plane's Literal (type-only import)
# so a vocabulary drift is a pyright error without a runtime coupling.
_ADMIN_TARGET_KIND: "StateVarTargetKind" = "storage_setter"


def _target_member_kinds(flow: Mapping[str, Any]) -> list[str]:
    """The destination kinds one flow asserts. ``several`` expands to its members
    — the fold names them precisely so a consumer can take the worst — and any
    flow whose kind cannot be read yields ``[""]``, which no rule below accepts."""
    kind = flow.get("target_kind")
    name = kind.get("kind") if isinstance(kind, dict) else None
    if name != "several":
        return [name if isinstance(name, str) else ""]
    entries = flow.get("target_kinds") or []
    members = [k.get("kind") if isinstance(k, dict) else None for k in entries]
    # An entry we cannot read contributes ``""``, which no rule accepts, rather
    # than being dropped. Silently skipping it would let a partly-unreadable
    # disjunction be judged on the members that happened to parse — the one place
    # in this predicate that could fail OPEN.
    return [str(m) if isinstance(m, str) else "" for m in members] or [""]


def static_destination_shape(fn: "FunctionFacts", directions: frozenset[str]) -> str | None:
    """The destination shape static PROVES for F, or ``None``.

    A universal, and it has to be earned across EVERY out-flow the function has:
    one site paying a caller-named address makes the function caller-redirectable
    no matter how fixed its other sites are. So the rule is a conjunction —
    every flow fixed ⇒ ``immutable_fixed``; every flow fixed-or-admin-settable
    with at least one admin ⇒ ``storage_determined``; anything else ⇒ no claim,
    and the sentinel is left to decide.

    Returning ``None`` is not a failure mode, it is the common case: ``param``,
    ``msg_sender``, ``self``, ``token_owner`` and ``indeterminate`` all yield it.
    Over-claiming here is the dangerous direction — calling an attacker-
    redirectable destination fixed is a false reassurance about the exact bit
    this stage exists to establish — so the predicate never generalizes from a
    subset of the sites.

    A landed sentinel still outranks this (see ``_resolve_destination_shape``):
    an EXISTENTIAL proof that the caller can redirect the funds beats a universal
    argued from the source, which is the correct precedence when they conflict."""
    # ROUTED flows count toward the conjunction even though the probe does not
    # measure them. The claim being made is "this function cannot send funds to a
    # destination the caller names", and a routed payout does exactly that — the
    # money leaves a contract this entry calls, at an address the caller chose.
    # Quantifying only over ``out``/``eth_out`` let a router publish
    # ``immutable_fixed`` off a fee transfer to a treasury while forwarding the
    # principal to ``vault.exit(to, …)``. The sentinel cannot catch it either: it
    # reads transfers out of THIS contract, and a routed payout is emitted by the
    # callee.
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
    """ABI payability of F, or ``None`` when the artifact predates the fact.
    Tri-state on purpose: only a recorded ``False`` may suppress a probe attempt —
    an absent fact leaves the attempt exactly as it is today."""
    value = fn.effect_info.get("payable")
    return value if isinstance(value, bool) else None


def _selector_of(signature: str) -> str | None:
    """The 4-byte selector, or ``None`` when ``signature`` is not a fully lowered
    ABI signature. A residual user-defined type name means the hash is not a
    dispatch value, and a probe keyed on it would call the wrong function."""
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
    """The recipient slot the static flow lattice resolved for a value-out flow.

    The lattice emits ``target_param_index`` only for a destination that IS one
    whole entry parameter (``target_kind == "param"``, agreed by every
    contributing site) — which is what a sentinel needs, and what the name-based
    path below cannot reach for a payout recipient that no gate mentions. Flows
    disagreeing on the slot yield nothing rather than a picked winner."""
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
    """Positional index of the address param the value-flow taint says the caller
    controls. ``None`` (⇒ no sentinel probe) when the taint is absent, the param
    name cannot be mapped to a slot, or that slot is not address-typed."""
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
