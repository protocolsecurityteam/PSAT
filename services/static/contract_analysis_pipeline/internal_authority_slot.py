"""Stamp the sequential storage slot of a getter-less address authority var onto its caller-equality operand, so
resolution can read it with ``eth_getStorageAt`` (ether.fi ``MembershipNFT.membershipManager``, whose getter
reverts on every deployment). Like the constant-slot ``view_call`` path, but for a named var at its layout
position.

Only address-typed scalars (address or contract reference), with no public getter under any name, not
constant/immutable, at storage offset 0 (the resolver decodes the low 20 bytes).
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from services.static.contract_analysis_pipeline.predicate_types import PredicateTree
from services.static.contract_analysis_pipeline.secondary_impl import _SlotLayout

logger = logging.getLogger(__name__)

_ADDRESS_ELEMENTARY = {"address", "address payable"}


def _is_address_like_type(var_type: Any) -> bool:
    """True for a type stored as an address: ``address``/``address payable`` or a contract/interface reference."""
    try:
        from slither.core.declarations.contract import Contract
        from slither.core.solidity_types.elementary_type import ElementaryType
        from slither.core.solidity_types.user_defined_type import UserDefinedType
    except Exception:  # pragma: no cover - import edge
        return False
    if isinstance(var_type, ElementaryType):
        return var_type.name in _ADDRESS_ELEMENTARY
    if isinstance(var_type, UserDefinedType):
        return isinstance(var_type.type, Contract)
    return False


def _public_nullary_function_names(contract: Any) -> set[str]:
    """Public/external nullary function names; a var matching one (or its de-underscored name) isn't getter-less."""
    names: set[str] = set()
    for fn in getattr(contract, "functions_entry_points", []) or []:
        if getattr(fn, "visibility", None) not in ("public", "external"):
            continue
        if getattr(fn, "parameters", None):
            continue  # a getter is nullary
        nm = getattr(fn, "name", None)
        if nm:
            names.add(nm)
    return names


def _slots_for_vars(contract: Any, wanted: set[str]) -> dict[str, str]:
    """``{var: 32-byte slot}`` for wanted vars that are getter-less, non-constant address scalars at offset 0,
    computed only for names a gate reads. Getter-less means no public getter by any name: OZ ``_owner`` is private
    but has ``owner()``, which is layout-independent and preferred.
    """
    getters = _public_nullary_function_names(contract)
    eligible: list[tuple[str, Any]] = []
    # ``state_variables_ordered`` includes inherited vars; ``state_variables`` drops them.
    variables = getattr(contract, "state_variables_ordered", None) or getattr(contract, "state_variables", []) or []
    for var in variables:
        name = getattr(var, "name", None)
        if not name or name not in wanted:
            continue
        if getattr(var, "visibility", None) == "public":
            continue  # auto-getter resolves it; no slot read needed
        if getattr(var, "is_constant", False) or getattr(var, "is_immutable", False):
            continue  # inlined in bytecode, not in storage
        if name in getters or name.lstrip("_") in getters:
            continue  # a public getter (e.g. owner() for _owner) reads it — use that
        if not _is_address_like_type(getattr(var, "type", None)):
            continue
        eligible.append((str(name), var))
    if not eligible:
        return {}
    layout = _SlotLayout(contract)
    slots: dict[str, str] = {}
    for name, var in eligible:
        if name in slots:
            continue
        so = layout.slot_offset(var)
        if so is None or so[1] != 0:  # need a known slot at byte offset 0
            continue
        slots[name] = "0x" + format(so[0], "064x")
    return slots


def _walk_leaves(node: Any, callback: Callable[[dict[str, Any]], None]) -> None:
    if not isinstance(node, dict):
        return
    if node.get("op") == "LEAF":
        leaf = node.get("leaf")
        if isinstance(leaf, dict):
            callback(leaf)
        return
    for child in node.get("children") or []:
        _walk_leaves(child, callback)


def _is_target_operand(op: Any) -> bool:
    """A bare state-variable operand without a slot yet."""
    return (
        isinstance(op, dict)
        and op.get("source") == "state_variable"
        and not op.get("member_path")
        and op.get("storage_slot") is None
        and isinstance(op.get("state_variable_name"), str)
    )


def apply_internal_authority_slot_pass(contract: Any, trees: dict[str, PredicateTree]) -> None:
    """Stamp ``storage_slot`` onto each ``msg.sender == <getter-less address var>`` operand."""
    wanted: set[str] = set()

    def collect(leaf: dict[str, Any]) -> None:
        if leaf.get("kind") != "equality" or leaf.get("authority_role") != "caller_authority":
            return
        for op in leaf.get("operands") or []:
            if _is_target_operand(op):
                wanted.add(op["state_variable_name"])

    for tree in trees.values():
        _walk_leaves(tree, collect)
    if not wanted:
        return

    slots = _slots_for_vars(contract, wanted)
    if not slots:
        return

    def attach(leaf: dict[str, Any]) -> None:
        if leaf.get("kind") != "equality" or leaf.get("authority_role") != "caller_authority":
            return
        for op in leaf.get("operands") or []:
            if _is_target_operand(op):
                slot = slots.get(op["state_variable_name"])
                if slot is not None:
                    op["storage_slot"] = slot

    for tree in trees.values():
        _walk_leaves(tree, attach)
