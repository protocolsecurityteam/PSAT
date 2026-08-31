"""Attach the sequential storage slot of a getter-less address authority var to
its caller-equality operand, so resolution can read the live value with
``eth_getStorageAt`` (claim #3 group D — ether.fi ``MembershipNFT.membershipManager``).

An address/contract-typed state var declared without ``public`` has no
auto-generated getter, so a ``msg.sender == <var>`` gate cannot be resolved by an
``eth_call`` — the getter (``membershipManager()``) reverts on *every* deployment,
not just a standalone impl. The value still lives in the contract's own storage at
a fixed sequential slot (the var is not a proxy/impl split — its ``public`` siblings
read clean via ``eth_call`` on the same address), which is exactly what
``eth_getStorageAt`` returns. This pass computes that slot from Slither's storage
layout and stamps it onto the operand; the read itself happens at resolution.

This mirrors the keccak-constant-slot path the ``view_call`` branch already carries
(Governable ``_pendingGovernor`` → ``keccak256("LRTSquare.pending.governor")``), but
for a *named state var* whose slot is its sequential layout position rather than an
inline ``sload(<constant>)``.

Precision — so a non-address word is never misread as a 20-byte principal:
  * address-typed *scalar* only: elementary ``address`` / ``address payable`` or a
    contract/interface reference (stored as an address); never a mapping, struct,
    array, enum, or user-defined value type;
  * no public getter — ``public`` vars resolve through their auto-getter, leave them;
  * not ``constant`` / ``immutable`` — those are inlined in bytecode, not in storage;
  * storage offset 0 only — a var packed at a non-zero byte offset would need a
    shifted decode the resolver's low-20-byte slot read does not perform.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from services.static.static_analysis.predicate_types import PredicateTree
from services.static.static_analysis.secondary_impl import _SlotLayout

logger = logging.getLogger(__name__)

_ADDRESS_ELEMENTARY = {"address", "address payable"}


def _is_address_like_type(var_type: Any) -> bool:
    """True for a type stored as a 20-byte address: an elementary ``address`` /
    ``address payable``, or a contract/interface reference (an
    ``IMembershipManager`` field holds the contract's address). A mapping, struct,
    array, enum, or user-defined value type is not."""
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
    """Names of the contract's public/external nullary functions — the getters a
    caller-equality var could be read through (``owner()`` for ``_owner``). A var
    whose name (or de-underscored name) is here is NOT getter-less."""
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
    """``{var_name: 0x-padded-32-byte-slot}`` for each *wanted* var that is a
    getter-less, non-constant, address-typed scalar of ``contract`` sitting at
    storage offset 0. Computes layout slots only for the names a gate actually
    reads, so a contract with no getter-less authority gate pays nothing.

    "Getter-less" means *no public getter under any name* — not merely a private
    var. OZ Ownable's ``_owner`` is private but the contract exposes ``owner()``;
    such a var must resolve through that getter (layout-independent, the canonical
    path), never through a layout-sensitive slot read. So a var is excluded when
    the contract has a public/external nullary function named after it (its own
    name or the de-underscored name). What's left is the genuine target: an
    address authority whose value cannot be read by any call (ether.fi
    ``MembershipNFT.membershipManager``)."""
    getters = _public_nullary_function_names(contract)
    eligible: list[tuple[str, Any]] = []
    # ``state_variables_ordered`` is the full storage-layout list (inherited +
    # declared, including private base vars); ``state_variables`` drops inherited
    # ones, so an authority var declared in a base contract would be missed.
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
    """A bare (non-struct-member) ``state_variable`` operand with no slot yet —
    the only shape this pass stamps."""
    return (
        isinstance(op, dict)
        and op.get("source") == "state_variable"
        and not op.get("member_path")
        and op.get("storage_slot") is None
        and isinstance(op.get("state_variable_name"), str)
    )


def apply_internal_authority_slot_pass(contract: Any, trees: dict[str, PredicateTree]) -> None:
    """Stamp ``storage_slot`` onto each ``msg.sender == <getter-less address var>``
    caller-equality operand so the resolver can read it via ``eth_getStorageAt``."""
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
