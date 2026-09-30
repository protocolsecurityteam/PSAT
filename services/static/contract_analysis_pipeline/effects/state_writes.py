"""State-write facts: member paths, hygiene classes, reentrancy-guard detection."""

from __future__ import annotations

from typing import Any
from weakref import WeakKeyDictionary

from ..shared import _all_state_variables
from .selectors import _node_irs
from .sinks import _is_view_or_pure, _node_kind_state_writes
from .types import SinkRecord, StateWriteFact


def _struct_member_types(state_variables: list[Any]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for variable in state_variables:
        declared = getattr(variable, "type", None)
        structure = getattr(declared, "type", None)
        elems = getattr(structure, "elems", None)
        if isinstance(elems, dict):
            name = getattr(variable, "name", "") or ""
            out[name] = {member: str(getattr(value, "type", "") or "") for member, value in elems.items()}
    return out


def _transitive_member_writes(function: Any, wanted: set[str]) -> dict[str, set[str]]:
    """``{var: {member}}`` member-level writes into ``wanted`` vars, pairing a ``Member`` IR with the ``Assignment``
    writing its reference. Same callee walk as sink discovery.
    """
    out: dict[str, set[str]] = {}
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        key = id(unit)
        if key in visited:
            return
        visited.add(key)
        ref_to_pair: dict[int, tuple[str, str]] = {}
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                op = type(ir).__name__
                if op == "Member":
                    base = getattr(ir, "variable_left", None)
                    base_name = getattr(base, "name", None)
                    member = getattr(ir, "variable_right", None)
                    member_name = getattr(member, "name", None) or str(member)
                    lvalue = getattr(ir, "lvalue", None)
                    if isinstance(base_name, str) and base_name in wanted and lvalue is not None:
                        ref_to_pair[id(lvalue)] = (base_name, str(member_name))
                elif op == "Assignment":
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is not None and id(lvalue) in ref_to_pair:
                        base_name, member_name = ref_to_pair[id(lvalue)]
                        out.setdefault(base_name, set()).add(member_name)
        for node in getattr(unit, "nodes", []) or []:
            for ir in _node_irs(node):
                if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                    continue
                callee = getattr(ir, "function", None)
                if callee is not None and getattr(callee, "nodes", None):
                    walk(callee)

    walk(function)
    return out


_SLOT_POINTER_CONSTANTS: WeakKeyDictionary[Any, frozenset[str]] = WeakKeyDictionary()


def _units_of(contract: Any) -> list[Any]:
    """Functions and modifiers of ``contract``."""
    return [*(getattr(contract, "functions", []) or []), *(getattr(contract, "modifiers", []) or [])]


def _collect_slot_pointer_constants(contract: Any) -> frozenset[str]:
    """Constant state vars the IR proves denote a storage slot: ``assembly { $.slot := C }`` (ERC-7201 namespaced
    struct) and ``assembly { sstore(C, v) }`` (Solady/EIP-1967; Solidity forbids assigning a constant otherwise).
    These shapes are why Slither attributes a write to the constant at all. Role ids and domain separators stay
    plain constants.
    """
    cached = _SLOT_POINTER_CONSTANTS.get(contract)
    if cached is not None:
        return cached
    constants = {
        name
        for variable in _all_state_variables(contract)
        if bool(getattr(variable, "is_constant", False)) and (name := getattr(variable, "name", "") or "")
    }
    found: set[str] = set()
    if constants:
        for unit in _units_of(contract):
            initializer = bool(getattr(unit, "is_constructor_variables", False))
            for node in getattr(unit, "nodes", []) or []:
                for ir in _node_irs(node):
                    if type(ir).__name__ != "Assignment":
                        continue
                    lvalue = getattr(ir, "lvalue", None)
                    rvalue = getattr(ir, "rvalue", None)
                    if bool(getattr(lvalue, "is_storage", False)):
                        rname = getattr(rvalue, "name", "") or ""
                        if rname in constants:
                            found.add(rname)
                    if initializer:
                        continue
                    lname = getattr(lvalue, "name", "") or ""
                    if lname in constants:
                        found.add(lname)
    result = frozenset(found)
    _SLOT_POINTER_CONSTANTS[contract] = result
    return result


_REENTRANCY_GUARDS: WeakKeyDictionary[Any, frozenset[str]] = WeakKeyDictionary()

# Guard helpers are a hop or two; ``seen`` already guarantees termination.
_GUARD_WALK_DEPTH = 6


def _nodes_state_writes(nodes: list[Any], seen: set[int], depth: int) -> set[str]:
    """State vars written by ``nodes``, following callees (OZ v5 splits guard set and restore into helpers)."""
    names: set[str] = set()
    for node in nodes:
        names.update(_node_kind_state_writes(node))
        if depth >= _GUARD_WALK_DEPTH:
            continue
        for ir in _node_irs(node):
            if type(ir).__name__ not in ("InternalCall", "LibraryCall"):
                continue
            callee = getattr(ir, "function", None)
            key = id(callee)
            if callee is None or key in seen or not getattr(callee, "nodes", None):
                continue
            names |= _nodes_state_writes(list(callee.nodes), seen | {key}, depth + 1)
    return names


def _nodes_around_placeholder(modifier: Any) -> tuple[list[Any], list[Any]] | None:
    """``(pre, post)`` nodes split at the modifier's ``_;``, or ``None``."""
    nodes = list(getattr(modifier, "nodes", []) or [])
    for index, node in enumerate(nodes):
        if str(getattr(node, "type", "")).endswith("PLACEHOLDER"):
            return (nodes[:index], nodes[index + 1 :])
    return None


def _collect_reentrancy_guard_vars(contract: Any) -> frozenset[str]:
    """State vars written on both sides of a modifier's ``_;``: set on entry, restored on exit, the shape of a
    reentrancy guard and nothing else. Follows callees for the OZ helper form.
    """
    cached = _REENTRANCY_GUARDS.get(contract)
    if cached is not None:
        return cached
    guards: set[str] = set()
    for modifier in getattr(contract, "modifiers", []) or []:
        split = _nodes_around_placeholder(modifier)
        if split is None:
            continue
        pre, post = split
        guards |= _nodes_state_writes(pre, set(), 0) & _nodes_state_writes(post, set(), 0)
    result = frozenset(guards)
    _REENTRANCY_GUARDS[contract] = result
    return result


# Name-based fallback, suppress-only (consumers only admit ``normal``), for guards set inline in a body with no
# placeholder; otherwise a bool guard would reach the pause matcher.
_REENTRANCY_GUARD_NAMES = frozenset(
    {"_status", "_reentrancyguard", "_reentrancystatus", "reentrancylock", "_locked", "locked", "_lock"}
)


def _is_reentrancy_guard_var(variable: Any, guards: frozenset[str]) -> bool:
    name = getattr(variable, "name", "") or ""
    if not name:
        return False
    if name in guards:
        return True
    low = name.lower()
    return "reentran" in low or low in _REENTRANCY_GUARD_NAMES


def _hygiene_class_for_var(variable: Any, function: Any, contract: Any) -> str:
    """Hygiene class for role facts: view-function ghost writes (OZ v5 namespaced getters), slot-locator constants
    and reentrancy guards are excluded from role facts but kept as raw writes.
    """
    if _is_view_or_pure(function):
        return "view_writer"
    if variable is None:
        return "normal"
    name = getattr(variable, "name", "") or ""
    if bool(getattr(variable, "is_constant", False)):
        if contract is not None and name in _collect_slot_pointer_constants(contract):
            return "storage_location_pseudo"
        return "constant"
    guards = _collect_reentrancy_guard_vars(contract) if contract is not None else frozenset()
    if _is_reentrancy_guard_var(variable, guards):
        return "reentrancy_guard"
    return "normal"


def _state_write_facts(function: Any, sinks: list[SinkRecord]) -> list[StateWriteFact]:
    """Enrich ``state_write`` sinks with member granularity, declared types and hygiene classes."""
    contract = getattr(function, "contract", None)
    state_variables = _all_state_variables(contract) if contract is not None else []
    by_name = {getattr(variable, "name", ""): variable for variable in state_variables}
    member_types = _struct_member_types(state_variables)

    write_sinks = [s for s in sinks if s["kind"] == "state_write"]
    wanted = {s["target"] for s in write_sinks if not s["target"].startswith("assembly_storage:")}
    member_writes = _transitive_member_writes(function, wanted) if wanted else {}

    facts: list[StateWriteFact] = []
    for sink in write_sinks:
        target = sink["target"]
        origin = sink.get("origin", "body")
        if target.startswith("assembly_storage:"):
            facts.append(
                {
                    "var": target,
                    "declared_type": "",
                    "member_path": [],
                    "granularity": "assembly_slot",
                    "hygiene_class": "view_writer" if _is_view_or_pure(function) else "normal",
                    "origin": origin,
                }
            )
            continue
        variable = by_name.get(target)
        hygiene = _hygiene_class_for_var(variable, function, contract)
        declared_type = str(getattr(variable, "type", "") or "")
        members = member_writes.get(target)
        if members:
            for member in sorted(members):
                facts.append(
                    {
                        "var": target,
                        "declared_type": member_types.get(target, {}).get(member) or declared_type,
                        "member_path": [member],
                        "granularity": "member",
                        "hygiene_class": hygiene,
                        "origin": origin,
                    }
                )
        else:
            facts.append(
                {
                    "var": target,
                    "declared_type": declared_type,
                    "member_path": [],
                    "granularity": "var",
                    "hygiene_class": hygiene,
                    "origin": origin,
                }
            )
    return facts
