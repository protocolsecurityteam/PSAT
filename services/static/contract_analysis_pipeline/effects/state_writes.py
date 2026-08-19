"""State-write facts: member paths, hygiene classes, reentrancy-guard detection."""

from __future__ import annotations

from typing import Any
from weakref import WeakKeyDictionary

from ..shared import _all_state_variables
from .selectors import _node_irs
from .sinks import _is_view_or_pure, _node_kind_state_writes
from .types import SinkRecord, StateWriteFact

# ---------------------------------------------------------------------------
# State-write facts (member paths + hygiene classes).
# ---------------------------------------------------------------------------


def _struct_member_types(state_variables: list[Any]) -> dict[str, dict[str, str]]:
    """``{var_name: {member_name: declared_type}}`` for struct-typed state
    vars, read from Slither's structure ``elems``."""
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
    """``{var_name: {member}}`` — member-level writes into the ``wanted``
    base state vars, tracked by pairing a ``Member`` IR (``$.member``) with
    the ``Assignment`` that writes the reference it produced. Walks the same
    internal/library/modifier callees as sink discovery."""
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
    """Every code unit whose IR belongs to ``contract`` — functions plus
    modifiers, the two places Slither lowers a body into nodes."""
    return [*(getattr(contract, "functions", []) or []), *(getattr(contract, "modifiers", []) or [])]


def _collect_slot_pointer_constants(contract: Any) -> frozenset[str]:
    """Constant state vars PROVEN by the lowered IR to denote a storage SLOT.

    Two assembly shapes, both facts of the IR rather than of the identifier:

    * ``assembly { $.slot := C }`` lowers to an ``Assignment`` that binds a
      *storage-location* local (``is_storage``) from the constant — the ERC-7201
      namespaced-struct form (OZ v5 ``_getXStorage()``).
    * ``assembly { sstore(C, v) }`` lowers to an ``Assignment`` whose *lvalue*
      IS the constant. Solidity forbids assigning to a constant, so outside the
      synthetic constant-initializer unit (``is_constructor_variables``) this can
      only be the constant used as a slot number — the Solady / EIP-1967 form.

    Those same two shapes are why Slither attributes a "write" to the constant at
    all, so the set is exactly the population this classification has to judge.
    An ordinary ``bytes32`` constant (a role id, a keccak'd domain separator)
    reaches neither shape and stays a plain ``constant``."""
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

# Bounds the transitive walk for the set/restore shape. Guard helpers are one or
# two hops (``nonReentrant`` -> ``_nonReentrantBefore`` -> ``_reentrancyGuardStorage``);
# the ``seen`` set already guarantees termination.
_GUARD_WALK_DEPTH = 6


def _nodes_state_writes(nodes: list[Any], seen: set[int], depth: int) -> set[str]:
    """State-var names written by ``nodes``, following internal/library callees
    (OZ v5 splits the guard's set and restore into helper calls)."""
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
    """``(pre, post)`` node lists split at the modifier's ``_;`` placeholder, or
    ``None`` when the modifier has no placeholder."""
    nodes = list(getattr(modifier, "nodes", []) or [])
    for index, node in enumerate(nodes):
        if str(getattr(node, "type", "")).endswith("PLACEHOLDER"):
            return (nodes[:index], nodes[index + 1 :])
    return None


def _collect_reentrancy_guard_vars(contract: Any) -> frozenset[str]:
    """State vars PROVEN by the IR to be reentrancy guards: written on BOTH
    sides of a modifier's ``_;`` placeholder.

    Set-at-entry / restore-at-exit around the wrapped body is the defining shape
    of a guard and of nothing else — an authority pointer, a pause latch or an
    accounting balance is never restored to its prior value as the call unwinds.
    The walk follows internal/library callees, so the OZ form
    (``nonReentrant`` -> ``_nonReentrantBefore()`` / ``_nonReentrantAfter()``)
    is recognized as well as the inline Solmate/OZ-v4 form."""
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


# Suppress-only name fallback for reentrancy guards. ``reentrancy_guard`` is a
# pure SUPPRESSOR — no consumer reads it to admit a fact, they only require
# ``normal`` — so an extra name-driven hit can withhold a fact but can never
# publish one, and the invariant "never fail toward an assertion" holds in the
# direction that matters. It stays because :func:`_collect_reentrancy_guard_vars`
# only sees the modifier form: a guard set and restored inline in a function body
# has no placeholder to split on, and letting a ``bool`` one through would put it
# in front of the pause-latch matcher as a flag some gate reverts on.
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
    """Classify a write for role-fact hygiene. A view/pure function that
    "writes" is a Slither attribution ghost (OZ v5 namespaced getters); a
    constant proven to be an assembly slot locator is a pseudo-var, not the
    value it points at; reentrancy guards are control noise. All of these must
    be excluded from role facts but remain raw writes."""
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
    """Project the ``state_write`` sinks into richer facts: member
    granularity for struct writes, declared types, and hygiene classes."""
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
