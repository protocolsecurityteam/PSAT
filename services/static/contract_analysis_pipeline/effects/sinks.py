"""Function inclusion predicates and transitive sink discovery."""

from __future__ import annotations

from typing import Any

from ..summaries import _resolve_cast_head
from .selectors import (
    _auto_getter_selector,
    _callee_signature,
    _function_full_name,
    _is_fallback_or_receive,
    _node_irs,
    _selector_for,
)
from .types import ReceiverDescriptor, SinkRecord


def _is_externally_observable(fn: Any) -> bool:
    """External/public or fallback/receive; not constructors or internal/private."""
    if getattr(fn, "is_constructor", False) or (getattr(fn, "name", "") or "") == "constructor":
        return False
    if _is_fallback_or_receive(fn):
        return True
    visibility = getattr(fn, "visibility", None)
    return visibility in ("external", "public")


def _is_state_changing_entry_point(fn: Any) -> bool:
    """A selector-bearing, non-view, non-pure external/public function."""
    if _is_fallback_or_receive(fn):
        return False
    if getattr(fn, "visibility", None) not in ("external", "public"):
        return False
    return not (getattr(fn, "view", False) or getattr(fn, "pure", False))


def _is_view_or_pure(fn: Any) -> bool:
    return bool(getattr(fn, "view", False) or getattr(fn, "pure", False))


def _bare_callee_name(signature: str | None) -> str | None:
    """The bare name of a ``name(types)`` signature, or ``None``; the join that survives interface-param hash
    differences.
    """
    if not isinstance(signature, str) or "(" not in signature:
        return None
    name = signature.split("(", 1)[0].strip()
    return name or None


def _sink_id(function_name: str, kind: str, target: str, idx: int) -> str:
    """Stable ``<function>:sink<idx>:<kind>:<target>`` id; the index separates repeats of the same kind and target."""
    return f"{function_name}:sink{idx}:{kind}:{target}"


def _is_modifier_call(ir: Any) -> bool:
    if getattr(ir, "is_modifier_call", False):
        return True
    callee = getattr(ir, "function", None)
    return type(callee).__name__ == "Modifier"


def _node_kind_state_writes(node: Any) -> list[str]:
    names: list[str] = []
    for variable in getattr(node, "state_variables_written", []) or []:
        name = getattr(variable, "name", "") or ""
        if name:
            names.append(name)
    return names


def _receiver_not_determined(reason: str) -> ReceiverDescriptor:
    return {
        "binding": "not_determined",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": None,
        "receiver_provenance": "not_determined",
        "not_determined_reason": reason,
    }


def _receiver_descriptor(
    resolved: Any, unit: Any, entry_param_ids: dict[int, int], entry_contract: Any
) -> ReceiverDescriptor:
    """A call receiver's structural descriptor.

    ``entry_param_ids`` maps the entry function's formals to positions. The walk is transitive, so a helper's formal has
    no ABI slot and is reported as ``internal_helper`` with no index and no ``caller_named`` claim.

    ``entry_contract`` limits the state-variable arm to the analysed contract: a library's ``public constant`` is
    inlined, isn't this contract's storage, and would collide byte-identically with a same-named contract constant.
    """
    from slither.core.declarations.solidity_variables import SolidityVariable
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.variables import Constant

    if resolved is None:
        return _receiver_not_determined("unresolved_head")
    type_name = type(resolved).__name__
    if "Temporary" in type_name or "Reference" in type_name or "Tuple" in type_name:
        # Stopped at a computed temporary or an element: no declaration.
        return _receiver_not_determined("unresolved_head")
    if isinstance(resolved, (SolidityVariable, Constant)):
        return _receiver_not_determined("unsupported_variable_kind")

    name = getattr(resolved, "name", None)
    variable = str(name) if isinstance(name, str) and name else None

    if isinstance(resolved, StateVariable):
        declaring = getattr(resolved, "contract", None)
        own = {id(entry_contract)} | {id(base) for base in getattr(entry_contract, "inheritance", []) or []}
        if entry_contract is None or declaring is None or id(declaring) not in own:
            return _receiver_not_determined("foreign_declaration")
        if getattr(resolved, "is_constant", False):
            mutability = "constant"
        elif getattr(resolved, "is_immutable", False):
            mutability = "immutable_in_implementation"
        else:
            mutability = "mutable"
        visibility = getattr(resolved, "visibility", None)
        return {
            "binding": "state_variable",
            "param_scope": None,
            "param_index": None,
            "mutability": mutability,
            "visibility": str(visibility) if visibility else None,
            "auto_getter_selector": _auto_getter_selector(resolved),
            "variable": variable,
            # Structural only; the address is minted where it's read, pinned to a block.
            "receiver_provenance": "contract_state_unresolved",
        }

    index = entry_param_ids.get(id(resolved))
    if index is not None:
        return {
            "binding": "parameter",
            "param_scope": "entry_point",
            "param_index": index,
            "mutability": None,
            "visibility": None,
            "auto_getter_selector": None,
            "variable": variable,
            "receiver_provenance": "caller_named",
        }
    if any(resolved is parameter for parameter in getattr(unit, "parameters", []) or []):
        return {
            "binding": "parameter",
            "param_scope": "internal_helper",
            "param_index": None,
            "mutability": None,
            "visibility": None,
            "auto_getter_selector": None,
            "variable": variable,
            "receiver_provenance": "not_determined",
        }
    return {
        "binding": "local",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": variable,
        "receiver_provenance": "not_determined",
    }


def _fold_receivers(descriptors: list[ReceiverDescriptor]) -> ReceiverDescriptor | None:
    """One descriptor per sink record, or ``not_determined`` when folded sites disagree.

    Collect-then-fold so a later agreeing site can't undo a disagreement.
    """
    if not descriptors:
        return None
    distinct = {tuple(sorted(descriptor.items())) for descriptor in descriptors}
    if len(distinct) == 1:
        return descriptors[0]
    return _receiver_not_determined("fold_disagreement")


def _classify_node_irs(
    node: Any, unit: Any, entry_param_ids: dict[int, int], entry_contract: Any
) -> list[tuple[str, str, str | None, ReceiverDescriptor | None]]:
    """Non-state-write sinks at a node as ``(kind, target, selector, receiver)``; ``receiver`` only for
    high-level/library calls. ``unit`` owns the node; ``entry_param_ids`` is always the entry's. State writes come
    from Slither's ``state_variables_written`` instead.
    """
    out: list[tuple[str, str, str | None, ReceiverDescriptor | None]] = []
    # Node-local def map, so an inline-cast receiver resolves past its temporary.
    def_by_id = {id(lv): ir for ir in _node_irs(node) if (lv := getattr(ir, "lvalue", None)) is not None}
    for ir in _node_irs(node):
        op = type(ir).__name__
        if op == "NewContract":
            target = getattr(ir, "contract_name", None) or str(getattr(ir, "contract_created", "")) or "unknown"
            out.append(("contract_creation", str(target), None, None))
        elif op in ("HighLevelCall", "LibraryCall"):
            function_name = getattr(ir, "function_name", None) or "call"
            selector = _selector_for(_callee_signature(ir))
            # A library call's receiver is its first argument; ``destination`` is the library.
            if op == "LibraryCall":
                arguments = list(getattr(ir, "arguments", []) or [])
                head = arguments[0] if arguments else getattr(ir, "destination", None)
            else:
                head = getattr(ir, "destination", None)
            resolved = _resolve_cast_head(head, def_by_id)
            destination_name = getattr(resolved, "name", None) or str(resolved) or "unknown"
            receiver = _receiver_descriptor(resolved, unit, entry_param_ids, entry_contract)
            out.append(("external_call", f"{destination_name}.{function_name}", selector, receiver))
        elif op == "LowLevelCall":
            target = getattr(getattr(ir, "destination", None), "name", None) or str(
                getattr(ir, "destination", None) or "unknown"
            )
            function_name = str(getattr(ir, "function_name", "") or "")
            if function_name == "delegatecall":
                out.append(("delegatecall", str(target), None, None))
            else:
                out.append(("external_call", f"{target}.{function_name or 'call'}", None, None))
        elif op == "SolidityCall":
            function_name = getattr(getattr(ir, "function", None), "name", "") or ""
            arguments = list(getattr(ir, "arguments", []) or [])
            if function_name.startswith("selfdestruct("):
                out.append(("selfdestruct", "selfdestruct", None, None))
            elif function_name.startswith("sstore("):
                # Slither doesn't record assembly writes in ``state_variables_written``; key by the slot expression.
                slot = str(arguments[0]) if arguments else "unknown"
                out.append(("state_write", f"assembly_storage:{slot}", None, None))
            elif function_name.startswith("delegatecall("):
                # Assembly delegatecall (e.g. an EIP-1967 fallback): ``delegatecall(gas, addr, ...)``.
                target = str(arguments[1]) if len(arguments) > 1 else "assembly_delegatecall"
                out.append(("delegatecall", f"assembly_delegatecall:{target}", None, None))
    return out


def _walk_unit_for_sinks(
    unit: Any,
    visited: set[Any],
    origin: str,
    entry_param_ids: dict[int, int],
    entry_contract: Any,
) -> list[tuple[str, str, str | None, str, ReceiverDescriptor | None]]:
    """Gather ``(kind, target, selector, origin, receiver)`` tuples from ``unit`` and its callees.

    ``origin`` becomes ``guard`` once the walk enters a modifier. ``entry_param_ids`` stays the entry's.
    """
    unit_key = getattr(unit, "canonical_name", None) or getattr(unit, "full_name", None) or id(unit)
    if unit_key in visited:
        return []
    visited.add(unit_key)

    found: list[tuple[str, str, str | None, str, ReceiverDescriptor | None]] = []
    for node in getattr(unit, "nodes", []) or []:
        for var_name in _node_kind_state_writes(node):
            found.append(("state_write", var_name, None, origin, None))
        for kind, target, selector, receiver in _classify_node_irs(node, unit, entry_param_ids, entry_contract):
            found.append((kind, target, selector, origin, receiver))
        for ir in _node_irs(node):
            op = type(ir).__name__
            if op not in ("InternalCall", "LibraryCall"):
                continue
            callee = getattr(ir, "function", None)
            if callee is None or not getattr(callee, "nodes", None):
                continue
            child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
            found.extend(_walk_unit_for_sinks(callee, visited, child_origin, entry_param_ids, entry_contract))
    return found


def _build_sink_records(function: Any) -> list[SinkRecord]:
    """One sink per ``(kind, target)``, order preserved; a sink reachable from both body and guard stays ``body``.

    Only ``external_call`` sinks carry a selector. Receivers are folded once after the walk so conflicts stick.
    """
    function_name = _function_full_name(function)
    entry_param_ids = {
        id(parameter): position for position, parameter in enumerate(getattr(function, "parameters", []) or [])
    }
    quints = _walk_unit_for_sinks(function, set(), "body", entry_param_ids, getattr(function, "contract", None))

    out: list[SinkRecord] = []
    index: dict[tuple[str, str, str | None], int] = {}
    receivers: dict[tuple[str, str, str | None], list[ReceiverDescriptor]] = {}
    for kind, target, selector, origin, receiver in quints:
        key = (kind, target, selector)
        if receiver is not None:
            receivers.setdefault(key, []).append(receiver)
        if key in index:
            if origin == "body":
                out[index[key]]["origin"] = "body"
            continue
        idx = len(out)
        record: SinkRecord = {
            "id": _sink_id(function_name, kind, target, idx),
            "function": function_name,
            "kind": kind,
            "target": target,
            "selector": selector,
            "origin": origin,
        }
        index[key] = idx
        out.append(record)
    for key, idx in index.items():
        folded = _fold_receivers(receivers.get(key, []))
        if folded is not None:
            out[idx]["receiver"] = folded
    return out
