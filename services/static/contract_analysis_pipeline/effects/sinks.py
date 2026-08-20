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


# ---------------------------------------------------------------------------
# Function inclusion (mirrors predicate_artifacts._is_externally_callable but
# keeps fallback/receive — see module docstring).
# ---------------------------------------------------------------------------
def _is_externally_observable(fn: Any) -> bool:
    """External/public OR fallback/receive. Skips constructor and
    internal/private functions."""
    if getattr(fn, "is_constructor", False) or (getattr(fn, "name", "") or "") == "constructor":
        return False
    if _is_fallback_or_receive(fn):
        return True
    visibility = getattr(fn, "visibility", None)
    return visibility in ("external", "public")


def _is_state_changing_entry_point(fn: Any) -> bool:
    """A selector-bearing external/public, non-view, non-pure function — the
    ABI mutability surface. Excludes fallback/receive (no selector) and
    view/pure reads."""
    if _is_fallback_or_receive(fn):
        return False
    if getattr(fn, "visibility", None) not in ("external", "public"):
        return False
    return not (getattr(fn, "view", False) or getattr(fn, "pure", False))


def _is_view_or_pure(fn: Any) -> bool:
    return bool(getattr(fn, "view", False) or getattr(fn, "pure", False))


def _bare_callee_name(signature: str | None) -> str | None:
    """The bare function name of a ``name(types)`` signature, or ``None``.
    The name half of a router-op identity: a DECLARED signature carrying an
    interface-typed parameter does not hash to the selector a leaf recorded,
    so the name is the join that survives canonicalization differences."""
    if not isinstance(signature, str) or "(" not in signature:
        return None
    name = signature.split("(", 1)[0].strip()
    return name or None


def _sink_id(function_name: str, kind: str, target: str, idx: int) -> str:
    """Stable, idx-disambiguated ID. The ``idx`` keeps multiple sinks
    of the same (kind, target) on one function distinct (e.g. two
    state_write sinks to the same var from different branches).

    Format is ``<function>:sink<idx>:<kind>:<target>`` so callers can
    reference individual sinks without relying on source order alone."""
    return f"{function_name}:sink{idx}:{kind}:{target}"


def _is_modifier_call(ir: Any) -> bool:
    """True iff ``ir`` is an InternalCall that dispatches a modifier body.
    Everything reached through it is guard-origin, not a real effect."""
    if getattr(ir, "is_modifier_call", False):
        return True
    callee = getattr(ir, "function", None)
    return type(callee).__name__ == "Modifier"


def _node_kind_state_writes(node: Any) -> list[str]:
    """Return the names of state variables written at this node."""
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
    """Describe a call's resolved receiver structurally.

    ``entry_param_ids`` maps the ENTRY function's formal-parameter object ids
    to their positions. The sink walk is transitive, so a receiver that is a
    formal of an internal helper is a real parameter of the unit being walked
    but occupies no ABI slot of the entry point — and whether the entry's own
    argument reaches it is a dataflow question this walk does not ask. Such a
    receiver is reported as a parameter of ``internal_helper`` scope with no
    index and NO ``caller_named`` claim; only identity against the entry's own
    parameter objects licenses that.

    ``entry_contract`` bounds the state-variable arm to declarations the
    ANALYSED CONTRACT actually has. The walk recurses into library calls, so a
    library's own ``public constant`` reaches this function as a perfectly good
    ``StateVariable`` — but it is inlined at each call site, it is not this
    unit's storage, and the accessor it would name does not exist in this
    contract's ABI, so a pinned read at the deployment address would revert or
    fall through. It also defeats the fold silently: two same-named constants,
    one on the contract and one on the library, produce BYTE-IDENTICAL
    descriptors (same name ⇒ same visibility, mutability and minted selector),
    so a disagreement between two distinct assets reads as agreement."""
    from slither.core.declarations.solidity_variables import SolidityVariable
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.variables import Constant

    if resolved is None:
        return _receiver_not_determined("unresolved_head")
    type_name = type(resolved).__name__
    if "Temporary" in type_name or "Reference" in type_name or "Tuple" in type_name:
        # The cast walk stopped at a temporary (a computed value) or at a
        # mapping/array element. Neither names a declaration.
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
            # Structural only. This plane resolves no address, so the receiver
            # is storage of the analysed unit and nothing more; the token that
            # carries an address is minted where the address is READ, pinned to
            # its block.
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
    """One descriptor per sink record, or ``not_determined`` when the sites
    that folded into that record disagreed.

    Collect-then-fold, mirroring :func:`_fold_param_index`: a first-seen loop
    that overwrote on collision would not be STICKY — a third site agreeing
    with the first could restore a value two disagreeing sites had already
    destroyed, making the published fact depend on IR order."""
    if not descriptors:
        return None
    distinct = {tuple(sorted(descriptor.items())) for descriptor in descriptors}
    if len(distinct) == 1:
        return descriptors[0]
    return _receiver_not_determined("fold_disagreement")


def _classify_node_irs(
    node: Any, unit: Any, entry_param_ids: dict[int, int], entry_contract: Any
) -> list[tuple[str, str, str | None, ReceiverDescriptor | None]]:
    """Classify the non-state-write sinks at a node. Returns a list of
    ``(kind, target, selector, receiver)`` quads; ``receiver`` is populated
    only for the high-level/library call arm, which is the one that resolves
    its head past casts, and is ``None`` everywhere else.

    ``unit`` is the unit whose body this node belongs to (an internal helper
    once the walk recurses); ``entry_param_ids`` always describes the ENTRY
    point, which is what makes the two parameter scopes separable.

    State writes are handled separately — Slither's
    ``node.state_variables_written`` is more reliable than walking IR
    assignments by hand."""
    out: list[tuple[str, str, str | None, ReceiverDescriptor | None]] = []
    # Non-SSA def map, node-local: the cast IRs defining an inline-cast receiver
    # (``IERC20(address(eETH)).safeTransferFrom`` emits both TypeConversions and
    # the call in one node) live here, letting the head resolve past the temporary.
    def_by_id = {id(lv): ir for ir in _node_irs(node) if (lv := getattr(ir, "lvalue", None)) is not None}
    for ir in _node_irs(node):
        op = type(ir).__name__
        if op == "NewContract":
            target = getattr(ir, "contract_name", None) or str(getattr(ir, "contract_created", "")) or "unknown"
            out.append(("contract_creation", str(target), None, None))
        elif op in ("HighLevelCall", "LibraryCall"):
            function_name = getattr(ir, "function_name", None) or "call"
            selector = _selector_for(_callee_signature(ir))
            # A LibraryCall's real receiver is its first argument; ``destination``
            # is the library contract itself.
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
                # Inline-assembly storage write. Slither does not populate
                # node.state_variables_written for assembly, so this is the
                # only place the write is visible. Key the sink by the slot
                # literal/expr; slot->named-var resolution is a separate concern.
                slot = str(arguments[0]) if arguments else "unknown"
                out.append(("state_write", f"assembly_storage:{slot}", None, None))
            elif function_name.startswith("delegatecall("):
                # Inline-assembly delegatecall, e.g. an EIP-1967 proxy fallback.
                # Signature: delegatecall(gas, addr, inOff, inLen, outOff, outLen).
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
    """Recursively gather ``(kind, target, selector, origin, receiver)`` sink
    tuples from ``unit`` and any internal/library/modifier callees. ``origin``
    flips to ``guard`` the moment the walk steps through a modifier call and
    stays there for the rest of that subtree. De-dup happens at the caller
    level so distinct indices are preserved.

    ``entry_param_ids`` is the ENTRY point's and is threaded down unchanged —
    the recursion is exactly what makes a callee's formal parameter NOT an ABI
    slot of the record being built."""
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
        # Recurse into internal/library callees so transitive writes
        # surface on the entry-point's record.
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
    """One sink per (kind, target) pair we discover, transitively
    deduped while preserving order. A sink reachable through both the body
    and a guard keeps ``origin=body`` (a real effect wins). The selector
    field is per-sink: only ``external_call`` sinks carry one, and only
    when Slither exposes the called function's canonical signature.

    The receiver descriptor is COLLECTED per key and folded once, after the
    walk, so a conflict between two sites that share a record is sticky."""
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
