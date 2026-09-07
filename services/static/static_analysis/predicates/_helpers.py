"""Generic leaf-construction and IR-walking helpers."""

from __future__ import annotations

from typing import Any

from ..predicate_types import (
    LeafKind,
    LeafOperator,
    LeafPredicate,
    Operand,
)
from ..provenance import ProvenanceMap
from ..revert_detect import RevertGate
from ..slither_compat import Index, Member, SolidityCall
from .operands import _operand_for_value

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _binary_op(bt: Any) -> str:
    """Map Slither BinaryType → leaf operator string."""
    if bt is None:
        return "unknown"
    name = getattr(bt, "name", str(bt)).upper()
    return {
        "EQUAL": "eq",
        "NOT_EQUAL": "ne",
        "LESS": "lt",
        "LESS_EQUAL": "lte",
        "GREATER": "gt",
        "GREATER_EQUAL": "gte",
        "ANDAND": "and",
        "OROR": "or",
    }.get(name, name.lower())


def _apply_polarity(operator: str, polarity: str) -> LeafOperator:
    """If polarity is allowed_when_false (if-revert), invert the
    operator. The inversion table: eq↔ne, lt↔gte, lte↔gt."""
    if polarity == "allowed_when_true":
        return operator  # pyright: ignore[reportReturnType]
    inv = {"eq": "ne", "ne": "eq", "lt": "gte", "gte": "lt", "lte": "gt", "gt": "lte"}
    return inv.get(operator, operator)  # pyright: ignore[reportReturnType]


def _make_leaf(
    *,
    kind: LeafKind,
    operator: LeafOperator,
    operands: list[Operand],
    gate: RevertGate,
) -> LeafPredicate:
    refs_caller = any(o["source"] in ("msg_sender", "tx_origin") for o in operands)
    param_indices: list[int] = [
        idx for o in operands if o["source"] == "parameter" and (idx := o.get("parameter_index")) is not None
    ]
    return {
        "kind": kind,
        "operator": operator,
        "authority_role": "business",  # filled in by caller
        "operands": operands,
        "references_msg_sender": refs_caller,
        "parameter_indices": param_indices,
        "expression": gate.expression_text or "",
        "basis": list(gate.basis),
    }


def _unsupported_leaf(reason: str, expression: str, *, references_msg_sender: bool = False) -> LeafPredicate:
    return {
        "kind": "unsupported",
        "operator": "truthy",  # placeholder; ignored for unsupported
        "authority_role": "business",
        "operands": [],
        "unsupported_reason": reason,
        "references_msg_sender": references_msg_sender,
        "parameter_indices": [],
        "expression": expression,
        "basis": [reason],
    }


def _gate_references_caller(gate: RevertGate) -> bool:
    node = gate.node
    values: list[Any] = []
    for attr in ("variables_read", "solidity_variables_read"):
        values.extend(getattr(node, attr, []) or [])
    text = " ".join(str(v) for v in values)
    return "msg.sender" in text or "tx.origin" in text


def _find_defining_ir(value: Any, node: Any, function: Any) -> Any | None:
    """Find the IR opcode whose lvalue equals ``value``. Looks in
    the gate's home node first, then walks back through the
    function's nodes AND each modifier's nodes (gates inside
    modifier bodies still admit the function and need their own
    operand resolution)."""
    name = getattr(value, "name", None)
    if name is None:
        return None
    # Build the search node list: start from the gate's node and walk
    # backward through whichever container (function or modifier) it
    # lives in. If we don't find the defining IR there, fall back to
    # scanning all containers' nodes in reverse.
    containers = [function]
    containers.extend(getattr(function, "modifiers", []) or [])
    # Prefer the container the gate lives in.
    if node is not None:
        for c in containers:
            cnodes = list(getattr(c, "nodes", []) or [])
            if node in cnodes:
                idx = cnodes.index(node)
                # Search backward from gate, then forward, then other
                # containers.
                ordered = cnodes[idx::-1] + cnodes[idx + 1 :]
                for n in ordered:
                    found = _scan_node_for_lvalue(n, name)
                    if found is not None:
                        return found
                break
    # Fallback: scan all containers.
    for c in containers:
        for n in reversed(list(getattr(c, "nodes", []) or [])):
            found = _scan_node_for_lvalue(n, name)
            if found is not None:
                return found
    return None


def _scan_node_for_lvalue(node: Any, name: str) -> Any | None:
    for ir in reversed(getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []):
        lv = getattr(ir, "lvalue", None)
        if lv is not None and getattr(lv, "name", None) == name:
            return ir
    return None


def _reconstruct_index_chain(ir: Any, prov: ProvenanceMap, function: Any | None = None) -> list[Operand]:
    """Walk an Index IR's variable_left chain to assemble all keys
    (outer → inner). For an N-level mapping like ``map[a][b][c]``,
    Slither emits N nested Index IRs, each whose variable_left is
    the previous Index's lvalue. We walk back through the function
    to collect each key in source order.

    Per codex round-7 review (F4 fix): when a key dimension is the
    result of ``keccak256(abi.encode(a, b, ...))``, we unwrap the
    hash inputs into separate operand entries instead of recording
    a single ``computed`` source. This treats hashed-key membership
    as a symbolic tuple key — preserving every component (role,
    domain separator, msg.sender, etc.) so the writer-gate / auth
    classifier sees them all, not just the collapsed hash output.
    """
    keys: list[list[Operand]] = []  # per-dimension list of operands
    visited: set[str] = set()
    current = ir
    while isinstance(current, Index):
        keys.insert(0, _expand_key_operand(current.variable_right, prov, function))
        left = current.variable_left
        left_name = getattr(left, "name", None)
        if left_name in visited:
            break  # cycle guard
        if left_name is not None:
            visited.add(left_name)
        # If the left is itself the lvalue of an outer Index, find
        # that IR and continue the walk. Also bridge struct-field
        # accesses (``map[k].field[m]`` shape):
        # the outer Index's left points at a Member whose variable_left
        # is itself an Index — continue from that inner Index.
        if function is None:
            break
        defining = _find_defining_ir(left, None, function)
        while isinstance(defining, Member):
            base = defining.variable_left
            base_name = getattr(base, "name", None)
            if base_name in visited:
                defining = None
                break
            if base_name is not None:
                visited.add(base_name)
            defining = _find_defining_ir(base, None, function)
        if not isinstance(defining, Index):
            break
        current = defining
    # Flatten: each Index dimension contributes one or more operands.
    # Hashed-key dimensions expand to N operands; plain keys stay as
    # a single operand. The result is the full symbolic tuple key.
    flat: list[Operand] = []
    for dim in keys:
        flat.extend(dim)
    return flat


def _expand_key_operand(value: Any, prov: ProvenanceMap, function: Any | None = None) -> list[Operand]:
    """If ``value`` is a hash result (keccak256 of abi.encode of N
    args), return one Operand per ultimate input. Otherwise return
    a single-element list with the value's standard operand.

    The unwrap chain handles common nested forms:
      - keccak256(bytes)
      - abi.encode(...) / abi.encodePacked(...) / abi.encodeWithSelector(...)
      - keccak256(abi.encode(a, b, c)) → walks both calls
    """
    if function is None:
        return [_operand_for_value(value, prov)]
    defining = _find_defining_ir(value, None, function)
    if not isinstance(defining, SolidityCall):
        return [_operand_for_value(value, prov)]
    fn_name = getattr(getattr(defining, "function", None), "name", None) or ""
    if not _is_hash_or_encode_call(fn_name):
        return [_operand_for_value(value, prov)]

    # Walk into the hash/encode arguments. Each argument may itself
    # be a hash/encode lvalue (chained) — recurse.
    out: list[Operand] = []
    for arg in getattr(defining, "arguments", []) or []:
        out.extend(_expand_key_operand(arg, prov, function))
    if not out:
        # Defensive: hash with no resolvable args → fall back.
        return [_operand_for_value(value, prov)]
    return out


def _is_hash_or_encode_call(fn_name: str) -> bool:
    """Recognize Solidity hashing + abi-encoding functions whose
    arguments form the components of a symbolic tuple key. Detection
    is by canonical signature, not identifier name — the function
    name here is the Solidity built-in's signature (e.g.,
    ``keccak256(bytes)``), which is structural metadata, not a
    user-chosen identifier."""
    if not fn_name:
        return False
    return (
        fn_name.startswith("keccak256(")
        or fn_name.startswith("sha256(")
        or fn_name.startswith("sha3(")
        or fn_name.startswith("ripemd160(")
        or fn_name.startswith("abi.encode(")
        or fn_name.startswith("abi.encodePacked(")
        or fn_name.startswith("abi.encodeWithSelector(")
        or fn_name.startswith("abi.encodeWithSignature(")
        or fn_name.startswith("abi.encodeCall(")
    )


def _find_index_base(ir: Any, function: Any | None = None) -> Any | None:
    """Walk back through chained Index IRs to the underlying storage
    variable (StateVariable). Returns the variable_left of the
    outermost Index in the chain.
    """
    current = ir
    visited: set[str] = set()
    while isinstance(current, Index):
        left = getattr(current, "variable_left", None)
        left_name = getattr(left, "name", None)
        if left_name in visited:
            return left
        if left_name is not None:
            visited.add(left_name)
        if function is None:
            return left
        defining = _find_defining_ir(left, None, function)
        # When the chain bottoms out through a ``Member`` access on a storage
        # struct reached via a pointer (ERC-7201 namespaced storage), ``left``
        # is a synthetic ref; the field being accessed (``_roles``) is the
        # logical storage variable. Prefer that field over the ref.
        member_field = None
        while isinstance(defining, Member):
            if member_field is None:
                member_field = getattr(defining, "variable_right", None)
            base = getattr(defining, "variable_left", None)
            base_name = getattr(base, "name", None)
            if base_name in visited:
                return member_field if member_field is not None else left
            if base_name is not None:
                visited.add(base_name)
            defining = _find_defining_ir(base, None, function)
        if not isinstance(defining, Index):
            return member_field if member_field is not None else left
        current = defining
    return None


def _value_type_of_index_ir(ir: Any) -> str:
    """Best-effort solidity type of the value produced by ``map[k]``.

    Used by ``ValuePredicate`` so downstream backends know how to
    decode the assigned value (event topic / calldata word). Falls
    back to ``"uint256"`` when the IR doesn't expose a usable type —
    callers must treat ``value_type`` as advisory, not authoritative.
    """
    lvalue = getattr(ir, "lvalue", None)
    type_obj = getattr(lvalue, "type", None) if lvalue is not None else None
    if type_obj is None:
        return "uint256"
    type_str = getattr(type_obj, "name", None) or str(type_obj)
    return type_str if type_str else "uint256"
