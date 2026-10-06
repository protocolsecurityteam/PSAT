"""Per-IR-kind leaf builders + threshold & auth-oracle matchers."""

from __future__ import annotations

from typing import Any, cast

from eth_utils.crypto import keccak

from ..predicate_types import (
    ComparisonOperator,
    LeafKind,
    LeafOperator,
    LeafPredicate,
    Operand,
    SetDescriptor,
    ValuePredicate,
)
from ..provenance import ProvenanceMap
from ..revert_detect import RevertGate
from ..shared import external_bool_leaf_is_gate_shape
from ..slither_compat import (
    Binary,
    Constant,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Send,
    SolidityCall,
    Transfer,
    TypeConversion,
    UnaryType,
    Unpack,
    Variable,
)
from ._helpers import (
    _apply_polarity,
    _binary_op,
    _find_defining_ir,
    _find_index_base,
    _make_leaf,
    _reconstruct_index_chain,
    _unsupported_leaf,
    _value_type_of_index_ir,
)
from .authority import (
    _CALLER_SOURCES,
    _classify_authority_equality,
    _classify_authority_membership,
)
from .operands import (
    _operand_for_value,
    _source_sort_key,
    _source_to_operand,
    _sources_for_value,
    _sources_from_destination,
)


def _build_binary_leaf(ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None = None) -> LeafPredicate:
    """A Binary IR gate: type gives the operator, operands classified via provenance."""
    bt = getattr(ir, "type", None)
    op_name = _binary_op(bt)
    left = _operand_for_value(ir.variable_left, prov)
    right = _operand_for_value(ir.variable_right, prov)
    operands = [left, right]

    if op_name in ("eq", "ne", "lt", "lte", "gt", "gte"):
        operator = _apply_polarity(op_name, gate.polarity)
        kind: LeafKind = "equality" if operator in ("eq", "ne") else "comparison"
        # Maker-wards ``map[k] == 1`` is membership: emit a membership leaf with ``truthy_value`` so writer-gate pass 2
        # and the resolver can route it.
        if kind == "equality" and function is not None:
            ml = _try_membership_via_value_compare(ir, prov, gate, function, operator)
            if ml is not None:
                return ml
            for value in (ir.variable_left, ir.variable_right):
                defining = _find_defining_ir(value, None, function)
                for _ in range(8):
                    if not isinstance(defining, TypeConversion):
                        break
                    defining = _find_defining_ir(defining.variable, None, function)
                if isinstance(defining, Index) and _value_type_of_index_ir(defining).startswith("address"):
                    keys = _reconstruct_index_chain(defining, prov, function)
                    if any(k.get("source") in _CALLER_SOURCES for k in keys):
                        unknown = _unsupported_leaf(
                            reason="unresolved_address_registry_comparison",
                            expression=gate.expression_text,
                            references_msg_sender=True,
                        )
                        unknown["authority_role"] = "caller_authority"
                        return unknown
        # ``map[k] >= threshold`` is an M-of-N counter check: emit a comparison leaf with ``set_descriptor`` so
        # writer-gate pass 2 can promote an authority-derived counter.
        if kind == "comparison" and function is not None:
            tl = _try_threshold_membership(ir, prov, gate, function, operator)
            if tl is not None:
                return tl
        # ``signature_recovery == address`` is ECDSA recover-then-compare: ``signature_auth``, always caller authority.
        if kind == "equality" and operator == "eq" and any(o["source"] == "signature_recovery" for o in operands):
            leaf = _make_leaf(
                kind="signature_auth",
                operator=operator,
                operands=operands,
                gate=gate,
            )
            leaf["authority_role"] = "caller_authority"
            return leaf
        # An external call result compared to a constant success value with a caller-linked argument is an authorization
        # oracle (EIP-1271 ``isValidSignature(...) == 0x1626ba7e``). Detected by shape, not name.
        if kind == "equality" and function is not None:
            oracle_leaf = _try_external_auth_oracle(ir, prov, gate, function, operator)
            if oracle_leaf is not None:
                return oracle_leaf
        leaf = _make_leaf(
            kind=kind,
            operator=operator,
            operands=operands,
            gate=gate,
        )
        leaf["authority_role"] = _classify_authority_equality(leaf, kind)
        if kind == "equality" and function is not None:
            _stamp_param_keyed_authority_mapping(ir, prov, function, leaf)
        _stamp_absorbed_operands(ir, prov, gate, function, leaf)
        return leaf
    # Binary AND/OR here is unsupported; the tree layer splits connectives into nodes.
    return _unsupported_leaf(reason=f"binary_op_{op_name}_unsupported", expression=str(ir))


# Additive ops make one operand an offset of the other; products and shifts aren't read as windows (``pausedUntil * 2``
# isn't a two-second bound).
_ADDITIVE_BINARY_TYPES = ("ADDITION", "SUBTRACTION")


def _stamp_absorbed_operands(
    ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None, leaf: LeafPredicate
) -> None:
    """Record operands an additive sub-expression contributed that the two-operand leaf dropped.

    ``block.timestamp < pausedUntil + MAX_PAUSE`` records ``{timestamp, MAX_PAUSE}`` (latch gone); ``block.timestamp -
    pausedUntil < 2592000`` records ``{pausedUntil, 2592000}`` (clock gone). Without the third fact every timed pause
    read as an indefinite latch.

    A sibling list, not a change to ``operands``: widening those would collapse amount kinds protocol-wide. Additive
    only, one level deep, absent when nothing was absorbed; nested ``a + b * c`` records an opaque ``computed`` for ``b
    * c``.
    """
    if function is None:
        return
    absorbed: list[Operand] = []
    for side in (getattr(ir, "variable_left", None), getattr(ir, "variable_right", None)):
        if side is None:
            continue
        defining = _find_defining_ir(side, getattr(gate, "node", None), function)
        if not isinstance(defining, Binary):
            continue
        if str(getattr(defining, "type", "")).split(".")[-1] not in _ADDITIVE_BINARY_TYPES:
            continue
        for inner in (getattr(defining, "variable_left", None), getattr(defining, "variable_right", None)):
            if inner is None:
                continue
            op = _operand_for_value(inner, prov)
            _attach_int_constant_value(op, inner)
            absorbed.append(op)
    if not absorbed:
        return
    # Deterministic order: the list is evidence.
    leaf["absorbed_operands"] = sorted(absorbed, key=lambda o: _operand_sort_key(o))


def _operand_sort_key(op: Operand) -> tuple[str, ...]:
    """Total order over operands.

    Element fields are stamped by a later pass, so each contributes a presence flag (absent first) and a string value
    slot.
    """
    fields = cast("dict[str, Any]", op)
    key = [
        str(fields.get(name) or "")
        for name in (
            "source",
            "state_variable_name",
            "parameter_name",
            "block_context_kind",
            "computed_kind",
            "constant_value",
        )
    ]
    for name in ("element_base_variable", "element_member_path", "element_key_param_index"):
        value = fields.get(name)
        key.append("0" if value is None else "1")
        if isinstance(value, (list, tuple)):
            key.append(".".join(str(part) for part in value))
        else:
            key.append("" if value is None else str(value))
    return tuple(key)


def _attach_int_constant_value(op: Operand, value: Any) -> None:
    """Resolve a ``constant`` state variable's integer literal onto an absorbed operand (``MAX_PAUSE = 30 days`` is
    compiler-fixed, not a name guess). Only here, so resolution and matchers see unchanged operands elsewhere.
    """
    if op.get("source") != "state_variable" or op.get("constant_value") is not None:
        return
    variable = getattr(value, "non_ssa_version", None) or value
    if not getattr(variable, "is_constant", False):
        return
    literal = getattr(variable, "expression", None)
    converted = getattr(literal, "converted_value", None)
    if converted is None:
        return
    try:
        op["constant_value"] = str(int(str(converted), 0))
    except (TypeError, ValueError):
        return


def _stamp_param_keyed_authority_mapping(ir: Any, prov: ProvenanceMap, function: Any, leaf: LeafPredicate) -> None:
    """Mark ``msg.sender == mapping[param]`` so resolution enumerates the mapping's value set.

    ``msg.sender == receivers[originEid]``: the authorized caller is whichever receiver the chosen key maps to,
    recovered by replaying setter events. ERC-7201 access collapses to a bare ``view_call``, so stamp ``mapping_name``
    for the event-hint pass and the equality resolver. Only for address-valued mappings keyed by a non-caller parameter
    (caller-keyed is allowlist membership).
    """
    operands = leaf.get("operands") or []
    if leaf.get("operator") not in ("eq", "ne") or len(operands) != 2:
        return
    caller_positions = [i for i, o in enumerate(operands) if o.get("source") in _CALLER_SOURCES]
    if len(caller_positions) != 1:
        return
    non_caller_idx = 1 - caller_positions[0]
    non_caller_value = ir.variable_left if non_caller_idx == 0 else ir.variable_right
    defining = _find_defining_ir(non_caller_value, None, function)
    if not isinstance(defining, Index):
        return
    value_type = _value_type_of_index_ir(defining)
    if value_type != "address" and not value_type.startswith("address"):
        return
    base = _find_index_base(defining, function)
    mapping_name = getattr(base, "name", None)
    if not isinstance(mapping_name, str) or not mapping_name:
        return
    keys = _reconstruct_index_chain(defining, prov, function)
    if not keys or any(k.get("source") in _CALLER_SOURCES for k in keys):
        return
    if not any(k.get("source") == "parameter" for k in keys):
        return
    operands[non_caller_idx]["mapping_name"] = mapping_name


def _try_membership_via_value_compare(
    ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any, operator: LeafOperator
) -> LeafPredicate | None:
    """``map[k] == constant`` as a membership leaf (Maker ``wards[ilk][user] == 1``) with ``truthy_value``, so it
    looks like bool membership and writer-gate pass 2 can promote it.
    """
    left = ir.variable_left
    right = ir.variable_right
    index_ir, const_value, mask_hex = _find_index_value_pair(left, right, function)
    if index_ir is None:
        index_ir, const_value, mask_hex = _find_index_value_pair(right, left, function)
    if index_ir is None or const_value is None:
        return None

    keys = _reconstruct_index_chain(index_ir, prov, function)
    descriptor: SetDescriptor = {
        "kind": "mapping_membership",
        "key_sources": keys,
        "truthy_value": str(const_value),
    }
    # Polarity-folded: ``value_predicate`` states the allowed relation, so backends needn't know revert semantics.
    allowed_op = "eq" if operator == "eq" else "ne"
    value_predicate: ValuePredicate = {
        "op": allowed_op,
        "rhs_values": [str(const_value)],
        "value_type": _value_type_of_index_ir(index_ir),
    }
    if mask_hex is not None:
        value_predicate["mask"] = mask_hex
    descriptor["value_predicate"] = value_predicate
    base_var = _find_index_base(index_ir, function)
    if base_var is not None:
        descriptor["storage_var"] = getattr(base_var, "name", None)
        declaration = getattr(base_var, "canonical_name", None)
        if value_predicate["value_type"].startswith("address") and isinstance(declaration, str):
            descriptor["storage_var_declaration"] = declaration

    # Nonzero membership is an allowlist; equality to the default zero is its absence. The value predicate already
    # carries revert polarity, so an address(0) conversion must not turn membership into a public exclusion.
    zero = str(const_value).lower() in {"0", "false", "0x0", "0x" + "0" * 40}
    if mask_hex is not None:
        membership_op: LeafOperator = "truthy" if operator == "eq" else "falsy"
    else:
        membership_op = "truthy" if (operator == "ne" if zero else operator == "eq") else "falsy"
    leaf = _make_leaf(
        kind="membership",
        operator=membership_op,
        operands=keys,
        gate=gate,
    )
    leaf["set_descriptor"] = descriptor
    leaf["authority_role"] = _classify_authority_membership(leaf, descriptor)
    return leaf


def _find_index_value_pair(a: Any, b: Any, function: Any) -> tuple[Any | None, Any | None, str | None]:
    """``(index_ir, const_value, mask_hex)`` when ``a`` is an Index lvalue (optionally masked) and ``b`` a constant,
    literal or constant/immutable state var; else Nones. Covers equality, masked and threshold forms.
    """
    if _is_mask_operand(b):
        const_value = _coerce_constant_value(b)
    else:
        # Solidity lowers address(0) to a temporary TypeConversion, so looking
        # only for literal operands loses address-valued registry membership.
        from ..storage_accessors import _constant

        const_value = _constant(b, function, {})
        if const_value is None:
            return None, None, None
    defining = _find_defining_ir(a, None, function)
    if isinstance(defining, Index):
        return defining, const_value, None
    # ``(map[k] & MASK) op CONST`` is a value compare on the Index; the mask is carried to the value side.
    if isinstance(defining, Binary):
        bt_name = getattr(getattr(defining, "type", None), "name", "").upper()
        if bt_name == "AND":  # bitwise & (Slither's BinaryType.AND); &&  is ANDAND
            left = defining.variable_left
            right = defining.variable_right
            # The mask may be a literal or a constant/immutable state var; the other side must be the Index.
            if _is_mask_operand(left) and not _is_mask_operand(right):
                left, right = right, left
            if not _is_mask_operand(right):
                return None, None, None
            inner = _find_defining_ir(left, None, function)
            if isinstance(inner, Index):
                return inner, const_value, _literal_to_hex(_coerce_constant_value(right))
    return None, None, None


def _coerce_constant_value(value: Any) -> Any:
    """The value of a Constant or constant/immutable state var, or None if not statically known."""
    if isinstance(value, Constant):
        return value.value
    nsv = getattr(value, "non_ssa_version", None)
    if nsv is not None:
        if getattr(nsv, "is_constant", False) or getattr(nsv, "is_immutable", False):
            expr = getattr(nsv, "expression", None)
            if expr is not None:
                return getattr(expr, "value", None) or str(expr)
            return getattr(nsv, "name", None)  # fallback to var name
    return None


def _literal_to_hex(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return hex(int(value))
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, str):
        raw = value.strip().lower()
        if raw.startswith("0x"):
            return raw
        try:
            return hex(int(raw))
        except ValueError:
            return None
    return None


def _try_threshold_membership(
    ir: Any,
    prov: ProvenanceMap,
    gate: RevertGate,
    function: Any,
    operator: LeafOperator,
) -> LeafPredicate | None:
    """``Index_lvalue [gt/gte/lt/lte] constant``: a threshold/counter check.

    Emits a comparison leaf (not membership: it's a counter crossing a threshold) with ``set_descriptor``; writer-gate
    pass 2 decides whether the counter is authority-derived.
    """
    if operator not in ("gt", "gte", "lt", "lte"):
        return None
    left = ir.variable_left
    right = ir.variable_right
    index_ir, threshold_value, mask_hex = _find_index_value_pair(left, right, function)
    if index_ir is None:
        index_ir, threshold_value, mask_hex = _find_index_value_pair(right, left, function)
        if index_ir is None:
            return None
        operator = _swap_operator(operator)
    if index_ir is None or threshold_value is None:
        return None

    keys = _reconstruct_index_chain(index_ir, prov, function)
    descriptor: SetDescriptor = {
        "kind": "mapping_membership",
        "key_sources": keys,
        "truthy_value": str(threshold_value),
    }
    # Polarity- and swap-folded: ``balances[msg.sender] < 10 revert`` gives ``gte``, ``["10"]``.
    threshold_value_predicate: ValuePredicate = {
        "op": operator,
        "rhs_values": [str(threshold_value)],
        "value_type": _value_type_of_index_ir(index_ir),
    }
    if mask_hex is not None:
        threshold_value_predicate["mask"] = mask_hex
    descriptor["value_predicate"] = threshold_value_predicate
    base_var = _find_index_base(index_ir, function)
    if base_var is not None:
        descriptor["storage_var"] = getattr(base_var, "name", None)
    operands = [_operand_for_value(ir.variable_left, prov), _operand_for_value(ir.variable_right, prov)]
    leaf = _make_leaf(
        kind="comparison",
        operator=operator,
        operands=operands,
        gate=gate,
    )
    leaf["set_descriptor"] = descriptor
    leaf["authority_role"] = "business"  # promoted to caller_authority by writer-gate pass-2 if applicable
    return leaf


_COMPARISON_SWAP: dict[ComparisonOperator, ComparisonOperator] = {
    "gt": "lt",
    "lt": "gt",
    "gte": "lte",
    "lte": "gte",
}


def _swap_operator(op: ComparisonOperator) -> ComparisonOperator:
    return _COMPARISON_SWAP[op]


EIP_1271_MAGIC_VALUE = "0x1626ba7e"


def _try_external_auth_oracle(
    ir: Any,
    prov: ProvenanceMap,
    gate: RevertGate,
    function: Any,
    operator: str,
) -> LeafPredicate | None:
    """``external_call_result OP constant`` as an authorization oracle when the call's arguments are caller-linked.

    EIP-1271's magic value emits ``signature_auth``; otherwise ``external_bool``, ``delegated_authority`` only for a
    gate-shaped callee (an effectful call moving the caller's own value is business).
    """
    left = ir.variable_left
    right = ir.variable_right
    call_value, const_value = _find_external_call_const_pair(left, right, function)
    if call_value is None:
        call_value, const_value = _find_external_call_const_pair(right, left, function)
    if call_value is None:
        return None
    call_ir = _find_defining_ir(call_value, None, function)
    if call_ir is None:
        return None

    # The EIP-1271 magic value alone identifies the check; the hash usually encodes the caller.
    is_eip1271 = _is_eip1271_magic(const_value)

    # Otherwise the args must be caller-linked, or it's just a state oracle.
    args_have_caller = False
    for arg in getattr(call_ir, "arguments", []) or []:
        sources = _sources_for_value(arg, prov)
        if any(s.kind in ("msg_sender", "tx_origin", "signature_recovery") for s in sources):
            args_have_caller = True
            break
    if not is_eip1271 and not args_have_caller:
        return None

    operands = [_operand_for_value(a, prov) for a in getattr(call_ir, "arguments", []) or []]
    membership_op: LeafOperator = "truthy" if operator == "eq" else "falsy"

    if is_eip1271:
        leaf = _make_leaf(
            kind="signature_auth",
            operator=membership_op,
            operands=operands,
            gate=gate,
        )
        leaf["authority_role"] = "caller_authority"
        return leaf

    leaf = _make_leaf(
        kind="external_bool",
        operator=membership_op,
        operands=operands,
        gate=gate,
    )
    # An effectful call with the caller as argument (``require(token.transferFrom(msg.sender, ...) == true)``) moves the
    # caller's value; only gate-shaped callees are authority. Mutability is stamped for downstream consumers.
    callee_mutability = _callee_state_mutability(call_ir)
    callee_signature = _callee_signature(call_ir)
    leaf["callee_state_mutability"] = callee_mutability
    if callee_signature is not None:
        leaf["callee_signature"] = callee_signature
    leaf["gate_kind"] = gate.kind
    if external_bool_leaf_is_gate_shape(callee_mutability, gate.kind, callee_signature):
        leaf["authority_role"] = "delegated_authority"
    else:
        leaf["authority_role"] = "business"
    return leaf


def _is_eip1271_magic(value: Any) -> bool:
    target = int(EIP_1271_MAGIC_VALUE, 16)
    if value is None:
        return False
    if isinstance(value, int):
        return value == target
    if isinstance(value, bytes):
        try:
            return int.from_bytes(value, "big") == target
        except Exception:
            return False
    if isinstance(value, str):
        v = value.strip().lower()
        if v.startswith("0x"):
            try:
                return int(v, 16) == target
            except ValueError:
                return False
        try:
            return int(v) == target
        except ValueError:
            return False
    return False


def _find_external_call_const_pair(a: Any, b: Any, function: Any) -> tuple[Any | None, Any | None]:
    """``(call_value, const_value)`` when ``a`` is an external call lvalue and ``b`` a Constant; else Nones."""
    if not isinstance(b, Constant):
        return None, None
    defining = _find_defining_ir(a, None, function)
    if defining is None:
        return None, None
    if isinstance(defining, HighLevelCall):
        return a, b.value
    return None, None


def _is_mask_operand(value: Any) -> bool:
    """A mask is a literal or a constant/immutable declaration; mutable state vars aren't masks."""
    if isinstance(value, Constant):
        return True
    nsv = getattr(value, "non_ssa_version", None)
    if nsv is not None:
        if getattr(nsv, "is_constant", False) or getattr(nsv, "is_immutable", False):
            return True
    return False


def _build_unary_leaf(ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None) -> LeafPredicate:
    """``require(!X)``: recurse with polarity flipped."""
    from .tree import _build_leaf_from_gate

    op_type = getattr(ir, "type", None)
    if op_type == getattr(UnaryType, "BANG", "!"):
        inner = ir.rvalue
        new_gate = gate.negated(inner)
        return _build_leaf_from_gate(new_gate, prov, function) or _unsupported_leaf(
            reason="negated_unknown", expression=str(ir)
        )
    return _unsupported_leaf(reason=f"unary_{op_type}_unsupported", expression=str(ir))


def _build_index_membership_leaf(
    ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None = None
) -> LeafPredicate:
    """``require(map[k][m])``: truthy or falsy by polarity, collecting every key of a multi-level mapping in source
    order.
    """
    operator: LeafOperator = "truthy" if gate.polarity == "allowed_when_true" else "falsy"
    keys = _reconstruct_index_chain(ir, prov, function)
    descriptor: SetDescriptor = {
        "kind": "mapping_membership",
        "key_sources": keys,
    }
    base_var = _find_index_base(ir, function)
    if base_var is not None:
        descriptor["storage_var"] = getattr(base_var, "name", None)
    leaf = _make_leaf(
        kind="membership",
        operator=operator,
        operands=keys,
        gate=gate,
    )
    leaf["set_descriptor"] = descriptor
    leaf["authority_role"] = _classify_authority_membership(leaf, descriptor)
    return leaf


def _callee_state_mutability(ir: Any) -> str | None:
    """Declared mutability of a call's callee: ``view``/``pure``, ``nonview`` for effectful external calls,
    ``nonview_library`` for effectful self-contained library calls, or None. Separates an ACL read
    (``acl.canPerform(msg.sender, ...)``) from a value move (``token.transferFrom(msg.sender, ...)``) without
    names. A library stays ``nonview_library`` only if it (transitively) makes no external calls (own-storage
    ``pendingAdmins.remove(msg.sender)``); SafeERC20-style wrappers are ``nonview``.
    """
    fn = getattr(ir, "function", None)
    if fn is None:
        return None
    if getattr(fn, "pure", False):
        return "pure"
    if getattr(fn, "view", False):
        return "view"
    # A public state variable's auto-getter is a read.
    if isinstance(fn, Variable):
        return "view"
    if isinstance(ir, LibraryCall):
        return "nonview" if _library_reaches_external_call(fn) else "nonview_library"
    return "nonview"


# Effectful Yul call builtins; ``staticcall`` can't move value.
_YUL_EXTERNAL_CALL_PREFIXES = ("call(", "callcode(", "delegatecall(")


def _library_reaches_external_call(fn: Any, _seen: set[int] | None = None) -> bool:
    """Whether a library function transitively makes an effectful external call, including Yul ``call`` builtins
    (Solmate SafeTransferLib has no LowLevelCall IR).
    """
    seen = _seen if _seen is not None else set()
    if id(fn) in seen:
        return False
    seen.add(id(fn))
    for node in getattr(fn, "nodes", []) or []:
        for body_ir in getattr(node, "irs", []) or []:
            if isinstance(body_ir, (LowLevelCall, Send, Transfer)):
                return True
            # LibraryCall subclasses HighLevelCall; recurse first so library hops aren't external.
            if isinstance(body_ir, (LibraryCall, InternalCall)):
                callee = getattr(body_ir, "function", None)
                if callee is not None and _library_reaches_external_call(callee, seen):
                    return True
                continue
            if isinstance(body_ir, HighLevelCall):
                return True
            if isinstance(body_ir, SolidityCall):
                name = str(getattr(getattr(body_ir, "function", None), "name", "") or "")
                if name.startswith(_YUL_EXTERNAL_CALL_PREFIXES):
                    return True
    return False


def _build_external_bool_leaf(ir: Any, prov: ProvenanceMap, gate: RevertGate) -> LeafPredicate:
    """``require(other.check(...))``: the call's result drives the gate."""
    callee_name = getattr(getattr(ir, "function", None), "name", None) or getattr(ir, "function_name", None)
    callee_signature = _callee_signature(ir)
    callee_selector = _selector_for_signature(callee_signature)
    args_operands = [_operand_for_value(a, prov) for a in getattr(ir, "arguments", ())]
    operator: LeafOperator = "truthy" if gate.polarity == "allowed_when_true" else "falsy"
    leaf = _make_leaf(
        kind="external_bool",
        operator=operator,
        operands=args_operands,
        gate=gate,
    )
    leaf["callee_state_mutability"] = _callee_state_mutability(ir)
    # A result check gates on the returned bool; ``external_call_revert``/``try_catch_revert`` gate on the callee's
    # whole revert surface. The caller-taint default needs the distinction.
    leaf["gate_kind"] = gate.kind
    leaf["callee_signature"] = callee_signature
    target_sources = _sources_from_destination(ir, prov)
    has_state_target = any(s.kind == "state_variable" for s in target_sources)
    target_state_var = next(
        (s.state_variable_name for s in sorted(target_sources, key=_source_sort_key) if s.kind == "state_variable"),
        None,
    )
    slot_targets = [s for s in target_sources if s.kind == "view_call" and s.storage_slot]
    target_operand = None
    if len({s.storage_slot for s in slot_targets}) == 1 and not any(
        s.kind in _CALLER_SOURCES or s.kind == "parameter" for s in target_sources
    ):
        target_operand = _source_to_operand(sorted(slot_targets, key=_source_sort_key)[0])
    has_caller_arg = any(
        any(s.kind in ("msg_sender", "tx_origin", "signature_recovery") for s in _sources_for_value(a, prov))
        for a in getattr(ir, "arguments", ())
    )
    # A state target plus caller argument isn't enough (``vault.enter(msg.sender, ...)``, ``token.permit(msg.sender,
    # ...)``); only gate-shaped callees get ``delegated_authority``.
    if (
        (has_state_target or target_operand is not None)
        and has_caller_arg
        and external_bool_leaf_is_gate_shape(leaf.get("callee_state_mutability"), gate.kind, callee_signature)
    ):
        leaf["authority_role"] = "delegated_authority"
        descriptor = _build_generic_external_set_descriptor(
            callee_name=callee_name,
            callee_signature=callee_signature,
            callee_selector=callee_selector,
            args_operands=args_operands,
            target_state_var=target_state_var,
            target_operand=target_operand,
        )
        if descriptor is not None:
            leaf["set_descriptor"] = cast(SetDescriptor, descriptor)
    else:
        leaf["authority_role"] = "business"
    leaf["expression"] = f"{callee_name}(...)"
    return leaf


def _self_gate_or_truthy_leaf(cond: Any, prov: ProvenanceMap, gate: RevertGate, operating_fn: Any) -> LeafPredicate:
    """The bare-bool fallback leaf, upgraded to a self-gate descriptor only when its operands are all opaque (e.g.

    Solady assembly roles). A resolved state variable (membership read, pause flag) is what enrollment and the
    pause/reentrancy passes key on, so it wins.
    """
    leaf = _build_truthy_leaf(cond, prov, gate)
    if leaf.get("set_descriptor"):
        return leaf
    if any((op or {}).get("source") == "state_variable" for op in leaf.get("operands") or []):
        return leaf
    self_gate = _build_self_gate_leaf(prov, gate, operating_fn)
    return self_gate if self_gate is not None else leaf


def _build_self_gate_leaf(prov: ProvenanceMap, gate: RevertGate, operating_fn: Any) -> LeafPredicate | None:
    """Self-gate descriptor for an unlowerable caller gate, emitted only after lowering failed, for a public/external
    ``view`` function with exactly one caller-tainted ``address`` parameter, declared on a contract (not a
    library).

    Mirrors the external-call form of the same gate (weETH ``roleRegistry.onlyUpgradeTimelock(msg.sender)``):
    ``external_bool`` with an ``external_set`` descriptor and ``self_address`` authority, so the enumerable role-store
    adapter can fold and probe it. Without an adapter it settles to a gated external check instead of the
    public-projecting business fallback.
    """
    from .tree import _operand_value_provenance

    fn = gate.containing_function or operating_fn
    if fn is None:
        return None
    if getattr(fn, "visibility", None) not in ("public", "external"):
        return None
    if not getattr(fn, "view", False):
        return None
    declarer = getattr(fn, "contract_declarer", None) or getattr(fn, "contract", None)
    if declarer is None or getattr(declarer, "is_library", False):
        return None
    params = list(getattr(fn, "parameters", []) or [])
    if len(params) != 1 or str(getattr(params[0], "type", "")) != "address":
        return None
    caller_kinds = ("msg_sender", "tx_origin")
    param_sources = _operand_value_provenance(params[0], prov)
    if not any(getattr(s, "kind", None) in caller_kinds for s in param_sources):
        return None
    signature = getattr(fn, "full_name", None)
    if not (isinstance(signature, str) and "(" in signature and signature.endswith(")")):
        return None
    selector = _selector_for_signature(signature)
    caller_operand: Operand = {"source": "msg_sender"}
    leaf = _make_leaf(
        kind="external_bool",
        operator="truthy",
        operands=[caller_operand],
        gate=gate,
    )
    leaf["authority_role"] = "delegated_authority"
    leaf["callee_state_mutability"] = "view"
    leaf["gate_kind"] = gate.kind
    leaf["callee_signature"] = signature
    leaf["set_descriptor"] = cast(
        SetDescriptor,
        {
            "kind": "external_set",
            "key_sources": [dict(caller_operand)],
            "authority_contract": {"address_source": {"source": "self_address"}},
            "callee_function": getattr(fn, "name", None),
            "callee_signature": signature,
            "callee_selector": selector,
        },
    )
    leaf["expression"] = f"{getattr(fn, 'name', signature)}(msg.sender)"
    return leaf


def _callee_signature(ir: Any) -> str | None:
    fn = getattr(ir, "function", None)
    for attr in ("full_name", "signature_str"):
        value = getattr(fn, attr, None)
        if isinstance(value, str) and "(" in value and value.endswith(")"):
            return value.rsplit(".", 1)[-1]
    value = getattr(ir, "function_name", None)
    if isinstance(value, str) and "(" in value and value.endswith(")"):
        return value.rsplit(".", 1)[-1]
    return None


def _selector_for_signature(signature: str | None) -> str | None:
    if not signature:
        return None
    if "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _build_generic_external_set_descriptor(
    *,
    callee_name: str | None,
    callee_signature: str | None,
    callee_selector: str | None,
    args_operands: list,
    target_state_var: str | None,
    target_operand: Operand | None = None,
) -> dict | None:
    if target_state_var is None and target_operand is None:
        return None
    descriptor: dict = {
        "kind": "external_set",
        "key_sources": args_operands,
        "authority_contract": {
            "address_source": target_operand
            or {
                "source": "state_variable",
                "state_variable_name": target_state_var,
            },
        },
        "callee_function": callee_name,
        "callee_signature": callee_signature,
        "callee_selector": callee_selector,
    }
    return descriptor


def _build_solidity_call_leaf(ir: Any, prov: ProvenanceMap, gate: RevertGate) -> LeafPredicate:
    """A bool SolidityCall used as a gate (rare): business; ecrecover is classified by provenance."""
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return _unsupported_leaf(
        reason=f"solidity_call_{name}_unsupported_as_gate",
        expression=str(ir),
    )


def _build_truthy_leaf(cond: Any, prov: ProvenanceMap, gate: RevertGate) -> LeafPredicate:
    """``require(boolFlag)`` on a bare value: truthy/falsy by polarity."""
    operator: LeafOperator = "truthy" if gate.polarity == "allowed_when_true" else "falsy"
    operand = _operand_for_value(cond, prov)
    leaf = _make_leaf(
        kind="equality",
        operator=operator,
        operands=[operand],
        gate=gate,
    )
    leaf["authority_role"] = "business"  # bare-bool gates rarely auth
    # ``require(sent)`` after ``msg.sender.call{value: ...}("")``: stamp mutability so the caller-taint default sees a
    # value-move check, not a caller-keyed flag.
    containing = getattr(gate, "containing_function", None)
    defining = _find_defining_ir(cond, getattr(gate, "node", None), containing)
    if isinstance(defining, Unpack):
        # ``(bool sent, ) = ...``: follow the tuple to the call.
        tuple_var = getattr(defining, "tuple", None)
        if tuple_var is not None:
            defining = _find_defining_ir(tuple_var, None, containing) or defining
    if isinstance(defining, (LowLevelCall, Send, Transfer)):
        leaf["callee_state_mutability"] = "nonview"
    elif isinstance(defining, HighLevelCall):
        leaf["callee_state_mutability"] = _callee_state_mutability(defining)
    return leaf
