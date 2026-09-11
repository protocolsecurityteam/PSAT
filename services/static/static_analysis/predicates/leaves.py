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
    _sources_for_value,
    _sources_from_destination,
)

# ---------------------------------------------------------------------------
# Per-IR-kind leaf builders
# ---------------------------------------------------------------------------


def _build_binary_leaf(ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None = None) -> LeafPredicate:
    """A Binary IR drives the gate. Type maps to operator; operands
    are classified via provenance."""
    bt = getattr(ir, "type", None)
    op_name = _binary_op(bt)
    left = _operand_for_value(ir.variable_left, prov)
    right = _operand_for_value(ir.variable_right, prov)
    operands = [left, right]

    if op_name in ("eq", "ne", "lt", "lte", "gt", "gte"):
        # Apply if-revert polarity flip to operator.
        operator = _apply_polarity(op_name, gate.polarity)
        kind: LeafKind = "equality" if operator in ("eq", "ne") else "comparison"
        # Maker-wards / value-flag membership: ``map[k] == 1`` is
        # semantically a membership check, not a generic equality.
        # Recognize when one operand is the lvalue of an Index IR
        # and the other is a constant — emit a membership leaf with
        # truthy_value=<constant> so writer-gate pass-2 (b.ii) and
        # the resolver can route on it.
        if kind == "equality" and function is not None:
            ml = _try_membership_via_value_compare(ir, prov, gate, function, operator)
            if ml is not None:
                return ml
        # Threshold-shape recognition (codex F2 fix): ``map[k] >=
        # threshold`` (or > / <= / <) where map is a state mapping
        # is the structural shape of M-of-N counter checks. Emit a
        # comparison leaf with set_descriptor populated so writer-
        # gate pass-2 can decide if the counter is authority-derived
        # (and promote to caller_authority).
        if kind == "comparison" and function is not None:
            tl = _try_threshold_membership(ir, prov, gate, function, operator)
            if tl is not None:
                return tl
        # Signature-auth detection: an equality between a
        # signature_recovery operand and an address operand is the
        # canonical ECDSA-recover-then-compare pattern. Emit kind=
        # signature_auth (shape-tight by construction; always
        # caller_authority).
        if kind == "equality" and operator == "eq" and any(o["source"] == "signature_recovery" for o in operands):
            leaf = _make_leaf(
                kind="signature_auth",
                operator=operator,
                operands=operands,
                gate=gate,
            )
            leaf["authority_role"] = "caller_authority"
            return leaf
        # External-auth-oracle detection (codex F3 fix): an equality
        # comparing an external_call result against a constant
        # success value, where the external call carries a caller-
        # linked argument. The canonical case is EIP-1271:
        # ``IERC1271(signer).isValidSignature(hash, sig) == 0x1626ba7e``
        # — the 4-byte magic value identifies it as a signature
        # check. More generally any external bool/byte-result oracle
        # gated on a fixed success value is an authorization
        # predicate. Detection is by the comparison shape, not by
        # function name.
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
    # AND/OR at the binary level — these would normally be handled by
    # short-circuit evaluation; for now we treat as unsupported and
    # let the predicate-tree composition layer (week 2) split them
    # into AND/OR tree nodes properly.
    return _unsupported_leaf(reason=f"binary_op_{op_name}_unsupported", expression=str(ir))


# Slither ``BinaryType`` names that make an expression an OFFSET of its other
# operand. A product, a quotient or a shift is not an offset and is never read as
# one: ``block.timestamp < pausedUntil * 2`` carries no window length, and
# publishing its ``2`` as a duration would be a two-second freeze bound on an
# open-ended latch — the severity-REDUCER direction, from arithmetic nobody read.
_ADDITIVE_BINARY_TYPES = ("ADDITION", "SUBTRACTION")


def _stamp_absorbed_operands(
    ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None, leaf: LeafPredicate
) -> None:
    """Record the operands an ADDITIVE sub-expression contributed and the leaf could
    not hold.

    A Solidity comparison lowers to a leaf with exactly TWO operands, and when one
    side is arithmetic the operand recorder keeps ONE sub-operand and discards the
    rest. Measured on compiled source: ``block.timestamp < pausedUntil +
    MAX_PAUSE`` records ``{timestamp, MAX_PAUSE}`` — the latch is gone — while
    ``block.timestamp - pausedUntil < 2592000`` records ``{pausedUntil, 2592000}``
    — the clock is gone. Three facts do not fit in two slots, so a reader asking
    "does this guard compare the CLOCK against this LATCH plus a fixed WINDOW?"
    could not be answered from any source shape, and every timed pause latch in
    the corpus published ``duration_bound_seconds: null`` — which the consumer
    contract read as *indefinite latch, most severe*. An extraction failure was
    being published as a proof about the contract.

    This is deliberately NOT a change to ``operands``: it is a sibling list of
    what the comparison ALSO read, so every existing operand consumer keeps the
    exact list it had (the value-flow lattice folds a source set to one origin and
    degrades to ``indeterminate`` the moment a set carries two, so widening
    ``operands`` would silently collapse amount kinds protocol-wide).

    Additive only, ONE level deep, and absent when nothing was absorbed — so
    absence means "no additive sub-expression fed this comparison", never "there
    was one and we could not read it": a nested ``a + b * c`` records ``a`` and the
    opaque ``computed`` operand for ``b * c``, which is a not-determined marker a
    reader must treat as such.
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
    # Deterministic order: the list is evidence, and two runs must publish the
    # same bytes. ``_published_source_key`` is the same canonical key the operand
    # sort uses elsewhere in this module.
    leaf["absorbed_operands"] = sorted(absorbed, key=lambda o: _operand_sort_key(o))


def _operand_sort_key(op: Operand) -> tuple[str, ...]:
    """Canonical total order over operands.

    Two operands distinguishable only by the element fields would otherwise
    settle on input order under a stable sort, which is not evidence. The
    element fields are read off a plain-dict view because they are stamped by
    a later unit: an operand that predates them must still order against one
    that carries them, so each contributes a presence flag (absent sorts first)
    and a value slot, and every slot stays a ``str``.
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
    """Resolve a compile-time ``constant`` state variable's INTEGER literal onto an
    absorbed operand.

    Scoped to :func:`_stamp_absorbed_operands` on purpose. ``uint256 public
    constant MAX_PAUSE = 30 days`` is a value the compiler fixed, so reading it is
    not the name-matching heuristic ``read_max_pause_duration`` refuses — but
    attaching it to every ``state_variable`` operand would change what resolution
    and the claims matchers see on operands they already read, which is not this
    item's surface.
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
    """Mark ``msg.sender == mapping[param]`` so resolution enumerates the mapping's
    VALUE set (claim #3 group C).

    L1BaseSyncPool gates ``onMessageReceived`` on ``msg.sender == receivers[originEid]``
    — a ``mapping(uint32 => address)`` keyed by a function PARAMETER. There is no
    single getter to read: the authorized caller is whichever receiver the
    caller-chosen ``originEid`` maps to, so the principal is the mapping's *value*
    set, recovered by replaying the mapping's setter events. The builder otherwise
    collapses ``$.receivers[originEid]`` to the bare storage-accessor ``view_call``
    operand (ERC-7201 namespaced storage), losing the mapping identity. This stamps
    ``mapping_name`` onto the non-caller operand so (1) the contract-wide
    ``apply_mapping_event_hint_pass`` attaches the value-enumeration writer specs and
    (2) :func:`_resolve_equality_principal` routes to value enumeration.

    Scoped to an ADDRESS-valued mapping keyed by a parameter (never the caller): a
    caller-keyed mapping is an allowlist *membership* (``allowed[msg.sender]``, a
    different leaf shape), and a non-address value can't be an authorized caller."""
    operands = leaf.get("operands") or []
    if leaf.get("operator") not in ("eq", "ne") or len(operands) != 2:
        return
    caller_positions = [i for i, o in enumerate(operands) if o.get("source") in _CALLER_SOURCES]
    if len(caller_positions) != 1:
        return
    non_caller_idx = 1 - caller_positions[0]
    # operands order mirrors (variable_left, variable_right) in _build_binary_leaf.
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
    """Recognize ``map[k] == constant`` as a membership leaf.

    Maker uses ``wards[ilk][user] == 1`` as the canonical "is this
    user authorized" check. By default our binary handler produces an
    equality leaf, which doesn't trip writer-gate's b.ii promotion
    rule. Detect when one operand is the lvalue of an Index IR and
    the other is a constant: emit a membership leaf with
    truthy_value=<constant> instead, so the descriptor carries the
    same shape as a bool-membership and pass-2 promotion can fire.
    """
    left = ir.variable_left
    right = ir.variable_right
    # Try: left is Index, right is Constant.
    index_ir, const_value, mask_hex = _find_index_value_pair(left, right, function)
    if index_ir is None:
        index_ir, const_value, mask_hex = _find_index_value_pair(right, left, function)
    if index_ir is None or const_value is None:
        return None

    # Build the same descriptor shape as _build_index_membership_leaf.
    keys = _reconstruct_index_chain(index_ir, prov, function)
    descriptor: SetDescriptor = {
        "kind": "mapping_membership",
        "key_sources": keys,
        "truthy_value": str(const_value),
    }
    # First-class predicate form (D.1). The function reverts when
    # ``map[k] != const``, which means the ALLOWED state is
    # ``map[k] == const``. Polarity-fold here so backends never need
    # to know the gate's revert semantics — they read
    # ``value_predicate`` as "filter values where this op + RHS holds".
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

    # Operator: == const becomes truthy; != const becomes falsy.
    membership_op: LeafOperator = "truthy" if operator == "eq" else "falsy"
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
    """Return (index_ir, const_value, mask_hex) if ``a`` is the lvalue of an
    Index IR (possibly with a bitwise mask applied) and ``b`` is a
    constant-like value (literal Constant, state-level
    ``constant``/``immutable``); otherwise (None, None).

    Per codex round-7 review (F1+F2): handles the direct
    ``map[k] == const`` form, bitwise-mask forms, and threshold
    forms ``map[k] >= const`` uniformly.
    """
    if not _is_mask_operand(b):
        return None, None, None
    const_value = _coerce_constant_value(b)
    defining = _find_defining_ir(a, None, function)
    if isinstance(defining, Index):
        return defining, const_value, None
    # Bitwise mask: ``a`` is the lvalue of a Binary AND whose left
    # is the Index lvalue and whose right is a constant. The outer
    # comparison ``(map[k] & MASK) op CONST`` is structurally a
    # value-compare on Index — emit the underlying Index, with the
    # bitwise mask folded into the value side. We don't lose the
    # mask information: when the value-predicate adapter populates
    # members later, it filters by `(value & MASK) op CONST`.
    if isinstance(defining, Binary):
        bt_name = getattr(getattr(defining, "type", None), "name", "").upper()
        if bt_name == "AND":  # bitwise & (Slither's BinaryType.AND); &&  is ANDAND
            left = defining.variable_left
            right = defining.variable_right
            # The "mask" side of `(value & MASK)` can be a literal
            # Constant OR a state-level `constant`/`immutable` value
            # (which Slither emits as a StateIRVariable). Either is
            # acceptable as the mask. Make sure the OTHER side is
            # the Index lvalue.
            if _is_mask_operand(left) and not _is_mask_operand(right):
                left, right = right, left
            if not _is_mask_operand(right):
                return None, None, None
            inner = _find_defining_ir(left, None, function)
            if isinstance(inner, Index):
                return inner, const_value, _literal_to_hex(_coerce_constant_value(right))
    return None, None, None


def _coerce_constant_value(value: Any) -> Any:
    """Extract the underlying value from a Constant or
    constant/immutable StateIRVariable. Returns None if the
    constant initializer isn't statically known."""
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
    """Normalize a numeric literal to the hex form value predicates expect."""
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
    """Recognize ``Index_lvalue [op] constant`` for ordering ops
    (gt/gte/lt/lte) — the structural shape of threshold/counter
    checks. Emits a comparison leaf with set_descriptor populated
    (storage_var + key_sources + threshold value), so writer-gate
    pass-2 can detect authority-derived counter patterns and
    promote the leaf to caller_authority.

    The leaf stays kind=comparison (not membership) because the
    semantic isn't "value satisfies a flag bit" — it's "counter
    crossed a threshold." Authority depends on whether the
    counter's writers are authority-gated, decided by pass-2.
    """
    if operator not in ("gt", "gte", "lt", "lte"):
        return None
    left = ir.variable_left
    right = ir.variable_right
    index_ir, threshold_value, mask_hex = _find_index_value_pair(left, right, function)
    if index_ir is None:
        # Try right as the Index side.
        index_ir, threshold_value, mask_hex = _find_index_value_pair(right, left, function)
        if index_ir is None:
            return None
        # Operator inverts when operands swap (a >= b is b <= a).
        operator = _swap_operator(operator)
    if index_ir is None or threshold_value is None:
        return None

    keys = _reconstruct_index_chain(index_ir, prov, function)
    descriptor: SetDescriptor = {
        "kind": "mapping_membership",
        "key_sources": keys,
        "truthy_value": str(threshold_value),
    }
    # First-class predicate form (D.1). ``operator`` here is already
    # polarity-folded + operand-swap-folded (see ``_apply_polarity``
    # earlier and ``_swap_operator`` above), so it describes the
    # ALLOWED relation directly. ``balances[msg.sender] < 10 revert``
    # → operator="gte", rhs=["10"]; downstream backends apply the
    # predicate to latest-value-per-key without re-deriving polarity.
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
    """Flip a comparison operator when its operands swap. e.g.
    ``a >= b`` ↔ ``b <= a``."""
    return _COMPARISON_SWAP[op]


EIP_1271_MAGIC_VALUE = "0x1626ba7e"


def _try_external_auth_oracle(
    ir: Any,
    prov: ProvenanceMap,
    gate: RevertGate,
    function: Any,
    operator: str,
) -> LeafPredicate | None:
    """Recognize ``external_call_result OP constant`` as an
    authorization-oracle gate.

    Per codex round-7: the structural pattern is "external call
    result compared against an accepted success value." When the
    call's args include msg.sender or signature_recovery (caller-
    linked), the comparison is an authorization predicate.

    EIP-1271 specifically: the magic value 0x1626ba7e identifies
    the comparison as an isValidSignature check; emit signature_auth.
    Generic case: emit external_bool; delegated_authority only when the
    callee is gate-shaped (``external_bool_leaf_is_gate_shape``) — a
    result-checked EFFECTFUL call whose args include the caller moves
    the caller's own value and is published as business.
    """
    left = ir.variable_left
    right = ir.variable_right
    # Identify (call_lvalue, constant) — order doesn't matter.
    call_value, const_value = _find_external_call_const_pair(left, right, function)
    if call_value is None:
        call_value, const_value = _find_external_call_const_pair(right, left, function)
    if call_value is None:
        return None
    call_ir = _find_defining_ir(call_value, None, function)
    if call_ir is None:
        return None

    # EIP-1271 specialization: the magic value 0x1626ba7e is itself
    # a structural fingerprint — the signer contract's
    # isValidSignature is the authority, regardless of whether the
    # call args directly include msg.sender (the hash typically
    # encodes caller intent without raw msg.sender). Detect by the
    # magic value alone.
    is_eip1271 = _is_eip1271_magic(const_value)

    # Generic external-auth oracle: require the call args to include
    # a caller-linked operand (msg.sender / signature_recovery).
    # Otherwise it's not authentication — could be any business
    # state oracle.
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
    # Same discriminator as ``_build_external_bool_leaf``: a result-checked
    # EFFECTFUL call whose args include the caller
    # (``require(bEIGEN.transferFrom(msg.sender, …) == true)``) moves the
    # caller's own value — not an authorization oracle. Only a gate-shaped
    # callee may publish delegated_authority. The mutability is stamped on
    # the leaf so downstream (permissionless_shapes, tracking) can apply the
    # identical judgment instead of reading an absent key as not-determined.
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
    """Recognize the EIP-1271 magic return value 0x1626ba7e in any
    representation (hex string, decimal int/string, bytes)."""
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
    """Return (call_value, const_value) if ``a`` is the lvalue of an
    external call (HighLevelCall or LowLevelCall) and ``b`` is a
    Constant; else (None, None)."""
    if not isinstance(b, Constant):
        return None, None
    defining = _find_defining_ir(a, None, function)
    if defining is None:
        return None, None
    if isinstance(defining, HighLevelCall):
        return a, b.value
    return None, None


def _is_mask_operand(value: Any) -> bool:
    """A bitwise mask operand is either a literal Constant or a
    state-level `constant` / `immutable` declaration. Both are
    fixed-ish at the structural level — the value can be folded into
    the SetDescriptor for downstream enumeration. Mutable state vars
    aren't masks (the value changes), so they're excluded."""
    if isinstance(value, Constant):
        return True
    # StateIRVariable for declared `constant`/`immutable` storage.
    nsv = getattr(value, "non_ssa_version", None)
    if nsv is not None:
        if getattr(nsv, "is_constant", False) or getattr(nsv, "is_immutable", False):
            return True
    return False


def _build_unary_leaf(ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None) -> LeafPredicate:
    """``require(!X)`` — condition is a Unary NOT. Recurse on the
    operand with the polarity flipped, so the resulting operator is
    correctly inverted."""
    from .tree import _build_leaf_from_gate

    op_type = getattr(ir, "type", None)
    if op_type == getattr(UnaryType, "BANG", "!"):
        inner = ir.rvalue
        flipped_polarity = "allowed_when_true" if gate.polarity == "allowed_when_false" else "allowed_when_false"
        new_gate = RevertGate(
            kind=gate.kind,
            condition_value=inner,
            polarity=flipped_polarity,
            node=gate.node,
            expression_text=gate.expression_text,
            basis=gate.basis,
        )
        return _build_leaf_from_gate(new_gate, prov, function) or _unsupported_leaf(
            reason="negated_unknown", expression=str(ir)
        )
    return _unsupported_leaf(reason=f"unary_{op_type}_unsupported", expression=str(ir))


def _build_index_membership_leaf(
    ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None = None
) -> LeafPredicate:
    """``require(map[k][m])`` style. Operator is truthy when polarity
    is allowed_when_true, falsy otherwise. For multi-key mappings
    (``map[a][b]``) we walk through chained Index IRs to collect
    every key in source order."""
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
    """Declared mutability of a HighLevelCall's callee: ``view``/``pure``
    for reads, ``nonview`` for effectful EXTERNAL calls,
    ``nonview_library`` for effectful SELF-CONTAINED library calls, None
    when the callee can't be resolved. This is the structural
    discriminator between an external ACL read (``acl.canPerform(
    msg.sender, …)`` — an authorization) and a value-movement call
    (``token.transferFrom(msg.sender, …)`` — permissionless); never
    classify by callee name. An effectful library call is kept distinct
    ONLY when its body (transitively) makes no external calls — it then
    manipulates the contract's OWN storage (``pendingAdmins.remove(
    msg.sender)`` — a membership-consume gate). A wrapper library whose
    body reaches an external call (SafeERC20/SafeTransferLib) moves
    another contract's assets exactly like a direct call → ``nonview``."""
    fn = getattr(ir, "function", None)
    if fn is None:
        return None
    if getattr(fn, "pure", False):
        return "pure"
    if getattr(fn, "view", False):
        return "view"
    # A public state-variable auto-getter (the IR callee is the Variable
    # itself, which carries no ``view`` attribute) is a read by construction.
    if isinstance(fn, Variable):
        return "view"
    if isinstance(ir, LibraryCall):
        return "nonview" if _library_reaches_external_call(fn) else "nonview_library"
    return "nonview"


# Effectful call-family Yul builtins (Slither lifts inline assembly to
# SolidityCall ops named after the builtin). ``staticcall`` is deliberately
# absent: a read can't move value, so a staticcall-only library stays on the
# own-storage (gated) side.
_YUL_EXTERNAL_CALL_PREFIXES = ("call(", "callcode(", "delegatecall(")


def _library_reaches_external_call(fn: Any, _seen: set[int] | None = None) -> bool:
    """Does this library function's body — transitively through internal and
    nested library callees — make any effectful EXTERNAL call? Covers plain
    Solidity forms (HighLevelCall to another contract, low-level ``.call``,
    ``.send``/``.transfer``) and inline-assembly forms (Yul ``call`` family,
    which Slither lifts as SolidityCall builtins — Solmate's SafeTransferLib
    has no LowLevelCall IR at all)."""
    seen = _seen if _seen is not None else set()
    if id(fn) in seen:
        return False
    seen.add(id(fn))
    for node in getattr(fn, "nodes", []) or []:
        for body_ir in getattr(node, "irs", []) or []:
            if isinstance(body_ir, (LowLevelCall, Send, Transfer)):
                return True
            # LibraryCall subclasses HighLevelCall — recurse before the
            # external-call arm so library-to-library hops aren't external.
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
    """``require(other.check(...))`` — HighLevelCall whose result
    drives the gate."""
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
    # A result-checked ``require(call())`` gates on the returned bool; an
    # ``external_call_revert``/``try_catch_revert`` gate is the callee's
    # ENTIRE revert surface — the caller-taint default needs the
    # distinction (plus the callee's arg types) to tell value movement
    # from a void merkle-witness verification.
    leaf["gate_kind"] = gate.kind
    leaf["callee_signature"] = callee_signature
    # Inputs to the authority classification below: does the call target
    # trace to a state_variable, and does any arg trace to msg_sender /
    # signature_recovery? That fingerprint alone never decides — the
    # gate-shape branch below is the contract.
    target_sources = _sources_from_destination(ir, prov)
    has_state_target = any(s.kind == "state_variable" for s in target_sources)
    target_state_var = next(
        (s.state_variable_name for s in sorted(target_sources, key=_source_sort_key) if s.kind == "state_variable"),
        None,
    )
    has_caller_arg = any(
        any(s.kind in ("msg_sender", "tx_origin", "signature_recovery") for s in _sources_for_value(a, prov))
        for a in getattr(ir, "arguments", ())
    )
    # The state-target + caller-arg fingerprint alone is not authority
    # evidence: ``vault.enter(msg.sender, …)``, ``token.permit(msg.sender,
    # …)`` and ``eETH.burnShares(msg.sender, …)`` all match it while the
    # msg.sender argument is the funds/burn subject. Only a gate-shaped
    # callee (see ``external_bool_leaf_is_gate_shape``) may publish the
    # delegated-authority claim and its resolvable descriptor.
    if (
        has_state_target
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
        )
        if descriptor is not None:
            leaf["set_descriptor"] = cast(SetDescriptor, descriptor)
    else:
        leaf["authority_role"] = "business"
    leaf["expression"] = f"{callee_name}(...)"
    return leaf


def _self_gate_or_truthy_leaf(cond: Any, prov: ProvenanceMap, gate: RevertGate, operating_fn: Any) -> LeafPredicate:
    """The bare-bool fallback leaf, upgraded to a SELF-GATE descriptor only
    when the fallback carries nothing an authority resolver could use.

    Order matters. ``_build_truthy_leaf``'s operand resolution recovers the
    underlying state variable for the common shapes — an inlined
    ``committeeMemberStates[_member].registered`` membership read, a pause flag,
    a struct member — and that state-var name is what controller enrollment and
    the pause/reentrancy passes key on. Replacing such a leaf with a probe
    descriptor would trade a named authority variable for a selector: strictly
    less. Only when the fallback's operands are ALL opaque (no state variable,
    no descriptor — the Solady assembly-role case, where the operand is the bare
    result of a read the lifter could not model) is the self-gate the better
    answer."""
    leaf = _build_truthy_leaf(cond, prov, gate)
    if leaf.get("set_descriptor"):
        return leaf
    if any((op or {}).get("source") == "state_variable" for op in leaf.get("operands") or []):
        return leaf
    self_gate = _build_self_gate_leaf(prov, gate, operating_fn)
    return self_gate if self_gate is not None else leaf


def _build_self_gate_leaf(prov: ProvenanceMap, gate: RevertGate, operating_fn: Any) -> LeafPredicate | None:
    """The SELF-gate descriptor for an un-lowerable caller gate.

    Emitted only when leaf lowering has already FAILED (the classify fallback)
    and the gate lives in a function the resolver can probe directly:

      * public/external ``view`` (an ``eth_call fn(candidate)`` reverts iff the
        gate rejects the candidate — the probed unit is the whole function, so
        ``operator`` is always ``truthy`` regardless of the inner polarity);
      * exactly one ``address`` parameter;
      * that parameter carries caller taint in this frame (the call chain
        bound it to ``msg.sender`` / ``tx.origin``);
      * declared on a contract, not a library (a library function has no
        selector on the analyzed deployment).

    The emitted leaf mirrors the external-call form of the identical gate
    (weETH's ``roleRegistry.onlyUpgradeTimelock(msg.sender)``): kind
    ``external_bool`` with an ``external_set`` descriptor, so the enumerable
    role-store adapter — which already answers this gate correctly for every
    OTHER contract — can fold + probe it. The authority is ``self_address``,
    resolved to the analyzed deployment at evaluation time. When no adapter
    recognizes the store, the resolver settles to a gated external check —
    still strictly better evidence than the bare-bool business fallback this
    replaces, which projected PUBLIC (RoleRegistry.upgradeTo)."""
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
    """Best-effort canonical ABI signature for a HighLevelCall callee."""
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
) -> dict | None:
    if target_state_var is None:
        return None
    descriptor: dict = {
        "kind": "external_set",
        "key_sources": args_operands,
        "authority_contract": {
            "address_source": {
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
    """SolidityCall returning a bool used as a gate (rare). Treat as
    business by default; specific SolidityCalls (ecrecover) are
    classified by the operand provenance, not here."""
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return _unsupported_leaf(
        reason=f"solidity_call_{name}_unsupported_as_gate",
        expression=str(ir),
    )


def _build_truthy_leaf(cond: Any, prov: ProvenanceMap, gate: RevertGate) -> LeafPredicate:
    """``require(boolFlag)`` where ``cond`` is a bare variable, not
    the result of a Binary/Index/etc. We treat as a unary boolean
    check on the value with operator=truthy/falsy by polarity."""
    operator: LeafOperator = "truthy" if gate.polarity == "allowed_when_true" else "falsy"
    operand = _operand_for_value(cond, prov)
    leaf = _make_leaf(
        kind="equality",
        operator=operator,
        operands=[operand],
        gate=gate,
    )
    leaf["authority_role"] = "business"  # bare-bool gates rarely auth
    # ``require(sent)`` after ``msg.sender.call{value: …}("")``: the bool is
    # an effectful-call result whose provenance folds to the caller (the
    # call's destination). Stamp mutability so the caller-taint default can
    # tell this value-movement success check apart from a caller-keyed
    # storage flag (``allowlisted[msg.sender].registered``).
    containing = getattr(gate, "containing_function", None)
    defining = _find_defining_ir(cond, getattr(gate, "node", None), containing)
    if isinstance(defining, Unpack):
        # ``(bool sent, ) = …`` — chase through the tuple to the call.
        tuple_var = getattr(defining, "tuple", None)
        if tuple_var is not None:
            defining = _find_defining_ir(tuple_var, None, containing) or defining
    if isinstance(defining, (LowLevelCall, Send, Transfer)):
        leaf["callee_state_mutability"] = "nonview"
    elif isinstance(defining, HighLevelCall):
        leaf["callee_state_mutability"] = _callee_state_mutability(defining)
    return leaf
