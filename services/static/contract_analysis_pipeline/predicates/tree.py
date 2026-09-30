"""The predicate-tree core: ``build_predicate_tree``/``build_return_predicate_tree``, recursive subtree builders,
per-gate leaf dispatch and inlined helper revert gates.
"""

from __future__ import annotations

import contextvars as _contextvars
import os
from typing import Any, cast

from ..predicate_types import (
    LeafPredicate,
    PredicateTree,
    make_and_node,
    make_leaf_node,
    make_or_node,
)
from ..provenance import (
    ProvenanceEngine,
    ProvenanceMap,
    Source,
    arg_origins,
)
from ..revert_detect import DEFAULT_INTERNAL_CALL_DEPTH, RevertDetector, RevertGate
from ..slither_compat import (
    SLITHER_AVAILABLE,
    Binary,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    SolidityCall,
    Unary,
    UnaryType,
)
from ._helpers import (
    _binary_op,
    _find_defining_ir,
    _gate_references_caller,
    _unsupported_leaf,
)
from .authority import _CALLER_SOURCES
from .confidence import apply_confidence_to_tree
from .control_flow import (
    _build_if_else_returns_or_children,
    _detect_assembly_combinator_op,
    _resolve_internal_call_return,
)
from .leaves import (
    _build_binary_leaf,
    _build_external_bool_leaf,
    _build_index_membership_leaf,
    _build_solidity_call_leaf,
    _build_truthy_leaf,
    _build_unary_leaf,
    _self_gate_or_truthy_leaf,
)
from .operands import _operand_for_value, _published_source_key, _source_to_operand

# ``(callee_id, bindings) -> ProvenanceMap`` for helpers shared across a contract's functions (``_checkRole`` behind
# grant/revoke/renounce). Set by ``build_predicate_artifacts``; ``None`` in direct test calls. Pure performance.
_helper_engine_cache: _contextvars.ContextVar[dict | None] = _contextvars.ContextVar(
    "psat_predicate_helper_engine_cache", default=None
)

# Callees being gate-inlined, breaking mutual recursion and bounding depth.
_inline_gate_callee_stack: _contextvars.ContextVar[tuple[str, ...]] = _contextvars.ContextVar(
    "psat_predicate_inline_gate_callee_stack", default=()
)


def _inline_helper_revert_gates_enabled() -> bool:
    """Conjoin an inlined bool helper's caller-tainted revert gates into the caller's tree.

    ``PSAT_INLINE_HELPER_REVERT_GATES=0`` disables.
    """
    return os.getenv("PSAT_INLINE_HELPER_REVERT_GATES", "1").lower() in ("1", "true", "yes")


def _cache_key_for(callee: Any, bindings: dict[str, Any]) -> tuple | None:
    """A hashable cache key from callee and bindings, or None (a miss) if something isn't hashable."""
    try:
        callee_id = getattr(callee, "full_name", None) or getattr(callee, "name", None)
        if callee_id is None:
            return None
        items = tuple((name, bindings[name]) for name in sorted(bindings))
        hash(items)
        return (callee_id, items)
    except Exception:
        return None


def build_predicate_tree(function: Any, *, uncertain_out: set[str] | None = None) -> PredicateTree | None:
    """A PredicateTree for one function, or None if it has no revert paths.

    ``uncertain_out`` collects functions that have gates but no tree where some gate is a direct
    ``msg.sender``/``tx.origin`` EQ/NEQ comparison: a missed access guard, so policy must not default it to public.
    Value checks and mapping reads are excluded.
    """
    if not SLITHER_AVAILABLE:
        raise RuntimeError("predicate builder requires slither")
    detector = RevertDetector(function)
    gates = detector.run()
    if not gates:
        return None

    engine = ProvenanceEngine(function)
    engine.run()
    prov = engine.provenance

    subtrees: list[PredicateTree] = []
    caller_eq_unmodeled = False
    for gate in gates:
        subtree = _build_subtree_from_gate(gate, prov, function)
        if subtree is not None:
            subtrees.append(subtree)
        elif uncertain_out is not None and _gate_condition_is_caller_eq_neq(gate, prov, function):
            caller_eq_unmodeled = True

    if not subtrees:
        if caller_eq_unmodeled and uncertain_out is not None:
            full_name = getattr(function, "full_name", None)
            if full_name:
                uncertain_out.add(full_name)
        return None
    tree = make_and_node(subtrees)
    apply_confidence_to_tree(tree)
    return tree


def _gate_condition_is_caller_eq_neq(gate: RevertGate, prov: ProvenanceMap, function: Any) -> bool:
    """True iff the gate's IF condition is a direct caller EQ/NEQ against a non-constant (a caller guard the builder
    couldn't lower, e.g. ``msg.sender == cfg.admin``). Excludes value checks, call-success checks, thresholds and
    ``msg.sender != address(0)``.
    """
    cond = getattr(gate, "condition_value", None)
    if cond is None:
        return False
    defining = _find_defining_ir(cond, getattr(gate, "node", None), function)
    if not isinstance(defining, Binary):
        return False
    if _binary_op(getattr(defining, "type", None)) not in ("eq", "ne"):
        return False
    operands = [
        _operand_for_value(getattr(defining, "variable_left", None), prov),
        _operand_for_value(getattr(defining, "variable_right", None), prov),
    ]
    caller_sources = {"msg_sender", "tx_origin"}
    has_caller = any(op.get("source") in caller_sources for op in operands)
    other_non_constant = any(
        op.get("source") not in caller_sources and op.get("source") != "constant" for op in operands
    )
    return has_caller and other_non_constant


def build_return_predicate_tree(function: Any) -> PredicateTree | None:
    """A PredicateTree from a bool-returning function's return expression.

    Authority providers like ``canCall(user, target, sig)`` return rather than revert; these resolver-only trees give
    external-call evaluation something to inline.
    """
    if not SLITHER_AVAILABLE:
        raise RuntimeError("predicate builder requires slither")
    if not _function_returns_bool(function):
        return None

    engine = ProvenanceEngine(function)
    engine.run()
    prov = engine.provenance

    base_gate = RevertGate(
        kind="assert",
        condition_value=None,
        polarity="allowed_when_true",
        node=None,
        containing_function=function,
        expression_text=f"return {getattr(function, 'full_name', 'bool')}",
        basis=["bool-return predicate"],
    )
    children = _build_if_else_returns_or_children(function, prov, base_gate)

    if not children:
        return None
    tree = make_or_node(children)
    apply_confidence_to_tree(tree)
    return tree


def _function_returns_bool(function: Any) -> bool:
    returns = list(getattr(function, "returns", []) or [])
    if returns:
        return any(str(getattr(rv, "type", rv)) == "bool" for rv in returns)
    raw_return_type = getattr(function, "return_type", None)
    if raw_return_type is None:
        return False
    if isinstance(raw_return_type, (list, tuple)):
        return any(str(item) == "bool" for item in raw_return_type)
    return str(raw_return_type) == "bool"


def _build_subtree_from_gate(
    gate: RevertGate,
    prov: ProvenanceMap,
    function: Any,
) -> PredicateTree | None:
    """Like ``_build_leaf_from_gate`` but returns a tree, so ``&&``/``||`` split into nodes.

    A gate in a cross-function helper is built in the helper's scope.
    """
    if gate.kind == "opaque":
        leaf = _unsupported_leaf(
            reason=gate.unsupported_reason or "opaque_control_flow",
            expression=gate.expression_text,
            references_msg_sender=_gate_references_caller(gate),
        )
        return make_leaf_node(leaf)

    if gate.kind in {"try_catch_revert", "external_call_revert"} and isinstance(gate.condition_value, HighLevelCall):
        leaf = _build_external_bool_leaf(gate.condition_value, prov, gate)
        return make_leaf_node(leaf)

    cond = gate.condition_value
    if cond is None:
        return make_leaf_node(
            _unsupported_leaf(
                reason="missing_condition",
                expression=gate.expression_text,
                references_msg_sender=_gate_references_caller(gate),
            )
        )

    # Bind the helper's parameters through the call chain and run provenance on it.
    operating_fn = gate.containing_function or function
    if operating_fn is not function:
        # Reuse the caller's provenance; if the chain ends at ``operating_fn``, reuse the last hop's too.
        bindings, chain_end_prov, chain_end_fn = _build_chain_bindings(
            gate.call_chain or [], operating_fn, function, top_prov=prov
        )
        if chain_end_fn is operating_fn and chain_end_prov is not None:
            prov = chain_end_prov
        else:
            helper_engine = ProvenanceEngine(operating_fn, parameter_bindings=bindings)
            helper_engine.run()
            prov = helper_engine.provenance

    return _build_subtree_from_value(cond, prov, gate, operating_fn)


def _build_chain_bindings(
    call_chain: list[Any],
    helper: Any,
    top_function: Any,
    *,
    top_prov: ProvenanceMap | None = None,
) -> tuple[dict[str, Any], ProvenanceMap | None, Any]:
    """Bind parameters along the call chain (each link an InternalCall into the next callee), so a leaf deep in a
    helper that reads ``account`` resolves to the caller's ``msg.sender`` and Rule B can promote it. E.g.
    ``gate(resolveKey(input))`` -> ``_check(key)`` -> ``_checkAddress(key, _msgSender())``.
    """
    if not call_chain:
        return {}, top_prov, top_function
    # Reuse the caller's provenance when given.
    if top_prov is not None:
        current_prov = top_prov
    else:
        top_engine = ProvenanceEngine(top_function)
        top_engine.run()
        current_prov = top_engine.provenance
    current_fn = top_function

    cache = _helper_engine_cache.get()
    for ir in call_chain:
        callee = getattr(ir, "function", None)
        if callee is None:
            continue
        args = list(getattr(ir, "arguments", []) or [])
        params = list(getattr(callee, "parameters", []) or [])
        new_bindings: dict[str, Any] = {}
        for param, arg in zip(params, args):
            param_name = getattr(param, "name", None)
            if not param_name:
                continue
            new_bindings[param_name] = _operand_value_provenance(arg, current_prov)

        cache_key = None
        if cache is not None:
            cache_key = _cache_key_for(callee, new_bindings)
        if cache is not None and cache_key is not None and cache_key in cache:
            current_prov = cache[cache_key]
        else:
            callee_engine = ProvenanceEngine(callee, parameter_bindings=new_bindings)
            callee_engine.run()
            current_prov = callee_engine.provenance
            if cache is not None and cache_key is not None:
                cache[cache_key] = current_prov
        current_fn = callee

    helper_bindings: dict[str, Any] = {}
    for param in getattr(helper, "parameters", []) or []:
        name = getattr(param, "name", None)
        if name and name in current_prov.sources:
            helper_bindings[name] = current_prov.sources[name]
    return helper_bindings, current_prov, current_fn


def _operand_value_provenance(value: Any, prov: ProvenanceMap) -> Any:
    """A value's provenance in ``prov``, with the engine's SSA-suffix fallback."""
    from ..provenance import EMPTY, Source, _strip_ssa_suffix

    if value is None:
        return EMPTY
    name = getattr(value, "name", None)
    if name is None:
        return EMPTY
    if name in prov.sources:
        return prov.sources[name]
    base = _strip_ssa_suffix(name)
    if base != name and base in prov.sources:
        return prov.sources[base]
    if name == "msg.sender":
        return frozenset({Source(kind="msg_sender")})
    if name == "tx.origin":
        return frozenset({Source(kind="tx_origin")})
    return EMPTY


def _build_subtree_from_value(
    cond_value: Any,
    prov: ProvenanceMap,
    gate: RevertGate,
    function: Any,
) -> PredicateTree:
    """Build a subtree from ``cond_value``: split Binary ANDAND/OROR recursively, else one leaf."""
    defining_ir = _find_defining_ir(cond_value, gate.node, function)
    if defining_ir is None:
        leaf = _build_truthy_leaf(cond_value, prov, gate)
        return make_leaf_node(leaf)

    # ``require(!(A && B))``: flip polarity and recurse, or it collapses to an empty bare-bool leaf (USDT.approve).
    if isinstance(defining_ir, Unary):
        op_type = getattr(defining_ir, "type", None)
        if op_type == getattr(UnaryType, "BANG", "!"):
            inner_value = defining_ir.rvalue
            flipped_polarity = "allowed_when_true" if gate.polarity == "allowed_when_false" else "allowed_when_false"
            inner_gate = RevertGate(
                kind=gate.kind,
                condition_value=inner_value,
                polarity=flipped_polarity,
                node=gate.node,
                containing_function=gate.containing_function,
                call_chain=list(gate.call_chain),
                expression_text=gate.expression_text,
                basis=list(gate.basis),
            )
            return _build_subtree_from_value(inner_value, prov, inner_gate, function)

    if isinstance(defining_ir, Binary):
        op_name = _binary_op(getattr(defining_ir, "type", None))
        if op_name in ("and", "or"):
            left_tree = _build_subtree_from_value(defining_ir.variable_left, prov, gate, function)
            right_tree = _build_subtree_from_value(defining_ir.variable_right, prov, gate, function)
            children = [left_tree, right_tree]
            if gate.polarity == "allowed_when_true":
                return make_and_node(children) if op_name == "and" else make_or_node(children)
            # If-revert polarity flips AND/OR (De Morgan).
            return make_or_node(children) if op_name == "and" else make_and_node(children)

    # A helper whose return is AND/OR (Solmate Auth, DSAuth, Maker ``wish``, USDT): recurse into its bindings so it
    # doesn't bottom out as unsupported business.
    if isinstance(defining_ir, (InternalCall, LibraryCall)):
        subtree = _build_internal_call_or_and_subtree(defining_ir, prov, gate)
        # The helper's revert gates are conjuncts at this call site, inside any enclosing OR branch.
        gate_subtrees = _internal_call_revert_gate_subtrees(defining_ir, prov)
        if gate_subtrees:
            if subtree is None:
                inline_leaf = _classify_leaf_from_ir(defining_ir, prov, gate, function)
                subtree = make_leaf_node(
                    inline_leaf if inline_leaf is not None else _build_truthy_leaf(cond_value, prov, gate)
                )
            return make_and_node([*gate_subtrees, subtree])
        if subtree is not None:
            return subtree

    leaf = _classify_leaf_from_ir(defining_ir, prov, gate, function)
    if leaf is None:
        # No typed builder (Assignment, TypeConversion, Phi...): the condition is still bool, so fall back to a
        # bare-bool leaf whose operand resolution finds the state var, letting the pause/reentrancy passes promote it
        # (``_requireNotPaused``).
        return make_leaf_node(_self_gate_or_truthy_leaf(cond_value, prov, gate, function))
    return make_leaf_node(leaf)


def _build_leaf_from_gate(
    gate: RevertGate,
    prov: ProvenanceMap,
    function: Any,
) -> LeafPredicate | None:
    """A typed leaf from the gate's condition, with source polarity and the if-revert flip folded into the operator."""
    if gate.kind == "opaque":
        return _unsupported_leaf(
            reason=gate.unsupported_reason or "opaque_control_flow", expression=gate.expression_text
        )

    cond = gate.condition_value
    if cond is None:
        return _unsupported_leaf(reason="missing_condition", expression=gate.expression_text)

    defining_ir = _find_defining_ir(cond, gate.node, function)
    if defining_ir is None:
        # A bare value (``require(boolFlag)``, ``require(_blacklist[msg.sender] == false)``).
        return _build_truthy_leaf(cond, prov, gate)

    leaf = _classify_leaf_from_ir(defining_ir, prov, gate, function)
    if leaf is None:
        # Phi/Assignment forward bare values (``require(!flag)``).
        return _self_gate_or_truthy_leaf(cond, prov, gate, function)
    return leaf


def _classify_leaf_from_ir(
    defining_ir: Any,
    prov: ProvenanceMap,
    gate: RevertGate,
    function: Any | None = None,
) -> LeafPredicate | None:
    if isinstance(defining_ir, Binary):
        return _build_binary_leaf(defining_ir, prov, gate, function)
    if isinstance(defining_ir, Unary):
        return _build_unary_leaf(defining_ir, prov, gate, function)
    if isinstance(defining_ir, Index):
        # ``require(map[k][m])``.
        return _build_index_membership_leaf(defining_ir, prov, gate, function)
    if isinstance(defining_ir, HighLevelCall):
        return _build_external_bool_leaf(defining_ir, prov, gate)
    if isinstance(defining_ir, SolidityCall):
        return _build_solidity_call_leaf(defining_ir, prov, gate)
    if isinstance(defining_ir, (InternalCall, LibraryCall)):
        return _build_internal_call_leaf(defining_ir, prov, gate, function)
    return None


def _build_internal_call_leaf(
    ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None
) -> LeafPredicate | None:
    """A bool InternalCall condition (``if (!check(role, account)) revert``): recurse into the callee with bound
    parameters and classify its return, unfolding helpers deeper than the revert chain.
    """
    resolved = _resolve_internal_call_return(ir, prov)
    if resolved is None:
        return None
    callee, sub_prov, return_value, inner = resolved
    if inner is None:
        # An unlowerable callee return (assembly-assigned, Solady EnumerableRoles) is built in the callee's frame where
        # the caller isn't represented; re-attach the call-site argument origins.
        leaf = _build_truthy_leaf(return_value, sub_prov, gate)
        return _attach_call_site_arg_origins(leaf, ir, prov)
    return _classify_leaf_from_ir(inner, sub_prov, gate, callee)


def _call_site_arg_origins(ir: Any, caller_prov: ProvenanceMap) -> set[Source]:
    """Flattened origins of an internal call's arguments in the caller's frame; members have ``derived_from=None``,
    so one level.
    """
    origins: set[Source] = set()
    for arg in getattr(ir, "arguments", ()) or ():
        origins.update(arg_origins(_operand_value_provenance(arg, caller_prov)))
    return origins


def _attach_call_site_arg_origins_to_tree(tree: PredicateTree, ir: Any, caller_prov: ProvenanceMap) -> PredicateTree:
    """``_attach_call_site_arg_origins`` over every leaf of a callee-frame subtree."""
    if not isinstance(tree, dict):
        return tree
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            _attach_call_site_arg_origins(cast(LeafPredicate, leaf), ir, caller_prov)
        return tree
    for child in tree.get("children") or []:
        _attach_call_site_arg_origins_to_tree(child, ir, caller_prov)
    return tree


def _attach_call_site_arg_origins(leaf: LeafPredicate, ir: Any, caller_prov: ProvenanceMap) -> LeafPredicate:
    """Union call-site argument origins into operands that already publish ``derived_from``
    (computed/view_call/external_call), sorted for determinism. ``references_msg_sender`` stays unset: the caller
    came in as an argument, not a direct operand.
    """
    origins = _call_site_arg_origins(ir, caller_prov)
    if not origins:
        return leaf
    for op in leaf.get("operands") or []:
        if op.get("source") not in ("computed", "view_call", "external_call"):
            continue
        existing = op.get("derived_from") or []
        merged = list(existing)
        for origin in sorted(origins, key=_published_source_key):
            rendered = _source_to_operand(origin, nested=True)
            if rendered not in merged:
                merged.append(rendered)
        op["derived_from"] = merged
    return leaf


def _build_internal_call_or_and_subtree(ir: Any, prov: ProvenanceMap, gate: RevertGate) -> PredicateTree | None:
    """An AND/OR subtree for a helper whose return is a connective (Solmate ``isAuthorized``, DSAuth, Maker ``wish``,
    USDT), which ``_build_binary_leaf`` can't handle.

    Shapes: a direct Binary AND/OR return; a return of an assembly combinator call (Maker ``return either(...)``); the
    helper itself being an assembly ``or``/``and`` combinator (below Slither's IR, so detected structurally with the
    call-site args as children); and an if/else chain of bool returns (see ``_build_if_else_returns_or_children``).
    """
    resolved = _resolve_internal_call_return(ir, prov)
    if resolved is None:
        return None
    callee, sub_prov, _return_value, inner = resolved
    op_name: str | None = None
    children: list[PredicateTree] = []
    if isinstance(inner, Binary):
        op_name = _binary_op(getattr(inner, "type", None))
        if op_name not in ("and", "or"):
            return None
        left = inner.variable_left
        right = inner.variable_right
        if left is None or right is None:
            return None
        children = [
            _build_subtree_from_value(left, sub_prov, gate, callee),
            _build_subtree_from_value(right, sub_prov, gate, callee),
        ]
    elif isinstance(inner, (InternalCall, LibraryCall)):
        # The return is itself an assembly combinator call; its args are the children.
        inner_callee = getattr(inner, "function", None)
        asm_op = _detect_assembly_combinator_op(inner_callee) if inner_callee else None
        if asm_op is None:
            return None
        op_name = asm_op
        call_args = list(getattr(inner, "arguments", []) or [])
        if not call_args:
            return None
        children = [_build_subtree_from_value(arg, sub_prov, gate, callee) for arg in call_args]
    else:
        # The helper is the assembly combinator; the call-site args are the children.
        asm_op = _detect_assembly_combinator_op(callee)
        if asm_op is not None:
            op_name = asm_op
            call_args = list(getattr(ir, "arguments", []) or [])
            if not call_args:
                return None
            children = [
                _build_subtree_from_value(arg, prov, gate, gate.containing_function or callee) for arg in call_args
            ]
        else:
            # If/else chain of bool returns: OR of each return-true path's conditions.
            children = _build_if_else_returns_or_children(callee, sub_prov, gate)
            if children:
                op_name = "or"
        if op_name is None or not children:
            return None
    if op_name is None or not children:
        return None
    # Re-attach call-site argument origins lost in the callee's frame.
    children = [_attach_call_site_arg_origins_to_tree(child, ir, prov) for child in children]
    if gate.polarity == "allowed_when_true":
        return make_and_node(children) if op_name == "and" else make_or_node(children)
    return make_or_node(children) if op_name == "and" else make_and_node(children)


# Explicit conditional reverts only: opaque fail-safes would add ``unsupported`` leaves, and external-call/try-catch
# markers fire on any call, manufacturing gates.
_INLINED_GATE_KINDS = ("require", "assert", "if_revert", "custom_revert")


def _internal_call_revert_gate_subtrees(ir: Any, prov: ProvenanceMap) -> list[PredicateTree]:
    """The inlined helper's own revert gates, rebuilt in the caller's frame.

    ``require(helper(args))`` also depends on the helper not reverting, but neither side owned its internal gates
    (RevertDetector skips read-result callees, the builder lifted only the return), so a caller-keyed allowlist in the
    helper vanished (EtherFiOracle.submitReport's committee gate read public).

    Each gate is built with arguments bound to the helper's parameters and conjoined at the call site, inside any OR
    branch, keeping short-circuiting: ``require(a || helper(x))`` gives ``OR(a, AND(helper_gates, helper_return))``.
    Gates keep their own polarity. Conservative: only explicit conditional forms, and only caller-tainted gates.
    """
    if not _inline_helper_revert_gates_enabled():
        return []
    callee = getattr(ir, "function", None)
    if callee is None:
        return []
    callee_id = getattr(callee, "full_name", None) or getattr(callee, "name", None)
    if not callee_id:
        return []
    stack = _inline_gate_callee_stack.get()
    if callee_id in stack or len(stack) >= DEFAULT_INTERNAL_CALL_DEPTH:
        return []

    try:
        inner_gates = RevertDetector(callee).run()
    except Exception:
        return []
    inner_gates = [g for g in inner_gates if g.kind in _INLINED_GATE_KINDS]
    if not inner_gates:
        return []

    # Bind like ``_resolve_internal_call_return``, through the helper-engine cache.
    bindings: dict[str, Any] = {}
    args = list(getattr(ir, "arguments", []) or [])
    params = list(getattr(callee, "parameters", []) or [])
    for param, arg in zip(params, args):
        name = getattr(param, "name", None)
        if name:
            bindings[name] = _operand_value_provenance(arg, prov)
    cache = _helper_engine_cache.get()
    cache_key = _cache_key_for(callee, bindings) if cache is not None else None
    if cache is not None and cache_key is not None and cache_key in cache:
        sub_prov = cache[cache_key]
    else:
        sub_engine = ProvenanceEngine(callee, parameter_bindings=bindings)
        sub_engine.run()
        sub_prov = sub_engine.provenance
        if cache is not None and cache_key is not None:
            cache[cache_key] = sub_prov

    token = _inline_gate_callee_stack.set(stack + (callee_id,))
    try:
        subtrees: list[PredicateTree] = []
        for inner_gate in inner_gates:
            subtree = _build_subtree_from_gate(inner_gate, sub_prov, callee)
            if subtree is None or not _tree_has_caller_tainted_leaf(subtree):
                continue
            _tag_tree_leaves_basis(subtree, f"inlined_internal_gate:{callee_id}")
            subtrees.append(subtree)
        return subtrees
    finally:
        _inline_gate_callee_stack.reset(token)


def _tree_has_caller_tainted_leaf(tree: Any) -> bool:
    """Whether any leaf's post-binding operand or key sources derive from the caller (as the evaluator's
    earned-public default decides).
    """
    if not isinstance(tree, dict):
        return False
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf") or {}
        for op in leaf.get("operands") or []:
            if (op or {}).get("source") in _CALLER_SOURCES:
                return True
        descriptor = leaf.get("set_descriptor") or {}
        return any((key or {}).get("source") in _CALLER_SOURCES for key in descriptor.get("key_sources") or [])
    return any(_tree_has_caller_tainted_leaf(child) for child in tree.get("children") or [])


def _tag_tree_leaves_basis(tree: Any, tag: str) -> None:
    """Tag every leaf's basis so conjoined helper gates are attributable."""
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            leaf["basis"] = list(leaf.get("basis") or []) + [tag]
        return
    for child in tree.get("children") or []:
        _tag_tree_leaves_basis(child, tag)
