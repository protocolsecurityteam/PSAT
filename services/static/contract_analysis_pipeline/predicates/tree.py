"""The predicate-tree core: ``build_predicate_tree``/``build_return_predicate_tree``, recursive subtree builders,
per-gate leaf dispatch and inlined helper revert gates.
"""

from __future__ import annotations

import contextvars as _contextvars
import os
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from typing import Any, cast

from utils.predicate_provenance import has_unknown_predicate_provenance

from ..predicate_types import (
    REACH_CONDITION_BASIS,
    REACH_READ,
    LeafPredicate,
    PredicateTree,
    is_reach_condition,
    make_and_node,
    make_leaf_node,
    make_or_node,
    mark_reach_condition,
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
from ..structural_evidence import evidence_for
from ._helpers import (
    _binary_op,
    _find_defining_ir,
    _gate_references_caller,
    _unsupported_leaf,
)
from .authority import _CALLER_SOURCES
from .confidence import apply_confidence_to_tree
from .control_flow import (
    _branch_value_is_only,
    _detect_assembly_combinator_op,
    _forward_reachable_node_ids,
    _guards_contain_opening,
    _helper_exits,
    _node_has_unclassified_call,
    _node_is_type,
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
from .reach import (
    REACHED_ALWAYS,
    branch_reads,
    call_site_unread,
    effect_before,
    modifiers_before,
    node_text,
    placeholders,
    reached_formula,
    reads_conflict,
    render,
    rendered_cache,
    runs_body_repeatedly,
    unreached_formula,
    value_reads,
)
from .reach_read import reach_read

# ``(callee_id, bindings) -> ProvenanceMap`` for helpers shared across a contract's functions (``_checkRole`` behind
# grant/revoke/renounce). Set by ``build_predicate_artifacts``; ``None`` in direct test calls. Pure performance.
_helper_engine_cache: _contextvars.ContextVar[dict | None] = _contextvars.ContextVar(
    "psat_predicate_helper_engine_cache", default=None
)

# ``id(function) -> (function, revert gates)`` for entry points and the helpers whose gates are inlined; set alongside
# ``_helper_engine_cache``. Pure performance.
_helper_gate_cache: _contextvars.ContextVar[dict | None] = _contextvars.ContextVar(
    "psat_predicate_helper_gate_cache", default=None
)

_HELPER_NEVER_RETURNS = "helper_never_returns_allowed_value"


def _node_is_if(node: Any) -> bool:
    return _node_is_type(node, "NodeType.IF")


# Callees being gate-inlined, breaking mutual recursion and bounding depth.
_inline_gate_callee_stack: _contextvars.ContextVar[tuple[int, ...]] = _contextvars.ContextVar(
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
        callee_id = id(callee)
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
    gates = _revert_gates(function)
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
            _stamp_gate_scope(subtree, gate, function)
            subtrees.append(_where_reached(subtree, gate, prov, function))
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


def _where_reached(
    subtree: PredicateTree,
    gate: RevertGate,
    prov: ProvenanceMap,
    function: Any,
    *,
    first_level: int = 0,
    outer: tuple[Any, list[Any]] | None = None,
) -> PredicateTree:
    """``subtree`` as an alternative to every condition under which ``gate`` isn't reached.

    Levels run from ``function`` down ``gate.call_chain`` to the gate's node; a level's modifiers that run before its
    anchor add the condition their ``_`` is reached under. ``first_level`` skips outer levels whose control flow the
    caller already accounts for. ``outer`` is the entry point and call chain that lead to ``function`` when it isn't
    the entry point itself, for the writes made before it. The alternatives' leaves carry the gate's scope, so whatever
    consumes the gate consumes them too.
    """
    entry, prefix = outer if outer is not None else (function, [])
    if gate.node is None:
        return subtree
    chain = list(gate.call_chain or [])
    frames = [function, *(getattr(ir, "function", None) for ir in chain)]
    anchors = [*(getattr(ir, "node", None) for ir in chain), gate.node]
    alternatives: list[PredicateTree] = []
    # Reach is read for one run of a body; a body a modifier or a loop runs again sees the first run's writes and
    # returns.
    unread: tuple[int, str] | None = None
    above = _unread_above(entry, prefix)
    if above is not None:
        unread = (0, above)
    for level, frame in enumerate(frames):
        if unread is not None:
            break
        reason = call_site_unread(frames[level - 1], chain[level - 1]) if level else None
        if reason is None and frame is not None and runs_body_repeatedly(frame):
            reason = "body_runs_repeatedly"
        if reason is not None:
            unread = (level, reason)
    for level in range(first_level, len(frames)):
        frame, anchor = frames[level], anchors[level]
        if frame is None or anchor is None:
            alternatives.append(make_leaf_node(_reach_unsupported_leaf("gate_location_not_determined", gate)))
            continue
        level_chain = chain[:level]
        targets = [(frame, [anchor], level_chain)]
        targets += [
            (call.function, placeholders(call.function), [*level_chain, call])
            for call in modifiers_before(frame, anchor)
        ]
        for target_fn, target_anchors, target_chain in targets:
            formula = unreached_formula(target_fn, target_anchors)
            if formula is None:
                continue
            if unread is not None and level >= unread[0]:
                alternatives.append(make_leaf_node(_reach_unsupported_leaf(unread[1], gate)))
                continue
            # Provenance only for a frame whose reach depends on a branch; most gates are reached unconditionally.
            target_prov: ProvenanceMap | None = prov
            if target_chain:
                _, target_prov, chain_end = _build_chain_bindings(target_chain, target_fn, function, top_prov=prov)
                if chain_end is not target_fn or target_prov is None:
                    alternatives.append(make_leaf_node(_reach_unsupported_leaf("gate_location_not_determined", gate)))
                    continue
            entry_chain = [*prefix, *target_chain]
            memo = rendered_cache(target_fn)
            key = (formula, tuple(id(call) for call in entry_chain), id(target_prov), id(entry))
            if key not in memo:
                rendered = render(
                    formula, target_fn, _branch_tree_builder(target_fn, target_prov, entry, entry_chain), reach=True
                )
                memo[key] = ((entry_chain, target_prov, entry), rendered)
            alternative = memo[key][1]
            if alternative is not None:
                alternatives.append(deepcopy(alternative))
    if not alternatives:
        return subtree
    for alternative in alternatives:
        _restamp_scope(alternative, gate, function)
    children: list[PredicateTree] = []
    for tree in [*alternatives, subtree]:
        children.extend(tree.get("children") or [] if tree.get("op") == "OR" else [tree])
    return make_or_node(children)


def _branch_tree_builder(
    frame: Any,
    prov: ProvenanceMap,
    entry: Any,
    entry_chain: list[Any],
    basis: list[str] | None = None,
) -> Callable[[Any, Any, bool], PredicateTree | None]:
    """Leaves for a branch outcome in ``frame``, reached from ``entry`` through ``entry_chain``.

    Leaves state storage as it is when the call starts, so an outcome whose condition reads storage the call may
    already have written on the way to the branch is not determined.
    """

    def build(node: Any, condition: Any, holds: bool) -> PredicateTree | None:
        reach = basis is None
        gate = RevertGate(
            kind="if_revert",
            condition_value=condition,
            polarity="allowed_when_true" if holds else "allowed_when_false",
            node=node,
            containing_function=frame,
            call_chain=list(entry_chain),
            expression_text=node_text(node, condition),
            basis=list(basis) if basis is not None else [REACH_CONDITION_BASIS],
        )
        tree = _build_subtree_from_value(condition, prov, gate, frame)
        leaf = tree.get("leaf") or {}
        # A bool helper that never returns the value this outcome needs makes the outcome impossible.
        if leaf.get("unsupported_reason") == _HELPER_NEVER_RETURNS:
            return None
        written, writes_other = effect_before(entry, entry_chain, frame, node)
        if written or writes_other:
            if reads_conflict(branch_reads(entry, entry_chain, frame, node), (written, writes_other)):
                unread = _unsupported_leaf("branch_reads_state_written_before", gate.expression_text)
                if reach:
                    mark_reach_condition(unread)
                return make_leaf_node(unread)
        return _with_reach_read(tree, reach_read(condition, entry, entry_chain), holds, reach_only=reach)

    return build


def _reach_unsupported_leaf(reason: str, gate: RevertGate) -> LeafPredicate:
    leaf = _unsupported_leaf(reason, gate.expression_text)
    mark_reach_condition(leaf)
    return leaf


def _with_reach_read(
    tree: PredicateTree, expression: dict[str, Any] | None, holds: bool, *, reach_only: bool
) -> PredicateTree:
    """``tree`` with the outcome it states as a read on each leaf (each reach leaf when ``reach_only``)."""
    if expression is None or expression.get("type") != "bool":
        return tree
    tree = deepcopy(tree)
    stamp = {"expression": expression, "holds": holds}

    def visit(node: PredicateTree) -> None:
        leaf = node.get("leaf")
        if leaf is not None and (is_reach_condition(leaf) or not reach_only):
            leaf[REACH_READ] = stamp
        for child in node.get("children") or []:
            visit(child)

    visit(tree)
    return tree


_STATE_SOURCES = frozenset({"state_variable", "constant", "self_address"})


def _reads_only_state(operand: Any) -> bool:
    if not isinstance(operand, dict):
        return False
    source = operand.get("source")
    if source == "view_call":
        signature = operand.get("callee_signature")
        return isinstance(signature, str) and signature.endswith("()")
    return source in _STATE_SOURCES


def _is_business_state_tree(tree: PredicateTree) -> bool:
    """Every leaf a business condition on this contract's state alone: no caller, calldata, block or other contract."""
    leaf = tree.get("leaf")
    if tree.get("op") == "LEAF":
        if not isinstance(leaf, dict) or leaf.get("kind") == "unsupported" or is_reach_condition(leaf):
            return False
        if leaf.get("authority_role") != "business" or leaf.get("references_msg_sender"):
            return False
        descriptor = leaf.get("set_descriptor") or {}
        operands = [
            *(leaf.get("operands") or []),
            *(leaf.get("absorbed_operands") or []),
            *(descriptor.get("key_sources") or []),
        ]
        if descriptor.get("authority_contract"):
            return False
        return bool(leaf.get("operands")) and all(_reads_only_state(operand) for operand in operands)
    children = tree.get("children") or []
    return bool(children) and all(_is_business_state_tree(child) for child in children)


def _state_disjuncts_as_reach(
    children: list[PredicateTree], read: Callable[[int], dict[str, Any] | None], holds: bool
) -> list[PredicateTree]:
    """A disjunct that only reads this contract's state, beside one that doesn't, is the condition under which the
    other isn't needed (``!flag || isExecutor(msg.sender)`` is ``if (flag) require(isExecutor(msg.sender))``), so it
    is a reach condition with its read (``read(i)`` for the ``i``-th), not an open path.
    """
    state = [_is_business_state_tree(child) for child in children]
    if all(state) or not any(state):
        return children
    out: list[PredicateTree] = []
    for index, (child, is_state) in enumerate(zip(children, state)):
        if not is_state:
            out.append(child)
            continue
        expression = read(index)
        child = _with_reach_read(child, expression, holds, reach_only=False)
        child = deepcopy(child) if expression is None or expression.get("type") != "bool" else child
        _mark_reach_leaves(child)
        out.append(child)
    return out


def _mark_reach_leaves(tree: PredicateTree) -> None:
    leaf = tree.get("leaf")
    if leaf is not None:
        mark_reach_condition(leaf)
    for child in tree.get("children") or []:
        _mark_reach_leaves(child)


def _unread_above(entry: Any, chain: list[Any]) -> str | None:
    """Why reach can't be read for one run of the frame ``chain`` leads into from ``entry``: a call on the way in isn't
    located in its caller, or a frame on the way runs a body more than once, or a call on the way may run more than
    once.
    """
    frames = [entry, *(getattr(call, "function", None) for call in chain)]
    reasons = {call_site_unread(frames[level], call) for level, call in enumerate(chain)}
    if "gate_location_not_determined" in reasons:
        return "gate_location_not_determined"
    if "body_runs_repeatedly" in reasons or any(frame is not None and runs_body_repeatedly(frame) for frame in frames):
        return "body_runs_repeatedly"
    return None


def _restamp_scope(tree: PredicateTree, gate: RevertGate, function: Any) -> None:
    leaf = tree.get("leaf")
    if leaf is not None:
        leaf["source_function"] = (gate.containing_function or function).canonical_name
        leaf["source_node_id"] = gate.node.node_id
    for child in tree.get("children") or []:
        _restamp_scope(child, gate, function)


def _stamp_gate_scope(tree: PredicateTree, gate: RevertGate, function: Any) -> None:
    leaf = tree.get("leaf")
    if leaf is not None and "source_function" not in leaf:
        leaf["source_function"] = (gate.containing_function or function).canonical_name
        leaf["source_node_id"] = gate.node.node_id
        owner = gate.containing_function or function
        summary = evidence_for(owner.contract).summary(owner)
        leaf["structural_predicate"] = {
            "polarity": gate.polarity,
            "value": summary.expression(gate.condition_value),
        }
    for child in tree.get("children") or []:
        _stamp_gate_scope(child, gate, function)


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
    tree = _helper_value_tree(function, prov, base_gate, [], function)
    if tree is None:
        return None
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
            values = [defining_ir.variable_left, defining_ir.variable_right]
            children = [_build_subtree_from_value(value, prov, gate, function) for value in values]
            # If-revert polarity flips AND/OR (De Morgan).
            if (op_name == "or") == (gate.polarity == "allowed_when_true"):
                holds = gate.polarity == "allowed_when_true"
                children = _state_disjuncts_as_reach(
                    children, lambda index: _disjunct_read(values[index], gate, function), holds
                )
                return make_or_node(children)
            return make_and_node(children)

    # A helper whose return is AND/OR (Solmate Auth, DSAuth, Maker ``wish``, USDT): recurse into its bindings so it
    # doesn't bottom out as unsupported business.
    if isinstance(defining_ir, (InternalCall, LibraryCall)):
        subtree, holds_gates = _build_internal_call_or_and_subtree(defining_ir, prov, gate)
        # The helper's revert gates are conjuncts at this call site, inside any enclosing OR branch.
        gate_subtrees = [] if holds_gates else _internal_call_revert_gate_subtrees(defining_ir, prov, gate)
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


_return_helper_stack: _contextvars.ContextVar[tuple[int, ...]] = _contextvars.ContextVar(
    "predicate_return_helper_stack", default=()
)


def _recursive_return_unknown(gate: RevertGate) -> LeafPredicate:
    leaf = _unsupported_leaf("internal_return_recursion_limit", gate.expression_text)
    leaf["authority_proof"] = {"state": "not_determined", "requirements": ["internal_return_recursion_limit"]}
    return leaf


def _build_internal_call_leaf(
    ir: Any, prov: ProvenanceMap, gate: RevertGate, function: Any | None
) -> LeafPredicate | None:
    key = id(getattr(ir, "function", ir))
    stack = _return_helper_stack.get()
    if key in stack or len(stack) >= 32:
        return _recursive_return_unknown(gate)
    token = _return_helper_stack.set((*stack, key))
    try:
        return _expand_internal_call_leaf(ir, prov, gate, function)
    finally:
        _return_helper_stack.reset(token)


def _expand_internal_call_leaf(
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


def _build_internal_call_or_and_subtree(
    ir: Any, prov: ProvenanceMap, gate: RevertGate
) -> tuple[PredicateTree | None, bool]:
    key = id(getattr(ir, "function", ir))
    stack = _return_helper_stack.get()
    if key in stack or len(stack) >= 32:
        return (make_leaf_node(_recursive_return_unknown(gate)), False)
    token = _return_helper_stack.set((*stack, key))
    try:
        return _expand_internal_call_or_and_subtree(ir, prov, gate)
    finally:
        _return_helper_stack.reset(token)


def _expand_internal_call_or_and_subtree(
    ir: Any, prov: ProvenanceMap, gate: RevertGate
) -> tuple[PredicateTree | None, bool]:
    """An AND/OR subtree for a helper whose return is a connective (Solmate ``isAuthorized``, DSAuth, Maker ``wish``,
    USDT), which ``_build_binary_leaf`` can't handle.

    Shapes: a direct Binary AND/OR return; a return of an assembly combinator call (Maker ``return either(...)``); the
    helper itself being an assembly ``or``/``and`` combinator (below Slither's IR, so detected structurally with the
    call-site args as children); and any helper with several returns or a non-connective one, read path by path (see
    ``_helper_value_tree``). The flag says the subtree already holds the helper's own revert gates.
    """
    resolved = _resolve_internal_call_return(ir, prov)
    if resolved is None:
        return None, False
    callee, sub_prov, _return_value, inner = resolved
    if len(_helper_exits(callee)) > 1:
        # The shapes below read the first return only.
        return _helper_return_paths_subtree(ir, prov, callee, sub_prov, gate), True
    op_name: str | None = None
    children: list[PredicateTree] = []
    # Values read in the callee's frame are reached through this call, so helpers they call see the full chain.
    inside = replace(gate, call_chain=[*(gate.call_chain or []), ir])
    if isinstance(inner, Binary):
        op_name = _binary_op(getattr(inner, "type", None))
        if op_name not in ("and", "or"):
            return None, False
        left = inner.variable_left
        right = inner.variable_right
        if left is None or right is None:
            return None, False
        children = [
            _build_subtree_from_value(left, sub_prov, inside, callee),
            _build_subtree_from_value(right, sub_prov, inside, callee),
        ]
        if (op_name == "or") == (gate.polarity == "allowed_when_true"):
            node = getattr(inner, "node", None)
            values = (left, right)
            children = _state_disjuncts_as_reach(
                children,
                lambda index: _disjunct_read(values[index], inside, callee, node),
                gate.polarity == "allowed_when_true",
            )
    elif isinstance(inner, (InternalCall, LibraryCall)):
        # The return is itself an assembly combinator call; its args are the children.
        inner_callee = getattr(inner, "function", None)
        asm_op = _detect_assembly_combinator_op(inner_callee) if inner_callee else None
        if asm_op is None:
            # Keep the nested helper's complete return paths and bound frame;
            # classifying only its first return can turn an owner gate into a
            # literal business condition.
            subtree = _build_subtree_from_value(_return_value, sub_prov, inside, callee)
            return _attach_call_site_arg_origins_to_tree(subtree, ir, prov), False
        op_name = asm_op
        call_args = list(getattr(inner, "arguments", []) or [])
        if not call_args:
            return None, False
        children = [_build_subtree_from_value(arg, sub_prov, inside, callee) for arg in call_args]
    else:
        # The helper is the assembly combinator; the call-site args are the children.
        asm_op = _detect_assembly_combinator_op(callee)
        if asm_op is None:
            return _helper_return_paths_subtree(ir, prov, callee, sub_prov, gate), True
        op_name = asm_op
        call_args = list(getattr(ir, "arguments", []) or [])
        if not call_args:
            return None, False
        children = [_build_subtree_from_value(arg, prov, gate, gate.containing_function or callee) for arg in call_args]
    if op_name is None or not children:
        return None, False
    # Re-attach call-site argument origins lost in the callee's frame.
    children = [_attach_call_site_arg_origins_to_tree(child, ir, prov) for child in children]
    if gate.polarity == "allowed_when_true":
        return (make_and_node(children) if op_name == "and" else make_or_node(children)), False
    return (make_or_node(children) if op_name == "and" else make_and_node(children)), False


def _helper_return_paths_subtree(
    ir: Any, prov: ProvenanceMap, callee: Any, sub_prov: ProvenanceMap, gate: RevertGate
) -> PredicateTree:
    entry, chain = _entry_and_chain(gate, callee)
    tree = _helper_value_tree(callee, sub_prov, gate, [*chain, ir], entry)
    if tree is None:
        return make_leaf_node(_unsupported_leaf(reason=_HELPER_NEVER_RETURNS, expression=gate.expression_text))
    return _attach_call_site_arg_origins_to_tree(tree, ir, prov)


def _entry_and_chain(gate: RevertGate, fallback: Any) -> tuple[Any, list[Any]]:
    """The entry point a gate was reached from and the calls leading to its frame."""
    chain = list(gate.call_chain or [])
    head = getattr(getattr(chain[0], "node", None), "function", None) if chain else None
    return (head if head is not None else gate.containing_function or fallback), chain


def _helper_value_tree(
    callee: Any, sub_prov: ProvenanceMap, gate: RevertGate, chain: list[Any], entry: Any
) -> PredicateTree | None:
    """When a bool helper, entered through ``chain``, returns the value ``gate`` allows on (``true`` under
    ``allowed_when_true``, ``false`` under a negated call), or ``None`` when no return yields it.

    Every explicit revert gate in the helper is a conjunct where it's reached. Each return that can yield the value
    contributes its path condition, read from the helper's control dependence (loops and ``try`` outcomes not
    determined), ANDed with its value when that isn't a literal. A branch whose true side only returns the wanted value
    is its own alternative, so the paths past its false side don't repeat its negation. Falling off the end returns
    the default ``false``. A wanted literal reached unconditionally with no gate to state, or an unproven call before a
    path whose condition opens cofinite, is ``unsupported``.
    """
    wanted = "True" if gate.polarity == "allowed_when_true" else "False"
    unread = "body_runs_repeatedly" if runs_body_repeatedly(callee) else _unread_above(entry, chain)
    if unread is not None:
        return make_leaf_node(_unsupported_leaf(unread, gate.expression_text))
    gates = _helper_gate_subtrees(callee, sub_prov, chain, entry, caller_tainted_only=False)
    cfg_nodes = list(getattr(callee, "nodes", []) or [])
    assume = frozenset(
        ("branch", node.node_id, False)
        for node in cfg_nodes
        if _node_is_if(node) and _branch_value_is_only(getattr(node, "son_true", None), wanted)
    )
    unclassified = [_forward_reachable_node_ids(node) for node in cfg_nodes if _node_has_unclassified_call(node)]
    builder = _branch_tree_builder(callee, sub_prov, entry, chain, basis=list(gate.basis))
    paths: list[PredicateTree] = []
    always = False
    for node, value in _helper_exits(callee):
        literal = "False" if value is None else str(getattr(value, "value", value))
        literal = literal if literal in ("True", "False") else None
        if literal is not None and literal != wanted:
            continue
        formula = reached_formula(callee, node, assume)
        path = None if formula == REACHED_ALWAYS else render(formula, callee, builder)
        if formula != REACHED_ALWAYS and path is None:
            continue
        if path is not None and _guards_contain_opening([path]) and any(id(node) in r for r in unclassified):
            paths.append(
                make_leaf_node(
                    _unsupported_leaf(
                        reason=f"unattributable_return_{(literal or 'value').lower()}",
                        expression=f"literal {(literal or 'value').lower()}",
                    )
                )
            )
            continue
        parts = [path] if path is not None else []
        if literal is None:
            value_gate = RevertGate(
                kind=gate.kind,
                condition_value=value,
                polarity=gate.polarity,
                node=node,
                containing_function=callee,
                call_chain=list(chain),
                expression_text=f"return {value}",
                basis=list(gate.basis),
            )
            parts.append(_build_subtree_from_value(value, sub_prov, value_gate, callee))
        if not parts:
            always = True
            continue
        paths.append(make_and_node(parts))
    if not paths and not always:
        return None
    if always:
        if not gates:
            return make_leaf_node(
                _unsupported_leaf(
                    reason=f"unattributable_return_{wanted.lower()}", expression=f"literal {wanted.lower()}"
                )
            )
        return make_and_node(gates)
    if len(paths) > 1:
        paths = _state_disjuncts_as_reach(paths, lambda _index: None, True)
    for path in paths:
        _drop_unmarked_reads(path)
    value = make_or_node(paths)
    return make_and_node([*gates, *(value.get("children") or [] if value.get("op") == "AND" else [value])])


def _drop_unmarked_reads(tree: PredicateTree) -> None:
    """A helper path's outcome reads are kept only where the outcome became a reach condition."""
    leaf = tree.get("leaf")
    if leaf is not None and not is_reach_condition(leaf):
        leaf.pop(REACH_READ, None)
    for child in tree.get("children") or []:
        _drop_unmarked_reads(child)


def _disjunct_read(value: Any, gate: RevertGate, function: Any, node: Any = None) -> dict[str, Any] | None:
    """``value``, one side of a connective at ``node`` (the gate's own by default), as a read, when nothing the call
    writes before it can change it.
    """
    entry, chain = _entry_and_chain(gate, function)
    frame = getattr(chain[-1], "function", None) if chain else entry
    node = node if node is not None else gate.node
    if node is None or frame is not function:
        return None
    written, writes_other = effect_before(entry, chain, frame, node)
    if (written or writes_other) and reads_conflict(value_reads(entry, chain, frame, value), (written, writes_other)):
        return None
    return reach_read(value, entry, chain)


# Explicit conditional reverts only: opaque fail-safes would add ``unsupported`` leaves, and external-call/try-catch
# markers fire on any call, manufacturing gates.
_INLINED_GATE_KINDS = ("require", "assert", "if_revert", "custom_revert")


def _internal_call_revert_gate_subtrees(ir: Any, prov: ProvenanceMap, gate: RevertGate) -> list[PredicateTree]:
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
    entry, chain = _entry_and_chain(gate, callee)
    return _helper_gate_subtrees(callee, sub_prov, [*chain, ir], entry, caller_tainted_only=True)


def _helper_gate_subtrees(
    callee: Any, sub_prov: ProvenanceMap, chain: list[Any], entry: Any, *, caller_tainted_only: bool
) -> list[PredicateTree]:
    """``callee``'s explicit revert gates, each as an alternative to where it isn't reached, built with ``callee``'s
    bound provenance; ``chain`` leads from ``entry`` to ``callee``.
    """
    callee_id = id(callee)
    stack = _inline_gate_callee_stack.get()
    if callee_id in stack or len(stack) >= DEFAULT_INTERNAL_CALL_DEPTH:
        return []
    try:
        inner_gates = [g for g in _revert_gates(callee) if g.kind in _INLINED_GATE_KINDS]
    except Exception:
        return []
    if not inner_gates:
        return []

    token = _inline_gate_callee_stack.set(stack + (callee_id,))
    try:
        subtrees: list[PredicateTree] = []
        for inner_gate in inner_gates:
            frame = inner_gate.containing_function or callee
            frame_prov: ProvenanceMap | None = sub_prov
            if inner_gate.call_chain:
                _, frame_prov, chain_end = _build_chain_bindings(
                    inner_gate.call_chain, frame, callee, top_prov=sub_prov
                )
                if chain_end is not frame:
                    frame_prov = None
            if inner_gate.condition_value is None or frame_prov is None:
                subtree = make_leaf_node(_unsupported_leaf("missing_condition", inner_gate.expression_text))
            else:
                # Built with the chain from the entry point, so helpers it reads see the writes made on the way in.
                rebased = replace(inner_gate, call_chain=[*chain, *inner_gate.call_chain])
                subtree = _build_subtree_from_value(inner_gate.condition_value, frame_prov, rebased, frame)
            if caller_tainted_only and not _tree_has_caller_tainted_leaf(subtree):
                continue
            subtree = _where_reached(subtree, inner_gate, sub_prov, callee, outer=(entry, chain))
            _tag_tree_leaves_basis(subtree, f"inlined_internal_gate:{_callee_label(callee)}")
            subtrees.append(subtree)
        return subtrees
    finally:
        _inline_gate_callee_stack.reset(token)


def _revert_gates(function: Any) -> list[RevertGate]:
    """``RevertDetector(function).run()``, shared within a contract pass."""
    cache = _helper_gate_cache.get()
    hit = cache.get(id(function)) if cache is not None else None
    if hit is not None:
        return hit[1]
    gates = RevertDetector(function).run()
    if cache is not None:
        cache[id(function)] = (function, gates)
    return gates


def _callee_label(callee: Any) -> str:
    return str(getattr(callee, "canonical_name", None) or getattr(callee, "full_name", None) or callee)


def _tree_has_caller_tainted_leaf(tree: Any) -> bool:
    """Whether any leaf's post-binding operand or key sources derive from the caller (as the evaluator's
    earned-public default decides).
    """
    if not isinstance(tree, dict):
        return False
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf") or {}
        if (
            has_unknown_predicate_provenance(leaf)
            or (leaf.get("authority_proof") or {}).get("state") == "not_determined"
        ):
            return True
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
