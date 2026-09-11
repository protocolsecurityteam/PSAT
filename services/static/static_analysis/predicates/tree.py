"""The mutually-recursive predicate-tree core: ``build_predicate_tree`` /
``build_return_predicate_tree`` entry points, recursive subtree builders,
per-gate leaf dispatch, and inlined helper revert gates."""

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

# ---------------------------------------------------------------------------
# Helper-engine cache (perf optimization for cross-fn build path)
# ---------------------------------------------------------------------------
#
# When ``build_predicate_artifacts`` walks every function on a
# contract, the same helper (e.g. ``_checkRole(role)``) often
# appears on the call_chain of multiple functions (grantRole /
# revokeRole / renounceRole all funnel through it). Each
# ``_build_chain_bindings`` invocation re-runs ProvenanceEngine on
# every helper in its chain — work that's pure repetition when
# the (callee, parameter_bindings) tuple matches a previous call.
#
# This contextvar holds an optional dict mapping
# ``(callee_id, bindings_signature)`` → ``ProvenanceMap``. The
# artifact builder sets it on entry and clears on exit; tests
# calling ``build_predicate_tree`` directly see ``None`` and run
# the engine as before (correctness is identical either way; the
# cache is a pure perf optimization).
_helper_engine_cache: _contextvars.ContextVar[dict | None] = _contextvars.ContextVar(
    "psat_predicate_helper_engine_cache", default=None
)

# Callee full_names currently being gate-inlined by
# ``_internal_call_revert_gate_subtrees`` — breaks mutual-recursion cycles
# and bounds the inlining depth (a helper's gate can itself be
# ``require(deeper_helper(...))``, which re-enters the same path).
_inline_gate_callee_stack: _contextvars.ContextVar[tuple[str, ...]] = _contextvars.ContextVar(
    "psat_predicate_inline_gate_callee_stack", default=()
)


def _inline_helper_revert_gates_enabled() -> bool:
    """Conjoin an inlined bool-helper's internal revert gates into the
    caller's tree (caller-tainted gates only). ON by default;
    ``PSAT_INLINE_HELPER_REVERT_GATES=0`` is the kill-switch back to
    return-expression-only inlining."""
    return os.getenv("PSAT_INLINE_HELPER_REVERT_GATES", "1").lower() in ("1", "true", "yes")


def _cache_key_for(callee: Any, bindings: dict[str, Any]) -> tuple | None:
    """Build a stable hashable key from a callee + parameter
    bindings. Returns None if any element isn't hashable —
    cache misses on unusual bindings rather than crashing."""
    try:
        callee_id = getattr(callee, "full_name", None) or getattr(callee, "name", None)
        if callee_id is None:
            return None
        # Bindings values are frozenset[Source] (Source is a
        # frozen dataclass) — hashable. Sort by name for
        # determinism.
        items = tuple((name, bindings[name]) for name in sorted(bindings))
        hash(items)
        return (callee_id, items)
    except Exception:
        return None


def build_predicate_tree(function: Any, *, uncertain_out: set[str] | None = None) -> PredicateTree | None:
    """Construct a PredicateTree for one function. Returns None if
    the function has no revert paths.

    ``uncertain_out`` (optional): when the function has gates but produces NO
    tree, and at least one of those un-modeled gates is a direct caller
    (``msg.sender``/``tx.origin``) EQ/NEQ comparison — a caller-authority guard
    shape the builder could not lower into a leaf — the function's ``full_name``
    is added to this set. This is the NARROW ``guard_extraction_uncertain``
    marker: a tree-less function carrying such a marker is a missed access
    guard, NOT a genuinely-public function, so the policy must not default it to
    public. Value comparisons (``require(amt>0)``) and mapping-index reads
    (``balances[msg.sender]>=x``) are excluded by construction."""
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
    """True iff the gate's IF-condition is a direct ``msg.sender``/``tx.origin``
    EQ/NEQ comparison against a non-constant operand.

    This is the discriminating shape for a caller-authority guard the builder
    failed to model (e.g. a struct-member compare ``msg.sender == cfg.admin``
    whose operand provenance didn't resolve to a clean leaf). It deliberately
    excludes: non-IF/non-Binary gate conditions (require value checks, external
    call-success, inline-asm), order comparisons (``>=``/``<`` thresholds), and
    caller-vs-constant checks (``msg.sender != address(0)``) — none of which are
    access gates, keeping the marker false-positive-free on public surfaces."""
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
    """Construct a PredicateTree from a bool-returning function's
    return expression.

    Guarded entrypoints are modeled from revert paths. External
    authority providers such as ``canCall(user,target,selector)`` often
    do not revert; they return the authorization predicate as ``bool``.
    These trees are stored as resolver-only check trees so recursive
    external-call evaluation has semantic material to inline without
    listing read-only check methods as protected functions.
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
    """Like ``_build_leaf_from_gate``, but returns a PredicateTree
    so binary ``&&`` / ``||`` at the gate's condition can split into
    AND/OR tree nodes instead of collapsing into a single
    ``unsupported`` leaf.

    When the gate's ``containing_function`` is a helper called from
    the function/modifier (cross-fn revert), use the helper as the
    operating context for defining-IR lookup and provenance — the
    condition's SSA values live in the helper's scope, not the
    top-level function's.
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

    # If gate is in a cross-fn helper, walk the call chain to build
    # parameter bindings for the helper, then run provenance on the
    # helper with those bindings — a full caller-side ParameterBindingEnv.
    operating_fn = gate.containing_function or function
    if operating_fn is not function:
        # Pass the caller's already-computed provenance down so
        # _build_chain_bindings doesn't re-run the top-function
        # engine. Walk also returns the final hop's provenance —
        # if the chain ENDS at operating_fn (the common case), we
        # can use that prov directly and skip the helper_engine
        # rebuild. Saves ~6-10ms per cross-fn gate.
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
    """Walk the call chain forward to build parameter bindings for
    the helper's scope. Each link is an InternalCall (or
    modifier-call InternalCall) IR taken to enter the next callee.

    For a multi-hop helper case:
      chain = [
        modifier_call to gate(resolveKey(input)),
        InternalCall to _check(key),
        InternalCall to _checkAddress(key, _msgSender()),
      ]
    The walk binds:
      gate.key          ← resolveKey(caller_arg) (view_call source)
      _check.key        ← gate.key (chained)
      _checkAddress.key ← _check.key
      _checkRoleAddr.account ← _msgSender() return = msg_sender source

    Then the helper's engine seeds parameters with these provenance
    sets, so a leaf inside the helper that reads ``account`` resolves
    to msg.sender taint, and Rule B (multi-key with caller key)
    promotes to caller_authority.
    """
    if not call_chain:
        return {}, top_prov, top_function
    # Start from the top function's provenance. Reuse the
    # caller-provided prov when available — build_predicate_tree
    # has already run ProvenanceEngine on top_function, so a
    # second walk is pure overhead. The fallback path keeps the
    # function self-contained for direct test calls.
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

        # Cache hit: skip the engine.run() for this callee +
        # bindings. The cache is scoped to one
        # build_predicate_artifacts call (set/reset by that
        # entry point); tests that call build_predicate_tree
        # directly see no cache and run the engine as before.
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
    """Resolve a Slither IR value's provenance (frozenset[Source])
    in the given map. Same SSA-suffix fallback as the engine's
    ``_sources_for_value`` so seeded base names match SSA-versioned
    references."""
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
    """Walk back from ``cond_value`` to its defining IR. If the IR
    is a Binary with type ANDAND / OROR, split into a subtree
    recursively. Otherwise build a single LeafPredicate."""
    defining_ir = _find_defining_ir(cond_value, gate.node, function)
    if defining_ir is None:
        leaf = _build_truthy_leaf(cond_value, prov, gate)
        return make_leaf_node(leaf)

    # Unary NOT wrapping a Binary AND / OR — flip polarity and
    # recurse on the inner. _build_unary_leaf only produces a single
    # leaf, so without this branch ``require(!(A && B))`` falls
    # through to a single bare-bool leaf with operands=[] (USDT.approve
    # was the case found empirically). De Morgan handling for the
    # AND/OR connective is already wired into the polarity-aware
    # branch below.
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
            # Apply if-revert polarity flip at the AND/OR level too:
            # `if (A || B) revert` means allowed iff !A && !B (De
            # Morgan). For now, polarity is propagated to leaves via
            # _build_leaf_from_gate; AND/OR composition uses the
            # source-level connective.
            if gate.polarity == "allowed_when_true":
                return make_and_node(children) if op_name == "and" else make_or_node(children)
            # if-revert polarity flips AND ↔ OR via De Morgan.
            return make_or_node(children) if op_name == "and" else make_and_node(children)

    # Cross-fn helper with Binary AND/OR in the return value. Without
    # this branch the helper bottoms out as ``unsupported_reason=
    # binary_op_{or,and}_unsupported`` and the function falls through
    # to authority_role=business — a real classification gap on every
    # Solmate Auth / DSAuth contract (BoringVault.manage, MKR DSToken,
    # Maker Vat's wish() guarded methods, USDT.approve, etc).
    # The helper's return-defining IR is a Binary AND/OR: recurse into
    # the helper's bindings + sub-engine, then build the AND/OR
    # subtree from each side. Polarity propagates the same way as
    # the inline AND/OR case above.
    if isinstance(defining_ir, (InternalCall, LibraryCall)):
        subtree = _build_internal_call_or_and_subtree(defining_ir, prov, gate)
        # The helper's internal require/revert gates are conjuncts of this
        # call site whatever shape its return expression takes — see
        # _internal_call_revert_gate_subtrees. Conjoining HERE (not at the
        # tree root) keeps an OR-branch helper's gates scoped to the branch
        # that executes it.
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
        # Defining IR isn't one we have a typed builder for (Assignment,
        # TypeConversion, Phi, etc.). The condition still gates an
        # if-revert / require, so it MUST be bool-typed. Fall back to
        # the bare-bool truthy/falsy leaf — operand resolution walks
        # the value's provenance and picks up the underlying state var
        # / parameter / signature_recovery source. Pause/reentrancy
        # passes can then promote business -> pause/reentrancy when
        # the operand reads a recognized guard var. The cross-function
        # pause shape (``_requireNotPaused`` calling
        # ``if (_paused) revert``) hits this path.
        return make_leaf_node(_self_gate_or_truthy_leaf(cond_value, prov, gate, function))
    return make_leaf_node(leaf)


# ---------------------------------------------------------------------------
# Leaf construction per gate
# ---------------------------------------------------------------------------


def _build_leaf_from_gate(
    gate: RevertGate,
    prov: ProvenanceMap,
    function: Any,
) -> LeafPredicate | None:
    """Walk back from the gate's condition value to its defining IR
    and produce a typed LeafPredicate. The operator captures the
    original-source polarity AND the if-revert flip, so by the time
    this returns the polarity is fully baked into the operator (no
    NOT survives downstream).
    """
    if gate.kind == "opaque":
        return _unsupported_leaf(
            reason=gate.unsupported_reason or "opaque_control_flow", expression=gate.expression_text
        )

    cond = gate.condition_value
    if cond is None:
        return _unsupported_leaf(reason="missing_condition", expression=gate.expression_text)

    # Walk back to find the defining IR for the condition.
    defining_ir = _find_defining_ir(cond, gate.node, function)
    if defining_ir is None:
        # The condition is a bare value (parameter / state-var read /
        # constant). For ``require(boolFlag)`` or
        # ``require(_blacklist[msg.sender] == false)`` this is the
        # case — the leaf is a truthy/falsy check on the value.
        return _build_truthy_leaf(cond, prov, gate)

    leaf = _classify_leaf_from_ir(defining_ir, prov, gate, function)
    if leaf is None:
        # Phi / Assignment defining IRs forward bare values; build a
        # truthy/falsy leaf from the original condition. This covers
        # ``require(!flag)`` where flag is a bool state var read
        # directly through a Phi.
        return _self_gate_or_truthy_leaf(cond, prov, gate, function)
    return leaf


def _classify_leaf_from_ir(
    defining_ir: Any,
    prov: ProvenanceMap,
    gate: RevertGate,
    function: Any | None = None,
) -> LeafPredicate | None:
    """Dispatch on the defining IR class to build a LeafPredicate."""
    if isinstance(defining_ir, Binary):
        return _build_binary_leaf(defining_ir, prov, gate, function)
    if isinstance(defining_ir, Unary):
        return _build_unary_leaf(defining_ir, prov, gate, function)
    if isinstance(defining_ir, Index):
        # Direct mapping membership: ``require(map[k][m])`` — the
        # condition value is the Index lvalue, classified as a
        # truthy/falsy membership leaf.
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
    """The condition is the lvalue of an InternalCall returning a
    bool — e.g. ``if (!check(role, account)) revert``. Recurse into
    the callee's body, bind parameters from caller-site arg
    provenance, and reclassify on the return-value's defining IR.

    This unfolds extra hops past the cross-fn revert chain: the gate
    lives in the helper that *contains* the revert, but the bool
    actually being negated may itself come from a deeper helper."""
    resolved = _resolve_internal_call_return(ir, prov)
    if resolved is None:
        return None
    callee, sub_prov, return_value, inner = resolved
    if inner is None:
        # The callee's return is not lowerable to a typed leaf (a named return
        # assigned inside ``assembly`` — Solady ``EnumerableRoles``). The leaf
        # is built in the CALLEE's frame, where the caller the CALL SITE passed
        # in is not represented at all, which is how the caller vanishes.
        # Re-attach the call-site argument origins so the caller-taint
        # default can see them.
        leaf = _build_truthy_leaf(return_value, sub_prov, gate)
        return _attach_call_site_arg_origins(leaf, ir, prov)
    return _classify_leaf_from_ir(inner, sub_prov, gate, callee)


def _call_site_arg_origins(ir: Any, caller_prov: ProvenanceMap) -> set[Source]:
    """Flattened origins of an internal call's arguments, read in the CALLER's
    frame. Members carry ``derived_from=None`` (``arg_origins`` strips them),
    so nesting stays bounded at one level."""
    origins: set[Source] = set()
    for arg in getattr(ir, "arguments", ()) or ():
        origins.update(arg_origins(_operand_value_provenance(arg, caller_prov)))
    return origins


def _attach_call_site_arg_origins_to_tree(tree: PredicateTree, ir: Any, caller_prov: ProvenanceMap) -> PredicateTree:
    """``_attach_call_site_arg_origins`` over every leaf of a subtree built in
    the callee's frame."""
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
    """Union the CALL-SITE argument origins into the leaf's operand
    ``derived_from``.

    Only touches operands that already publish ``derived_from`` (``computed`` /
    ``view_call`` / ``external_call``), so it neither invents the field on an
    operand where absence means "does not apply" nor changes an operand's
    identity — a state-var attribution stays a state-var attribution. Sorted
    by the published key for cross-process determinism.

    ``references_msg_sender`` is deliberately NOT set: the caller reached the
    gate through a call argument, not as a direct operand, and the static flag
    is read as the latter.
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
    """If the helper's return-defining IR is a Binary AND/OR,
    recursively build an AND/OR subtree where each child is itself
    walked through ``_build_subtree_from_value`` (so deeper
    AND/OR / typed-leaf classification all kicks in per side).

    This closes the gap on real-world auth helpers that returned a
    Binary OR/AND result (Solmate Auth.isAuthorized, DSAuth.is-
    Authorized, Maker Vat's wish, USDT's allowance check, etc) —
    previously ``_classify_leaf_from_ir`` saw a Binary with op_name
    ``and`` / ``or``, ``_build_binary_leaf`` only handles comparison
    ops, so the function fell through to ``authority_role=business``.

    Two paths:

    1. Direct Binary OR/AND in the helper's return IR — walk each
       side as its own subtree.
    2. Inline-assembly logical combinator (Maker's ``either`` /
       ``both``) where the helper body is just ``assembly { z := or
       (x, y) }`` or ``and(x, y)``. Slither doesn't expose these as
       Binary IRs (the assembly is below the IR level), so the inner
       defining IR comes back as None. Detect the shape structurally:
       a function whose body is ASSEMBLY-only and whose ``inline_asm``
       text starts with ``or(`` or ``and(``. Walk the call-site args
       as the children of the OR/AND tree (they're the bool inputs
       to the assembly combinator).
    """
    resolved = _resolve_internal_call_return(ir, prov)
    if resolved is None:
        return None
    callee, sub_prov, _return_value, inner = resolved
    op_name: str | None = None
    children: list[PredicateTree] = []
    if isinstance(inner, Binary):
        # Path 1: helper returns Binary AND/OR directly.
        op_name = _binary_op(getattr(inner, "type", None))
        if op_name not in ("and", "or"):
            return None
        # Slither types these as Optional but a well-formed Binary IR has both
        # operands present; if one is missing the helper isn't recognizable.
        left = inner.variable_left
        right = inner.variable_right
        if left is None or right is None:
            return None
        children = [
            _build_subtree_from_value(left, sub_prov, gate, callee),
            _build_subtree_from_value(right, sub_prov, gate, callee),
        ]
    elif isinstance(inner, (InternalCall, LibraryCall)):
        # Path 3: helper returns ``return combinator(a, b)`` where
        # ``combinator`` is itself an assembly OR/AND helper. Maker's
        # ``wish`` does this: ``return either(bit == usr,
        # can[bit][usr] == 1)``. Detect by looking at the inner-call's
        # callee for the assembly-combinator shape, and use the inner-
        # call's ARGS (resolved through the outer helper's sub_prov)
        # as the children.
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
        # Path 2: helper IS the assembly OR/AND combinator (Maker's
        # ``either`` / ``both``). Slither doesn't expose the assembly
        # OR/AND as Binary IR (it lives below the IR layer), so the
        # inner defining IR comes back as None or some non-classifying
        # shape. Detect structurally: helper's body has an ASSEMBLY
        # node whose inline_asm reduces to ``or(...)`` / ``and(...)``.
        # Walk the call-site args as the children.
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
            # Path 4: helper is an if-else chain returning bool
            # literals + a tail bool expression:
            #
            #   if (src == this)        return true;
            #   else if (src == owner)  return true;
            #   else if (auth == 0)     return false;
            #   else                    return auth.check(...);
            #
            # The function's effective bool semantics is OR of
            # (path-condition for each return-true / return-expr
            # path). We approximate by collecting per-Return:
            #   - return literal-true → use the closest dominating
            #     IF's condition as the OR branch
            #   - return bool-expr   → walk the expression as a
            #     subtree (ignoring the negated-prefix for now —
            #     accuracy can be increased by collecting the full
            #     dominator chain in a follow-up)
            #   - return literal-false → skip (denied path)
            children = _build_if_else_returns_or_children(callee, sub_prov, gate)
            if children:
                op_name = "or"
        if op_name is None or not children:
            return None
    if op_name is None or not children:
        return None
    # Every child above was built in the CALLEE's frame, where the caller the
    # call site passed in has no representation — that is where it is lost.
    # Re-attach the call-site argument origins onto the children's collapsing
    # operands so the caller-taint default can see them.
    children = [_attach_call_site_arg_origins_to_tree(child, ir, prov) for child in children]
    # Polarity propagates the same way as the inline AND/OR case in
    # _build_subtree_from_value's main path.
    if gate.polarity == "allowed_when_true":
        return make_and_node(children) if op_name == "and" else make_or_node(children)
    return make_or_node(children) if op_name == "and" else make_and_node(children)


# Internal revert forms worth conjoining at an inlined call site: the
# explicit conditional gates. Opaque fail-safes would conjoin
# ``unsupported`` leaves (gating callers on shapes we didn't lift), and
# external-call/try-catch markers fire on ANY external call in the helper
# — both manufacture gates rather than recover them, so they stay out.
_INLINED_GATE_KINDS = ("require", "assert", "if_revert", "custom_revert")


def _internal_call_revert_gate_subtrees(ir: Any, prov: ProvenanceMap) -> list[PredicateTree]:
    """The inlined helper's own revert gates, rebuilt in the caller's frame.

    ``require(helper(args))`` admits a caller only when the helper RETURNS
    true — and the helper didn't revert on the way to that return. The
    return expression is lifted by ``_build_internal_call_leaf`` /
    ``_build_internal_call_or_and_subtree``; the helper's internal
    ``require``/``revert`` gates were owned by NEITHER side: RevertDetector
    deliberately skips read-result callees ("the predicate builder lifts
    that path") and the builder lifted only the return value. A
    caller-keyed allowlist living inside the helper vanished and the caller
    classified public (EtherFiOracle.submitReport's
    ``shouldSubmitReport(msg.sender)`` committee gate).

    Build one subtree per internal gate with the call arguments bound to
    the helper's parameters (``registered[_member]`` resolves with
    ``_member := msg.sender``). The caller conjoins these AT THE CALL SITE
    in its tree — inside any enclosing OR branch — which preserves
    short-circuit semantics: ``require(a || helper(x))`` becomes
    ``OR(a, AND(helper_gates, helper_return))``, so the helper's gates
    bind only the branch that actually executes it. Call-site polarity
    deliberately does NOT apply: the helper reverts on a failed internal
    gate however the caller uses the returned bool, so each gate keeps its
    own polarity.

    Conservative on purpose — this can only ADD gates, and only ones the
    helper provably enforces:
      * only explicit conditional revert forms (``_INLINED_GATE_KINDS``);
      * only CALLER-TAINTED gates (an operand or membership key derives
        from the caller identity after binding). A business precondition
        can't change the authority verdict, so dropping it preserves
        today's trees instead of risking false-gates on unliftable shapes.
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

    # Bind call-site argument provenance to the callee's parameters — the
    # same binding _resolve_internal_call_return uses for the return
    # expression — through the per-contract helper-engine cache.
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
    """Does any leaf condition the caller's identity? Reads operand and
    membership-key sources (the post-binding signal), not the leaf's
    pre-binding ``references_msg_sender`` flag — mirroring how the
    evaluator's earned-public default decides taint."""
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
    """Stamp ``tag`` onto every leaf's basis so a conjoined helper gate is
    attributable in dumps/diffs."""
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            leaf["basis"] = list(leaf.get("basis") or []) + [tag]
        return
    for child in tree.get("children") or []:
        _tag_tree_leaves_basis(child, tag)
