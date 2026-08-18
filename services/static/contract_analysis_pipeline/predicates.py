"""Predicate builder — produces a ``PredicateTree`` per function.

For each function:
  1. Run ``RevertDetector`` to find all gated revert paths.
  2. Run ``ProvenanceEngine`` to classify every SSA value's source(s).
  3. For each RevertGate, walk the condition value's defining IR back
     to its structural shape (Binary equality, Index membership, Unary
     negation, HighLevelCall returning bool, ecrecover comparison) and
     emit a ``LeafPredicate`` with kind + operator + operands.
  4. Apply polarity normalization: ``if (R) revert`` becomes the leaf
     for the allowed condition (NOT R), with the NOT pushed into the
     leaf's operator (no NOT survives in the tree).
  5. Combine leaves into a tree: multiple sequential gates AND at the
     root.

This module is the main user of ``ProvenanceEngine`` + ``RevertDetector``
and the producer of the semantic ``predicate_tree`` artifact field.

Scope of this initial cut: equality / membership leaves with the
caller_authority detection rules from v6 round-5 #1. external_bool /
signature_auth / comparison / unsupported leaves are added in
follow-ups (this commit lays the scaffold + the two most common kinds).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
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
import contextvars as _contextvars  # noqa: E402
import os
from typing import Any, cast

from eth_utils.crypto import keccak

from .predicate_types import (
    AuthorityRole,
    ComparisonOperator,
    Confidence,
    LeafKind,
    LeafOperator,
    LeafPredicate,
    Operand,
    PredicateTree,
    SetDescriptor,
    ValuePredicate,
    make_and_node,
    make_leaf_node,
    make_or_node,
)
from .provenance import (
    EMPTY,
    TOP,
    ProvenanceEngine,
    ProvenanceMap,
    Source,
    SourceSet,
    arg_origins,
    is_top,
)
from .revert_detect import DEFAULT_INTERNAL_CALL_DEPTH, Polarity, RevertDetector, RevertGate
from .shared import external_bool_leaf_is_gate_shape
from .slither_compat import (
    SLITHER_AVAILABLE,
    Assignment,
    Binary,
    Condition,
    Constant,
    HighLevelCall,
    Index,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Member,
    Phi,
    ReferenceVariable,
    Return,
    Send,
    SolidityCall,
    SolidityVariable,
    StateVariable,
    Transfer,
    Unary,
    UnaryType,
    Unpack,
    Variable,
)

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
    from .provenance import EMPTY, Source, _strip_ssa_suffix

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
        left = inner.variable_left  # type: ignore[union-attr]
        right = inner.variable_right  # type: ignore[union-attr]
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


def _node_is_type(node: Any, type_name: str) -> bool:
    return str(getattr(node, "type", "")) == type_name


def _if_condition_value(if_node: Any) -> Any | None:
    """The IR value an IF node branches on (its Condition IR's value)."""
    for ir in getattr(if_node, "irs_ssa", None) or getattr(if_node, "irs", []) or []:
        if isinstance(ir, Condition):
            return getattr(ir, "value", None)
    return None


def _return_literal(node: Any) -> str | None:
    """``"True"`` / ``"False"`` for a RETURN node returning a bool
    literal, else None (non-literal expression or no return value)."""
    for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
        if isinstance(ir, Return):
            values = getattr(ir, "values", ()) or ()
            if values:
                s = str(getattr(values[0], "value", values[0]))
                return s if s in ("True", "False") else None
    return None


def _is_literal_false(value: Any) -> bool:
    """A boolean ``false`` literal operand (``require(false)`` / ``assert(false)``)."""
    return isinstance(value, Constant) and str(getattr(value, "value", value)) == "False"


# Cross-function recursion bound for ``_callee_always_reverts`` — deep
# enough for real auth-helper nesting, small enough to stay cheap and
# guarantee termination on mutually-recursive callees.
_ALWAYS_REVERTS_MAX_DEPTH = 4


def _node_terminates_control(node: Any, _depth: int = 0) -> bool:
    """True for a node past which structured control never falls through:
    a ``return`` / old-style ``throw``, an unconditional ``revert(...)``, a
    ``require(false)`` / ``assert(false)``, or a call
    (``InternalCall`` / ``LibraryCall`` / ``HighLevelCall``) to a callee
    that provably ALWAYS reverts (``_callee_always_reverts``). Slither keeps
    a structural fall-through ``son`` edge from a revert/throw to the ENDIF
    merge for CFG completeness even though control never continues there — so
    unless these are treated as CFG sinks a branch's deny leaks into the
    sibling's post-join region and the guard is silently dropped. A
    helper-based deny (``if(!auth) _deny();`` where ``_deny`` reverts)
    leaks its guard the exact same way an inline ``revert()`` would, so a
    call to an always-reverting callee must sink too. A
    ``require(cond)`` / ``assert(cond)`` with a non-``false`` condition is NOT
    a terminator: its ``son`` edge is the real happy-path continuation (it is
    picked up separately as a dominating positive guard)."""
    if _node_is_type(node, "NodeType.RETURN") or _node_is_type(node, "NodeType.THROW"):
        return True
    for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
        if isinstance(ir, SolidityCall):
            name = str(getattr(getattr(ir, "function", None), "name", "") or "")
            if name.startswith("revert"):
                return True
            if name.startswith(("require", "assert")):
                args = list(getattr(ir, "arguments", []) or [])
                if args and _is_literal_false(args[0]):
                    return True
        elif _depth < _ALWAYS_REVERTS_MAX_DEPTH and isinstance(ir, (InternalCall, LibraryCall, HighLevelCall)):
            if _callee_always_reverts(getattr(ir, "function", None), _depth=_depth + 1):
                return True
    return False


def _callee_always_reverts(callee: Any, _depth: int = 0) -> bool:
    """True iff EVERY execution path through ``callee`` ends in a
    revert / throw / ``require(false)`` — no ordinary ``RETURN`` (value or
    void) and no normal fall-through leaf is reachable. A call to such a
    callee never returns to its caller, so ``_node_terminates_control``
    treats the call node as a CFG sink, mirroring an inline ``revert(...)``.

    Fail-closed on uncertainty: a callee with no visible body (interface /
    unresolved external) is NOT proven always-reverting and returns False,
    leaving the call as a normal (leaking) edge — the unclassified-mid-body
    -call backstop in ``_build_if_else_returns_or_children`` then fails the
    child closed if that leak would otherwise emit a lone opening.

    Terminators are treated as sinks during the walk for the same reason as
    everywhere else: a branchy all-revert helper
    (``if(x) revert(); else revert();``) keeps a structural ``son`` edge to
    its ENDIF leaf, which must not be mistaken for a normal exit. Bounded and
    cycle-safe against mutual recursion via ``_depth`` (each call hop
    increments it) and a per-callee ``seen`` set (intra-callee loops)."""
    if callee is None or _depth > _ALWAYS_REVERTS_MAX_DEPTH:
        return False
    nodes = list(getattr(callee, "nodes", []) or [])
    if not nodes:
        return False  # no visible body — cannot prove it reverts
    seen: set[int] = set()
    work = [getattr(callee, "entry_point", None) or nodes[0]]
    saw_revert = False
    while work:
        node = work.pop()
        nid = id(node)
        if nid in seen:
            continue
        seen.add(nid)
        if _node_is_type(node, "NodeType.RETURN"):
            return False  # a normal return ⇒ control can reach the caller
        if _node_terminates_control(node, _depth=_depth):
            saw_revert = True  # revert / throw / require(false) sink
            continue
        sons = getattr(node, "sons", []) or []
        if not sons:
            return False  # a non-terminating leaf = a normal fall-through exit
        for son in sons:
            if son is not None:
                work.append(son)
    return saw_revert


def _node_has_unclassified_call(node: Any) -> bool:
    """True for a mid-body statement node (an EXPRESSION or a VARIABLE
    declaration — ``uint x = _f();`` lowers to a VARIABLE node carrying an
    ``InternalCall``) whose call the builder does NOT model: an
    ``InternalCall`` / ``LibraryCall`` / ``HighLevelCall`` / ``LowLevelCall``,
    or a ``SolidityCall`` other than the recognized ``require`` / ``assert`` /
    ``revert`` forms — and which is not itself a proven revert sink
    (``_node_terminates_control``). Such a call could divert control (revert)
    on a path the builder can't see, so if one sits on a path to a
    ``return true`` whose collected guards have already opened cofinite, the
    child fails closed rather than emit the lone public-minus-set opening.
    IF nodes are excluded (a call in the condition is modeled as the IF's
    guard), RETURN nodes are excluded (a ``return expr`` call is its own
    subtree), and proven always-reverting calls are excluded (their edge is
    already cut)."""
    if _node_is_type(node, "NodeType.IF") or _node_is_type(node, "NodeType.RETURN"):
        return False
    if _node_terminates_control(node):
        return False
    for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
        if isinstance(ir, (InternalCall, LibraryCall, HighLevelCall, LowLevelCall)):
            return True
        if isinstance(ir, SolidityCall):
            name = str(getattr(getattr(ir, "function", None), "name", "") or "")
            if not name.startswith(("require", "assert", "revert")):
                return True
    return False


def _forward_reachable_node_ids(start: Any) -> set[int]:
    """``id()``s of CFG nodes reachable from ``start`` via ``node.sons``.
    Control-terminating nodes are sinks: Slither keeps a merge/ENDIF
    successor link on a ``return`` / ``revert`` / ``throw`` for CFG
    completeness, but a value returned (or a deny reverted) inside one branch
    must not leak into a sibling branch's post-join region, so traversal
    stops at any ``_node_terminates_control`` node. ``start`` is included.
    Cycle-safe."""
    seen: set[int] = set()
    if start is None:
        return seen
    work = [start]
    while work:
        node = work.pop()
        nid = id(node)
        if nid in seen:
            continue
        seen.add(nid)
        if _node_terminates_control(node):
            continue
        for son in getattr(node, "sons", []) or []:
            if son is not None and id(son) not in seen:
                work.append(son)
    return seen


def _branch_value_is_only_true(start: Any) -> bool:
    """True iff every terminating outcome reachable from ``start``
    (terminator-as-sink) is a literal ``return true`` and at least one is
    reached — i.e. the branch's bool value is exactly ``{True}`` (an *allow*
    branch). A branch that can reach ``return false``, a non-literal/absent
    return, or a ``revert`` / ``throw`` / ``require(false)`` is NOT ``{True}``
    and is treated as a deny / non-allow branch. Treating the terminators as
    sinks here matters for the same reason as in ``_forward_reachable_node_ids``:
    without it the leaked fall-through edge from a bare ``if(!auth) revert;``
    would misread the revert branch as reaching a downstream ``return true``
    and wrongly classify it as an allow (skipping the guard's negation)."""
    if start is None:
        return False
    seen: set[int] = set()
    work = [start]
    saw_return = False
    while work:
        node = work.pop()
        nid = id(node)
        if nid in seen:
            continue
        seen.add(nid)
        if _node_is_type(node, "NodeType.RETURN"):
            saw_return = True
            if _return_literal(node) != "True":
                return False
            continue
        if _node_terminates_control(node):
            # A non-return terminating outcome (revert / throw / require(false))
            # ⇒ the branch value is not the singleton {True}.
            return False
        for son in getattr(node, "sons", []) or []:
            if son is not None:
                work.append(son)
    return saw_return


def _return_guard_gate(base: RevertGate, cond_value: Any, polarity: Polarity, node: Any, callee: Any) -> RevertGate:
    """A per-guard RevertGate for one path-edge condition of a ``return
    true`` path (an IF condition or a ``require`` argument)."""
    return RevertGate(
        kind=base.kind,
        condition_value=cond_value,
        polarity=polarity,
        node=node,
        containing_function=callee,
        call_chain=list(base.call_chain),
        expression_text=f"return {cond_value}",
        basis=list(base.basis),
    )


def _guards_contain_opening(guards: list[PredicateTree]) -> bool:
    """True iff any leaf under ``guards`` is a cofinite / public-minus
    projection — a ``falsy`` membership or an ``ne`` equality. Such a leaf
    widens toward public downstream, so pairing it with an *unattributable*
    dominating guard must fail closed rather than emit the lone opening."""
    opening = {"falsy", "ne"}
    stack: list[Any] = list(guards)
    while stack:
        tree = stack.pop()
        if not isinstance(tree, dict):
            continue
        if tree.get("op") == "LEAF":
            leaf = tree.get("leaf") or {}
            if leaf.get("operator") in opening:
                return True
        else:
            stack.extend(tree.get("children") or [])
    return False


def _build_if_else_returns_or_children(callee: Any, sub_prov: ProvenanceMap, gate: RevertGate) -> list[PredicateTree]:
    """For a bool-returning helper shaped as an if/else chain of literal
    and expression returns, build OR-children — one per non-``false``
    return path (``return false`` is a denial and contributes nothing).

    For each ``return true`` node the child is the conjunction of the
    path guards that reach it, derived from CFG forward-reachability over
    every IF in the function:

      * reachable from ``IF.son_true`` only → the condition is a positive
        guard on this path → AND it (``allowed_when_true``).
      * reachable from ``IF.son_false`` only → the else / fall-through:
          - if ``IF.son_true``'s value is exactly ``{True}`` (an *allow*
            branch), the access it grants is already an OR-child of its
            own ``return true`` → skip (keeps the DSAuth allow-chain
            byte-identical).
          - otherwise the IF is a *deny* (``return false`` / non-``{True}``)
            and the else path requires its negation → AND ``!cond``
            (``allowed_when_false`` → ``falsy`` membership).
      * reachable from both (post-join) or neither (off-path) → the IF
        does not guard this return → skip.

    Standalone ``require(cond)`` / ``assert(cond)`` guards are NOT IF nodes
    (Slither lowers them to a ``SolidityCall`` in a linear EXPRESSION node),
    so they are collected separately and each is ANDed as a positive guard
    (``cond`` truthy) onto every ``return true`` it *dominates*. Missing this
    would emit a bare cofinite ``falsy`` child for
    ``require(wl[src]); if(bl[src]) return false; return true;`` = public
    minus ``bl`` — a fabrication (the ``require(wl)`` guard silently dropped).

    A deny expressed as a helper call rather than an inline ``revert`` —
    ``if(!auth[src]) _deny();`` where ``_deny`` always reverts — leaks its
    guard the same way a bare ``revert`` would, so ``_node_terminates_control``
    sinks a call to any provably always-reverting callee
    (``_callee_always_reverts``); its ``son`` edge is then cut and the ``!auth``
    negation is ANDed. For a call whose control effect can't be proven (an
    external / conditionally-reverting call) the edge is left intact, but if
    such an unclassified mid-body call sits on a path to a ``return true``
    whose guards already opened cofinite, that child fails closed — a leaked
    guard could otherwise have manufactured the opening.

    A ``return true`` with no contributing guard (truly unconditional, or no
    IF in scope) is unattributable → a fail-closed ``unsupported`` leaf,
    never an always-true business leaf. Likewise, if a dominating guard the
    builder cannot attribute (an IF/require whose condition doesn't model, or
    an unclassified mid-body call on the path) coexists with a cofinite
    ``falsy`` / ``ne`` opening, the whole child fails closed rather than emit
    that lone public-minus-set opening. ANDing the negations of ALL dominating
    deny-IFs is what stops a multi-deny chain
    (``if(a)return false; if(b)return false; return true;``) from dropping
    the ``!a`` guard and fabricating access for principals in ``a``.

    A non-literal tail return (``return expr``) is walked as its own
    expression subtree (the DSAuth ``else return authority.canCall(...)``
    shape — left unchanged here).
    """
    children: list[PredicateTree] = []
    nodes = list(getattr(callee, "nodes", []) or [])
    if not nodes:
        return []

    # Per-IF CFG facts, computed once: condition value (``None`` when the
    # condition doesn't model — kept so a *discriminating* unmodelable IF can
    # still be detected as an unattributable dominating guard), the node-id
    # sets reachable from each son, and whether the true-son is an allow
    # branch ({True}).
    if_facts: list[tuple[Any, set[int], set[int], bool]] = []
    for if_node in nodes:
        if not _node_is_type(if_node, "NodeType.IF"):
            continue
        son_true = getattr(if_node, "son_true", None)
        son_false = getattr(if_node, "son_false", None)
        if son_true is None or son_false is None:
            continue
        if_facts.append(
            (
                _if_condition_value(if_node),
                _forward_reachable_node_ids(son_true),
                _forward_reachable_node_ids(son_false),
                _branch_value_is_only_true(son_true),
            )
        )

    # Standalone ``require(cond)`` / ``assert(cond)`` guards: a SolidityCall
    # in a linear EXPRESSION node (not an IF), so they never appear in
    # ``if_facts``. Each is a positive path guard on every return it
    # dominates. ``require(false)`` / ``assert(false)`` is an unconditional
    # deny (a terminator sink, handled by ``_node_terminates_control``), not
    # a guard, so it is excluded here.
    require_guards: list[tuple[Any, Any]] = []
    for guard_node in nodes:
        for ir in getattr(guard_node, "irs_ssa", None) or getattr(guard_node, "irs", []) or []:
            if not isinstance(ir, SolidityCall):
                continue
            name = str(getattr(getattr(ir, "function", None), "name", "") or "")
            if not name.startswith(("require", "assert")):
                continue
            args = list(getattr(ir, "arguments", []) or [])
            cond = args[0] if args else None
            if cond is None or _is_literal_false(cond):
                break
            require_guards.append((cond, guard_node))
            break

    # Backstop for calls whose control-flow effect isn't proven (an external
    # / conditionally-reverting call that ``_callee_always_reverts`` can't
    # sink): the forward-reachable node set of each unclassified mid-body
    # call. A ``return true`` reachable from one may have had a guard leak
    # through that call, so if its collected guards already opened cofinite
    # the child fails closed (see the ``unmodeled_guard`` join below).
    unclassified_reach: list[set[int]] = [
        _forward_reachable_node_ids(guard_node) for guard_node in nodes if _node_has_unclassified_call(guard_node)
    ]

    for node in nodes:
        if not _node_is_type(node, "NodeType.RETURN"):
            continue
        # Pull the Return IR's value.
        return_value = None
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, Return):
                values = getattr(ir, "values", ()) or ()
                if values:
                    return_value = values[0]
                    break
        if return_value is None:
            continue
        # Distinguish literal True / False / non-literal.
        rv_str = str(getattr(return_value, "value", return_value))
        if rv_str == "False":
            continue  # denied path
        if rv_str == "True":
            # Conjunction of every dominating guard for THIS return-true.
            rid = id(node)
            guards: list[PredicateTree] = []
            unmodeled_guard = False

            # Dominating require/assert guards → positive conjuncts.
            dom_ids = {id(d) for d in getattr(node, "dominators", None) or []}
            for req_cond, req_node in require_guards:
                if id(req_node) not in dom_ids:
                    continue
                guards.append(
                    _build_subtree_from_value(
                        req_cond,
                        sub_prov,
                        _return_guard_gate(gate, req_cond, "allowed_when_true", node, callee),
                        callee,
                    )
                )
            if require_guards and not dom_ids:
                # Dominators unavailable but require/assert guards exist →
                # can't rule out a dropped positive guard.
                unmodeled_guard = True

            # IF path-edge guards.
            for cond_value, t_ids, f_ids, t_is_allow in if_facts:
                t_reach = rid in t_ids
                f_reach = rid in f_ids
                if t_reach == f_reach:
                    continue  # both (post-join) or neither (off-path)
                if f_reach and t_is_allow:
                    continue  # else of an allow-IF — OR-covered elsewhere
                if cond_value is None:
                    # A discriminating IF whose condition doesn't model — an
                    # unattributable dominating guard.
                    unmodeled_guard = True
                    continue
                polarity: Polarity = "allowed_when_true" if t_reach else "allowed_when_false"
                guards.append(
                    _build_subtree_from_value(
                        cond_value, sub_prov, _return_guard_gate(gate, cond_value, polarity, node, callee), callee
                    )
                )

            # An unclassified mid-body call on a path to this return-true
            # could have leaked a guard we couldn't model → treat as an
            # unattributable dominating guard (fails closed below only if the
            # collected guards already opened cofinite).
            if any(rid in reach for reach in unclassified_reach):
                unmodeled_guard = True

            if not guards or (unmodeled_guard and _guards_contain_opening(guards)):
                # Zero attributed guards (truly unconditional / no IF), or an
                # unattributable dominating guard paired with a cofinite
                # ``falsy`` / ``ne`` opening → fail-closed. Never a lone
                # public-minus-set child or an always-true business leaf.
                children.append(
                    make_leaf_node(
                        _unsupported_leaf(
                            reason="unattributable_return_true",
                            expression="literal true",
                        )
                    )
                )
            else:
                children.append(make_and_node(guards))
            continue
        # Non-literal Return: walk the expression itself.
        branch_gate = RevertGate(
            kind=gate.kind,
            condition_value=return_value,
            polarity="allowed_when_true",
            node=node,
            containing_function=callee,
            call_chain=list(gate.call_chain),
            expression_text=f"return {return_value}",
            basis=list(gate.basis),
        )
        children.append(_build_subtree_from_value(return_value, sub_prov, branch_gate, callee))
    return children


def _detect_assembly_combinator_op(callee: Any) -> str | None:
    """Detect Maker-style ``either(x,y){assembly{z:=or(x,y)}}`` /
    ``both(x,y){assembly{z:=and(x,y)}}`` helpers. Returns ``"or"`` /
    ``"and"`` / None.

    Detection is structural: the helper has an ASSEMBLY node whose
    ``inline_asm`` text contains a top-level ``or(`` or ``and(`` Yul
    expression. We're not matching by FUNCTION NAME — any helper
    whose body reduces to a Yul OR/AND over its parameters lights
    up here, regardless of identifier choice.
    """
    nodes = list(getattr(callee, "nodes", []) or [])
    asm_text = ""
    for n in nodes:
        if str(getattr(n, "type", "")) == "NodeType.ASSEMBLY":
            asm = getattr(n, "inline_asm", None)
            if asm:
                asm_text = str(asm)
                break
    if not asm_text:
        return None
    # Look for a Yul top-level op. Maker convention is
    # ``{ z := or(x, y) }`` / ``{ z := and(x, y) }``. Match whichever
    # appears as a function-call form (the trailing paren disambiguates
    # ``or`` keyword-vs-prefix matches in identifiers).
    if "or(" in asm_text and "and(" not in asm_text:
        return "or"
    if "and(" in asm_text and "or(" not in asm_text:
        return "and"
    return None


def _resolve_internal_call_return(ir: Any, prov: ProvenanceMap) -> tuple[Any, ProvenanceMap, Any, Any | None] | None:
    """Shared helper: bind args + run sub-engine + locate return
    value's defining IR. Returns ``(callee, sub_prov, return_value,
    inner_ir)`` or None when the call can't be resolved."""
    callee = getattr(ir, "function", None)
    if callee is None:
        return None
    bindings: dict[str, Any] = {}
    args = list(getattr(ir, "arguments", []) or [])
    params = list(getattr(callee, "parameters", []) or [])
    for param, arg in zip(params, args):
        name = getattr(param, "name", None)
        if name:
            bindings[name] = _operand_value_provenance(arg, prov)
    sub_engine = ProvenanceEngine(callee, parameter_bindings=bindings)
    sub_engine.run()
    sub_prov = sub_engine.provenance
    return_value = _find_callee_return_value(callee)
    if return_value is None:
        return None
    inner = _find_defining_ir(return_value, None, callee)
    return callee, sub_prov, return_value, inner


def _find_callee_return_value(callee: Any) -> Any | None:
    """Pick a representative Return IR's value from the callee. We
    take the first Return found — multi-return helpers gating on a
    bool typically have one return path."""
    for node in getattr(callee, "nodes", []) or []:
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, Return):
                values = getattr(ir, "values", ()) or ()
                if values:
                    return values[0]
    return None


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
        "op": allowed_op,  # type: ignore[typeddict-item]
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
            left = defining.variable_left  # type: ignore[union-attr]
            right = defining.variable_right  # type: ignore[union-attr]
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


# ---------------------------------------------------------------------------
# Operand classification
# ---------------------------------------------------------------------------


def _source_sort_key(source: Source) -> tuple[str, ...]:
    """Total deterministic order over Source records. ``SourceSet`` is a
    frozenset of string-bearing dataclasses, so its iteration order varies
    with PYTHONHASHSEED — any "pick the first matching source" over it is
    nondeterministic ACROSS PROCESSES (a fold flickered between
    ``ownerOf(uint256)`` and ``_getQueue()`` run to run, flipping the
    public/gated verdict of WithdrawalQueueERC721.approve). Every
    single-source pick must sort by this key first. Deliberately *not* a
    semantic preference: preferring e.g. arg-taking views could attribute a
    nullary authority getter to an inner keyed lookup and manufacture an
    open."""
    return (
        str(source.kind),
        str(source.parameter_index),
        str(source.parameter_name),
        str(source.state_variable_name),
        str(source.member_path),
        str(source.callee),
        str(source.callee_signature),
        str(source.callee_selector),
        str(source.callee_args_digest),
        str(source.constant_value),
        str(source.value_type),
        str(source.computed_kind),
        str(source.block_context_kind),
        str(source.storage_slot),
        _derived_from_sort_key(source.derived_from),
    )


def _published_source_key(source: Source) -> tuple[str, ...]:
    """Order over the fields a Source actually *publishes* to an operand.

    ``callee_args_digest`` is deliberately excluded. It is never emitted, so
    two Sources that differ only in the digest render identically and their
    relative order cannot matter. (The digest is content-stable now —
    ``provenance._digest`` hashes the sorted canonical member keys — so
    including it would no longer vary run to run, but it still orders nothing
    a reader can see.)
    """
    return (
        str(source.kind),
        str(source.parameter_index),
        str(source.parameter_name),
        str(source.state_variable_name),
        str(source.member_path),
        str(source.callee),
        str(source.callee_signature),
        str(source.callee_selector),
        str(source.constant_value),
        str(source.value_type),
        str(source.computed_kind),
        str(source.block_context_kind),
        str(source.storage_slot),
    )


def _derived_from_sort_key(derived_from: frozenset[Source] | None) -> str:
    """Canonical string for ``Source.derived_from`` inside ``_source_sort_key``.

    ``str()`` of a frozenset is iteration-ordered, which is the exact
    nondeterminism ``_source_sort_key`` exists to remove, so the members are
    sorted by their published key first. Recursion terminates at one level:
    every member is stored with ``derived_from=None``.
    """
    if derived_from is None:
        return "None"
    return "|".join(
        "\x1f".join(_published_source_key(origin)) for origin in sorted(derived_from, key=_published_source_key)
    )


def _operand_for_value(value: Any, prov: ProvenanceMap) -> Operand:
    """Translate a Slither IR value's source set into the semantic Operand
    record. Picks the most informative source if multiple are
    present."""
    sources = _sources_for_value(value, prov)
    if not sources:
        op: Operand = {"source": "constant", "constant_value": str(value) if value is not None else ""}
        _attach_value_type(op, value)
        return op
    op = _picked_source_operand(value, sources)
    _attach_element_read(op, value, sources, prov)
    return op


def _picked_source_operand(value: Any, sources: SourceSet) -> Operand:
    """The source the projection publishes, out of everything that reached the
    value. Extracted so the element-read stamp runs once, over whichever source
    won."""
    view_call = _derived_view_call_source(sources)
    if view_call is not None:
        op = _source_to_operand(view_call)
        _attach_state_constant_value(op, value)
        return op
    # Priority: msg_sender > signature_recovery > parameter > state_variable
    # > view_call > external_call > computed > constant > block_context > top.
    priority = (
        "msg_sender",
        "tx_origin",
        "signature_recovery",
        "self_address",  # ``address(this)`` self-call gate (auth-shaped)
        "parameter",
        "state_variable",
        "view_call",
        "external_call",
        "computed",
        "constant",
        "block_context",
        "top",
    )
    for kind in priority:
        matches = sorted((s for s in sources if s.kind == kind), key=_source_sort_key)
        if kind == "state_variable":
            # Stable sort: member-path depth first, sort-key order within ties.
            matches = sorted(matches, key=lambda source: len(getattr(source, "member_path", ()) or ()), reverse=True)
        for s in matches:
            op = _source_to_operand(s)
            _attach_state_constant_value(op, value)
            return op
    # Fallback: any source (deterministically the sort-key minimum).
    op = _source_to_operand(min(sources, key=_source_sort_key))
    _attach_state_constant_value(op, value)
    return op


# Deeper nesting than ``record.member.member`` is a coverage question of its own
# and is not answered here, so it publishes nothing rather than a truncated path.
_MAX_ELEMENT_MEMBER_DEPTH = 2
# An access chain is straight-line ``Index``/``Member`` IR; the cap only bounds a
# malformed self-referential one.
_ELEMENT_CHAIN_CAP = 8


def _attach_element_read(op: Operand, value: Any, sources: SourceSet, prov: ProvenanceMap) -> None:
    """Stamp the three ``element_*`` facts when ``value`` is one resolved storage
    element read, and stamp nothing at all otherwise.

    All three or none: they describe a single cell, so a chain that pins a base
    but not its key must publish no cell — the consumer joining an amount to a
    guard has no way to recover the missing half and would otherwise join on the
    base name alone.

    All-or-none is also what keeps ``_operand_sort_key`` total across these
    fields. Its presence flag for ``element_key_param_index`` cannot on its own
    separate an operand carrying no element read from one whose key is a proven
    ``None`` — both render as the absent flag — and it is
    ``element_base_variable``'s slot, present exactly when the other two are,
    that discriminates them. A later unit that relaxes all-or-none collapses
    that distinction in the published order and owes the sort key a fix.
    """
    fields = _element_read_fields(value, sources, prov)
    if fields is None:
        return
    base_variable, member_path, key_param_index = fields
    op["element_base_variable"] = base_variable
    op["element_member_path"] = member_path
    op["element_key_param_index"] = key_param_index


def _element_read_fields(
    value: Any, sources: SourceSet, prov: ProvenanceMap
) -> tuple[str, list[str], int | None] | None:
    if not SLITHER_AVAILABLE or not isinstance(value, ReferenceVariable):
        return None
    chain = _element_access_chain(value)
    if chain is None:
        return None
    base, member_path, keys = chain
    # Exactly one key level: the published slot names ONE level, and a second
    # would have nowhere to land — an ambiguous cell, not a narrower one.
    if len(keys) != 1 or len(member_path) > _MAX_ELEMENT_MEMBER_DEPTH:
        return None
    canonical = getattr(base, "canonical_name", None)
    if not canonical:
        return None
    # Provenance has to have seen the read the IR walk just described: one base
    # declaration, and a state-variable source carrying exactly this member path.
    # A chain merged through a phi, or one whose base saturated to top, fails
    # here instead of publishing a cell nothing proves was read.
    if {source.state_variable_name for source in sources if source.kind == "state_variable"} != {base.name}:
        return None
    if not any(source.kind == "state_variable" and tuple(source.member_path) == member_path for source in sources):
        return None
    resolved, key_param_index = _element_key_param_index(keys[0], prov)
    if not resolved or _key_definition_is_merged(keys[0], value):
        return None
    return str(canonical), list(member_path), key_param_index


def _element_access_chain(value: Any) -> tuple[Any, tuple[str, ...], list[Any]] | None:
    """Walk a reference back through its defining ``Index``/``Member`` IR to the
    state variable it reads, collecting the member path and the index keys.

    ``None`` for anything else on the chain — a storage-pointer local, an
    assignment, a type conversion, a reference whose definition is not singular —
    because a read this walk cannot follow is a read it cannot name.
    """
    member_path: list[str] = []
    keys: list[Any] = []
    current = value
    for _ in range(_ELEMENT_CHAIN_CAP):
        if not isinstance(current, ReferenceVariable):
            break
        ir = _defining_reference_ir(current)
        if isinstance(ir, Member):
            field = getattr(ir.variable_right, "value", None) or getattr(ir.variable_right, "name", None)
            if not isinstance(field, str) or not field:
                return None
            member_path.append(field)
            current = ir.variable_left
        elif isinstance(ir, Index):
            keys.append(ir.variable_right)
            current = ir.variable_left
        else:
            return None
    else:
        return None
    if not isinstance(current, StateVariable):
        return None
    member_path.reverse()
    keys.reverse()
    return current, tuple(member_path), keys


def _defining_reference_ir(ref: Any) -> Any | None:
    """The ONE IR in the reference's home node whose lvalue IS this reference.

    The uniqueness rule is what makes the answer safe: a reference with two
    definitions in its node is a chain this walk cannot read, so it yields
    nothing rather than the first candidate. Identity rather than name because
    identity is what "this reference" means; ``REF_n`` names carry no promise.
    """
    node = getattr(ref, "node", None)
    if node is None:
        return None
    defining = [ir for ir in (getattr(node, "irs_ssa", None) or ()) if getattr(ir, "lvalue", None) is ref]
    return defining[0] if len(defining) == 1 else None


def _key_definition_is_merged(key: Any, value: Any) -> bool:
    """True when the index key's SSA definition chain passes through a ``Phi``
    that joins more than one value — ``recs[flag ? a : b]`` and its if/else form.

    Structural on purpose, because the key's SOURCE SET does not answer this and
    cannot be made to: provenance folds a merged local back to a single source,
    so ``recs[flag ? a : b]`` reports the one parameter ``b`` and the cardinality
    test that refuses ``recs[_bidId + 1]`` never fires. Publishing that slot
    would name a cell the read is only sometimes keyed by, and
    ``balances[flag ? msg.sender : who]`` would publish a possibly-caller-keyed
    cell as parameter-keyed — inverting the one distinction these fields exist
    to carry.

    Refuses outright when the containing declaration cannot be reached: a key
    whose definitions cannot be enumerated is not a proven key. The BASE chain
    needs no equivalent test — ``_element_access_chain`` follows only
    ``Index``/``Member``, so a ``Phi`` on the base stops the walk before any cell
    is named.
    """
    definitions = _ssa_definitions(value)
    if definitions is None:
        return True
    seen: set[int] = set()
    pending = [key]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        defining = definitions.get(id(current)) or []
        if len(defining) > 1:
            return True
        if not defining:
            continue
        ir = defining[0]
        if isinstance(ir, Phi):
            rvalues = list(getattr(ir, "rvalues", None) or ())
            if len({id(rvalue) for rvalue in rvalues}) > 1:
                return True
            pending.extend(rvalues)
        elif isinstance(ir, Assignment):
            pending.append(getattr(ir, "rvalue", None))
    return False


def _ssa_definitions(value: Any) -> dict[int, list[Any]] | None:
    """Every SSA lvalue in the reference's containing declaration and its
    modifiers, mapped by identity to the IRs that define it.

    ``None`` when the declaration cannot be reached at all, which the caller
    reads as a refusal rather than as an empty answer.
    """
    node = getattr(value, "node", None)
    container = getattr(node, "function", None) if node is not None else None
    if container is None:
        return None
    declarations = [container]
    declarations.extend(getattr(container, "modifiers", []) or [])
    definitions: dict[int, list[Any]] = {}
    for declaration in declarations:
        for declaration_node in getattr(declaration, "nodes", []) or []:
            for ir in getattr(declaration_node, "irs_ssa", None) or ():
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None:
                    definitions.setdefault(id(lvalue), []).append(ir)
    return definitions


def _element_key_param_index(key: Any, prov: ProvenanceMap) -> tuple[bool, int | None]:
    """``(resolved, slot)`` for an index key: the entry-parameter slot it came
    from, or ``None`` for a key proven to be ``msg.sender``.

    One source and one source only. ``bids[_bidId + 1]`` carries the parameter's
    own source alongside the arithmetic, and reading the slot off it would
    publish agreement with ``bids[_bidId]`` over two different cells. ``None`` is
    reserved for the caller: it is the one non-parameter key whose identity is
    proven rather than merely unresolved, and a consumer reads it as "no entry
    parameter names this cell", not as "the key is unknown".
    """
    key_sources = _sources_for_value(key, prov)
    if len(key_sources) != 1:
        return (False, None)
    (source,) = tuple(key_sources)
    if source.kind == "parameter" and source.parameter_index is not None:
        return (True, source.parameter_index)
    if source.kind == "msg_sender":
        return (True, None)
    return (False, None)


def _derived_view_call_source(sources: SourceSet) -> Source | None:
    if any(s.kind in ("msg_sender", "tx_origin", "signature_recovery", "root_caller") for s in sources):
        return None
    has_state = any(s.kind == "state_variable" for s in sources)
    has_parameter = any(s.kind == "parameter" for s in sources)
    if not has_state or not has_parameter:
        return None
    return min((s for s in sources if s.kind == "view_call"), key=_source_sort_key, default=None)


def _source_to_operand(source: Source, *, nested: bool = False) -> Operand:
    op: Operand = {"source": source.kind}
    if source.parameter_index is not None:
        op["parameter_index"] = source.parameter_index
    if source.parameter_name is not None:
        op["parameter_name"] = source.parameter_name
    if source.state_variable_name is not None:
        op["state_variable_name"] = source.state_variable_name
    if getattr(source, "member_path", None):
        op["member_path"] = list(source.member_path)
    if source.callee is not None:
        op["callee"] = source.callee
    if source.callee_signature is not None:
        op["callee_signature"] = source.callee_signature
    if source.callee_selector is not None:
        op["callee_selector"] = source.callee_selector
    if getattr(source, "storage_slot", None) is not None:
        op["storage_slot"] = source.storage_slot
    if source.constant_value is not None:
        op["constant_value"] = source.constant_value
    if getattr(source, "value_type", None) is not None:
        op["value_type"] = source.value_type
    if source.computed_kind is not None:
        op["computed_kind"] = source.computed_kind
    if source.block_context_kind is not None:
        op["block_context_kind"] = source.block_context_kind
    if source.kind in ("computed", "view_call", "external_call") and not nested:
        # Always emitted on a computed / view_call / external_call operand, and
        # only there, so absence is "the question does not apply" rather than a
        # silent third meaning. (view_call/external_call are included because
        # the call's argument provenance — the caller, in the RoleRegistry
        # shape — must survive onto the operand; the digest alone is opaque.)
        # ``null`` is not-determined; a list (possibly empty) is determined.
        # ``nested`` renders the members, whose own ``derived_from`` was
        # stripped by ``arg_origins`` after being spliced into this list —
        # emitting ``null`` there would read as an unknown that isn't one.
        op["derived_from"] = (
            None
            if source.derived_from is None
            else [
                _source_to_operand(origin, nested=True)
                for origin in sorted(source.derived_from, key=_published_source_key)
            ]
        )
    return op


def _attach_state_constant_value(op: Operand, value: Any) -> None:
    if op.get("source") != "state_variable":
        return
    constant_value = _state_variable_bytes32_constant_value(value)
    if constant_value is not None:
        op["constant_value"] = constant_value


def _attach_value_type(op: Operand, value: Any) -> None:
    type_obj = getattr(value, "type", None)
    if type_obj is None:
        return
    type_name = getattr(type_obj, "name", None) or str(type_obj)
    if type_name:
        op["value_type"] = type_name


def _state_variable_bytes32_constant_value(value: Any) -> str | None:
    variable = value
    nsv = getattr(value, "non_ssa_version", None)
    if nsv is not None:
        variable = nsv
    if not getattr(variable, "is_constant", False):
        return None
    if str(getattr(variable, "type", "")) != "bytes32":
        return None
    return _bytes32_constant_expression_value(getattr(variable, "expression", None))


def _bytes32_constant_expression_value(expression: Any) -> str | None:
    literal = getattr(expression, "value", None)
    if literal is not None:
        return _coerce_bytes32_hex(literal)

    called = str(getattr(expression, "called", ""))
    if not called.startswith("keccak256"):
        return None
    args = list(getattr(expression, "arguments", []) or [])
    if len(args) != 1:
        return None
    text = _single_string_literal(args[0])
    if text is None:
        return None
    return "0x" + keccak(text=text).hex()


def _single_string_literal(expression: Any) -> str | None:
    value = getattr(expression, "value", None)
    if isinstance(value, str):
        return value

    called = str(getattr(expression, "called", ""))
    if called != "abi.encodePacked":
        return None
    args = list(getattr(expression, "arguments", []) or [])
    if len(args) != 1:
        return None
    value = getattr(args[0], "value", None)
    return value if isinstance(value, str) else None


def _coerce_bytes32_hex(value: Any) -> str | None:
    if isinstance(value, int):
        if value < 0:
            return None
        return "0x" + value.to_bytes(32, "big").hex()
    if not isinstance(value, str):
        return None
    raw = value.strip().lower()
    if not raw.startswith("0x"):
        return None
    body = raw[2:]
    if len(body) > 64:
        return None
    try:
        int(body or "0", 16)
    except ValueError:
        return None
    return "0x" + body.rjust(64, "0")


def _value_type_name(value: Any) -> str | None:
    type_obj = getattr(value, "type", None)
    if type_obj is None:
        return None
    type_name = getattr(type_obj, "name", None) or str(type_obj)
    return type_name or None


def _sources_for_value(value: Any, prov: ProvenanceMap) -> SourceSet:
    """Read provenance for a Slither value.

    For SolidityVariables (msg.sender / tx.origin / block.*) we
    classify on-demand — they don't appear as SSA lvalues in the
    provenance map. For StateVariables we emit a state_variable
    source directly. For Constants we emit a constant source. For
    everything else (LocalIRVariables, ReferenceVariables, TMPs,
    Phi outputs) we look up the name in the provenance map.
    """
    if value is None:
        return EMPTY
    if isinstance(value, Constant):
        return frozenset(
            {
                Source(
                    kind="constant",
                    constant_value=str(value.value),
                    value_type=_value_type_name(value),
                )
            }
        )
    if isinstance(value, SolidityVariable):
        return _classify_solidity_variable(value)
    if isinstance(value, StateVariable):
        return frozenset({Source(kind="state_variable", state_variable_name=value.name)})
    name = getattr(value, "name", None)
    if name is None:
        return EMPTY
    return prov.get(name)


def _classify_solidity_variable(var: Any) -> SourceSet:
    """Same logic as ProvenanceEngine._classify_solidity_variable but
    re-implemented here so the predicate builder can call it on
    operands without needing the engine instance."""
    name = getattr(var, "name", "")
    if name == "msg.sender":
        return frozenset({Source(kind="msg_sender")})
    if name == "tx.origin":
        return frozenset({Source(kind="tx_origin")})
    if name in (
        "block.timestamp",
        "block.number",
        "block.chainid",
        "block.coinbase",
        "block.difficulty",
        "block.gaslimit",
        "now",
        "block.basefee",
        "block.prevrandao",
    ):
        return frozenset(
            {
                Source(
                    kind="block_context",
                    block_context_kind=name.split(".", 1)[-1] if "." in name else name,
                )
            }
        )
    if name in ("msg.value", "msg.data", "msg.sig", "msg.gas"):
        return frozenset({Source(kind="computed", computed_kind=name)})
    return TOP


def _sources_from_destination(ir: Any, prov: ProvenanceMap) -> SourceSet:
    """For a HighLevelCall, return the destination (call target)'s
    provenance. Slither exposes this as ``destination``."""
    dest = getattr(ir, "destination", None)
    return _sources_for_value(dest, prov) if dest is not None else EMPTY


# ---------------------------------------------------------------------------
# Authority classification (v5/v6 round-2 fix; minimal cut)
# ---------------------------------------------------------------------------


_CALLER_SOURCES = ("msg_sender", "tx_origin", "signature_recovery")
# Sources that can plausibly carry an Ethereum address, used ONLY to qualify the
# non-caller side of a ``msg.sender == X`` equality as an authorization gate.
# ``computed``, ``top``, and ``block_context`` stay excluded — those are genuinely
# opaque (``msg.sender == keccak(...)`` / arithmetic), not authorities.
_ADDRESS_TYPED_SOURCES = (
    "state_variable",
    "view_call",
    # An external call result (``msg.sender == pauserRegistry.unpauser()`` /
    # ``== avsOperators[id].avsNodeRunner()``): for the ``==`` to type-check,
    # Solidity forces the call's return to be ``address``, so it is necessarily
    # address-typed AND a caller-authority gate (the authority just lives in
    # another contract). Excluding it lowered these to ``business`` →
    # ``conditional_universal`` → public — a false-open on every registry /
    # cross-contract-authority pattern. The resolver renders an unread external
    # getter as ``external_check_only`` (gated), never public.
    "external_call",
    "parameter",
    "signature_recovery",
    # ``address(this)`` self-call gate. Used by Compound Timelock
    # setDelay / setPendingAdmin and many module patterns. Self-call
    # is auth (``msg.sender == address(this)`` allows only the
    # contract calling itself, e.g. through a queued timelock
    # transaction).
    "self_address",
)


def _classify_authority_equality(leaf: LeafPredicate, kind: LeafKind) -> AuthorityRole:
    """Rule A (caller equality): kind=="equality", op=="eq", one
    operand is msg_sender/tx_origin/signature_recovery, the OTHER is
    address-typed (state/view/parameter/sig/constant). Otherwise
    business.

    The "other operand must be address-typed" check (v6 round-5 #1
    expansion) prevents misclassifying weird shapes like
    ``require(msg.sender == block.timestamp)`` or
    ``require(msg.sender == keccak256(x))`` as caller_authority just
    because msg.sender appears.

    Time gate: at least one operand sources from block_context AND
    no operand sources from msg.sender/tx.origin/signature_recovery
    (the caller takes priority — ``require(block.timestamp >
    cooldown[msg.sender])`` is still primarily a caller-keyed check).
    """
    operands = leaf.get("operands", [])
    if not operands:
        return "business"
    has_caller = any(o.get("source") in _CALLER_SOURCES for o in operands)
    has_block_context = any(o.get("source") == "block_context" for o in operands)
    if has_block_context and not has_caller:
        return "time"
    if kind == "equality" and leaf.get("operator") == "eq" and has_caller:
        non_caller = [o for o in operands if o.get("source") not in _CALLER_SOURCES]
        # Single-operand truthy/falsy paths don't reach here, but
        # defend anyway: a leaf with only a caller-source operand
        # is shape-tight (someone-else-implicit) and stays auth.
        if not non_caller:
            return "caller_authority"
        # Every non-caller operand must look address-typed. A leaf
        # like ``require(msg.sender == 0xabc...`` (address literal), ``==
        # ownerVar`` (state_variable), ``== auth.admin()``
        # (view_call), or ``== adminParam`` (parameter) all qualify.
        if all(_operand_is_address_typed(o) for o in non_caller):
            return "caller_authority"
    return "business"


def _operand_is_address_typed(operand: Operand) -> bool:
    source = operand.get("source")
    if source in _ADDRESS_TYPED_SOURCES:
        return True
    if source == "constant":
        if operand.get("value_type") == "address":
            return True
        value = operand.get("constant_value")
        return isinstance(value, str) and value.startswith("0x") and len(value) == 42
    return False


def _classify_authority_membership(leaf: LeafPredicate, descriptor: SetDescriptor) -> AuthorityRole:
    """Rule B (auth-shaped membership): membership op=truthy/falsy,
    msg.sender as a key, multi-key direct-promote (>=2 keys is a
    permission table by structure). 1-key requires the writer-key
    two-pass (week 3 deliverable) — until then default to business.
    """
    keys = descriptor.get("key_sources", [])
    if not keys:
        return "business"
    has_caller_key = any(k["source"] in ("msg_sender", "tx_origin", "signature_recovery") for k in keys)
    if not has_caller_key:
        return "business"
    if len(keys) >= 2:
        # Multi-key with caller as one key: permission table.
        return "caller_authority"
    # 1-key caller-only: needs writer-key analysis (week 3).
    # For now, default to business so we don't over-admit. The
    # writer-key two-pass will promote when applicable.
    return "business"


# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


def apply_confidence_to_tree(tree: PredicateTree | None) -> None:
    """Walk a PredicateTree in place and stamp ``confidence`` on
    every leaf using ``_derive_confidence``. Idempotent — safe to
    call after every pass that mutates ``authority_role``."""
    if tree is None:
        return
    op = tree.get("op")
    if op == "LEAF":
        leaf = tree.get("leaf")
        if leaf is not None:
            leaf["confidence"] = _derive_confidence(leaf)
        return
    for child in tree.get("children", []) or []:
        apply_confidence_to_tree(child)


def _derive_confidence(leaf: LeafPredicate) -> Confidence:
    """Map a fully-classified leaf to HIGH/MEDIUM/LOW confidence.

    Rules (structural):
      HIGH — shape-tight matches with no indirect inference:
        • equality/eq with caller-source operand vs address-typed
          state/view/parameter/sig_recovery operand (Rule A direct).
        • signature_auth (ecrecover-then-equality, shape-tight by
          construction).
        • multi-key (≥2) membership with caller key (Rule B direct
          promote — permission table by structure).
        • time (block_context comparison without caller).
        • reentrancy/pause (cross-referenced via dedicated analyzer).
        • EIP-1271 magic-value match (caller_authority on F3 path).

      MEDIUM — inferred / dependent on writer or
      threshold analysis:
        • 1-key caller-keyed membership promoted by writer-gate
          Path 1 (rules b.i/b.ii — depends on writer side analysis).
        • F2 threshold-promote (comparison kind, authority-derived
          counter inference).
        • delegated_authority via external_bool (depends on the
          oracle resolving correctly at evaluation time).

      LOW — residual / no auth signal:
        • business default for residual leaves.
        • bare-bool truthy leaves with no caller / state context.
        • unsupported leaves (we tried but couldn't classify).
    """
    role = leaf.get("authority_role", "business")
    kind = leaf.get("kind")
    operator = leaf.get("operator")
    operands = leaf.get("operands", []) or []
    descriptor = leaf.get("set_descriptor")
    basis_text = " ".join(leaf.get("basis", []) or [])

    if kind == "unsupported" or role == "business":
        return "low"

    if role in ("reentrancy", "pause", "time", "one_shot"):
        return "high"

    if kind == "signature_auth":
        return "high"

    if role == "delegated_authority":
        return "medium"

    if role == "caller_authority":
        if kind == "equality" and operator == "eq":
            non_caller = [
                o for o in operands if o.get("source") not in ("msg_sender", "tx_origin", "signature_recovery")
            ]
            if any(
                o.get("source") in ("state_variable", "view_call", "parameter", "signature_recovery")
                for o in non_caller
            ):
                return "high"
            return "medium"
        if kind == "membership" and descriptor:
            keys = descriptor.get("key_sources", []) or []
            caller_key = any(k.get("source") in ("msg_sender", "tx_origin", "signature_recovery") for k in keys)
            if len(keys) >= 2 and caller_key:
                # Multi-key permission table — Rule B direct promote.
                return "high"
            if len(keys) == 1 and "self-administered" in basis_text:
                # Rule b.ii — writer reads the same map (Maker-wards
                # canonical self-admin ACL). Tight structural match.
                return "high"
            if len(keys) == 1 and "writers are authority-gated" in basis_text:
                # Rule b.i — writer has some other auth. Transitive,
                # so the auth signal is weaker than direct shape.
                return "medium"
            # 1-key direct (no writer-gate basis) — could be member /
            # KYC / personal flag. Don't claim HIGH without writer
            # context; codex round on this called it out explicitly.
            return "medium"
        if kind == "comparison":
            # threshold-promote (F2) is an inferred authority signal.
            return "medium"
        return "medium"

    return "low"


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
        return operator  # type: ignore[return-value]
    inv = {"eq": "ne", "ne": "eq", "lt": "gte", "gte": "lt", "lte": "gt", "gt": "lte"}
    return inv.get(operator, operator)  # type: ignore[return-value]


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
        keys.insert(0, _expand_key_operand(current.variable_right, prov, function))  # type: ignore[union-attr]
        left = current.variable_left  # type: ignore[union-attr]
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


# Re-export for tests / consumers.
__all__ = [
    "build_predicate_tree",
    "build_return_predicate_tree",
    "ProvenanceMap",
    "TOP",
    "EMPTY",
    "is_top",
]
