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

from typing import Any, cast

from eth_utils.crypto import keccak

try:
    from slither.core.declarations import SolidityVariable  # type: ignore[import]
    from slither.core.variables.state_variable import StateVariable  # type: ignore[import]
    from slither.slithir.operations import (  # type: ignore[import]
        Binary,
        Condition,
        HighLevelCall,
        Index,
        InternalCall,
        LibraryCall,
        Member,
        Return,
        SolidityCall,
        Unary,
        UnaryType,
    )
    from slither.slithir.variables import Constant  # type: ignore[import]

    SLITHER_AVAILABLE = True
except Exception:  # pragma: no cover
    SLITHER_AVAILABLE = False

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

from .predicate_types import (
    AuthorityRole,
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
    is_top,
)
from .revert_detect import RevertDetector, RevertGate

_helper_engine_cache: _contextvars.ContextVar[dict | None] = _contextvars.ContextVar(
    "psat_predicate_helper_engine_cache", default=None
)


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


def build_predicate_tree(function: Any) -> PredicateTree | None:
    """Construct a PredicateTree for one function. Returns None if
    the function has no revert paths."""
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
    for gate in gates:
        subtree = _build_subtree_from_gate(gate, prov, function)
        if subtree is not None:
            subtrees.append(subtree)

    if not subtrees:
        return None
    tree = make_and_node(subtrees)
    apply_confidence_to_tree(tree)
    return tree


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
    # helper with those bindings. Full caller-side
    # ParameterBindingEnv per v4 plan §predicates (round-2 #2 fix).
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
        return make_leaf_node(_build_truthy_leaf(cond_value, prov, gate))
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
        return _build_truthy_leaf(cond, prov, gate)
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
        return _build_truthy_leaf(return_value, sub_prov, gate)
    return _classify_leaf_from_ir(inner, sub_prov, gate, callee)


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
    # Polarity propagates the same way as the inline AND/OR case in
    # _build_subtree_from_value's main path.
    if gate.polarity == "allowed_when_true":
        return make_and_node(children) if op_name == "and" else make_or_node(children)
    return make_or_node(children) if op_name == "and" else make_and_node(children)


def _build_if_else_returns_or_children(callee: Any, sub_prov: ProvenanceMap, gate: RevertGate) -> list[PredicateTree]:
    """For helpers with an if-else chain returning bool literals/
    expressions, build OR-children — one per Return node.

      - Return literal True  → child is the closest dominating IF's
                                condition value as a subtree
      - Return bool-expr     → child is the expression as a subtree
      - Return literal False → skipped (denied path)

    The dominator walk takes the closest predecessor IF node (in
    fn.nodes order). For DSAuth's flat if-else chain that yields
    the right per-branch condition; for nested IFs the result is
    conservative (uses the innermost IF). A more complete dominator
    walk could OR the full path predicate; this approximation is
    deliberately simple and was sufficient for the canonical DSAuth
    shape.
    """
    children: list[PredicateTree] = []
    nodes = list(getattr(callee, "nodes", []) or [])
    if not nodes:
        return []
    for idx, node in enumerate(nodes):
        if str(getattr(node, "type", "")) != "NodeType.RETURN":
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
            # Walk back to the closest preceding IF node — its
            # Condition IR's value is the path predicate.
            cond_value = None
            for back_idx in range(idx - 1, -1, -1):
                back_node = nodes[back_idx]
                if str(getattr(back_node, "type", "")) != "NodeType.IF":
                    continue
                for ir in getattr(back_node, "irs_ssa", None) or getattr(back_node, "irs", []) or []:
                    if isinstance(ir, Condition):
                        cond_value = getattr(ir, "value", None)
                        break
                break
            if cond_value is None:
                children.append(
                    make_leaf_node(
                        {
                            "kind": "comparison",
                            "operator": "truthy",
                            "authority_role": "business",
                            "operands": [],
                            "references_msg_sender": False,
                            "parameter_indices": [],
                            "expression": "literal true",
                            "basis": list(gate.basis) + ["literal_true_return"],
                        }
                    )
                )
                continue
            # Use a fresh per-branch gate so polarity matches the
            # outer require's allowed_when_true (children are
            # combined under OR — each child contributes a "true"
            # path).
            branch_gate = RevertGate(
                kind=gate.kind,
                condition_value=cond_value,
                polarity="allowed_when_true",
                node=node,
                containing_function=callee,
                call_chain=list(gate.call_chain),
                expression_text=f"return {cond_value}",
                basis=list(gate.basis),
            )
            children.append(_build_subtree_from_value(cond_value, sub_prov, branch_gate, callee))
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
        return leaf
    # AND/OR at the binary level — these would normally be handled by
    # short-circuit evaluation; for now we treat as unsupported and
    # let the predicate-tree composition layer (week 2) split them
    # into AND/OR tree nodes properly.
    return _unsupported_leaf(reason=f"binary_op_{op_name}_unsupported", expression=str(ir))


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
        "op": operator,  # type: ignore[typeddict-item]
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


def _swap_operator(op: LeafOperator) -> LeafOperator:
    """Flip a comparison operator when its operands swap. e.g.
    ``a >= b`` ↔ ``b <= a``."""
    return {"gt": "lt", "lt": "gt", "gte": "lte", "lte": "gte"}.get(op, op)  # type: ignore[return-value]


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
    Generic case: emit external_bool with delegated_authority.
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
    leaf["authority_role"] = "delegated_authority"
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
    # Authority classification for external_bool: delegated_authority
    # if the call target traces to a state_variable AND any arg
    # traces to msg_sender or signature_recovery.
    target_sources = _sources_from_destination(ir, prov)
    has_state_target = any(s.kind == "state_variable" for s in target_sources)
    target_state_var = next(
        (s.state_variable_name for s in target_sources if s.kind == "state_variable"),
        None,
    )
    has_caller_arg = any(
        any(s.kind in ("msg_sender", "tx_origin", "signature_recovery") for s in _sources_for_value(a, prov))
        for a in getattr(ir, "arguments", ())
    )
    if has_state_target and has_caller_arg:
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
    return leaf


# ---------------------------------------------------------------------------
# Operand classification
# ---------------------------------------------------------------------------


def _operand_for_value(value: Any, prov: ProvenanceMap) -> Operand:
    """Translate a Slither IR value's source set into the semantic Operand
    record. Picks the most informative source if multiple are
    present."""
    sources = _sources_for_value(value, prov)
    if not sources:
        op: Operand = {"source": "constant", "constant_value": str(value) if value is not None else ""}
        _attach_value_type(op, value)
        return op
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
        matches = [s for s in sources if s.kind == kind]
        if kind == "state_variable":
            matches = sorted(matches, key=lambda source: len(getattr(source, "member_path", ()) or ()), reverse=True)
        for s in matches:
            op = _source_to_operand(s)
            _attach_state_constant_value(op, value)
            return op
    # Fallback: any source.
    op = _source_to_operand(next(iter(sources)))
    _attach_state_constant_value(op, value)
    return op


def _derived_view_call_source(sources: SourceSet) -> Source | None:
    if any(s.kind in ("msg_sender", "tx_origin", "signature_recovery", "root_caller") for s in sources):
        return None
    has_state = any(s.kind == "state_variable" for s in sources)
    has_parameter = any(s.kind == "parameter" for s in sources)
    if not has_state or not has_parameter:
        return None
    return next((s for s in sources if s.kind == "view_call"), None)


def _source_to_operand(source: Source) -> Operand:
    op: Operand = {"source": source.kind}  # type: ignore[typeddict-item]
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

    if role in ("reentrancy", "pause", "time"):
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
