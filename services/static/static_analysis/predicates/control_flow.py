"""CFG terminator/reachability analysis and if/else-return lowering."""

from __future__ import annotations

from typing import Any

from ..predicate_types import PredicateTree, make_and_node, make_leaf_node
from ..provenance import ProvenanceEngine, ProvenanceMap
from ..revert_detect import Polarity, RevertGate
from ..slither_compat import (
    Condition,
    Constant,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    LowLevelCall,
    Return,
    SolidityCall,
)
from ._helpers import _find_defining_ir, _unsupported_leaf


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
    from .tree import _build_subtree_from_value

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
    from .tree import _operand_value_provenance

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
