"""CFG terminator/reachability analysis and if/else-return lowering."""

from __future__ import annotations

from typing import Any

from ..predicate_types import PredicateTree, make_and_node, make_leaf_node
from ..provenance import ProvenanceEngine, ProvenanceMap
from ..revert_detect import Polarity, RevertGate, is_error_argument
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
    for ir in getattr(if_node, "irs_ssa", None) or getattr(if_node, "irs", []) or []:
        if isinstance(ir, Condition):
            return getattr(ir, "value", None)
    return None


def _return_literal(node: Any) -> str | None:
    """``"True"``/``"False"`` for a RETURN of a bool literal, else None."""
    for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
        if isinstance(ir, Return):
            values = getattr(ir, "values", ()) or ()
            if values:
                s = str(getattr(values[0], "value", values[0]))
                return s if s in ("True", "False") else None
    return None


def _is_literal_false(value: Any) -> bool:
    return isinstance(value, Constant) and str(getattr(value, "value", value)) == "False"


# Bounds cross-function recursion and guarantees termination.
_ALWAYS_REVERTS_MAX_DEPTH = 4


def _node_terminates_control(node: Any, _depth: int = 0) -> bool:
    """True for a node control never falls through: ``return``/``throw``, unconditional ``revert``,
    ``require(false)``/``assert(false)``, or a call to a callee that always reverts.

    Slither keeps a fall-through edge from reverts to the ENDIF for CFG completeness, so without treating these as sinks
    a branch's deny leaks past the join and the guard is dropped; a helper-based deny (``if(!auth) _deny();``) leaks the
    same way. ``require(cond)`` with a real condition is not a terminator.
    """
    if _node_is_type(node, "NodeType.RETURN") or _node_is_type(node, "NodeType.THROW"):
        return True
    for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
        if isinstance(ir, SolidityCall):
            name = str(getattr(getattr(ir, "function", None), "name", "") or "")
            if name.startswith("revert") and not is_error_argument(ir, node):
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
    """True iff every path through ``callee`` reverts, so a call to it never returns.

    A callee without a visible body isn't proven and returns False (the unclassified-call backstop then fails closed).
    Terminators are sinks here too (``if(x) revert(); else revert();`` keeps an ENDIF edge). Bounded by ``_depth`` and a
    per-callee ``seen``.
    """
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
    """True for a mid-body statement (EXPRESSION or VARIABLE) whose call the builder doesn't model and that isn't a
    proven revert sink. It might revert on a path the builder can't see, so a ``return true`` reached through it
    with a cofinite opening fails closed. IF conditions, returns and proven sinks are excluded.
    """
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
    """Ids of nodes reachable from ``start`` (included), stopping at terminating nodes so a branch's return or revert
    doesn't leak past the join. Cycle-safe.
    """
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


def _branch_value_is_only(start: Any, literal: str) -> bool:
    """True iff every terminating outcome reachable from ``start`` is ``return <literal>`` and one is reached.

    Terminators are sinks, else a bare ``if(!auth) revert;`` would read as reaching a later return.
    """
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
            if _return_literal(node) != literal:
                return False
            continue
        if _node_terminates_control(node):
            return False
        sons = [son for son in getattr(node, "sons", []) or [] if son is not None]
        if not sons:
            # Falling off the end returns the default ``false``.
            saw_return = True
            if literal != "False":
                return False
        work.extend(sons)
    return saw_return


def _return_guard_gate(base: RevertGate, cond_value: Any, polarity: Polarity, node: Any, callee: Any) -> RevertGate:
    """A RevertGate for one path condition of a ``return true`` path (IF condition or ``require`` argument)."""
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
    """True iff any leaf is a cofinite opening (``falsy`` membership or ``ne``), which widens toward public, so an
    unattributable guard beside it must fail closed.
    """
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


def _helper_exits(callee: Any) -> list[tuple[Any, Any | None]]:
    """``(node, returned value)`` for every way a bool helper returns: its ``return`` nodes, and falling off the end
    (value ``None``, the default ``false``). Exits reached only through a revert aren't exits.
    """
    nodes = list(getattr(callee, "nodes", []) or [])
    if not nodes:
        return []
    live = _forward_reachable_node_ids(getattr(callee, "entry_point", None) or nodes[0])
    exits: list[tuple[Any, Any | None]] = []
    for node in nodes:
        if id(node) not in live:
            continue
        if _node_is_type(node, "NodeType.RETURN"):
            for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
                if isinstance(ir, Return):
                    values = getattr(ir, "values", ()) or ()
                    if values:
                        exits.append((node, values[0]))
                        break
        elif not [son for son in getattr(node, "sons", []) or [] if son is not None] and not _node_terminates_control(
            node
        ):
            exits.append((node, None))
    return exits


def _build_if_else_returns_or_children(callee: Any, sub_prov: ProvenanceMap, gate: RevertGate) -> list[PredicateTree]:
    """OR-children for a bool helper: one child per return path that can yield the value ``gate`` allows on (``true``
    under ``allowed_when_true``, ``false`` under a negated call).

    A literal return of that value is the AND of the guards reaching it; a non-literal return also ANDs its value, built
    under ``gate``'s polarity. Guards keep their own polarity whichever value is wanted: a condition reachable only from
    ``IF.son_true`` is a positive guard; from ``son_false`` only, skip it if the true branch only returns the wanted
    value (it's its own child), otherwise AND ``!cond``. Post-join or off-path IFs don't guard it. Falling off the end
    returns the default ``false``.

    ``require``/``assert`` are linear expressions, not IFs, so they're collected separately and ANDed as written onto
    every return they dominate: they revert whichever value the caller wants (else ``require(wl[src]); if(bl[src])
    return false; return true;`` would publish public-minus-``bl``). Helper denies that always revert are sinks;
    unproven calls on a path whose guards already opened cofinite fail the child closed.

    A literal return with no guard, or an unattributable guard beside a cofinite opening, becomes a fail-closed
    ``unsupported`` leaf, never an always-true one. ANDing every dominating deny's negation keeps multi-deny chains from
    dropping a guard.
    """
    from .tree import _build_subtree_from_value

    children: list[PredicateTree] = []
    nodes = list(getattr(callee, "nodes", []) or [])
    if not nodes:
        return []
    wanted = "True" if gate.polarity == "allowed_when_true" else "False"

    # Per-IF facts: condition (``None`` if unmodelable, still detectable as an unattributable guard), reach sets per
    # son, and whether the true son only returns the wanted value.
    if_facts: list[tuple[Any, set[int], set[int], bool, Any]] = []
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
                _branch_value_is_only(son_true, wanted),
                if_node,
            )
        )

    # ``require``/``assert`` guards (not IFs); ``require(false)`` is a terminator, not a guard.
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

    # Reach sets of unclassified mid-body calls: a return reachable from one may have lost a guard.
    unclassified_reach: list[set[int]] = [
        _forward_reachable_node_ids(guard_node) for guard_node in nodes if _node_has_unclassified_call(guard_node)
    ]

    for node, return_value in _helper_exits(callee):
        literal = "False" if return_value is None else str(getattr(return_value, "value", return_value))
        if literal not in ("True", "False"):
            literal = None
        if literal is not None and literal != wanted:
            continue
        rid = id(node)
        guards: list[PredicateTree] = []
        unmodeled_guard = False

        dom_ids = {id(d) for d in getattr(node, "dominators", None) or []}
        for req_cond, req_node in require_guards:
            if id(req_node) not in dom_ids:
                continue
            guards.append(
                _build_subtree_from_value(
                    req_cond,
                    sub_prov,
                    _return_guard_gate(gate, req_cond, "allowed_when_true", req_node, callee),
                    callee,
                )
            )
        if require_guards and not dom_ids:
            # No dominators but require guards exist: can't rule out a dropped guard.
            unmodeled_guard = True

        for cond_value, t_ids, f_ids, t_only_wanted, condition_node in if_facts:
            t_reach = rid in t_ids
            f_reach = rid in f_ids
            if t_reach == f_reach:
                continue  # both (post-join) or neither (off-path)
            if f_reach and t_only_wanted:
                continue  # else of an IF whose true branch is its own child
            if cond_value is None:
                # An unmodelable discriminating IF.
                unmodeled_guard = True
                continue
            polarity: Polarity = "allowed_when_true" if t_reach else "allowed_when_false"
            guards.append(
                _build_subtree_from_value(
                    cond_value,
                    sub_prov,
                    _return_guard_gate(gate, cond_value, polarity, condition_node, callee),
                    callee,
                )
            )

        # An unclassified call on the path may have leaked a guard (fails closed only with a cofinite opening among the
        # path's guards).
        if any(rid in reach for reach in unclassified_reach):
            unmodeled_guard = True
        opening = _guards_contain_opening(guards)

        if literal is None:
            guards.append(
                _build_subtree_from_value(
                    return_value,
                    sub_prov,
                    RevertGate(
                        kind=gate.kind,
                        condition_value=return_value,
                        polarity=gate.polarity,
                        node=node,
                        containing_function=callee,
                        call_chain=list(gate.call_chain),
                        expression_text=f"return {return_value}",
                        basis=list(gate.basis),
                    ),
                    callee,
                )
            )
        if not guards or (unmodeled_guard and opening):
            # No attributed guard, or an unattributable one with a cofinite opening: fail closed.
            children.append(
                make_leaf_node(
                    _unsupported_leaf(
                        reason=f"unattributable_return_{(literal or 'value').lower()}",
                        expression=f"literal {(literal or 'value').lower()}",
                    )
                )
            )
        else:
            children.append(make_and_node(guards))
    return children


def _detect_assembly_combinator_op(callee: Any) -> str | None:
    """``"or"``/``"and"`` for a Maker-style ``either``/``both`` helper whose assembly body is a top-level Yul
    ``or(``/``and(``, else None. Structural, not by name.
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
    # The trailing paren avoids matching ``or``/``and`` inside identifiers.
    if "or(" in asm_text and "and(" not in asm_text:
        return "or"
    if "and(" in asm_text and "or(" not in asm_text:
        return "and"
    return None


def _resolve_internal_call_return(ir: Any, prov: ProvenanceMap) -> tuple[Any, ProvenanceMap, Any, Any | None] | None:
    """Bind arguments, run the sub-engine, and find the return value's defining IR: ``(callee, sub_prov,
    return_value, inner_ir)`` or None.
    """
    from .tree import _cache_key_for, _helper_engine_cache, _operand_value_provenance

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
    return_value = _find_callee_return_value(callee)
    if return_value is None:
        return None
    inner = _find_defining_ir(return_value, None, callee)
    return callee, sub_prov, return_value, inner


def _find_callee_return_value(callee: Any) -> Any | None:
    """The first Return value in the callee (bool gate helpers usually have one)."""
    for node in getattr(callee, "nodes", []) or []:
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, Return):
                values = getattr(ir, "values", ()) or ()
                if values:
                    return values[0]
    return None
