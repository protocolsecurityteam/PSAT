"""When a revert gate is reached: the branch conditions a gate's node is control dependent on, so a gate under an
``if``, after an early ``return`` or behind a modifier's conditional ``_`` isn't published as unconditional.

Control dependence is taken over successful paths: ``return`` and falling off the end are exits, and a node that never
returns (a revert, an always-reverting call) is a dead end, since a call that reaches it fails whatever else holds. A
node then runs on a successful call iff one of its control-dependence parents runs and branches toward it. Branches
the tree vocabulary can't state (a loop's iteration, a ``try``) become ``unsupported`` alternatives.
"""

from __future__ import annotations

import contextvars
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from ..predicate_types import PredicateTree, make_and_node, make_leaf_node, make_or_node
from ._helpers import _unsupported_leaf
from .control_flow import _if_condition_value, _node_is_type, _node_terminates_control

# A formula over branch outcomes: ``None`` is "always reached"; ``("branch", node_id, son_is_true)``,
# ``("unsupported", reason)``, ``("and" | "or", children)``.
Formula = tuple

# ``id(function) -> (function, _Cfg)`` for one contract pass; the function is held so its id can't be reused.
_cfg_cache: contextvars.ContextVar[dict | None] = contextvars.ContextVar("psat_predicate_reach_cfg_cache", default=None)

# Larger reach conditions are published as not determined rather than expanded.
_REACH_LEAF_BUDGET = 32
_REACH_DEPTH_LIMIT = 64


@dataclass
class _Cfg:
    nodes: dict[int, Any]
    # node_id -> [(branch node, son)] it is control dependent on.
    control_parents: dict[int, list[tuple[Any, Any]]]
    cyclic: set[int]
    exits_reachable: set[int]
    # ``(node, call)`` for each modifier invocation in the function's body.
    modifier_calls: list[tuple[Any, Any]]
    # node_id -> the negated reach formula, memoized per function.
    unreached: dict[int, Formula | None] = field(default_factory=dict)


def _sons(node: Any) -> list[Any]:
    seen: set[int] = set()
    out = []
    for son in getattr(node, "sons", []) or []:
        if son is not None and id(son) not in seen:
            seen.add(id(son))
            out.append(son)
    return out


def _build_cfg(function: Any) -> _Cfg:
    nodes = [n for n in getattr(function, "nodes", []) or [] if n is not None]
    index = {id(n): i for i, n in enumerate(nodes)}
    count = len(nodes)
    is_exit = [False] * count
    succ: list[list[int]] = []
    for i, node in enumerate(nodes):
        if _node_is_type(node, "NodeType.RETURN"):
            is_exit[i] = True
            succ.append([])
        elif _node_terminates_control(node):
            succ.append([])
        else:
            sons = _sons(node)
            if _node_is_type(node, "NodeType.TRY"):
                # Slither also links a ``try`` to the statement after it, but every outcome runs a clause first.
                sons = [s for s in sons if _node_is_type(s, "NodeType.CATCH")] or sons
            sons_idx = [index[id(s)] for s in sons if id(s) in index]
            is_exit[i] = not sons_idx
            succ.append(sons_idx)
    exit_bit = 1 << count
    preds: list[list[int]] = [[] for _ in nodes]
    for i, sons in enumerate(succ):
        for s in sons:
            preds[s].append(i)

    reaches_exit = [False] * count
    work = [i for i in range(count) if is_exit[i]]
    for i in work:
        reaches_exit[i] = True
    while work:
        i = work.pop()
        for p in preds[i]:
            if not reaches_exit[p]:
                reaches_exit[p] = True
                work.append(p)

    full = (1 << (count + 1)) - 1
    pdom = [full] * count
    changed = True
    while changed:
        changed = False
        for i in range(count - 1, -1, -1):
            if not reaches_exit[i]:
                continue
            live = [s for s in succ[i] if reaches_exit[s]]
            acc = exit_bit if is_exit[i] else full
            for s in live:
                acc &= pdom[s]
            value = acc | (1 << i)
            if value != pdom[i]:
                pdom[i] = value
                changed = True

    control_parents: dict[int, list[tuple[Any, Any]]] = {}
    for b, sons in enumerate(succ):
        if len(sons) < 2 or not reaches_exit[b]:
            continue
        strict = pdom[b] & ~(1 << b)
        for s in sons:
            if not reaches_exit[s]:
                continue
            dependent = pdom[s] & ~strict & ~exit_bit
            while dependent:
                low = dependent & -dependent
                n = low.bit_length() - 1
                dependent ^= low
                control_parents.setdefault(nodes[n].node_id, []).append((nodes[b], nodes[s]))

    return _Cfg(
        nodes={n.node_id: n for n in nodes},
        control_parents=control_parents,
        cyclic=_cyclic_node_ids(nodes, succ),
        exits_reachable={nodes[i].node_id for i in range(count) if reaches_exit[i]},
        modifier_calls=[
            (node, ir)
            for node in nodes
            for ir in getattr(node, "irs", []) or []
            if getattr(ir, "is_modifier_call", False) or type(getattr(ir, "function", None)).__name__ == "Modifier"
        ],
    )


def _cyclic_node_ids(nodes: list[Any], succ: list[list[int]]) -> set[int]:
    """Node ids in a loop (a strongly connected component with an edge), by iterative Tarjan."""
    count = len(nodes)
    order = [-1] * count
    low = [0] * count
    on_stack = [False] * count
    stack: list[int] = []
    cyclic: set[int] = set()
    counter = 0
    for root in range(count):
        if order[root] != -1:
            continue
        work = [(root, 0)]
        while work:
            v, child = work[-1]
            if child == 0:
                order[v] = low[v] = counter
                counter += 1
                stack.append(v)
                on_stack[v] = True
            if child < len(succ[v]):
                work[-1] = (v, child + 1)
                w = succ[v][child]
                if order[w] == -1:
                    work.append((w, 0))
                elif on_stack[w]:
                    low[v] = min(low[v], order[w])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == order[v]:
                component = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    component.append(w)
                    if w == v:
                        break
                if len(component) > 1 or v in succ[v]:
                    cyclic.update(nodes[w].node_id for w in component)
    return cyclic


def _cfg(function: Any) -> _Cfg:
    cache = _cfg_cache.get()
    if cache is None:
        return _build_cfg(function)
    hit = cache.get(id(function))
    if hit is None:
        hit = cache[id(function)] = (function, _build_cfg(function))
    return hit[1]


def _unreached(cfg: _Cfg, node: Any, depth: int = 0) -> Formula | None:
    """The condition under which ``node`` is not reached, or ``None`` when every exit's path passes it."""
    key = node.node_id
    if key in cfg.unreached:
        return cfg.unreached[key]
    if key not in cfg.exits_reachable:
        result: Formula | None = ("unsupported", "gate_on_reverting_path")
    elif depth > _REACH_DEPTH_LIMIT:
        return ("unsupported", "gate_reach_condition_budget")
    else:
        conjuncts: list[Formula] = []
        for branch, son in cfg.control_parents.get(key, []):
            outcome = _branch_outcome(cfg, branch, son)
            above = _unreached(cfg, branch, depth + 1) if outcome[0] == "branch" else None
            conjuncts.append(_or([above, _negate_outcome(outcome)]))
        result = _and(conjuncts) if conjuncts else None
    cfg.unreached[key] = result
    return result


def _branch_outcome(cfg: _Cfg, branch: Any, son: Any) -> Formula:
    if branch.node_id in cfg.cyclic:
        return ("unsupported", "loop_iteration_not_determined")
    if not _node_is_type(branch, "NodeType.IF") or _if_condition_value(branch) is None:
        return ("unsupported", "branch_condition_not_determined")
    son_true = getattr(branch, "son_true", None)
    son_false = getattr(branch, "son_false", None)
    if son is son_true and son is not son_false:
        return ("branch", branch.node_id, True)
    if son is son_false and son is not son_true:
        return ("branch", branch.node_id, False)
    return ("unsupported", "branch_condition_not_determined")


def _negate_outcome(outcome: Formula) -> Formula:
    if outcome[0] == "branch":
        return ("branch", outcome[1], not outcome[2])
    return outcome


def _flatten(op: str, items: Sequence[Formula | None]) -> list[Formula]:
    out: list[Formula] = []
    for item in items:
        if item is None:
            continue
        parts = item[1] if item[0] == op else [item]
        for part in parts:
            if part not in out:
                out.append(part)
    return out


def _or(items: Sequence[Formula | None]) -> Formula:
    parts = _flatten("or", items)
    return parts[0] if len(parts) == 1 else ("or", parts)


def _and(items: Sequence[Formula | None]) -> Formula:
    parts = _flatten("and", items)
    return parts[0] if len(parts) == 1 else ("and", parts)


def _leaf_count(formula: Formula) -> int:
    if formula[0] in ("and", "or"):
        return sum(_leaf_count(child) for child in formula[1])
    return 1


def unreached_formula(function: Any, anchors: list[Any]) -> Formula | None:
    """The condition under which none of ``anchors`` is reached in ``function``, or ``None`` when one always is."""
    cfg = _cfg(function)
    formulas = []
    for anchor in anchors:
        if anchor is None or getattr(anchor, "node_id", None) not in cfg.nodes:
            return ("unsupported", "gate_location_not_determined")
        formula = _unreached(cfg, anchor)
        if formula is None:
            return None
        formulas.append(formula)
    if not formulas:
        return None
    combined = _and(formulas)
    if _leaf_count(combined) > _REACH_LEAF_BUDGET:
        return ("unsupported", "gate_reach_condition_budget")
    return combined


def render(
    formula: Formula, function: Any, branch_tree: Callable[[Any, Any, bool], PredicateTree | None]
) -> PredicateTree | None:
    """A formula as a tree, or ``None`` when it can't hold.

    ``branch_tree(node, condition, holds)`` builds the leaves for a branch condition holding (``holds``) or failing, or
    ``None`` when that outcome is impossible.
    """
    kind = formula[0]
    if kind == "unsupported":
        return make_leaf_node(_unsupported_leaf(reason=formula[1], expression=formula[1]))
    if kind == "branch":
        node = _cfg(function).nodes[formula[1]]
        return branch_tree(node, _if_condition_value(node), formula[2])
    children = [render(child, function, branch_tree) for child in formula[1]]
    if kind == "and":
        return None if any(child is None for child in children) else make_and_node(cast(list, children))
    possible = [child for child in children if child is not None]
    return make_or_node(possible) if possible else None


def placeholders(modifier: Any) -> list[Any]:
    return [n for n in getattr(modifier, "nodes", []) or [] if _node_is_type(n, "NodeType.PLACEHOLDER")]


def modifiers_before(function: Any, anchor: Any) -> list[Any]:
    """The modifier invocations in ``function`` that run before ``anchor``: the anchor runs inside their ``_``."""
    dominators = getattr(anchor, "dominators", None) or ()
    return [ir for node, ir in _cfg(function).modifier_calls if node is not anchor and node in dominators]
