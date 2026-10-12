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
from ..slither_compat import (
    Condition,
    Constant,
    Delete,
    HighLevelCall,
    Index,
    InternalCall,
    Length,
    LibraryCall,
    LocalVariable,
    LowLevelCall,
    Member,
    NewContract,
    ReferenceVariable,
    SolidityCall,
    StateVariable,
)
from ..structural_evidence import storage_cell
from ._helpers import _unsupported_leaf
from .control_flow import _if_condition_value, _node_is_type, _node_terminates_control

# A formula over branch outcomes: ``None`` is "always reached"; ``("branch", node_id, son_is_true)``,
# ``("unsupported", reason)``, ``("and" | "or", children)``.
Formula = tuple

# ``id(function) -> (function, _Cfg)``, and ``(kind, id(x)) -> (x, result)`` for the storage-effect summaries, for one
# contract pass; the keyed object is held so its id can't be reused.
_cfg_cache: contextvars.ContextVar[dict | None] = contextvars.ContextVar("psat_predicate_reach_cfg_cache", default=None)

# Larger reach conditions are published as not determined rather than expanded.
_REACH_LEAF_BUDGET = 32
_REACH_DEPTH_LIMIT = 64


@dataclass
class _Cfg:
    # Declared first so the factory fields below can default.
    preds: dict[int, list[int]]
    nodes: dict[int, Any]
    # node_id -> [(branch node, son)] it is control dependent on.
    control_parents: dict[int, list[tuple[Any, Any]]]
    cyclic: set[int]
    exits_reachable: set[int]
    # ``(node, call)`` for each modifier invocation in the function's body.
    modifier_calls: list[tuple[Any, Any]]
    # node_id -> the negated reach formula, memoized per function.
    unreached: dict[int, Formula | None] = field(default_factory=dict)
    # node_id -> ids of the nodes some successful path runs before it (itself included).
    preceding: dict[int, set[int]] = field(default_factory=dict)
    # Whether a modifier the function invokes may run its body more than once.
    repeats: bool | None = None
    # Rendered alternatives, shared by the gates under one branch; the key's objects are held so ids stay unique.
    rendered: dict[tuple, tuple[Any, PredicateTree | None]] = field(default_factory=dict)


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
        preds={nodes[i].node_id: [nodes[p].node_id for p in preds[i]] for i in range(count)},
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


TRUE: Formula = ("true",)
FALSE: Formula = ("false",)
REACHED_ALWAYS = TRUE


def _unreached(cfg: _Cfg, node: Any, depth: int = 0) -> Formula:
    """The condition under which ``node`` is not reached (``FALSE`` when every exit's path passes it)."""
    key = node.node_id
    if key in cfg.unreached:
        return cast(Formula, cfg.unreached[key])
    if key not in cfg.exits_reachable:
        result: Formula = ("unsupported", "gate_on_reverting_path")
    elif depth > _REACH_DEPTH_LIMIT:
        return ("unsupported", "gate_reach_condition_budget")
    else:
        conjuncts: list[Formula] = []
        for branch, son in cfg.control_parents.get(key, []):
            outcome = _branch_outcome(cfg, branch, son)
            above = _unreached(cfg, branch, depth + 1) if outcome[0] == "branch" else FALSE
            conjuncts.append(_or([above, _negate_outcome(outcome)]))
        result = _and(conjuncts) if conjuncts else FALSE
    cfg.unreached[key] = result
    return result


def _reached(cfg: _Cfg, node: Any, assume: frozenset, memo: dict, depth: int = 0) -> Formula:
    """The condition under which ``node`` is reached on a successful call (``TRUE`` when always), with the branch
    outcomes in ``assume`` taken as holding.
    """
    key = node.node_id
    if key in memo:
        return memo[key]
    if key not in cfg.exits_reachable:
        result: Formula = FALSE
    elif depth > _REACH_DEPTH_LIMIT:
        return ("unsupported", "gate_reach_condition_budget")
    else:
        disjuncts: list[Formula] = []
        for branch, son in cfg.control_parents.get(key, []):
            outcome = _branch_outcome(cfg, branch, son)
            above = _reached(cfg, branch, assume, memo, depth + 1) if outcome[0] == "branch" else TRUE
            disjuncts.append(_and([above, TRUE if outcome in assume else outcome]))
        result = _or(disjuncts) if disjuncts else TRUE
    memo[key] = result
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


def _flatten(op: str, items: Sequence[Formula]) -> list[Formula]:
    out: list[Formula] = []
    for item in items:
        for part in item[1] if item[0] == op else [item]:
            if part not in out:
                out.append(part)
    return out


def _or(items: Sequence[Formula]) -> Formula:
    if TRUE in items:
        return TRUE
    parts = [part for part in _flatten("or", items) if part != FALSE]
    if not parts:
        return FALSE
    return parts[0] if len(parts) == 1 else ("or", tuple(parts))


def _and(items: Sequence[Formula]) -> Formula:
    if FALSE in items:
        return FALSE
    parts = [part for part in _flatten("and", items) if part != TRUE]
    # A branch node runs at most once outside a loop, so its two outcomes exclude each other.
    outcomes = {(part[1], part[2]) for part in parts if part[0] == "branch"}
    if any((node_id, not holds) in outcomes for node_id, holds in outcomes):
        return FALSE
    if not parts:
        return TRUE
    return parts[0] if len(parts) == 1 else ("and", tuple(parts))


def _leaf_count(formula: Formula) -> int:
    if formula[0] in ("and", "or"):
        return sum(_leaf_count(child) for child in formula[1])
    return 1


def _within_budget(formula: Formula) -> Formula:
    if _leaf_count(formula) > _REACH_LEAF_BUDGET:
        return ("unsupported", "gate_reach_condition_budget")
    return formula


def unreached_formula(function: Any, anchors: list[Any]) -> Formula | None:
    """The condition under which none of ``anchors`` is reached in ``function``, or ``None`` when one always is."""
    cfg = _cfg(function)
    formulas = []
    for anchor in anchors:
        if anchor is None or getattr(anchor, "node_id", None) not in cfg.nodes:
            return ("unsupported", "gate_location_not_determined")
        formulas.append(_unreached(cfg, anchor))
    combined = _and(formulas) if formulas else FALSE
    return None if combined == FALSE else _within_budget(combined)


def reached_formula(function: Any, node: Any, assume: frozenset = frozenset()) -> Formula:
    """The condition under which ``node`` is reached on a successful call: ``TRUE``, ``FALSE`` or a formula. Outcomes
    in ``assume`` are taken as holding.
    """
    cfg = _cfg(function)
    if getattr(node, "node_id", None) not in cfg.nodes:
        return ("unsupported", "gate_location_not_determined")
    formula = _reached(cfg, node, assume, {})
    return formula if formula in (TRUE, FALSE) else _within_budget(formula)


def render(
    formula: Formula, function: Any, branch_tree: Callable[[Any, Any, bool], PredicateTree | None]
) -> PredicateTree | None:
    """A formula as a tree, or ``None`` when it can't hold.

    ``branch_tree(node, condition, holds)`` builds the leaves for a branch condition holding (``holds``) or failing, or
    ``None`` when that outcome is impossible.
    """
    kind = formula[0]
    if kind == "false":
        return None
    if kind == "true":
        return make_leaf_node(_unsupported_leaf(reason="gate_never_reached", expression="gate_never_reached"))
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


def rendered_cache(function: Any) -> dict[tuple, tuple[Any, PredicateTree | None]]:
    return _cfg(function).rendered


def node_text(node: Any, fallback: Any) -> str:
    """A node's source expression text, rendered once per contract pass."""
    cache = _cfg_cache.get()
    key = ("text", id(node))
    if cache is not None and key in cache:
        return cache[key][1]
    text = str(getattr(node, "expression", None) or fallback)
    if cache is not None:
        cache[key] = (node, text)
    return text


def placeholders(modifier: Any) -> list[Any]:
    return [n for n in getattr(modifier, "nodes", []) or [] if _node_is_type(n, "NodeType.PLACEHOLDER")]


def modifiers_before(function: Any, anchor: Any) -> list[Any]:
    """The modifier invocations in ``function`` that run before ``anchor``: the anchor runs inside their ``_``."""
    dominators = getattr(anchor, "dominators", None) or ()
    return [ir for node, ir in _cfg(function).modifier_calls if node is not anchor and node in dominators]


# A storage effect: the declared state variables written, and whether anything else may be (a storage pointer,
# assembly, or an external call that can re-enter).
Effect = tuple[frozenset, bool]
_NO_EFFECT: Effect = (frozenset(), False)


def _preceding(cfg: _Cfg, node_id: int) -> set[int]:
    hit = cfg.preceding.get(node_id)
    if hit is None:
        hit = {node_id}
        work = [node_id]
        while work:
            for pred in cfg.preds.get(work.pop(), []):
                if pred not in hit:
                    hit.add(pred)
                    work.append(pred)
        cfg.preceding[node_id] = hit
    return hit


def _ir_effect(ir: Any, active: tuple) -> Effect:
    if isinstance(ir, (InternalCall, LibraryCall)):
        callee = getattr(ir, "function", None)
        if callee is None or not getattr(callee, "nodes", None):
            return (frozenset(), True)
        names, opaque = _function_effect(callee, active)
        written_params = _writes_storage_parameters(callee)
        for arg in (getattr(ir, "arguments", None) or []) if written_params else []:
            origin = getattr(arg, "points_to_origin", arg)
            if type(origin).__name__ == "StateVariable":
                names = names | {origin.name}
            elif isinstance(origin, LocalVariable) and str(getattr(origin, "location", "")) == "storage":
                opaque = True
        return (names, opaque)
    if isinstance(ir, HighLevelCall):
        function = getattr(ir, "function", None)
        read_only = getattr(function, "view", False) or getattr(function, "pure", False)
        return _NO_EFFECT if read_only or type(function).__name__ == "StateVariable" else (frozenset(), True)
    if isinstance(ir, LowLevelCall):
        return _NO_EFFECT if str(getattr(ir, "function_name", "")) == "staticcall" else (frozenset(), True)
    if isinstance(ir, SolidityCall):
        name = str(getattr(getattr(ir, "function", None), "name", "") or "")
        if name.startswith("tstore("):
            return (frozenset({TRANSIENT_STORAGE}), False)
        return (
            (frozenset(), True)
            if name.startswith(("sstore(", "call(", "callcode(", "delegatecall(", "create"))
            else _NO_EFFECT
        )
    if isinstance(ir, NewContract):
        return (frozenset(), True)
    if type(ir).__name__ == "InlineAssemblyOperation":
        code = str(getattr(ir, "inline_asm", "") or "")
        if "sstore" in code or "call(" in code:
            return (frozenset(), True)
        return (frozenset({TRANSIENT_STORAGE}), False) if "tstore" in code else _NO_EFFECT
    target = getattr(ir, "variable", None) if isinstance(ir, Delete) else getattr(ir, "lvalue", None)
    if isinstance(target, ReferenceVariable) and not isinstance(ir, (Index, Member, Length)):
        origin = getattr(target, "points_to_origin", None)
        if isinstance(origin, LocalVariable) and str(getattr(origin, "location", "")) == "storage":
            function = getattr(origin, "function", None)
            if origin in (getattr(function, "parameters", None) or []):
                # Charged at each call site, to the storage passed in.
                return _NO_EFFECT
            cell = storage_cell(origin, function) if function is not None else None
            return (frozenset({cell.variable.name}), False) if cell is not None else (frozenset(), True)
    return _NO_EFFECT


def _writes_storage_parameters(function: Any) -> bool:
    cache = _cfg_cache.get()
    key = ("writes_parameters", id(function))
    if cache is not None and key in cache:
        return cache[key][1]
    result = _scan_storage_parameter_writes(function)
    if cache is not None:
        cache[key] = (function, result)
    return result


def _scan_storage_parameter_writes(function: Any) -> bool:
    for node in getattr(function, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            target = getattr(ir, "variable", None) if isinstance(ir, Delete) else getattr(ir, "lvalue", None)
            if isinstance(target, ReferenceVariable) and not isinstance(ir, (Index, Member, Length)):
                if getattr(target, "points_to_origin", None) in (getattr(function, "parameters", None) or []):
                    return True
    return False


def _node_effect(node: Any, active: tuple, skip: Any = None) -> Effect:
    if skip is not None:
        return _scan_node_effect(node, active, skip)
    cache = _cfg_cache.get()
    key = ("node_effect", id(node))
    if cache is not None and key in cache:
        return cache[key][1]
    effect = _scan_node_effect(node, active, None)
    if cache is not None and not active:
        cache[key] = (node, effect)
    return effect


def _scan_node_effect(node: Any, active: tuple, skip: Any) -> Effect:
    names = {getattr(v, "name", "") for v in getattr(node, "state_variables_written", []) or []}
    opaque = False
    irs = list(getattr(node, "irs", []) or [])
    ssa = list(getattr(node, "irs_ssa", []) or [])
    # ``skip`` is the call that leads into the next frame, possibly as its SSA twin. Operations run in IR order, so
    # only those before it in the node run first; another call to the same function still counts.
    position = None
    if skip is not None:
        position = next((index for index, ir in enumerate(irs) if ir is skip), None)
        if position is None and len(ssa) == len(irs):
            position = next((index for index, ir in enumerate(ssa) if ir is skip), None)
    for ir in irs if position is None else irs[:position]:
        more, more_opaque = _ir_effect(ir, active)
        names |= more
        opaque = opaque or more_opaque
    return (frozenset(names), opaque)


def _function_effect(function: Any, active: tuple = ()) -> Effect:
    """Everything ``function`` may write, through its callees too; a recursive cycle counts as opaque."""
    if id(function) in active:
        return (frozenset(), True)
    cache = _cfg_cache.get()
    key = ("effect", id(function))
    if cache is not None and key in cache:
        return cache[key][1]
    names: set = set()
    opaque = False
    for node in getattr(function, "nodes", []) or []:
        more, more_opaque = _node_effect(node, (*active, id(function)))
        names |= more
        opaque = opaque or more_opaque
    effect: Effect = (frozenset(names), opaque)
    if cache is not None:
        cache[key] = (function, effect)
    return effect


def _memo(kind: str, entry: Any, chain: list[Any], node: Any, compute: Callable[[], Any]) -> Any:
    cache = _cfg_cache.get()
    if cache is None:
        return compute()
    key = (kind, id(entry), tuple(id(call) for call in chain), id(node))
    hit = cache.get(key)
    if hit is None:
        hit = cache[key] = ((entry, list(chain), node), compute())
    return hit[1]


def effect_before(entry: Any, chain: list[Any], frame: Any, node: Any) -> Effect:
    return _memo("effect_before", entry, chain, node, lambda: _effect_before(entry, chain, frame, node))


def _effect_before(entry: Any, chain: list[Any], frame: Any, node: Any) -> Effect:
    """What a successful call may write before ``node`` in ``frame`` runs: earlier nodes in ``frame`` (and ``node``
    itself), and at each outer level of ``chain`` the nodes before the call that leads in, from ``entry`` down. A
    modifier's code after ``_`` runs after the body it wraps, so a ``_`` before the anchor adds everything the wrapped
    function may write.
    """
    frames = [entry, *(getattr(call, "function", None) for call in chain)]
    targets = [(frames[i], getattr(call, "node", None), call) for i, call in enumerate(chain)]
    targets.append((frame, node, None))
    names: set = set()
    opaque = False
    for level, (function, anchor, call) in enumerate(targets):
        if function is None or anchor is None:
            return (frozenset(), True)
        cfg = _cfg(function)
        if anchor.node_id not in cfg.nodes:
            return (frozenset(), True)
        effects = []
        for node_id in _preceding(cfg, anchor.node_id):
            effects.append(_node_effect(cfg.nodes[node_id], (), skip=call if node_id == anchor.node_id else None))
            if level and _node_is_type(cfg.nodes[node_id], "NodeType.PLACEHOLDER"):
                effects.append(
                    _function_effect(frames[level - 1]) if frames[level - 1] is not None else (frozenset(), True)
                )
        for more, more_opaque in effects:
            names |= more
            opaque = opaque or more_opaque
    return (frozenset(names), opaque)


def runs_body_repeatedly(function: Any) -> bool:
    """Whether a modifier ``function`` invokes may run its body more than once in a call: a ``_`` that can reach
    another ``_``, or one in a loop.
    """
    cfg = _cfg(function)
    if cfg.repeats is None:
        cfg.repeats = _modifier_repeats_body(cfg)
    return cfg.repeats


def _modifier_repeats_body(function_cfg: _Cfg) -> bool:
    for _, call in function_cfg.modifier_calls:
        modifier = getattr(call, "function", None)
        cfg = _cfg(modifier)
        marks = [node.node_id for node in placeholders(modifier) if node.node_id in cfg.nodes]
        if any(mark in cfg.cyclic for mark in marks):
            return True
        if any(first != second and first in _preceding(cfg, second) for first in marks for second in marks):
            return True
    return False


# What a branch condition reads: declared state variables (elements and pointers resolved to their variable), whether
# it reads storage of this contract it can't attribute, and whether it reads another contract.
Reads = tuple[frozenset, bool, bool]


def _storage_variable(value: Any, function: Any) -> tuple[str | None, bool]:
    """The state variable a storage reference resolves to, or whether it is unattributable storage."""
    origin = getattr(value, "points_to_origin", None) if isinstance(value, ReferenceVariable) else value
    if isinstance(origin, StateVariable):
        return (None, False) if origin.is_constant or getattr(origin, "is_immutable", False) else (origin.name, False)
    if isinstance(origin, LocalVariable) and str(getattr(origin, "location", "")) == "storage":
        cell = storage_cell(origin, getattr(origin, "function", None) or function)
        return (cell.variable.name, False) if cell is not None else (None, True)
    return (None, False)


_YUL_CALLS = ("call(", "staticcall(", "delegatecall(", "callcode(")
# Transient storage as one cell: ``tstore`` changes only what ``tload`` reads.
TRANSIENT_STORAGE = "<transient storage>"
# Builtins reading another account's state, which a call out can change.
_ACCOUNT_READS = ("balance(", "selfbalance(", "code(", "codehash(", "extcodesize(", "extcodehash(", "extcodecopy(")


def _read_kind(ir: Any) -> tuple[bool, bool, bool]:
    """Whether ``ir`` reads this contract's storage unattributed, another account, or transient storage."""
    if isinstance(ir, LowLevelCall) or (isinstance(ir, HighLevelCall) and not isinstance(ir, LibraryCall)):
        return False, True, False
    if isinstance(ir, SolidityCall):
        name = str(getattr(ir.function, "name", ""))
        return name.startswith("sload("), name.startswith((*_ACCOUNT_READS, *_YUL_CALLS)), name.startswith("tload(")
    if type(ir).__name__ == "InlineAssemblyOperation":
        code = str(getattr(ir, "inline_asm", "") or "")
        return "sload" in code, any(word in code for word in ("call(", "balance(", "extcode")), "tload" in code
    return False, False, False


def reads_conflict(reads: Reads, effect: Effect) -> bool:
    """Whether storage a branch reads may have been written: a variable it reads, any persistent storage when it reads
    some it can't attribute, or anything at all after a call that could write anywhere.
    """
    names, other, external = reads
    written, written_other = effect
    if written_other:
        return bool(names or other or external)
    return bool(names & written) or (other and bool(written - {TRANSIENT_STORAGE}))


def _function_reads(function: Any) -> Reads:
    cache = _cfg_cache.get()
    key = ("reads", id(function))
    if cache is not None and key in cache:
        return cache[key][1]
    names: set = set()
    other = external = False
    try:
        variables = function.all_state_variables_read()
        nodes = function.all_nodes()
    except Exception:
        return (frozenset(), True, True)
    for variable in variables:
        if not variable.is_constant and not getattr(variable, "is_immutable", False):
            names.add(variable.name)
    for node in nodes:
        for ir in getattr(node, "irs", []) or []:
            more_other, more_external, transient = _read_kind(ir)
            other = other or more_other
            external = external or more_external
            if transient:
                names.add(TRANSIENT_STORAGE)
            for value in getattr(ir, "read", None) or []:
                name, unattributed = _storage_variable(value, function)
                if name is not None:
                    names.add(name)
                other = other or unattributed
    reads: Reads = (frozenset(names), other, external)
    if cache is not None:
        cache[key] = (function, reads)
    return reads


def _definitions(function: Any) -> dict[str, list[Any]]:
    cache = _cfg_cache.get()
    key = ("definitions", id(function))
    if cache is not None and key in cache:
        return cache[key][1]
    defs: dict[str, list[Any]] = {}
    for node in getattr(function, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is not None:
                defs.setdefault(str(lvalue), []).append(ir)
    if cache is not None:
        cache[key] = (function, defs)
    return defs


def branch_reads(entry: Any, chain: list[Any], frame: Any, node: Any) -> Reads:
    return _memo("branch_reads", entry, chain, node, lambda: _branch_reads(entry, chain, frame, node))


def _branch_reads(entry: Any, chain: list[Any], frame: Any, node: Any) -> Reads:
    """What the condition of ``node`` in ``frame`` reads, followed through the locals and helpers that feed it and,
    for a parameter of an inner frame, through the argument passed in from the frame above.
    """
    frames = [entry, *(getattr(call, "function", None) for call in chain)]
    names: set = set()
    other = external = False
    work: list[tuple[int, Any]] = [
        (len(chain), value)
        for ir in getattr(node, "irs", []) or []
        if isinstance(ir, Condition)
        for value in getattr(ir, "read", None) or []
    ]
    seen: set = set()
    while work:
        level, value = work.pop()
        value = getattr(value, "non_ssa_version", None) or value
        if value is None or isinstance(value, Constant) or (level, id(value)) in seen:
            continue
        seen.add((level, id(value)))
        function = frames[level]
        if function is None:
            return (frozenset(), True, True)
        name, unattributed = _storage_variable(value, function)
        if name is not None:
            names.add(name)
        other = other or unattributed
        parameters = list(getattr(function, "parameters", None) or [])
        if value in parameters:
            if level:
                arguments = list(getattr(chain[level - 1], "arguments", None) or [])
                index = parameters.index(value)
                if index < len(arguments):
                    work.append((level - 1, arguments[index]))
            continue
        for ir in _definitions(function).get(str(value), []):
            if isinstance(ir, (InternalCall, LibraryCall)):
                callee = getattr(ir, "function", None)
                more, more_other, more_external = _function_reads(callee) if callee is not None else (set(), True, True)
                names |= more
                other = other or more_other
                external = external or more_external
            else:
                more_other, more_external, transient = _read_kind(ir)
                other = other or more_other
                external = external or more_external
                if transient:
                    names.add(TRANSIENT_STORAGE)
            work.extend((level, read) for read in getattr(ir, "read", None) or [])
    return (frozenset(names), other, external)
