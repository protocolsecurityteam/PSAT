"""Structural reentrancy and pause detection (no names), reclassifying state-variable reads in predicate trees as
``reentrancy``/``pause`` side conditions instead of business.

A reentrancy guard writes the same variable before and after a modifier's ``_;`` and reverts on it at entry
(``require(_status != _ENTERED)``). A pause flag is a bool written by a caller-gated function and reverted on elsewhere
(``whenNotPaused``/``pause() onlyOwner``).

Both are contract-scoped; ``verified_guard_verdicts`` is the per-function export, so a guard declared elsewhere can't
stand in for one applied to this function.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict, get_args

from .predicate_types import AuthorityRole, LeafPredicate, PredicateTree
from .shared import _all_modifiers, _all_state_variables
from .slither_compat import (
    SLITHER_AVAILABLE,
    Assignment,
    Binary,
    BinaryType,
    InternalCall,
    LibraryCall,
    NodeType,
    SolidityCall,
    Unary,
)

StructuralGuardKind = Literal["reentrancy", "pause"]
# A rename there must not strand these tokens.
assert set(get_args(StructuralGuardKind)) <= set(get_args(AuthorityRole))


class PauseInfo(TypedDict):
    """Export from ``apply_reentrancy_pause_pass``: the flagged pause and reentrancy vars and the functions derived
    from them.
    """

    pause_state_vars: list[str]
    pause_toggle_functions: list[str]
    reentrancy_state_vars: list[str]
    reentrancy_guarded_functions: list[str]


W2_VERIFIED_GUARD_BASIS = "w2_verified_guard"

# No proven guard modifier on this function, though the contract has one.
W2_REASON_GUARD_NOT_APPLIED = "guard_modifier_not_applied"
# No modifier on the contract passes the test.
W2_REASON_NO_VERIFIED_GUARD = "no_verified_guard_modifier"
# Two live declarations for one signature; refuse rather than pick.
W2_REASON_AMBIGUOUS_DECLARATION = "ambiguous_function_declaration"


class VerifiedGuardVerdict(TypedDict):
    """W2's verified-guard satisfier for one function: ``proven`` only when a modifier passing the pre/post-write and
    revert test is applied to this function, else ``not_determined`` with a reason. Never claims a function needs
    no guard. ``declaration`` names the body the verdict is about.
    """

    state: Literal["proven", "not_determined"]
    basis: str | None
    reason: str | None
    declaration: str | None
    guard_vars: list[str]
    guard_modifiers: list[str]


class ReentrancyAnalyzer:
    """State vars proven to be reentrancy guards by the modifier write pattern."""

    def __init__(self, contract: Any) -> None:
        if not SLITHER_AVAILABLE:
            raise RuntimeError("ReentrancyAnalyzer requires slither")
        self.contract = contract

    def run(self) -> set[str]:
        guards: set[str] = set()
        # A modifier holding two guard vars publishes both (iteration order used to pick one).
        for proven in self.reentrancy_guard_modifiers().values():
            guards |= proven
        # Inline body guards are rare and not modeled yet.
        for fn in getattr(self.contract, "functions", []) or []:
            v = self._function_guard_var(fn)
            if v is not None:
                guards.add(v)
        return guards

    def reentrancy_guard_modifiers(self) -> dict[int, frozenset[str]]:
        """``id(modifier) -> proven guard vars`` for modifiers passing the test, keyed by identity because Slither
        gives derived contracts the same modifier object their functions list.
        """
        proven: dict[int, frozenset[str]] = {}
        for modifier in getattr(self.contract, "modifiers", []) or []:
            guard_vars = self._proven_guard_vars(modifier)
            if guard_vars:
                proven[id(modifier)] = guard_vars
        return proven

    def _proven_guard_vars(self, modifier: Any) -> frozenset[str]:
        nodes = getattr(modifier, "nodes", []) or []
        placeholder_idx = self._find_placeholder_index(nodes)
        if placeholder_idx is None:
            return frozenset()
        pre_writes = self._state_var_writes(nodes[:placeholder_idx])
        post_writes = self._state_var_writes(nodes[placeholder_idx + 1 :])
        common = pre_writes & post_writes
        # And reverts on the var before the pre-write.
        return frozenset(var for var in common if self._has_revert_reading_var(nodes[:placeholder_idx], var))

    def _modifier_guard_var(self, modifier: Any) -> str | None:
        guard_vars = self._proven_guard_vars(modifier)
        if not guard_vars:
            return None
        return sorted(guard_vars)[0]

    def _function_guard_var(self, fn: Any) -> str | None:
        return None

    def _find_placeholder_index(self, nodes: list[Any]) -> int | None:
        for i, n in enumerate(nodes):
            if getattr(n, "type", None) == getattr(NodeType, "PLACEHOLDER", -1):
                return i
        return None

    def _state_var_writes(self, nodes: list[Any]) -> set[str]:
        return self._collect_state_var_writes(nodes, set())

    def _collect_state_var_writes(self, nodes: list[Any], visited: set[int]) -> set[str]:
        """Every state-variable write in ``nodes``, following helpers (some guards split their writes into helpers).

        Cycle-safe.
        """
        names: set[str] = set()
        for n in nodes:
            for ir in getattr(n, "irs_ssa", None) or getattr(n, "irs", []) or []:
                if isinstance(ir, Assignment):
                    base_name = _base_state_var_name(ir.lvalue)
                    if base_name is not None:
                        names.add(base_name)
                if isinstance(ir, (InternalCall, LibraryCall)):
                    callee = getattr(ir, "function", None)
                    cid = id(callee) if callee is not None else 0
                    if callee is None or cid in visited:
                        continue
                    callee_nodes = list(getattr(callee, "nodes", []) or [])
                    if callee_nodes:
                        names |= self._collect_state_var_writes(callee_nodes, visited | {cid})
        return names

    def _has_revert_reading_var(self, nodes: list[Any], var_name: str) -> bool:
        """Whether some node, or recursively a helper, has both a require/revert and a Binary reading ``var_name``,
        not necessarily in the same node; the helper's scope bounds it.
        """
        return self._search_revert_reading_var(nodes, var_name, set())

    def _search_revert_reading_var(self, nodes: list[Any], var_name: str, visited: set[int]) -> bool:
        has_revert = False
        has_var_read = False
        for n in nodes:
            irs = list(getattr(n, "irs_ssa", None) or getattr(n, "irs", []) or [])
            for ir in irs:
                if _ir_is_require_or_revert(ir):
                    has_revert = True
                if isinstance(ir, Binary):
                    for operand in (ir.variable_left, ir.variable_right):
                        if _base_state_var_name(operand) == var_name:
                            has_var_read = True
            if has_revert and has_var_read:
                return True
        if has_revert and has_var_read:
            return True
        for n in nodes:
            irs = list(getattr(n, "irs_ssa", None) or getattr(n, "irs", []) or [])
            for ir in irs:
                if isinstance(ir, (InternalCall, LibraryCall)):
                    callee = getattr(ir, "function", None)
                    cid = id(callee) if callee is not None else 0
                    if callee is None or cid in visited:
                        continue
                    callee_nodes = list(getattr(callee, "nodes", []) or [])
                    if callee_nodes and self._search_revert_reading_var(callee_nodes, var_name, visited | {cid}):
                        return True
        return False


def reentrancy_guard_modifiers(contract: Any) -> dict[int, frozenset[str]]:
    """``id(modifier) -> proven guard vars`` for ``contract``.

    Structural only: the name fallback in ``effects`` is suppress-only and must not reach this.
    """
    return ReentrancyAnalyzer(contract).reentrancy_guard_modifiers()


def live_declarations(contract: Any) -> dict[str, list[Any]]:
    """``full_name -> live non-constructor declarations``, dropping shadowed bases (``contract.functions`` includes
    overridden bases). A list, since several survivors is possible and must be refused. Missing ``is_shadowed``
    reads as live.
    """
    by_signature: dict[str, list[Any]] = {}
    for fn in getattr(contract, "functions", []) or []:
        if getattr(fn, "is_constructor", False) or getattr(fn, "is_shadowed", False):
            continue
        full_name = getattr(fn, "full_name", None) or getattr(fn, "name", None)
        if not isinstance(full_name, str) or not full_name:
            continue
        by_signature.setdefault(full_name, []).append(fn)
    return by_signature


def verified_guard_verdicts(contract: Any) -> dict[str, VerifiedGuardVerdict]:
    """Per-function W2 verified-guard verdicts by ``full_name``, total over live signatures.

    Signatures with two live bodies are refused. A function earns the proof only by carrying a proven guard modifier
    itself.
    """
    proven_modifiers = reentrancy_guard_modifiers(contract)
    contract_has_guard = bool(proven_modifiers)
    verdicts: dict[str, VerifiedGuardVerdict] = {}
    for full_name, declarations in live_declarations(contract).items():
        if len(declarations) > 1:
            verdicts[full_name] = _guard_refusal(W2_REASON_AMBIGUOUS_DECLARATION)
            continue
        fn = declarations[0]
        declaration = getattr(fn, "canonical_name", None) or full_name
        applied = [m for m in (getattr(fn, "modifiers", []) or []) if id(m) in proven_modifiers]
        if not applied:
            verdicts[full_name] = _guard_refusal(
                W2_REASON_GUARD_NOT_APPLIED if contract_has_guard else W2_REASON_NO_VERIFIED_GUARD,
                declaration,
            )
            continue
        guard_vars: set[str] = set()
        for modifier in applied:
            guard_vars |= proven_modifiers[id(modifier)]
        verdicts[full_name] = {
            "state": "proven",
            "basis": W2_VERIFIED_GUARD_BASIS,
            "reason": None,
            "declaration": declaration,
            "guard_vars": sorted(guard_vars),
            "guard_modifiers": sorted(
                {getattr(m, "canonical_name", None) or getattr(m, "name", "") for m in applied} - {""}
            ),
        }
    return verdicts


def _guard_refusal(reason: str, declaration: str | None = None) -> VerifiedGuardVerdict:
    return {
        "state": "not_determined",
        "basis": None,
        "reason": reason,
        "declaration": declaration,
        "guard_vars": [],
        "guard_modifiers": [],
    }


class PauseAnalyzer:
    """Pause state vars: written by an auth-gated function and reverted on in others."""

    def __init__(self, contract: Any, predicate_trees: dict[str, PredicateTree]) -> None:
        if not SLITHER_AVAILABLE:
            raise RuntimeError("PauseAnalyzer requires slither")
        self.contract = contract
        self.predicate_trees = predicate_trees

    def run(self) -> set[str]:
        pause_vars: set[str] = set()
        writers_by_var: dict[str, list[Any]] = {}
        for fn in self.contract.functions:
            if fn.is_constructor:
                continue
            for sv in fn.state_variables_written:
                writers_by_var.setdefault(sv.name, []).append(fn)
        for var_name, writers in writers_by_var.items():
            sv = self._lookup_state_var(var_name)
            if sv is None or not self._is_pause_typed(sv):
                continue
            if not self._is_latch_shaped(sv, var_name, writers):
                continue
            if any(self._writer_is_auth_gated(w) for w in writers):
                if self._read_with_revert_in_others(var_name, writers):
                    pause_vars.add(var_name)
        return pause_vars

    def _lookup_state_var(self, name: str) -> Any | None:
        """Inheritance-aware lookup: ``contract.state_variables`` omits an ancestor's ``private`` var, which can
        still be the latch (EigenLayer ``Pausable._paused``). ``_all_state_variables`` lists the contract first,
        so local shadowing wins.
        """
        for sv in _all_state_variables(self.contract):
            if sv.name == name:
                return sv
        return None

    def _is_pause_typed(self, sv: Any) -> bool:
        type_name = str(getattr(sv, "type", ""))
        return type_name in ("bool", "uint8", "uint256")

    def _is_latch_shaped(self, sv: Any, var_name: str, writers: list[Any]) -> bool:
        """A latch is a flag, not a quantity: OZ TimelockController's ``_minDelay`` also has the auth-write plus
        revert-read fingerprint.

        ``bool`` qualifies. ``uint8``/``uint256`` need flag evidence: a writer assigning a constant; a modifier reading
        it in a require/revert (EigenLayer); or a non-writer reverting on it compared ``==``/``!=`` to a constant.
        Governed quantities are compared relationally against parameters, which never matches. The equality test runs on
        predicate leaves (already polarity-folded, through getters and masks), with a same-node IR scan for degraded
        trees.
        """
        type_name = str(getattr(sv, "type", ""))
        if type_name == "bool":
            return True
        if self._has_constant_write(var_name, writers):
            return True
        # Inheritance-aware, and flag comparisons only: a relational bounds check in a modifier is a quantity read.
        for modifier in _all_modifiers(self.contract):
            if self._reads_with_revert(modifier, var_name, flag_comparison_only=True):
                return True
        if self._flag_read_with_revert(var_name, writers):
            return True
        return False

    def _flag_read_with_revert(self, var_name: str, writers: list[Any]) -> bool:
        """Some non-writer reverts on the var compared ``==``/``!=`` to a constant, checked on predicate leaves;
        falls back to the IR scan when the tree degraded.
        """
        writer_ids = {id(w) for w in writers}
        for fn in self.contract.functions:
            if fn.is_constructor or id(fn) in writer_ids:
                continue
            full_name = getattr(fn, "full_name", None)
            if not isinstance(full_name, str):
                continue
            tree = self.predicate_trees.get(full_name)
            if tree is not None and _tree_has_constant_equality_on_var(tree, var_name):
                return True
        return self._has_constant_equality_revert_read(var_name, writers)

    def _has_constant_equality_revert_read(self, var_name: str, writers: list[Any]) -> bool:
        """IR fallback: a non-writer's require/revert node directly compares the var to a Constant."""
        writer_ids = {id(w) for w in writers}
        for fn in self.contract.functions:
            if fn.is_constructor or id(fn) in writer_ids:
                continue
            for n in getattr(fn, "nodes", []) or []:
                irs = list(getattr(n, "irs_ssa", None) or getattr(n, "irs", []) or [])
                if not any(_ir_is_require_or_revert(ir) for ir in irs):
                    continue
                for ir in irs:
                    if not isinstance(ir, Binary):
                        continue
                    if getattr(ir, "type", None) not in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                        continue
                    for var_op, other_op in (
                        (ir.variable_left, ir.variable_right),
                        (ir.variable_right, ir.variable_left),
                    ):
                        if _base_state_var_name(var_op) != var_name:
                            continue
                        if type(other_op).__name__ == "Constant":
                            return True
        return False

    def _has_constant_write(self, var_name: str, writers: list[Any]) -> bool:
        for fn in writers:
            for node in getattr(fn, "nodes", []) or []:
                for ir in getattr(node, "irs", []) or []:
                    if type(ir).__name__ != "Assignment":
                        continue
                    if _base_state_var_name(getattr(ir, "lvalue", None)) != var_name:
                        continue
                    if type(getattr(ir, "rvalue", None)).__name__ == "Constant":
                        return True
        return False

    def _writer_is_auth_gated(self, fn: Any) -> bool:
        tree = self.predicate_trees.get(fn.full_name)
        if tree is None:
            return False
        return _tree_has_authority(tree)

    def _read_with_revert_in_others(self, var_name: str, writer_fns: list[Any]) -> bool:
        writer_ids = {id(w) for w in writer_fns}
        # Leaves only come from revert gates, so an operand on the var is a revert read, including through helpers
        # (``_requireNotPaused``).
        for fn in self.contract.functions:
            if fn.is_constructor or id(fn) in writer_ids:
                continue
            full_name = getattr(fn, "full_name", None)
            if not isinstance(full_name, str):
                continue
            tree = self.predicate_trees.get(full_name)
            if tree is not None and _tree_has_state_var_operand(tree, var_name):
                return True
        # Direct IR walk for inline ``require(!_paused)`` where the tree came out unsupported.
        for fn in self.contract.functions:
            if fn.is_constructor or id(fn) in writer_ids:
                continue
            containers = [fn] + (list(getattr(fn, "modifiers", []) or []))
            for c in containers:
                if self._reads_with_revert(c, var_name):
                    return True
        return False

    def _reads_with_revert(self, container: Any, var_name: str, *, flag_comparison_only: bool = False) -> bool:
        """Whether ``container`` has a require/revert reading ``var_name`` (Binary, Unary or direct), including
        through a helper call on a require node (EigenLayer ``require(!paused(index))``).

        With ``flag_comparison_only``, a Binary only counts when compared ``==``/``!=`` to a constant (a relational
        ``require(delay >= _minDelay)`` once made a delay setter both pause and unpause); truthiness reads still count.
        """
        for n in getattr(container, "nodes", []) or []:
            irs = list(getattr(n, "irs_ssa", None) or getattr(n, "irs", []) or [])
            if not any(_ir_is_require_or_revert(ir) for ir in irs):
                continue
            # The argument can be a Binary temporary, a Unary temporary or the var itself.
            if flag_comparison_only and _node_constant_equality_on_var(irs, var_name):
                return True
            for ir in irs:
                if isinstance(ir, Binary) and not flag_comparison_only:
                    for operand in (ir.variable_left, ir.variable_right):
                        if _base_state_var_name(operand) == var_name:
                            return True
                if isinstance(ir, Unary):
                    if _base_state_var_name(ir.rvalue) == var_name:
                        return True
                if _ir_is_require_or_revert(ir):
                    args = getattr(ir, "arguments", None) or []
                    for a in args:
                        if _base_state_var_name(a) == var_name:
                            return True
                if isinstance(ir, (InternalCall, LibraryCall)):
                    callee = getattr(ir, "function", None)
                    if callee is None:
                        continue
                    if flag_comparison_only:
                        if _function_constant_equality_on_var(callee, var_name):
                            return True
                    elif _function_reads_state_var(callee, var_name):
                        return True
        return False


def _function_reads_state_var(fn: Any, var_name: str, _seen: set[int] | None = None) -> bool:
    """Whether ``fn`` or its callees read the named state variable."""
    seen = _seen if _seen is not None else set()
    if id(fn) in seen:
        return False
    seen.add(id(fn))
    for sv in getattr(fn, "state_variables_read", []) or []:
        if getattr(sv, "name", None) == var_name:
            return True
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if isinstance(ir, (InternalCall, LibraryCall)):
                callee = getattr(ir, "function", None)
                if callee is not None and _function_reads_state_var(callee, var_name, seen):
                    return True
    return False


def _node_constant_equality_on_var(irs: list[Any], var_name: str) -> bool:
    """Whether, within one node, the var or a value derived from it is compared ``==``/``!=`` to a Constant or to one
    of its own feeds (the ``(_paused & mask) == mask`` idiom). Rejects relational bounds and comparisons against
    parameters. Taint flows forward in SSA order.
    """
    tainted: dict[str, set[str]] = {}

    def _feeds_of(op: Any) -> set[str] | None:
        if _base_state_var_name(op) == var_name:
            return set()
        name = getattr(op, "name", None)
        if isinstance(name, str) and name in tainted:
            return tainted[name]
        return None

    def _record(ir: Any, feeds: set[str]) -> None:
        lname = getattr(getattr(ir, "lvalue", None), "name", None)
        if isinstance(lname, str):
            tainted[lname] = feeds

    def _merged_feeds(operands: list[Any]) -> set[str]:
        feeds: set[str] = set()
        for op in operands:
            name = getattr(op, "name", None)
            if isinstance(name, str):
                feeds.add(name)
            op_feeds = _feeds_of(op)
            if op_feeds:
                feeds |= op_feeds
        return feeds

    for ir in irs:
        if isinstance(ir, Binary):
            left, right = ir.variable_left, ir.variable_right
            if getattr(ir, "type", None) in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
                for var_op, other_op in ((left, right), (right, left)):
                    feeds = _feeds_of(var_op)
                    if feeds is None:
                        continue
                    if type(other_op).__name__ == "Constant":
                        return True
                    other_name = getattr(other_op, "name", None)
                    if isinstance(other_name, str) and other_name in feeds:
                        return True
            if _feeds_of(left) is not None or _feeds_of(right) is not None:
                _record(ir, _merged_feeds([left, right]))
        elif isinstance(ir, Unary):
            rvalue = getattr(ir, "rvalue", None)
            if _feeds_of(rvalue) is not None:
                _record(ir, _merged_feeds([rvalue]))
        elif type(ir).__name__ == "Assignment":
            rvalue = getattr(ir, "rvalue", None)
            if _feeds_of(rvalue) is not None:
                _record(ir, _merged_feeds([rvalue]))
    return False


def _function_constant_equality_on_var(fn: Any, var_name: str, _seen: set[int] | None = None) -> bool:
    """Helper-hop variant over ``fn`` and its callees; nodes aren't limited to require nodes because EigenLayer's
    ``paused()`` computes the test on a return path.
    """
    seen = _seen if _seen is not None else set()
    if id(fn) in seen:
        return False
    seen.add(id(fn))
    for node in getattr(fn, "nodes", []) or []:
        irs = list(getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or [])
        if _node_constant_equality_on_var(irs, var_name):
            return True
        for ir in irs:
            if isinstance(ir, (InternalCall, LibraryCall)):
                callee = getattr(ir, "function", None)
                if callee is not None and _function_constant_equality_on_var(callee, var_name, seen):
                    return True
    return False


def _base_state_var_name(value: Any) -> str | None:
    """The state variable an SSA value traces to, without the SSA suffix."""
    if value is None:
        return None
    name = getattr(value, "name", None)
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    if hasattr(value, "non_ssa_version"):
        nsv = getattr(value, "non_ssa_version", None)
        if nsv is not None:
            return getattr(nsv, "name", None)
    return name


def _ir_is_require_or_revert(ir: Any) -> bool:
    if not isinstance(ir, SolidityCall):
        return False
    fn = getattr(ir, "function", None)
    nm = getattr(fn, "name", None) or str(fn or "")
    return nm.startswith("require(") or nm.startswith("revert(") or nm.startswith("revert ") or nm == "assert(bool)"


def _tree_has_state_var_operand(tree: PredicateTree, var_name: str) -> bool:
    """True iff some leaf reads ``var_name``; catches reads in helpers invisible in the outer IR."""
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is None:
            return False
        for op in leaf.get("operands") or []:
            if op.get("state_variable_name") == var_name:
                return True
        return False
    for child in tree.get("children") or []:
        if _tree_has_state_var_operand(child, var_name):
            return True
    return False


def _tree_has_constant_equality_on_var(tree: PredicateTree, var_name: str) -> bool:
    """True iff some leaf compares ``var_name`` ``eq``/``ne`` to a constant (a revert-gated latch read, since leaves
    only come from revert gates).
    """
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is None:
            return False
        if leaf.get("operator") not in ("eq", "ne"):
            return False
        operands = leaf.get("operands") or []
        reads_var = any(op.get("state_variable_name") == var_name for op in operands)
        has_constant = any(op.get("source") == "constant" for op in operands)
        return reads_var and has_constant
    for child in tree.get("children") or []:
        if _tree_has_constant_equality_on_var(child, var_name):
            return True
    return False


def _tree_has_authority(tree: PredicateTree) -> bool:
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is None:
            return False
        return leaf.get("authority_role") in ("caller_authority", "delegated_authority")
    for child in tree.get("children") or []:
        if _tree_has_authority(child):
            return True
    return False


def apply_reentrancy_pause_pass(
    contract: Any,
    predicate_trees: dict[str, PredicateTree],
) -> PauseInfo:
    """Run both analyzers, relabel leaves reading guard vars in place, and return ``PauseInfo``."""
    if not SLITHER_AVAILABLE:
        raise RuntimeError("apply_reentrancy_pause_pass requires slither")
    reentrancy_vars = ReentrancyAnalyzer(contract).run()
    pause_vars = PauseAnalyzer(contract, predicate_trees).run()

    pause_info = _build_pause_info(contract, pause_vars, reentrancy_vars)

    if not reentrancy_vars and not pause_vars:
        return pause_info
    for tree in predicate_trees.values():
        if tree is None:
            continue
        _walk_and_classify(tree, reentrancy_vars, pause_vars)

    # Promoted leaves need fresh confidence.
    from .predicates import apply_confidence_to_tree

    for tree in predicate_trees.values():
        apply_confidence_to_tree(tree)
    return pause_info


def _build_pause_info(
    contract: Any,
    pause_vars: set[str],
    reentrancy_vars: set[str],
) -> PauseInfo:
    """Function lists from the flagged vars: every writer of a pause var (not only the gated one), and every function
    applying a modifier that writes a reentrancy var.

    The latter is weak (the revert isn't rechecked per modifier) and is descriptive only; anything that must not trust a
    contract-scoped var uses :func:`verified_guard_verdicts`.
    """
    pause_toggle_fns: list[str] = []
    reentrancy_guarded_fns: list[str] = []
    seen_pause: set[str] = set()
    seen_reentrancy: set[str] = set()

    if pause_vars:
        for fn in getattr(contract, "functions", []) or []:
            if getattr(fn, "is_constructor", False):
                continue
            written = {getattr(v, "name", "") for v in (getattr(fn, "state_variables_written", []) or [])}
            if written & pause_vars:
                full_name = getattr(fn, "full_name", None) or getattr(fn, "name", None)
                if isinstance(full_name, str) and full_name and full_name not in seen_pause:
                    seen_pause.add(full_name)
                    pause_toggle_fns.append(full_name)

    if reentrancy_vars:
        reentrancy_modifier_ids: set[int] = set()
        for modifier in getattr(contract, "modifiers", []) or []:
            written = {getattr(v, "name", "") for v in (getattr(modifier, "state_variables_written", []) or [])}
            if written & reentrancy_vars:
                reentrancy_modifier_ids.add(id(modifier))
        for fn in getattr(contract, "functions", []) or []:
            if getattr(fn, "is_constructor", False):
                continue
            applied = list(getattr(fn, "modifiers", []) or [])
            if any(id(m) in reentrancy_modifier_ids for m in applied):
                full_name = getattr(fn, "full_name", None) or getattr(fn, "name", None)
                if isinstance(full_name, str) and full_name and full_name not in seen_reentrancy:
                    seen_reentrancy.add(full_name)
                    reentrancy_guarded_fns.append(full_name)

    return {
        "pause_state_vars": sorted(pause_vars),
        "pause_toggle_functions": sorted(pause_toggle_fns),
        "reentrancy_state_vars": sorted(reentrancy_vars),
        "reentrancy_guarded_functions": sorted(reentrancy_guarded_fns),
    }


def _walk_and_classify(tree: PredicateTree, reentrancy_vars: set[str], pause_vars: set[str]) -> None:
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is not None:
            _maybe_classify_guard_leaf(leaf, reentrancy_vars, pause_vars)
        return
    for child in tree.get("children") or []:
        _walk_and_classify(child, reentrancy_vars, pause_vars)


def _maybe_classify_guard_leaf(leaf: LeafPredicate, reentrancy_vars: set[str], pause_vars: set[str]) -> None:
    if leaf.get("authority_role") not in ("business", None):
        return
    operands = leaf.get("operands") or []
    for op in operands:
        sv_name = op.get("state_variable_name")
        if sv_name is None:
            continue
        if sv_name in reentrancy_vars:
            leaf["authority_role"] = "reentrancy"
            leaf["basis"] = list(leaf.get("basis", [])) + [f"reentrancy guard: {sv_name}"]
            return
        if sv_name in pause_vars and leaf.get("operator") in ("eq", "ne", "truthy", "falsy"):
            leaf["authority_role"] = "pause"
            leaf["basis"] = list(leaf.get("basis", [])) + [f"pause guard: {sv_name}"]
            return
