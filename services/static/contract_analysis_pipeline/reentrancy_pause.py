"""ReentrancyAnalyzer + PauseAnalyzer — week 3 deliverables.

Both classify state-variable reads in predicate trees as
``authority_role="reentrancy"`` or ``"pause"`` rather than
the default business — so the resolver knows these aren't caller-
authority gates and the UI can render them as side-conditions.

Detection is purely structural — no name matching:

ReentrancyAnalyzer:
  A modifier or function body M qualifies as a reentrancy guard if:
    (a) it has writes to the same state variable V both BEFORE and
        AFTER a PLACEHOLDER node (or before/after each external
        call site for non-modifier guards), AND
    (b) it reads V with require/revert at entry and the revert
        condition involves V being equal to the "entered" sentinel
        (which is the post-write value before the placeholder).

  Common reentrancy-guard shape:
      require(_status != _ENTERED);
      _status = _ENTERED;          // pre-placeholder write
      _;                           // placeholder
      _status = _NOT_ENTERED;      // post-placeholder write

PauseAnalyzer:
  A bool state variable V is a pause flag if:
    (a) at least one writer function W has a caller_authority or
        delegated_authority leaf in its predicate tree, AND
    (b) other functions read V and revert when V is true (or
        whichever value indicates "paused" — detected by the
        presence of a single write per writer that toggles V).

  Common pausable shape:
      modifier whenNotPaused() { require(!_paused); _; }
      function pause() onlyOwner { _paused = true; }

Output: per-storage-var classification dict ``{var_name → role}``.
The predicate builder consumes this in a follow-up pass to update
membership/equality leaves reading those vars.
"""

from __future__ import annotations

from typing import Any, Literal, TypedDict

try:
    from slither.core.cfg.node import NodeType  # type: ignore[import]
    from slither.slithir.operations import (  # type: ignore[import]
        Assignment,
        Binary,
        BinaryType,
        InternalCall,
        LibraryCall,
        SolidityCall,
        Unary,
    )

    SLITHER_AVAILABLE = True
except Exception:  # pragma: no cover
    SLITHER_AVAILABLE = False

from .predicate_types import LeafPredicate, PredicateTree

GuardKind = Literal["reentrancy", "pause"]


class PauseInfo(TypedDict):
    """Structured export from ``apply_reentrancy_pause_pass``.

    Lets ``_detect_pausability`` consume the structural classification
    directly. ``pause_state_vars`` + ``reentrancy_state_vars`` are the
    names PauseAnalyzer/ReentrancyAnalyzer flagged; the function lists
    are derived from each state var's writers / from modifiers that
    toggle the var."""

    pause_state_vars: list[str]
    pause_toggle_functions: list[str]
    reentrancy_state_vars: list[str]
    reentrancy_guarded_functions: list[str]


# ---------------------------------------------------------------------------
# ReentrancyAnalyzer
# ---------------------------------------------------------------------------


class ReentrancyAnalyzer:
    """Identify reentrancy guard state vars by walking modifier
    bodies for the canonical pre/post-placeholder write pattern.

    Output: a set of state variable names that, when read in a
    function's gate, mean the function has reentrancy protection
    (not caller authority)."""

    def __init__(self, contract: Any) -> None:
        if not SLITHER_AVAILABLE:
            raise RuntimeError("ReentrancyAnalyzer requires slither")
        self.contract = contract

    def run(self) -> set[str]:
        guards: set[str] = set()
        # Scan modifier bodies. Modifiers are the canonical home for
        # ReentrancyGuard-style patterns (the entire write-pre-write-
        # post-placeholder dance lives there).
        for modifier in getattr(self.contract, "modifiers", []) or []:
            v = self._modifier_guard_var(modifier)
            if v is not None:
                guards.add(v)
        # Function bodies could also contain inline guards (rare but
        # legal). Walk them with the same pre-/post-call pattern.
        for fn in getattr(self.contract, "functions", []) or []:
            v = self._function_guard_var(fn)
            if v is not None:
                guards.add(v)
        return guards

    def _modifier_guard_var(self, modifier: Any) -> str | None:
        nodes = getattr(modifier, "nodes", []) or []
        placeholder_idx = self._find_placeholder_index(nodes)
        if placeholder_idx is None:
            return None
        pre_writes = self._state_var_writes(nodes[:placeholder_idx])
        post_writes = self._state_var_writes(nodes[placeholder_idx + 1 :])
        # The same var written before AND after the placeholder.
        common = pre_writes & post_writes
        if not common:
            return None
        # Must also have a require/revert reading the same var
        # before the pre-write.
        for var in common:
            if self._has_revert_reading_var(nodes[:placeholder_idx], var):
                return var
        return None

    def _function_guard_var(self, fn: Any) -> str | None:
        # Inline guard pattern: same write/restore around each
        # external call within the function. Rare; not modeled yet.
        return None

    def _find_placeholder_index(self, nodes: list[Any]) -> int | None:
        for i, n in enumerate(nodes):
            if getattr(n, "type", None) == getattr(NodeType, "PLACEHOLDER", -1):
                return i
        return None

    def _state_var_writes(self, nodes: list[Any]) -> set[str]:
        return self._collect_state_var_writes(nodes, set())

    def _collect_state_var_writes(self, nodes: list[Any], visited: set[int]) -> set[str]:
        """Walk ``nodes`` recursively through InternalCall helpers to
        find every state-variable write. Some guard implementations split
        pre-write/post-write logic into helper functions, so the modifier's
        own nodes may only contain InternalCall IRs. Cycle-safe via
        ``visited``."""
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
        """A helper-aware search: returns True if some descendant (node
        or recursively-walked InternalCall callee) contains BOTH a
        require/revert AND a Binary reading ``var_name``. They don't
        need to be in the same node. Same-node co-location was the previous overly-tight
        match; loosening to per-callee scope catches the cross-fn
        if-revert structure without false positives (the helper's
        scope already bounds what counts as 'this revert reads this
        var')."""
        return self._search_revert_reading_var(nodes, var_name, set())

    def _search_revert_reading_var(self, nodes: list[Any], var_name: str, visited: set[int]) -> bool:
        # First pass: same-scope check (var-read + require/revert in
        # the current ``nodes`` list). Co-location not required —
        # they just have to coexist in this helper's body.
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
        # Recurse into helpers — the var-read AND revert may both live
        # one level deeper.
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


# ---------------------------------------------------------------------------
# PauseAnalyzer
# ---------------------------------------------------------------------------


class PauseAnalyzer:
    """Identify pause state-vars: a state var written by an auth-
    gated function and read with revert in other functions."""

    def __init__(self, contract: Any, predicate_trees: dict[str, PredicateTree]) -> None:
        if not SLITHER_AVAILABLE:
            raise RuntimeError("PauseAnalyzer requires slither")
        self.contract = contract
        self.predicate_trees = predicate_trees

    def run(self) -> set[str]:
        pause_vars: set[str] = set()
        # Build write index: state_var → writer functions.
        writers_by_var: dict[str, list[Any]] = {}
        for fn in self.contract.functions:
            if fn.is_constructor:
                continue
            for sv in fn.state_variables_written:
                writers_by_var.setdefault(sv.name, []).append(fn)
        # For each candidate var, check writer authority.
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
        for sv in getattr(self.contract, "state_variables", []) or []:
            if sv.name == name:
                return sv
        return None

    def _is_pause_typed(self, sv: Any) -> bool:
        # bool or uint8 typically; we accept both.
        type_name = str(getattr(sv, "type", ""))
        return type_name in ("bool", "uint8", "uint256")

    def _is_latch_shaped(self, sv: Any, var_name: str, writers: list[Any]) -> bool:
        """A pause latch is a FLAG, not a quantity. The written-by-auth +
        read-with-revert fingerprint alone also matches a governed NUMERIC
        parameter — OZ TimelockController's ``uint256 _minDelay`` is written
        by the auth-gated ``updateDelay`` and read inside ``schedule``'s
        insufficient-delay revert, and classifying it as a latch published
        ``is_pausable=true`` on contracts with no pause mechanism at all.

        * ``bool`` — a flag by type; qualifies as-is (covers both
          constant-toggle ``pause()/unpause()`` pairs and parameter-driven
          ``setPaused(bool)`` setters).
        * ``uint8``/``uint256`` — qualifies only on flag evidence:
          - some writer assigns a CONSTANT to the var (``paused = 1``); a
            duration/delay setter assigns a parameter or derived value; or
          - a modifier reads the var inside a require/revert (the
            EigenLayer shape: ``uint256 _paused`` written from a parameter
            but gating via ``whenNotPaused``-style modifiers); or
          - a non-writer reverts on the var compared for EQUALITY against
            a CONSTANT (``require(pausedStatus == 0)`` inline in a function
            body — parameter-written, no modifier). A latch is checked
            against a distinguished value; a governed quantity's revert
            read is RELATIONAL against a parameter (``_minDelay`` under
            ``require(delay >= getMinDelay())``), which never matches the
            ``==``/``!=``-vs-constant fingerprint.
        """
        type_name = str(getattr(sv, "type", ""))
        if type_name == "bool":
            return True
        if self._has_constant_write(var_name, writers):
            return True
        for modifier in getattr(self.contract, "modifiers", []) or []:
            if self._reads_with_revert(modifier, var_name):
                return True
        if self._has_constant_equality_revert_read(var_name, writers):
            return True
        return False

    def _has_constant_equality_revert_read(self, var_name: str, writers: list[Any]) -> bool:
        """Some non-writer function has a require/revert-carrying node whose
        Binary compares the var itself ``==``/``!=`` a Constant. Direct
        operands only — a compare reached through arithmetic or a helper
        call is out (the modifier arm covers the helper shapes)."""
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
        # Fast path 1: scan already-built predicate_trees. A leaf with
        # an operand carrying ``state_variable_name == var_name`` came
        # from a revert-detected gate by construction (build_predicate-
        # _tree only emits leaves from RevertGate paths). This catches
        # cross-fn cases where the actual read lives in a helper
        # (``_requireNotPaused`` calling
        # ``if (_paused) revert``) — the helper's revert doesn't show
        # up in the modifier's body IRs but the predicate builder has
        # already resolved it via cross-fn provenance walking.
        for fn in self.contract.functions:
            if fn.is_constructor or id(fn) in writer_ids:
                continue
            full_name = getattr(fn, "full_name", None)
            if not isinstance(full_name, str):
                continue
            tree = self.predicate_trees.get(full_name)
            if tree is not None and _tree_has_state_var_operand(tree, var_name):
                return True
        # Fast path 2: direct-IR walk for inline patterns
        # (``require(!_paused)`` in the modifier itself). Kept for
        # belt-and-braces — there are shapes where the predicate tree
        # might emit unsupported but the underlying body still has a
        # direct revert-with-statevar read.
        for fn in self.contract.functions:
            if fn.is_constructor or id(fn) in writer_ids:
                continue
            containers = [fn] + (list(getattr(fn, "modifiers", []) or []))
            for c in containers:
                if self._reads_with_revert(c, var_name):
                    return True
        return False

    def _reads_with_revert(self, container: Any, var_name: str) -> bool:
        """Returns True if container has a require/revert that
        reads ``var_name``. Checks Binary, Unary, and direct require
        of the state-var value — and, on a require-carrying node, reads
        reached through a helper call: EigenLayer's Pausable gates as
        ``modifier onlyWhenNotPaused(uint8 index) { require(!paused(index)); }``
        with the ``_paused`` read inside ``paused(index)``, so without the
        helper hop the real latch is invisible and the detector's only
        admission for such contracts was a fabricated quantity latch. The
        latch-shape check (``_is_latch_shaped``) is what keeps this hop
        safe: a duration read through a getter under a bounds require
        (TimelockController's ``getMinDelay()``) still fails the flag test."""
        for n in getattr(container, "nodes", []) or []:
            irs = list(getattr(n, "irs_ssa", None) or getattr(n, "irs", []) or [])
            if not any(_ir_is_require_or_revert(ir) for ir in irs):
                continue
            # The argument(s) to the require/revert can be: a TMP from
            # a Binary (require(a == b)), a TMP from a Unary
            # (require(!flag)), or a state-var read directly
            # (require(boolFlag)). We check all three.
            for ir in irs:
                if isinstance(ir, Binary):
                    for operand in (ir.variable_left, ir.variable_right):
                        if _base_state_var_name(operand) == var_name:
                            return True
                if isinstance(ir, Unary):
                    if _base_state_var_name(ir.rvalue) == var_name:
                        return True
                if _ir_is_require_or_revert(ir):
                    # require(stateVar) directly — first argument is the var.
                    args = getattr(ir, "arguments", None) or []
                    for a in args:
                        if _base_state_var_name(a) == var_name:
                            return True
                if isinstance(ir, (InternalCall, LibraryCall)):
                    callee = getattr(ir, "function", None)
                    if callee is not None and _function_reads_state_var(callee, var_name):
                        return True
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _function_reads_state_var(fn: Any, var_name: str, _seen: set[int] | None = None) -> bool:
    """Does ``fn`` (transitively through internal/library callees) read the
    named state variable? Bounded recursion with a visited set."""
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


def _base_state_var_name(value: Any) -> str | None:
    """Return the underlying state-variable name for an SSA value
    that traces back to one. Strips Slither's ``_<n>`` SSA suffix."""
    if value is None:
        return None
    name = getattr(value, "name", None)
    if not isinstance(name, str):
        return None
    # SSA suffix: ``_status_3`` → ``_status``.
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    # Direct StateVariable / ReferenceVariable references.
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
    """True iff some leaf in ``tree`` has an operand reading the
    state-variable ``var_name``. Used by PauseAnalyzer to detect
    cross-fn revert paths (helper calls if-revert on _paused) where
    the var read doesn't appear in the outer function's IRs."""
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


# ---------------------------------------------------------------------------
# Apply pass: classify gate leaves whose operand reads a guard var.
# ---------------------------------------------------------------------------


def apply_reentrancy_pause_pass(
    contract: Any,
    predicate_trees: dict[str, PredicateTree],
) -> PauseInfo:
    """Run both analyzers, mutate predicate_trees in place, and return
    a ``PauseInfo`` so ``_detect_pausability`` can consume the
    structural classification directly.

    Leaves whose operands read a reentrancy/pause var get their
    ``authority_role`` updated. Pure-side-condition leaves (no other
    auth basis) end up annotated rather than admitted.
    """
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

    # Re-stamp confidence so leaves promoted to reentrancy/pause
    # don't keep their previous business/low confidence value.
    from .predicates import apply_confidence_to_tree

    for tree in predicate_trees.values():
        apply_confidence_to_tree(tree)
    return pause_info


def _build_pause_info(
    contract: Any,
    pause_vars: set[str],
    reentrancy_vars: set[str],
) -> PauseInfo:
    """Derive function lists from the analyzer-flagged state-var sets.

    * ``pause_toggle_functions``: every non-constructor function that
      writes any pause state var. PauseAnalyzer only admits a var after
      one writer has been auth-gated, but we list ALL writers so
      consumers can spot misconfigured-but-detectable pause shapes.
    * ``reentrancy_guarded_functions``: every function whose modifier
      list includes a reentrancy-classified modifier (one whose body
      writes a reentrancy var on both sides of PLACEHOLDER).
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
        # A modifier is reentrancy-classified if its body writes any
        # reentrancy var. Functions that apply such a modifier are
        # reentrancy-guarded.
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
    # Skip already-classified non-business leaves.
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
        if sv_name in pause_vars:
            leaf["authority_role"] = "pause"
            leaf["basis"] = list(leaf.get("basis", [])) + [f"pause guard: {sv_name}"]
            return
