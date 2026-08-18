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

Both of the above are contract-scoped. ``verified_guard_verdicts`` is the
per-FUNCTION export built on the same structural proof, for consumers that
must not let a guard var declared somewhere on the contract stand in for a
guard applied to the function in hand.
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
# The guard roles this pass stamps are leaf-classifier vocabulary; a rename
# there must not strand these tokens.
assert set(get_args(StructuralGuardKind)) <= set(get_args(AuthorityRole))


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


W2_VERIFIED_GUARD_BASIS = "w2_verified_guard"

#: The function carries no modifier that the pre/post-placeholder + revert test
#: proves is a reentrancy guard, though the contract declares at least one such
#: modifier — a contract-scoped guard var licenses nothing here.
W2_REASON_GUARD_NOT_APPLIED = "guard_modifier_not_applied"
#: No modifier on the contract passes the test at all (fake set/restore pairs,
#: name-only locks, and transient-storage guards all land here).
W2_REASON_NO_VERIFIED_GUARD = "no_verified_guard_modifier"
#: Two live declarations answer to the same signature, so no single body is THE
#: function being asked about. Refuse rather than pick one.
W2_REASON_AMBIGUOUS_DECLARATION = "ambiguous_function_declaration"


class VerifiedGuardVerdict(TypedDict):
    """W2's verified-guard satisfier for ONE function, three-valued.

    ``state`` is ``"proven"`` only when a modifier that the analyzer's own
    pre/post-placeholder-write **and** revert-reading-the-var test proved is a
    reentrancy guard is applied to this very function. Everything else is
    ``"not_determined"`` carrying the reason — never a bare bool, and never a
    proven-absent: this arm cannot earn "this function needs no guard", so it
    never claims it.

    On a refusal ``basis`` is ``None`` and the evidence lists are empty; on a
    proof ``reason`` is ``None``. ``basis`` names WHICH proof succeeded so a
    consumer joining several W2 satisfiers can tell them apart.

    ``declaration`` is the canonical name of the body the verdict is about — the
    audit trail for the identity question, since a signature alone does not name
    a body in an inheritance chain.
    """

    state: Literal["proven", "not_determined"]
    basis: str | None
    reason: str | None
    declaration: str | None
    guard_vars: list[str]
    guard_modifiers: list[str]


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
        #
        # A modifier holding two guard vars at once used to contribute whichever
        # one set iteration reached first, i.e. a hash-seed-dependent answer.
        # Unioning the proven set publishes every var the modifier earned.
        for proven in self.reentrancy_guard_modifiers().values():
            guards |= proven
        # Function bodies could also contain inline guards (rare but
        # legal). Walk them with the same pre-/post-call pattern.
        for fn in getattr(self.contract, "functions", []) or []:
            v = self._function_guard_var(fn)
            if v is not None:
                guards.add(v)
        return guards

    def reentrancy_guard_modifiers(self) -> dict[int, frozenset[str]]:
        """``id(modifier) -> the guard vars that modifier is PROVEN to hold``,
        for every modifier the pre/post-placeholder + revert test admits.

        Same computation as :meth:`_modifier_guard_var`, with the modifier
        retained — which is what lets a caller ask whether *this* function
        carries a proven guard instead of only whether the contract declares a
        guard var somewhere. Modifiers proving nothing are absent.

        Keyed on ``id()`` rather than a name because that is the identity
        ``fn.modifiers`` can be joined against: Slither hands the derived
        contract its own copy of an inherited modifier, and the copy in
        ``contract.modifiers`` is the same object the applying function lists.
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
        # The same var written before AND after the placeholder.
        common = pre_writes & post_writes
        # Must also have a require/revert reading the same var
        # before the pre-write.
        return frozenset(var for var in common if self._has_revert_reading_var(nodes[:placeholder_idx], var))

    def _modifier_guard_var(self, modifier: Any) -> str | None:
        # Retained for callers wanting the single-var shape; ``run`` unions.
        guard_vars = self._proven_guard_vars(modifier)
        if not guard_vars:
            return None
        return sorted(guard_vars)[0]

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
# W2's verified-guard satisfier (the arm the payout witness consumes)
# ---------------------------------------------------------------------------


def reentrancy_guard_modifiers(contract: Any) -> dict[int, frozenset[str]]:
    """``id(modifier) -> proven guard vars`` for ``contract``.

    Deliberately NOT the name fallback: ``effects.py::_is_reentrancy_guard_var``
    ORs its structural proof with an identifier match, which is admissible only
    because that class is a pure suppressor. Nothing here is reachable from it.
    """
    return ReentrancyAnalyzer(contract).reentrancy_guard_modifiers()


def live_declarations(contract: Any) -> dict[str, list[Any]]:
    """``full_name -> the non-constructor declarations that signature still
    reaches``, shadowed ones dropped.

    ``contract.functions`` is every declaration in the linearized chain, so a
    signature overridden down the chain appears more than once and the base
    body — which the deployed contract never executes — is in there beside the
    override. Slither states the relation itself as ``is_shadowed``; that is the
    primitive used here rather than any iteration-order assumption. A signature
    is left as a LIST because more than one survivor is a real (if unusual)
    parse outcome, and the caller must decide, not a last-write-wins dict.

    ``is_shadowed`` missing is read as live, which can only produce a
    multi-survivor list — refused below — never a silent pick.
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
    """Per-function W2 verified-guard verdicts, keyed by ``full_name``.

    A signature is only a usable key because the declarations behind it are
    resolved first: the verdict describes the body that actually runs, and a
    signature answered by two live bodies is refused outright rather than
    decided by which one Slither yielded last. ``declaration`` carries the
    canonical name of whichever body was read.

    Total over the contract's live non-constructor signatures, so a caller reads
    a stated ``not_determined`` rather than inferring one from a missing key. The
    guard var set is contract-scoped; the join below is not — a function earns
    the proof only by carrying a proven guard modifier itself.
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
        """Inheritance-aware: ``contract.state_variables`` is the *accessible*
        view and excludes a ``private`` variable declared in an ancestor, but
        such a variable is still part of the derived contract's storage and
        can be its pause latch (EigenLayer's abstract ``Pausable`` declares
        ``uint256 private _paused``; every strategy inherits it). The writer
        index is built from ``contract.functions`` — inherited writers
        included — so the lookup must see the same declaration set or an
        inherited latch is vetoed at admission. ``_all_state_variables``
        orders ``[contract, *inheritance]``, so a shadowing local declaration
        still wins."""
        for sv in _all_state_variables(self.contract):
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
            ``==``/``!=``-vs-constant fingerprint. Tested on the
            predicate-LEAF plane (``_flag_read_with_revert``), where
            ``build_predicate_tree`` has already polarity-folded the gate
            and resolved indirection — so ``if (flag != 0) revert
            Paused()``, ``require(pausedStatus() == 0)`` (getter hop) and
            ``require(_paused & 1 == 0)`` (mask arithmetic) all surface as
            an ``eq``/``ne`` leaf pairing the state var with a constant.
            A same-node IR scan remains only as the fallback for functions
            whose tree degraded.
        """
        type_name = str(getattr(sv, "type", ""))
        if type_name == "bool":
            return True
        if self._has_constant_write(var_name, writers):
            return True
        # Inheritance-aware for the same reason as ``_lookup_state_var``:
        # the gating modifier is typically declared in the same ancestor as
        # the latch (mirrors ``_detect_pausability``'s ``_all_modifiers``).
        # Flag-comparison-only: a modifier-hosted RELATIONAL bounds check
        # (``modifier respectsDelay(uint256 d) { require(d >= _minDelay); }``)
        # is a governed quantity's read, not flag evidence — the same
        # discipline the constant-write and inline-equality arms already
        # apply.
        for modifier in _all_modifiers(self.contract):
            if self._reads_with_revert(modifier, var_name, flag_comparison_only=True):
                return True
        if self._flag_read_with_revert(var_name, writers):
            return True
        return False

    def _flag_read_with_revert(self, var_name: str, writers: list[Any]) -> bool:
        """Some non-writer reads the var under a revert compared for
        EQUALITY against a CONSTANT — checked on the same predicate-leaf
        plane ``_read_with_revert_in_others`` traverses (leaves only exist
        on RevertGate paths by construction, and the builder normalizes
        custom-error if/revert gates, getter hops, and mask arithmetic
        into an ``eq``/``ne`` leaf with a state-variable operand and a
        constant operand). A governed quantity's revert read publishes a
        RELATIONAL leaf (``comparison``/``gte`` against a parameter) and
        never matches. Falls back to the stricter same-node IR scan for
        functions whose tree degraded to None/unsupported."""
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
        """IR-plane fallback for ``_flag_read_with_revert`` when no
        predicate tree carries the read: a non-writer function has a
        require/revert-carrying node whose Binary compares the var itself
        ``==``/``!=`` a Constant. Direct operands only — a compare reached
        through arithmetic or a helper call is covered by the leaf-plane
        test (or, for modifier shapes, the modifier arm)."""
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

    def _reads_with_revert(self, container: Any, var_name: str, *, flag_comparison_only: bool = False) -> bool:
        """Returns True if container has a require/revert that
        reads ``var_name``. Checks Binary, Unary, and direct require
        of the state-var value — and, on a require-carrying node, reads
        reached through a helper call: EigenLayer's Pausable gates as
        ``modifier onlyWhenNotPaused(uint8 index) { require(!paused(index)); }``
        with the ``_paused`` read inside ``paused(index)``, so without the
        helper hop the real latch is invisible and the detector's only
        admission for such contracts was a fabricated quantity latch.

        ``flag_comparison_only`` (the ``_is_latch_shaped`` modifier arm): a
        Binary read qualifies only when the require-carrying node compares
        the var — or a value derived from it — ``==``/``!=`` against a
        CONSTANT. A relational bounds check (``require(delay >= _minDelay)``
        in a modifier) is a governed quantity's read, never flag evidence,
        and admitting it published ``is_pausable=true`` with the delay
        setter as both pause and unpause. The helper hop is filtered the
        same way (the callee must carry the flag comparison, not merely
        read the var). Truthiness reads of the var itself (Unary ``!`` /
        a direct require argument) are an implicit eq-vs-false — never
        relational — and keep qualifying. Default ``False`` preserves the
        permissive traversal for ``_read_with_revert_in_others``, where
        ``_is_latch_shaped`` has already vetted the shape."""
        for n in getattr(container, "nodes", []) or []:
            irs = list(getattr(n, "irs_ssa", None) or getattr(n, "irs", []) or [])
            if not any(_ir_is_require_or_revert(ir) for ir in irs):
                continue
            # The argument(s) to the require/revert can be: a TMP from
            # a Binary (require(a == b)), a TMP from a Unary
            # (require(!flag)), or a state-var read directly
            # (require(boolFlag)). We check all three.
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
                    # require(stateVar) directly — first argument is the var.
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


def _node_constant_equality_on_var(irs: list[Any], var_name: str) -> bool:
    """Within one node's (SSA) IR list: is the var — or a temporary derived
    from it through arithmetic/negation/assignment — compared ``==``/``!=``
    against a Constant, or back against one of its own derivation operands
    (the bit-test idiom ``(_paused & mask) == mask``)? Catches the direct
    latch check (``_paused == 0``) and both mask forms while rejecting
    relational bounds (``delay >= _minDelay``) and equality of the var
    against a parameter or unrelated temporary. Taint flows forward only,
    which matches SSA IR order within a node; each tainted temporary
    remembers the operand names that fed it."""
    tainted: dict[str, set[str]] = {}

    def _feeds_of(op: Any) -> set[str] | None:
        """Feed-set when ``op`` is the var itself (empty set) or a tainted
        temporary; ``None`` when it does not read the var."""
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
    """Helper-hop variant of ``_node_constant_equality_on_var``: does ``fn``
    (transitively through internal/library callees) carry a constant-
    equality comparison on the var in any node? Nodes are NOT filtered to
    require-carrying ones — in the EigenLayer shape the ``paused()`` getter
    computes the flag test on a return path while the revert lives at the
    modifier's own require."""
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


def _tree_has_constant_equality_on_var(tree: PredicateTree, var_name: str) -> bool:
    """True iff some leaf pairs a read of state-variable ``var_name`` with a
    CONSTANT under an ``eq``/``ne`` operator — the latch fingerprint on the
    leaf plane. The builder emits leaves only from RevertGate paths, so a
    match is a revert-gated equality-vs-constant read by construction."""
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

    That last selection is the WEAK predicate — "some modifier writes a var the
    analyzer flagged" — and it is not a guard proof: the revert conjunct is not
    re-checked per modifier, so a modifier that merely touches the var enrolls
    its functions. It stays as-is because this list is a descriptive export.
    Anything that must not be licensed by a contract-scoped var reads
    :func:`verified_guard_verdicts` instead, which joins against the proven set.
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
