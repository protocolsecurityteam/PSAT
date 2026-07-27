"""RevertDetector — structured walk of all gated revert paths in a function.

Returns a list of ``RevertGate`` records, each describing:
  * the IR-level condition value that, when violated, leads to the revert
  * the polarity: ``allowed_when="C"`` means require(C); ``allowed_when=
    "not C"`` means if(C) revert (predicate builder pushes the NOT into
    each leaf's operator).
  * the kind: ``require / assert / custom_revert / inline_asm /
    try_catch_revert / external_call_revert / function_pointer_check / opaque``

Per the v4 plan (round-2 finding #8 on edge-case soundness), we cover:
  1. require / require with msg
  2. assert
  3. if (C) revert / revert ErrorName(args)
  4. SolidityCall(revert)
  5. assembly { if iszero(X) { revert(0,0) } }   — inline asm conditional
  6. try external.call() catch { revert(); }     — try/catch fallback
  7. State-stored function pointer dispatch:
        function p; require(p == expectedSig)
     The function-pointer source is classified via ProvenanceEngine; the
     gate is then a normal equality leaf of two state-vars (or
     state-var+constant). Authority classification depends on whether
     either operand traces to msg.sender; otherwise the leaf is
     business.
  8. Fully-opaque control flow (Yul jumps not modeled by Slither): the
     detector emits a single ``opaque`` gate with no condition and the
     predicate builder turns this into a ``kind="unsupported",
     reason="opaque_control_flow"`` leaf.

Cases 1-4 use shared structural revert primitives; cases 5-7 are added
here. Case 8 is detected by checking whether the function has any
InlineAssemblyOperation IR that we couldn't resolve — at which point
we mark the function as needing review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

try:
    from slither.core.cfg.node import NodeType  # type: ignore[import]
    from slither.core.declarations.modifier import Modifier  # type: ignore[import]
    from slither.slithir.operations import (  # type: ignore[import]
        Condition,
        HighLevelCall,
        InternalCall,
        LibraryCall,
    )

    SLITHER_AVAILABLE = True
except Exception:  # pragma: no cover
    SLITHER_AVAILABLE = False
    Modifier = type(None)  # placeholder


DEFAULT_INTERNAL_CALL_DEPTH = 4

# How far the branch walk chases a helper-calls-helper chain when deciding
# whether a CALLEE always reverts. A direct always-reverting helper (Solady
# ``_revertEnumerableRolesUnauthorized``) and one further hop resolve; deeper
# chains fall back to the conservative False (miss the gate rather than
# fabricate one). Kept small: real revert helpers are 1-2 hops deep.
CALLEE_REVERT_MAX_DEPTH = 3


RevertKind = Literal[
    "require",
    "assert",
    "custom_revert",
    "if_revert",
    "inline_asm",
    "try_catch_revert",
    "external_call_revert",
    "opaque",
]

Polarity = Literal["allowed_when_true", "allowed_when_false"]


@dataclass
class RevertGate:
    """One gated revert path in a function.

    The predicate builder consumes a list of these to construct the
    function's PredicateTree. Multiple gates AND together at the tree
    root.
    """

    kind: RevertKind
    # The condition IR value that drives the revert. None for opaque
    # / unconditional revert paths.
    condition_value: Any = None
    polarity: Polarity = "allowed_when_true"
    # Slither node where the gate lives — used by the predicate builder
    # for parameter-binding / modifier-frame lookups.
    node: Any = None
    # Slither function/modifier whose body contains the gate node.
    # When the gate is inside a cross-function helper (e.g.,
    # ``_checkRole`` called from a modifier), this is the helper —
    # the predicate builder uses it to walk the condition's defining
    # IR through the right scope.
    containing_function: Any = None
    # Cross-fn call chain: list of InternalCall/LibraryCall IRs taken
    # to reach the gate's containing_function from the top-level
    # function being analyzed. Used by the predicate builder to
    # substitute the helper's parameters with the caller's argument
    # provenance (full ParameterBindingEnv per v4 plan §predicates).
    call_chain: list[Any] = field(default_factory=list)
    # Diagnostic text for predicate.expression / leaf.basis.
    expression_text: str = ""
    basis: list[str] = field(default_factory=list)
    # If kind=="opaque", the reason string surfaced as
    # unsupported_reason on the predicate leaf.
    unsupported_reason: str | None = None


# ---------------------------------------------------------------------------
# Primitive predicates exposed as building blocks the predicate builder
# can call directly.
# ---------------------------------------------------------------------------


def _ir_class(ir: Any) -> str:
    return type(ir).__name__


def _ir_is_solidity_revert(ir: Any) -> bool:
    """Slither emits SolidityCall(``revert(...)``) for both Solidity-
    level reverts and Yul-level revert(offset, length). The signature
    string varies (``revert()``, ``revert(string)``, ``revert(uint256,
    uint256)``, ``revert ErrorName``), so we accept any SolidityCall
    whose function name begins with ``revert(`` or ``revert ``."""
    if _ir_class(ir) != "SolidityCall":
        return False
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return name.startswith("revert(") or name.startswith("revert ")


def _ir_is_require(ir: Any) -> bool:
    if _ir_class(ir) != "SolidityCall":
        return False
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    # ``require(bool,error)`` is the Solidity >=0.8.26 custom-error form
    # (``require(cond, MyError())``). Slither lowers it to a SolidityCall
    # named exactly that, with the condition as the first argument — the
    # same shape ``_gate_from_solidity_call`` already consumes. Omitting it
    # silently dropped the gate, leaving the predicate tree empty and the
    # function defaulting to public; it must be recognized like the other
    # two forms.
    return name in ("require(bool)", "require(bool,string)", "require(bool,error)")


def _ir_is_assert(ir: Any) -> bool:
    if _ir_class(ir) != "SolidityCall":
        return False
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return name == "assert(bool)"


def _ir_is_revert(ir: Any) -> bool:
    """Any ``revert`` form, including ``revert(string)``. Used only to decide
    that a value is on the REVERT path (a message operand) rather than on the
    guard path — see ``_lvalue_already_lifted``."""
    if _ir_class(ir) != "SolidityCall":
        return False
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return name.startswith("revert")


# ---------------------------------------------------------------------------
# Detector entry point
# ---------------------------------------------------------------------------


class RevertDetector:
    """Walk a function's IR and return all gated revert paths.

    Usage:
        detector = RevertDetector(function)
        gates = detector.run()  # list[RevertGate]
    """

    def __init__(
        self,
        function: Any,
        *,
        internal_call_depth: int = DEFAULT_INTERNAL_CALL_DEPTH,
    ) -> None:
        if not SLITHER_AVAILABLE:
            raise RuntimeError("RevertDetector requires slither")
        self.function = function
        self.internal_call_depth = internal_call_depth
        self._gates: list[RevertGate] = []
        self._call_stack: list[str] = []
        # Stack of InternalCall IRs traversed to reach the current
        # node. Each gate found inside a helper records this chain
        # so the predicate builder can build parameter bindings.
        self._call_chain_irs: list[Any] = []
        # Every node we walked (this function + recursed helpers), so the
        # coverage invariant in ``run`` can tell a node that produced a gate
        # apart from one carrying an unmodeled require/assert (the fail-safe
        # against silent-public on a require form we don't structurally lift).
        self._scanned_nodes: list[Any] = []
        # Per-container cache of the value names that transitively reach a
        # branch condition or a require/assert argument, for the
        # already-lifted test in ``_scan_node``.
        self._container_condition_reads: dict[int, set[str]] = {}
        # Memo for ``_callee_always_reverts``, keyed by (id(callee), depth).
        # Depth is part of the key because the ``CALLEE_REVERT_MAX_DEPTH`` cutoff
        # makes the answer depth-relative — a helper resolved at one depth may be
        # cut off (conservative False) at a deeper one. ``id()`` keys are scoped
        # to this per-function detector, so they never outlive the Slither parse.
        self._callee_revert_cache: dict[tuple[int, int], bool] = {}
        # Callee ids currently on the always-reverts recursion stack, so a helper
        # that (in)directly calls itself reports escape on the back-edge rather
        # than spinning.
        self._callee_revert_inprogress: set[int] = set()
        # Per-detector memo for ``str(node.expression)``, keyed by
        # ``id(expression)``. Scoped to this (per-function) detector so it's
        # GC'd with the instance — the id() keys never outlive the Slither
        # parse they index. Repeated ``str(expr)`` over literal/binary chains
        # is the dominant predicate-bench cost, so the memo stays; only its
        # lifetime is bounded.
        self._expression_text_cache: dict[int, str] = {}

    def _expression_text(self, node: Any) -> str:
        expr = getattr(node, "expression", None)
        if expr is None:
            return ""
        key = id(expr)
        cached = self._expression_text_cache.get(key)
        if cached is not None:
            return cached
        text = str(expr)
        self._expression_text_cache[key] = text
        return text

    def run(self) -> list[RevertGate]:
        # Walk the function's own body. Modifier-call IRs and
        # internal-call IRs are both traversed via the in-body scan
        # (the recursion handles both uniformly), so the call_chain
        # captures modifier parameter bindings naturally — needed
        # for full caller-side ParameterBindingEnv when a public entrypoint
        # routes through nested helper guards with dynamic parameters.
        for node in self.function.nodes:
            self._scan_node(node, container=self.function)
        # Case 8: opaque-Yul fallback.
        if self._has_unresolved_revert_in_assembly():
            self._gates.append(
                RevertGate(
                    kind="opaque",
                    unsupported_reason="opaque_control_flow",
                    expression_text="<inline assembly with unresolved revert>",
                )
            )
        # Coverage invariant (fail-safe): a require()/assert() SolidityCall we
        # walked but did NOT lift into a gate means a revert *form* we don't
        # model (a future require variant, a shape the lifter rejected). Letting
        # it slip leaves the tree empty and the function defaults to public —
        # exactly the silent open-on-extraction-gap this detector must never
        # produce. Surface it as ``unsupported`` so the function resolves gated,
        # not public. ``require(bool,error)`` is recognized now, so this fires
        # only on genuinely unmodeled forms — never on the known three.
        if self._has_unmodeled_require_assert_gate():
            self._gates.append(
                RevertGate(
                    kind="opaque",
                    unsupported_reason="unmodeled_require_gate",
                    expression_text="<require/assert form not structurally modeled>",
                )
            )
        return self._gates

    # ------------------------------------------------------------------
    # Per-node classification
    # ------------------------------------------------------------------

    def _lvalue_already_lifted(self, lvalue: Any, container: Any) -> bool:
        """Does a call's result reach a branch condition, or any argument of a
        require / assert / revert, in ``container``'s body?

        Only such a result is either lifted into a leaf by the predicate
        builder or already on the revert path itself, so only such a result may
        suppress the recursion into the callee. Being read *at all* is a
        strictly weaker property and answering with it lost every gate behind a
        ``return gatedCallee(...)`` forwarder: the RETURN node reads the result,
        no condition ever does, and the callee's own require was therefore
        never walked — the function resolved unguarded.

        The revert family is in the seed set for the opposite reason. A
        ``revert(string(abi.encodePacked(..., Strings.toHexString(...))))``
        message builder is ON the revert path, not on the guard path, and its
        own internal ``require`` is a bounds check inside a formatter. Recursing
        into it lifts that check as a gate on the CALLER — OZ's ``_checkRole``
        would acquire a "hex length insufficient" authority leaf. Seeding on the
        whole IR's read set (condition AND message operands) keeps both out.

        The reachability is transitive (``bool ok = _check(); bool z = ok &&
        other; require(z);``), so it is a backwards closure from those operands
        over each IR's ``lvalue -> read`` edges. Names (not identities) are
        compared because nodes mix ``irs_ssa`` and ``irs`` views."""
        if container is None:
            return True  # no scope to prove otherwise — keep the legacy skip
        key = id(container)
        feeding = self._container_condition_reads.get(key)
        if feeding is None:
            defs: dict[str, set[str]] = {}
            seeds: set[str] = set()
            for body_node in getattr(container, "nodes", []) or []:
                for body_ir in list(getattr(body_node, "irs_ssa", None) or []) + list(
                    getattr(body_node, "irs", []) or []
                ):
                    reads = {str(read) for read in (getattr(body_ir, "read", []) or [])}
                    body_lvalue = getattr(body_ir, "lvalue", None)
                    if body_lvalue is not None and reads:
                        defs.setdefault(str(body_lvalue), set()).update(reads)
                    if (
                        isinstance(body_ir, Condition)
                        or _ir_is_require(body_ir)
                        or _ir_is_assert(body_ir)
                        or _ir_is_revert(body_ir)
                    ):
                        seeds |= reads
            feeding = set(seeds)
            work = list(seeds)
            while work:
                name = work.pop()
                for source in defs.get(name, ()):
                    if source not in feeding:
                        feeding.add(source)
                        work.append(source)
            self._container_condition_reads[key] = feeding
        return str(lvalue) in feeding

    def _scan_node(self, node: Any, container: Any = None) -> None:
        self._scanned_nodes.append(node)
        # Case 1-2: require / assert directly in this node.
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if _ir_is_require(ir):
                self._gates.append(self._gate_from_solidity_call(ir, node, "require", container))
                return
            if _ir_is_assert(ir):
                self._gates.append(self._gate_from_solidity_call(ir, node, "assert", container))
                return

        # Case 6: try/catch with revert in the catch block. The
        # function reverts iff the try-body call reverts. When the
        # try-body has a SINGLE HighLevelCall, we record it as
        # ``try_catch_revert``
        # with the call IR preserved so the predicate builder can lift
        # the call's selector + target into an external_check_only leaf.
        # When the try-body has zero or multiple HighLevelCalls, we fall
        # back to the original opaque marker — the call's identity is
        # ambiguous and downstream cannot characterize the gate further.
        if getattr(node, "type", None) == getattr(NodeType, "TRY", -999):
            if self._try_catch_has_revert(node):
                primary_call = self._try_node_primary_call(node)
                if primary_call is not None:
                    self._gates.append(
                        RevertGate(
                            kind="try_catch_revert",
                            condition_value=primary_call,
                            polarity="allowed_when_true",
                            node=node,
                            containing_function=container,
                            call_chain=list(self._call_chain_irs),
                            expression_text=self._expression_text(node) or "<try/catch>",
                            basis=["try/catch with revert in catch (recognized call shape)"],
                            unsupported_reason=None,
                        )
                    )
                    return
                self._gates.append(
                    RevertGate(
                        kind="opaque",
                        condition_value=None,
                        polarity="allowed_when_true",
                        node=node,
                        containing_function=container,
                        call_chain=list(self._call_chain_irs),
                        expression_text=self._expression_text(node) or "<try/catch>",
                        basis=["try/catch with revert in catch"],
                        unsupported_reason="opaque_try_catch",
                    )
                )
                return
            return

        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, HighLevelCall) and getattr(ir, "lvalue", None) is None:
                self._gates.append(
                    RevertGate(
                        kind="external_call_revert",
                        condition_value=ir,
                        polarity="allowed_when_true",
                        node=node,
                        containing_function=container,
                        call_chain=list(self._call_chain_irs),
                        expression_text=self._expression_text(node) or str(ir),
                        basis=["external call must not revert"],
                    )
                )

        # Cross-function revert detection: recurse into InternalCall /
        # LibraryCall callees to find gates the modifier doesn't directly
        # contain.
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, (InternalCall, LibraryCall)):
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None and self._lvalue_already_lifted(lvalue, container):
                    # The result reaches a branch condition / require argument
                    # — the predicate builder lifts that path. Recursing too
                    # would double-count.
                    continue
                # No result, a DISCARDED result, or a result that only ever
                # leaves the function (``return gatedCallee(...)``):
                # ``modifier hasRole(r) {
                # _hasRole(r, msg.sender); _; }`` calls a bool-returning guard
                # helper and ignores the bool — the require lives in the
                # callee. Skipping these silently dropped the whole gate
                # (every EtherFiRedemptionManager admin function went public).
                callee = getattr(ir, "function", None)
                if callee is None:
                    continue
                # Modifier callees are now traversed (not skipped)
                # so the call_chain captures modifier parameter
                # bindings — required for full caller-side
                # ParameterBindingEnv. The recursion is the single
                # source of truth for cross-fn body walking; we no
                # longer iterate function.modifiers separately.
                callee_id = getattr(callee, "full_name", None) or getattr(callee, "name", None)
                if not callee_id or callee_id in self._call_stack:
                    continue
                if len(self._call_stack) >= self.internal_call_depth:
                    continue
                self._call_stack.append(callee_id)
                self._call_chain_irs.append(ir)
                try:
                    for sub_node in getattr(callee, "nodes", []) or []:
                        self._scan_node(sub_node, container=callee)
                finally:
                    self._call_stack.pop()
                    self._call_chain_irs.pop()

        # Cases 3-4: if (C) revert ErrorName / SolidityCall(revert) where the
        # revert can sit ANY number of hops below the IF — Slither lowers a
        # multi-statement guard body (`if(C){ emit/assign…; revert; }`) into a
        # chain of EXPRESSION nodes, so a one-hop son scan misses it.
        condition_ir = self._extract_condition_ir(node)
        if condition_ir is None:
            return

        # A guard is a fork where exactly ONE branch is a pure revert path (every
        # path leaving it reverts before escaping the function); the other branch
        # is the normal continuation. Both-revert => unconditional revert (not an
        # access gate); neither => any revert below is conditional and belongs to
        # a nested IF, scanned independently.
        son_true = getattr(node, "son_true", None)
        son_false = getattr(node, "son_false", None)
        t_rev, t_ir = self._branch_always_reverts(son_true) if son_true is not None else (False, None)
        f_rev, f_ir = self._branch_always_reverts(son_false) if son_false is not None else (False, None)
        chosen_son, chosen_ir = (None, None)
        if t_rev and not f_rev:
            chosen_son, chosen_ir = son_true, t_ir
        elif f_rev and not t_rev:
            chosen_son, chosen_ir = son_false, f_ir
        if chosen_son is not None:
            ir = chosen_ir
            polarity = self._branch_polarity(node, chosen_son)
            self._gates.append(
                RevertGate(
                    kind="custom_revert"
                    if "revert " in str(getattr(getattr(ir, "function", None), "name", ""))
                    else "if_revert",
                    condition_value=getattr(condition_ir, "value", None),
                    polarity=polarity,
                    node=node,
                    containing_function=container,
                    call_chain=list(self._call_chain_irs),
                    expression_text=self._expression_text(node),
                    basis=["if-revert via always-reverting branch"],
                )
            )
            return

        # Case 5: inline assembly conditional revert — limited support.
        if self._node_has_assembly_revert(node):
            self._gates.append(
                RevertGate(
                    kind="inline_asm",
                    condition_value=getattr(condition_ir, "value", None),
                    polarity="allowed_when_true",
                    node=node,
                    containing_function=container,
                    call_chain=list(self._call_chain_irs),
                    expression_text=self._expression_text(node) or "<asm>",
                    basis=["inline assembly conditional revert"],
                    unsupported_reason=None,  # captured but limited
                )
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _gate_from_solidity_call(self, ir: Any, node: Any, kind: RevertKind, container: Any = None) -> RevertGate:
        # require/assert take the condition as the first argument.
        args = getattr(ir, "arguments", None) or getattr(ir, "read", None) or []
        cond = args[0] if args else None
        return RevertGate(
            kind=kind,
            condition_value=cond,
            polarity="allowed_when_true",
            node=node,
            containing_function=container,
            call_chain=list(self._call_chain_irs),
            expression_text=self._expression_text(node),
            basis=[f"{kind}({cond})" if cond is not None else kind],
        )

    def _branch_always_reverts(self, start: Any) -> tuple[bool, Any]:
        """True iff EVERY path leaving ``start`` hits a revert before escaping
        the function (reaching a no-successor / RETURN node).

        Revert nodes are sinks: their successors (the merge/ENDIF link Slither
        keeps for CFG completeness) are NOT followed, so a guard's revert never
        leaks into post-merge code. Returns ``(True, first_revert_ir)`` when the
        branch always reverts, else ``(False, None)``. Cycle-safe via a seen-set
        (loops/back-edges); a worklist that drains with no revert seen — e.g. a
        ``while(true)`` with no revert/return — escapes (not a guard)."""
        return self._walk_all_paths_revert(start, 0)

    def _walk_all_paths_revert(self, start: Any, depth: int) -> tuple[bool, Any]:
        """Core every-path-reverts CFG walk shared by branch-guard detection and
        callee analysis. A path's revert SINK is either a direct Solidity/Yul
        ``revert`` (``_ir_is_solidity_revert``) OR a call to a helper whose own
        body always reverts (``_callee_always_reverts``) — the Solady
        EnumerableRoles shape, where ``if (!isOwner()) _revertUnauthorized();``
        routes the revert through an always-reverting assembly helper.

        ``depth`` bounds the helper-calls-helper chase (see
        ``CALLEE_REVERT_MAX_DEPTH``). Returns ``(True, first_sink_ir)`` when every
        explored path reverts, else ``(False, None)``."""
        return_type = getattr(NodeType, "RETURN", -997)
        seen: set[int] = set()
        work = [start]
        first_rev = None
        while work:
            node = work.pop()
            nid = id(node)
            if nid in seen:
                continue
            seen.add(nid)
            sink_ir = self._node_revert_sink(node, depth)
            if sink_ir is not None:
                if first_rev is None:
                    first_rev = sink_ir
                # this node reverts: it is a sink, don't follow its successors
                continue
            sons = getattr(node, "sons", []) or []
            if not sons or getattr(node, "type", None) == return_type:
                # reached function exit / a return without reverting -> escapes
                return (False, None)
            work.extend(sons)
        # Worklist drained. If a revert was seen on every explored path the branch
        # always reverts; if it drained with NO revert seen, the only way out was
        # an unbounded cycle (``while(true)`` with no revert/return) — that is not
        # a guard, so report escape rather than fabricating an if_revert gate.
        return (first_rev is not None, first_rev)

    def _node_revert_sink(self, node: Any, depth: int) -> Any:
        """The first IR in ``node`` that terminates the current path in a revert:
        a direct Solidity/Yul ``revert`` SolidityCall, or a call to a callee whose
        every path reverts. ``require``/``assert`` are deliberately NOT sinks —
        they revert only conditionally, so a helper that merely ``require``s has a
        non-reverting exit and must never manufacture a gate. Returns the IR (a
        truthy sentinel for the caller) or ``None``."""
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if _ir_is_solidity_revert(ir):
                return ir
            if isinstance(ir, (InternalCall, LibraryCall)) and self._callee_always_reverts(
                getattr(ir, "function", None), depth + 1
            ):
                return ir
        return None

    def _callee_always_reverts(self, callee: Any, depth: int) -> bool:
        """True iff EVERY path through ``callee``'s own body reverts before it
        returns — an unconditionally-reverting helper such as Solady's
        ``_revertEnumerableRolesUnauthorized`` (assembly ``revert``). A callee
        with ANY non-reverting exit (a ``require`` that can pass, a normal
        ``return``) is NOT counted: that conservative condition is what stops a
        conditionally-reverting helper from fabricating a gate.

        Memoized per ``(id(callee), depth)``; cycle-safe via
        ``_callee_revert_inprogress``; the chase is bounded to
        ``CALLEE_REVERT_MAX_DEPTH`` hops, beyond which we conservatively return
        False (miss the gate rather than invent one)."""
        if callee is None or depth >= CALLEE_REVERT_MAX_DEPTH:
            return False
        key = (id(callee), depth)
        cached = self._callee_revert_cache.get(key)
        if cached is not None:
            return cached
        cid = id(callee)
        if cid in self._callee_revert_inprogress:
            # recursion back-edge: conservative escape, and don't cache (the
            # answer here is an artifact of the in-flight walk, not intrinsic).
            return False
        entry = getattr(callee, "entry_point", None)
        if entry is None:
            nodes = getattr(callee, "nodes", None) or []
            entry = nodes[0] if nodes else None
        if entry is None:
            return False
        self._callee_revert_inprogress.add(cid)
        try:
            result, _ = self._walk_all_paths_revert(entry, depth)
        finally:
            self._callee_revert_inprogress.discard(cid)
        self._callee_revert_cache[key] = result
        return result

    def _extract_condition_ir(self, node: Any) -> Any | None:
        """If `node` is an IF node, return its Condition IR (the value
        being branched on). Otherwise None."""
        if getattr(node, "type", None) != getattr(NodeType, "IF", -999):
            return None
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, Condition):
                return ir
        return None

    def _branch_polarity(self, if_node: Any, successor: Any) -> Polarity:
        """Determine whether the successor is the true-branch or the
        false-branch of an IF.

        Slither exposes ``son_true`` / ``son_false`` on IF nodes — if
        the revert lives on the true branch, the condition being true
        takes the revert path, so allowed_when_false."""
        son_true = getattr(if_node, "son_true", None)
        son_false = getattr(if_node, "son_false", None)
        if son_true is successor:
            return "allowed_when_false"
        if son_false is successor:
            return "allowed_when_true"
        # Fallback: if we can't tell, assume the revert was on the
        # less common false branch (typical pattern is `if (bad)
        # revert`, so true is the bad branch).
        return "allowed_when_false"

    def _try_node_primary_call(self, try_node: Any) -> Any | None:
        """Return the HighLevelCall IR whose return value drives the TRY's
        body, or None when the call's return is unused (the
        ``try h.helper() {} catch { revert }`` shape — opaque, no signal).

        A try/catch authority check is structurally a single bool-returning
        HighLevelCall. Calls returning ``void`` or non-bool values cannot be
        lifted into an authority predicate by shape alone. When there are
        multiple candidate calls, we leave the gate opaque."""
        calls = [
            ir
            for ir in (getattr(try_node, "irs_ssa", None) or getattr(try_node, "irs", []) or [])
            if isinstance(ir, HighLevelCall) and self._call_lvalue_is_bool(ir)
        ]
        if len(calls) == 1:
            return calls[0]
        return None

    def _call_lvalue_is_bool(self, ir: Any) -> bool:
        lvalue = getattr(ir, "lvalue", None)
        if lvalue is None:
            return False
        return str(getattr(lvalue, "type", "") or "") == "bool"

    def _try_catch_has_revert(self, try_node: Any) -> bool:
        """Walk descendants reachable from a TRY node through CATCH
        successors and check whether any of them contains a revert
        (SolidityCall(revert) or a require/assert that would always
        fail). Bounded BFS with a visited set to handle CFG cycles.

        We only scan the catch arm — the success arm of a try is
        the call's lvalue path and doesn't itself revert."""
        try:
            catch_type = NodeType.CATCH  # type: ignore[attr-defined]
        except AttributeError:
            return False
        # First descend into the CATCH siblings; the TRY node's sons
        # include both the call's success path (NEW_VARIABLE / IF /
        # ENDIF) and the catch arm — Slither alternates per
        # solidity version, so we walk every successor and only mark
        # nodes typed CATCH (or descendants of CATCH) as the catch arm.
        seen: set[int] = set()
        worklist: list[tuple[Any, bool]] = [(s, False) for s in (getattr(try_node, "sons", []) or [])]
        while worklist:
            node, in_catch = worklist.pop()
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            if getattr(node, "type", None) == catch_type:
                in_catch = True
            if in_catch:
                # Direct revert IR in the catch body.
                for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
                    if _ir_is_solidity_revert(ir):
                        return True
                    # require/assert with literal-false condition
                    # wrapped inside the catch counts too — rare but
                    # cheap to catch.
                    if _ir_is_require(ir) or _ir_is_assert(ir):
                        return True
                # Bound the BFS — we don't follow successors past the
                # immediate catch body to avoid mistaking a downstream
                # revert (after the try/catch finishes) as the catch's.
            worklist.extend((s, in_catch) for s in (getattr(node, "sons", []) or []))
        return False

    def _node_has_assembly_revert(self, node: Any) -> bool:
        """Heuristic: a node containing assembly that ends in revert.

        Slither doesn't expose YulAST richly, so we check whether the
        node's expression text mentions `revert(` inside an
        InlineAssemblyOperation. This is a coarse signal — false
        positives are caught by the predicate builder routing it to
        an unsupported leaf rather than a typed leaf."""
        irs = getattr(node, "irs", []) or []
        for ir in irs:
            if _ir_class(ir) == "InlineAssemblyOperation":
                code = getattr(ir, "inline_asm", None) or ""
                if "revert(" in str(code):
                    return True
        return False

    def _has_unmodeled_require_assert_gate(self) -> bool:
        """A ``require(...)`` / ``assert(...)`` SolidityCall we walked that did
        NOT become a gate.

        ``require``/``assert`` live directly in their own node, so a gate lifted
        from one has ``gate.node`` == that node. Any scanned node holding a
        require/assert SolidityCall whose id isn't among the gate nodes is a
        revert form the structural lifter rejected — the coverage gap that, left
        silent, defaults the function to public. Matched by name *prefix*
        (``require(`` / ``assert(``) so an unknown future arity (beyond the three
        ``_ir_is_require`` recognizes) is still caught rather than dropped.
        """
        accounted = {id(g.node) for g in self._gates if g.node is not None}
        for node in self._scanned_nodes:
            if id(node) in accounted:
                continue
            for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
                if _ir_class(ir) != "SolidityCall":
                    continue
                fn = getattr(ir, "function", None)
                name = getattr(fn, "name", None) or str(fn or "")
                if name.startswith("require(") or name.startswith("assert("):
                    return True
        return False

    def _has_unresolved_revert_in_assembly(self) -> bool:
        """Function has an InlineAssemblyOperation IR whose body
        contains a textual `revert` keyword that we did NOT
        structurally extract (Slither already parses
        ``if iszero(x) { revert(0,0) }`` into IF + SolidityCall, which
        we capture in the normal scan; this catches the residue —
        e.g. computed-target jumps to revert handlers, JUMPI tables,
        or assembly that conditionally reverts via paths Slither
        can't model)."""
        # Set of node IDs where we already classified a revert via
        # cases 1-5; assembly-residing reverts inside these nodes are
        # already accounted for.
        accounted_nodes = {id(g.node) for g in self._gates if g.node is not None}
        for node in self.function.nodes:
            for ir in getattr(node, "irs", []) or []:
                if _ir_class(ir) != "InlineAssemblyOperation":
                    continue
                code = str(getattr(ir, "inline_asm", "") or "")
                if "revert" not in code:
                    continue
                if id(node) in accounted_nodes:
                    continue
                # Assembly mentions revert and we don't have a
                # corresponding structured gate. Surface as opaque.
                return True
        return False
