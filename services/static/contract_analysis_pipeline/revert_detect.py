"""RevertDetector: every gated revert path in a function as a ``RevertGate`` (the condition value, its polarity, and
a kind).

Covers ``require``/``assert`` (with message or custom error), ``if (C) revert`` / ``revert Error()``, assembly ``if
iszero(X) { revert }``, ``try ... catch { revert }``, stored function-pointer checks (an ordinary equality leaf), and
unresolvable assembly reverts, which become one ``opaque`` gate the builder turns into an unsupported leaf.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .slither_compat import (
    SLITHER_AVAILABLE,
    Condition,
    HighLevelCall,
    InternalCall,
    LibraryCall,
    NodeType,
)

DEFAULT_INTERNAL_CALL_DEPTH = 4

# Real revert helpers are 1-2 hops (Solady ``_revertEnumerableRolesUnauthorized``); deeper returns False (miss a gate
# rather than fabricate one).
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
    """One gated revert path; the builder ANDs them at the tree root."""

    kind: RevertKind
    # None for opaque or unconditional reverts.
    condition_value: Any = None
    polarity: Polarity = "allowed_when_true"
    node: Any = None
    # The function or modifier whose body holds the gate (a helper like ``_checkRole`` for cross-function gates), so the
    # builder resolves the condition in the right scope.
    containing_function: Any = None
    # InternalCall/LibraryCall IRs from the analyzed function to the gate's container, for parameter binding.
    call_chain: list[Any] = field(default_factory=list)
    expression_text: str = ""
    basis: list[str] = field(default_factory=list)
    # For ``opaque`` gates.
    unsupported_reason: str | None = None


def _ir_class(ir: Any) -> str:
    return type(ir).__name__


def _ir_is_solidity_revert(ir: Any) -> bool:
    """Any SolidityCall named ``revert(`` or ``revert `` (Solidity and Yul forms share this lowering)."""
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
    # ``require(bool,error)`` is the >=0.8.26 custom-error form; missing it left the tree empty and the function public.
    return name in ("require(bool)", "require(bool,string)", "require(bool,error)")


def _ir_is_assert(ir: Any) -> bool:
    if _ir_class(ir) != "SolidityCall":
        return False
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return name == "assert(bool)"


def _ir_is_revert(ir: Any) -> bool:
    """Any ``revert`` form, to tell message operands on the revert path from guard operands
    (``_lvalue_already_lifted``).
    """
    if _ir_class(ir) != "SolidityCall":
        return False
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return name.startswith("revert")


class RevertDetector:
    """Walk a function's IR and return every gated revert path: ``RevertDetector(function).run()``."""

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
        # InternalCalls taken to reach the current node, recorded on each gate for parameter binding.
        self._call_chain_irs: list[Any] = []
        # Every walked node, so ``run`` can spot require/assert nodes that produced no gate.
        self._scanned_nodes: list[Any] = []
        # Per container: names reaching a branch condition or require/assert argument.
        self._container_condition_reads: dict[int, set[str]] = {}
        # Keyed by (callee id, depth) because the depth cutoff makes answers depth-relative; ids are scoped to this
        # detector.
        self._callee_revert_cache: dict[tuple[int, int], bool] = {}
        # Self-recursive helpers report escape on the back-edge.
        self._callee_revert_inprogress: set[int] = set()
        # ``str(node.expression)`` is the dominant cost; memoized for this detector's lifetime.
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
        # Modifier and internal calls are traversed by the in-body scan, so the call chain captures modifier parameter
        # bindings.
        for node in self.function.nodes:
            self._scan_node(node, container=self.function)
        if self._has_unresolved_revert_in_assembly():
            self._gates.append(
                RevertGate(
                    kind="opaque",
                    unsupported_reason="opaque_control_flow",
                    expression_text="<inline assembly with unresolved revert>",
                )
            )
        # Fail-safe: a require/assert that didn't become a gate is an unmodeled form; publish ``unsupported`` so the
        # function resolves gated, not public.
        if self._has_unmodeled_require_assert_gate():
            self._gates.append(
                RevertGate(
                    kind="opaque",
                    unsupported_reason="unmodeled_require_gate",
                    expression_text="<require/assert form not structurally modeled>",
                )
            )
        return self._gates

    def _lvalue_already_lifted(self, lvalue: Any, container: Any) -> bool:
        """Whether a call's result reaches a branch condition or any require/assert/revert argument in ``container``.

        Only then does the builder lift it (or is it on the revert path), so only then may recursion into the callee be
        skipped.

        Being read at all isn't enough: ``return gatedCallee(...)`` reads the result but no condition does, and skipping
        the callee lost its require. Revert arguments are included so a message formatter's internal bounds check (OZ
        ``_checkRole``'s ``Strings.toHexString``) isn't lifted as a caller gate. Transitive over ``lvalue -> read``
        edges; compared by name since nodes mix SSA and non-SSA views.
        """
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
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if _ir_is_require(ir):
                self._gates.append(self._gate_from_solidity_call(ir, node, "require", container))
                return
            if _ir_is_assert(ir):
                self._gates.append(self._gate_from_solidity_call(ir, node, "assert", container))
                return

        # try/catch reverting in the catch: with a single HighLevelCall in the try body, record ``try_catch_revert``
        # with the call so the builder can lift it; otherwise opaque.
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

        # Recurse into internal/library callees for gates the modifier doesn't hold directly.
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, (InternalCall, LibraryCall)):
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is not None and self._lvalue_already_lifted(lvalue, container):
                    # The builder lifts this path; recursing would double-count.
                    continue
                # No result, a discarded one, or one only returned: the require lives in the callee (``modifier
                # hasRole(r) { _hasRole(r, msg.sender); _; }``). Skipping these made every EtherFiRedemptionManager
                # admin function public.
                callee = getattr(ir, "function", None)
                if callee is None:
                    continue
                # Modifiers are traversed too, so the chain captures their bindings.
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

        # ``if (C) revert`` where the revert may be several nodes below the IF (Slither splits multi-statement guard
        # bodies).
        condition_ir = self._extract_condition_ir(node)
        if condition_ir is None:
            return

        # A guard is a fork where exactly one branch always reverts. Both reverting is unconditional; neither means any
        # revert below belongs to a nested IF.
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

    def _gate_from_solidity_call(self, ir: Any, node: Any, kind: RevertKind, container: Any = None) -> RevertGate:
        # The condition is the first argument.
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
        """``(True, first_revert_ir)`` iff every path from ``start`` reverts before leaving the function.

        Revert nodes are sinks (their ENDIF successor isn't followed). A drained worklist with no revert
        (``while(true)``) escapes.
        """
        return self._walk_all_paths_revert(start, 0)

    def _walk_all_paths_revert(self, start: Any, depth: int) -> tuple[bool, Any]:
        """Shared every-path-reverts walk.

        A path's revert sink is a direct ``revert`` or a call to an always-reverting helper (Solady ``if (!isOwner())
        _revertUnauthorized();``). ``depth`` bounds the helper chase.
        """
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
                continue
            sons = getattr(node, "sons", []) or []
            if not sons or getattr(node, "type", None) == return_type:
                return (False, None)
            work.extend(sons)
        # Drained with no revert means an unbounded cycle, not a guard.
        return (first_rev is not None, first_rev)

    def _node_revert_sink(self, node: Any, depth: int) -> Any:
        """The first IR in ``node`` ending the path in a revert (direct ``revert`` or an always-reverting callee), or
        ``None``. ``require``/``assert`` aren't sinks: they revert only conditionally.
        """
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if _ir_is_solidity_revert(ir):
                return ir
            if isinstance(ir, (InternalCall, LibraryCall)) and self._callee_always_reverts(
                getattr(ir, "function", None), depth + 1
            ):
                return ir
        return None

    def _callee_always_reverts(self, callee: Any, depth: int) -> bool:
        """True iff every path through ``callee`` reverts (Solady ``_revertEnumerableRolesUnauthorized``).

        Any non-reverting exit disqualifies it, so conditional helpers can't fabricate gates. Memoized per (callee,
        depth), cycle-safe, bounded by ``CALLEE_REVERT_MAX_DEPTH`` (then False).
        """
        if callee is None or depth >= CALLEE_REVERT_MAX_DEPTH:
            return False
        key = (id(callee), depth)
        cached = self._callee_revert_cache.get(key)
        if cached is not None:
            return cached
        cid = id(callee)
        if cid in self._callee_revert_inprogress:
            # Back-edge: conservative escape, not cached.
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
        if getattr(node, "type", None) != getattr(NodeType, "IF", -999):
            return None
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, Condition):
                return ir
        return None

    def _branch_polarity(self, if_node: Any, successor: Any) -> Polarity:
        """Whether ``successor`` is an IF's true or false branch; a revert on the true branch means
        ``allowed_when_false``.
        """
        son_true = getattr(if_node, "son_true", None)
        son_false = getattr(if_node, "son_false", None)
        if son_true is successor:
            return "allowed_when_false"
        if son_false is successor:
            return "allowed_when_true"
        # Unknown: assume the usual ``if (bad) revert`` shape.
        return "allowed_when_false"

    def _try_node_primary_call(self, try_node: Any) -> Any | None:
        """The HighLevelCall whose bool result drives a TRY, or None (unused result, non-bool return, or several
        candidates stay opaque).
        """
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
        """Whether the catch arm reaching from a TRY node reverts (including an always-failing require/assert).

        Bounded BFS; the success arm isn't scanned.
        """
        try:
            catch_type = NodeType.CATCH
        except AttributeError:
            return False
        # Slither orders TRY successors differently across versions, so walk all and only count nodes in the CATCH arm.
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
                for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
                    if _ir_is_solidity_revert(ir):
                        return True
                    if _ir_is_require(ir) or _ir_is_assert(ir):
                        return True
                # Don't follow past the catch body, or a later revert would be attributed to it.
            worklist.extend((s, in_catch) for s in (getattr(node, "sons", []) or []))
        return False

    def _node_has_assembly_revert(self, node: Any) -> bool:
        """Heuristic: a node whose assembly text mentions ``revert(``. False positives become unsupported leaves."""
        irs = getattr(node, "irs", []) or []
        for ir in irs:
            if _ir_class(ir) == "InlineAssemblyOperation":
                code = getattr(ir, "inline_asm", None) or ""
                if "revert(" in str(code):
                    return True
        return False

    def _has_unmodeled_require_assert_gate(self) -> bool:
        """A walked require/assert node that didn't become a gate (matched by name prefix, so unknown future forms
        are caught): a coverage gap that would otherwise default to public.
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
        """An assembly op mentioning ``revert`` that wasn't extracted structurally (Slither already lowers ``if
        iszero(x) { revert(0,0) }``); this catches computed jumps and other unmodeled reverts.
        """
        # Nodes already classified.
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
                return True
        return False
