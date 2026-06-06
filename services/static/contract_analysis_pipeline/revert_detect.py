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

from typing import Any

from schemas.static_pipeline_schemas import Polarity, RevertGate, RevertKind

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


# ---------------------------------------------------------------------------
# Primitive predicates exposed as building blocks the predicate builder
# can call directly.
# ---------------------------------------------------------------------------


def _ir_class(ir: Any) -> str:
    return type(ir).__name__


# Module-level memo for str(node.expression). Slither expression objects
# are stable for the lifetime of the parsed Slither instance and the
# repeated calls (one per build_predicate_tree invocation per node) are
# the dominant cost in the Maker-wards bench profile (300ms of 2s ~=
# 14% of runtime, all in literal/binary __str__ chains). Keyed by
# id(expression) since Slither expression objects aren't hashable.
# Memory bound: O(unique expressions in parsed contracts) per process.
_EXPRESSION_TEXT_CACHE: dict[int, str] = {}


def _expression_text(node: Any) -> str:
    expr = getattr(node, "expression", None)
    if expr is None:
        return ""
    key = id(expr)
    cached = _EXPRESSION_TEXT_CACHE.get(key)
    if cached is not None:
        return cached
    text = str(expr)
    _EXPRESSION_TEXT_CACHE[key] = text
    return text


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
    return name in ("require(bool)", "require(bool,string)")


def _ir_is_assert(ir: Any) -> bool:
    if _ir_class(ir) != "SolidityCall":
        return False
    fn = getattr(ir, "function", None)
    name = getattr(fn, "name", None) or str(fn or "")
    return name == "assert(bool)"


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
        return self._gates

    # ------------------------------------------------------------------
    # Per-node classification
    # ------------------------------------------------------------------

    def _scan_node(self, node: Any, container: Any = None) -> None:
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
                            expression_text=_expression_text(node) or "<try/catch>",
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
                        expression_text=_expression_text(node) or "<try/catch>",
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
                        expression_text=_expression_text(node) or str(ir),
                        basis=["external call must not revert"],
                    )
                )

        # Cross-function revert detection: recurse into InternalCall /
        # LibraryCall callees to find gates the modifier doesn't directly
        # contain.
        for ir in getattr(node, "irs_ssa", None) or getattr(node, "irs", []) or []:
            if isinstance(ir, (InternalCall, LibraryCall)):
                if getattr(ir, "lvalue", None) is not None:
                    continue
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

        # Cases 3-4: if (C) revert ErrorName / SolidityCall(revert) in
        # the THIS node OR a one-hop successor (slither splits these).
        condition_ir = self._extract_condition_ir(node)
        if condition_ir is None:
            return

        # Look at successor nodes — does any one-hop successor revert?
        for son in getattr(node, "sons", []) or []:
            for ir in getattr(son, "irs_ssa", None) or getattr(son, "irs", []) or []:
                if _ir_is_solidity_revert(ir):
                    # The revert is reached via this branch of the IF.
                    # Polarity: if Slither's CFG follows true→son,
                    # the condition being true takes the revert branch,
                    # so allowed_when_false. (If the false branch
                    # contains the revert, polarity is allowed_when_true.)
                    polarity = self._branch_polarity(node, son)
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
                            expression_text=_expression_text(node),
                            basis=[f"if-revert via successor {son.type}"],
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
                    expression_text=_expression_text(node) or "<asm>",
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
            expression_text=_expression_text(node),
            basis=[f"{kind}({cond})" if cond is not None else kind],
        )

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
