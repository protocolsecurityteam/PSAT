"""Shared Plane-0 fact readers for the behavior-family matchers.

Underscore-prefixed so matcher auto-discovery skips it — it registers no
claims. Everything here reads the tolerant :class:`ClaimContext` view (effects
facts + predicate trees + the Slither subject) and, where a signal only exists
in IR, the ``contract`` object. Per-contract derivations that several triggers
share (pause targets, address-pointer writers) are memoized against the context
instance so a full ``build_claims`` pass computes them once.
"""

from __future__ import annotations

from typing import Any
from weakref import WeakKeyDictionary

from ..context import ClaimContext

# Per-context memo tables (keyed by the ClaimContext instance, which lives only
# for one contract's build_claims pass).
_PAUSE_TARGETS: WeakKeyDictionary[ClaimContext, set[tuple[str, str | None]]] = WeakKeyDictionary()
_MANDATORY_READS: WeakKeyDictionary[ClaimContext, set[tuple[str, str | None]]] = WeakKeyDictionary()


# ---------------------------------------------------------------------------
# Predicate-tree readers
# ---------------------------------------------------------------------------


def _iter_leaves(tree: Any) -> Any:
    if not isinstance(tree, dict):
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if isinstance(leaf, dict):
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _iter_leaves(child)


def tree_has_role(tree: Any, roles: tuple[str, ...]) -> bool:
    return any(leaf.get("authority_role") in roles for leaf in _iter_leaves(tree))


def tree_is_authority_gated(tree: Any) -> bool:
    """The function's guard depends on the caller's identity/authority."""
    return tree_has_role(tree, ("caller_authority", "delegated_authority"))


def tree_is_one_shot(tree: Any) -> bool:
    """An initializer latch (``initializer``/``reinitializer``) — writes here
    are a one-time set, never a recurring toggle."""
    return tree_has_role(tree, ("one_shot",))


def _mandatory_operands(tree: Any) -> set[tuple[str, str | None]]:
    """State-var operands read on a *mandatory* gate path — every ancestor is a
    conjunction (``AND``), so the operand's value can force a revert with no
    ``OR`` escape. This is the structural separator between a real pause gate
    (``if (paused) revert`` at the top level) and a mode selector under a branch
    (``if (executorRequired) require(sig)`` — reachable via an ``OR`` in the
    tree)."""
    out: set[tuple[str, str | None]] = set()

    def walk(node: Any, mandatory: bool) -> None:
        if not isinstance(node, dict):
            return
        op = node.get("op")
        if op == "LEAF":
            if not mandatory:
                return
            leaf = node.get("leaf")
            if not isinstance(leaf, dict):
                return
            for operand in leaf.get("operands") or []:
                if not isinstance(operand, dict):
                    continue
                name = operand.get("state_variable_name")
                if not name:
                    continue
                member_path = operand.get("member_path") or []
                out.add((name, member_path[0] if member_path else None))
            return
        child_mandatory = mandatory and op != "OR"
        for child in node.get("children") or []:
            walk(child, child_mandatory)

    walk(tree, True)
    return out


def mandatory_gate_reads(ctx: ClaimContext) -> set[tuple[str, str | None]]:
    """Every ``(var, member)`` pair read as a mandatory revert gate anywhere in
    the contract's predicate trees (cached per contract)."""
    cached = _MANDATORY_READS.get(ctx)
    if cached is not None:
        return cached
    reads: set[tuple[str, str | None]] = set()
    for signature in ctx.function_signatures():
        tree = ctx.predicate_tree(signature)
        if tree is not None:
            reads |= _mandatory_operands(tree)
    _MANDATORY_READS[ctx] = reads
    return reads


# ---------------------------------------------------------------------------
# State-write facts
# ---------------------------------------------------------------------------


def state_writes(ctx: ClaimContext, function: str, *, body_only: bool = True) -> list[dict[str, Any]]:
    record = ctx.effect_record(function)
    writes = record.get("state_writes")
    if not isinstance(writes, list):
        return []
    out = [w for w in writes if isinstance(w, dict)]
    if body_only:
        out = [w for w in out if w.get("origin") != "guard"]
    return out


def bool_write_targets(ctx: ClaimContext, function: str) -> set[tuple[str, str | None]]:
    """``(var, member)`` pairs this function writes as a ``bool`` in its body."""
    out: set[tuple[str, str | None]] = set()
    for write in state_writes(ctx, function):
        if write.get("declared_type") != "bool":
            continue
        member_path = write.get("member_path") or []
        out.add((write["var"], member_path[0] if member_path else None))
    return out


def value_flows(ctx: ClaimContext, function: str, *, body_only: bool = True) -> list[dict[str, Any]]:
    record = ctx.effect_record(function)
    flows = record.get("value_flows")
    if not isinstance(flows, list):
        return []
    out = [f for f in flows if isinstance(f, dict)]
    if body_only:
        out = [f for f in out if f.get("origin") != "guard"]
    return out


def body_sinks(ctx: ClaimContext, function: str) -> list[dict[str, Any]]:
    return [s for s in ctx.sinks(function) if s.get("origin") != "guard"]


# ---------------------------------------------------------------------------
# Contract-shape helpers
# ---------------------------------------------------------------------------


def _is_scalar_pointer_type(declared_type: str) -> bool:
    """address- or contract/interface-typed scalar (a callable pointer), not a
    mapping/array/value type."""
    if not declared_type:
        return False
    if declared_type.startswith("mapping") or "[]" in declared_type:
        return False
    if declared_type == "address":
        return True
    # User-defined contract / interface types render capitalised.
    return declared_type[0].isupper()


def is_erc20(ctx: ClaimContext) -> bool:
    ercs = getattr(ctx.contract, "ercs", None)
    if not callable(ercs):
        return False
    try:
        values: Any = ercs()
        return "ERC20" in {str(value) for value in values}
    except Exception:
        return False


def written_state_variables(function: Any) -> list[Any]:
    getter = getattr(function, "all_state_variables_written", None)
    if not callable(getter):
        return []
    try:
        result: Any = getter()
        return list(result)
    except Exception:
        return []


def contract_function(ctx: ClaimContext, signature: str) -> Any | None:
    """The Slither function object for an effects full-name signature.

    Two functions can share a full-name — a concrete body and an inherited
    interface re-declaration (0 nodes). Prefer the implemented body so IR reads
    (polarity, supply sign, use-links) see the real code, mirroring the effects
    builder's own tie-break."""
    best = None
    for fn in getattr(ctx.contract, "functions", []) or []:
        full = getattr(fn, "full_name", None) or getattr(fn, "name", None)
        if full != signature:
            continue
        if best is None or _fn_prefers(fn, best):
            best = fn
    return best


def _fn_prefers(new_fn: Any, old_fn: Any) -> bool:
    new_impl = bool(getattr(new_fn, "is_implemented", False)) and bool(getattr(new_fn, "nodes", None))
    old_impl = bool(getattr(old_fn, "is_implemented", False)) and bool(getattr(old_fn, "nodes", None))
    if new_impl != old_impl:
        return new_impl
    # A base function shadowed by a most-derived override is not the entry point.
    new_shadow = bool(getattr(new_fn, "is_shadowed", False))
    old_shadow = bool(getattr(old_fn, "is_shadowed", False))
    if new_shadow != old_shadow:
        return not new_shadow
    return len(getattr(new_fn, "nodes", []) or []) > len(getattr(old_fn, "nodes", []) or [])


def contract_functions(ctx: ClaimContext, signature: str) -> list[Any]:
    """Every Slither function object with this full-name (both a most-derived
    override and its shadowed base), for evidence that may live on either."""
    return [
        fn
        for fn in getattr(ctx.contract, "functions", []) or []
        if (getattr(fn, "full_name", None) or getattr(fn, "name", None)) == signature
    ]


# ---------------------------------------------------------------------------
# Pause derivation (facts + trees; the PauseAnalyzer idiom with its four fixes)
# ---------------------------------------------------------------------------


def pause_targets(ctx: ClaimContext) -> set[tuple[str, str | None]]:
    """``(var, member)`` bool flags that gate the contract's own entry points.

    A target is a ``bool`` written in some function body that is also read as a
    *mandatory* revert gate by another function (``mandatory_gate_reads``). The
    member-path facts recover struct-member pauses (Accountant ``state.isPaused``)
    and inherited-private pauses (EtherFiNodesManager ``_paused``) that the
    scalar ``state_variables`` view misses, while the mandatory-gate structure
    keeps a branch-mode selector (OneSig ``executorRequired``) out."""
    cached = _PAUSE_TARGETS.get(ctx)
    if cached is not None:
        return cached
    gate_reads = mandatory_gate_reads(ctx)
    all_bool_writes: set[tuple[str, str | None]] = set()
    for signature in ctx.function_signatures():
        all_bool_writes |= bool_write_targets(ctx, signature)
    targets = {pair for pair in all_bool_writes if _pair_is_gate_read(pair, gate_reads)}
    _PAUSE_TARGETS[ctx] = targets
    return targets


def _pair_is_gate_read(pair: tuple[str, str | None], gate_reads: set[tuple[str, str | None]]) -> bool:
    var, member = pair
    if pair in gate_reads:
        return True
    # A scalar bool read (member None) still matches a var-granular write.
    return member is not None and (var, None) in gate_reads


def function_pause_targets(ctx: ClaimContext, function: str) -> set[tuple[str, str | None]]:
    """The contract's pause targets that ``function`` writes in its body."""
    return bool_write_targets(ctx, function) & pause_targets(ctx)


def toggle_polarity(function: Any, var: str, member: str | None) -> str:
    """``"set"`` (writes the flag true), ``"unset"`` (writes it false), or
    ``"both"`` (parameter-driven / branch-dependent). Member writes are paired
    through their ``Member`` reference the way the effects builder pairs them.
    Walks internal callees so an OZ ``_pause()``/``_unpause()`` indirection is
    attributed to the entry point."""
    polarities: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            ref_pair: dict[int, tuple[str, str]] = {}
            irs = list(getattr(node, "irs", []) or [])
            for ir in irs:
                if type(ir).__name__ != "Member":
                    continue
                base = getattr(getattr(ir, "variable_left", None), "name", None)
                member_name = getattr(getattr(ir, "variable_right", None), "name", None)
                lvalue = getattr(ir, "lvalue", None)
                if base is not None and lvalue is not None:
                    ref_pair[id(lvalue)] = (str(base), str(member_name))
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                lvalue = getattr(ir, "lvalue", None)
                if member is None:
                    if _base_name(getattr(lvalue, "name", None)) != var:
                        continue
                elif lvalue is None or ref_pair.get(id(lvalue)) != (var, member):
                    continue
                polarity = _constant_bool_polarity(getattr(ir, "rvalue", None))
                if polarity:
                    polarities.add(polarity)
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if polarities == {"set"}:
        return "set"
    if polarities == {"unset"}:
        return "unset"
    return "both"


def _base_name(name: Any) -> str | None:
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


def _constant_bool_polarity(rvalue: Any) -> str | None:
    text = getattr(rvalue, "value", None)
    if text is None:
        text = getattr(rvalue, "name", None)
    text = str(text if text is not None else rvalue or "").strip().lower()
    if text in ("true", "1"):
        return "set"
    if text in ("false", "0"):
        return "unset"
    return None


# ---------------------------------------------------------------------------
# Supply-sign derivation (totalSupply +/- via the Binary IR operation)
# ---------------------------------------------------------------------------

_TOTAL_SUPPLY_NAMES = frozenset({"totalSupply", "_totalSupply"})


def total_supply_sign(function: Any) -> str | None:
    """``"mint"`` if the function increases a ``totalSupply`` var, ``"burn"`` if
    it decreases one, via the Binary IR *operation type* (Addition/Subtraction)
    on the supply var — no source-string parsing. Walks internal/library callees
    so a supply change through ``_mint``/``_burn`` is attributed to the entry."""
    signs: set[str] = set()
    visited: set[int] = set()

    def walk(unit: Any) -> None:
        if id(unit) in visited:
            return
        visited.add(id(unit))
        for node in getattr(unit, "nodes", []) or []:
            irs = list(getattr(node, "irs", []) or [])
            binary_sign: dict[int, str] = {}
            for ir in irs:
                if type(ir).__name__ != "Binary":
                    continue
                op_type = getattr(getattr(ir, "type", None), "name", "") or ""
                left = _base_name(getattr(getattr(ir, "variable_left", None), "name", None))
                right = _base_name(getattr(getattr(ir, "variable_right", None), "name", None))
                lvalue = getattr(ir, "lvalue", None)
                sign = None
                if op_type == "ADDITION" and (left in _TOTAL_SUPPLY_NAMES or right in _TOTAL_SUPPLY_NAMES):
                    sign = "mint"
                elif op_type == "SUBTRACTION" and left in _TOTAL_SUPPLY_NAMES:
                    sign = "burn"
                if sign is None:
                    continue
                # In-place (`totalSupply += x`): the Binary lvalue is the supply
                # var itself. Two-step: a TMP the next Assignment stores back.
                if _base_name(getattr(lvalue, "name", None)) in _TOTAL_SUPPLY_NAMES:
                    signs.add(sign)
                elif lvalue is not None:
                    binary_sign[id(lvalue)] = sign
            for ir in irs:
                if type(ir).__name__ != "Assignment":
                    continue
                target = _base_name(getattr(getattr(ir, "lvalue", None), "name", None))
                rvalue = getattr(ir, "rvalue", None)
                if target in _TOTAL_SUPPLY_NAMES and rvalue is not None and id(rvalue) in binary_sign:
                    signs.add(binary_sign[id(rvalue)])
            for ir in irs:
                if type(ir).__name__ in ("InternalCall", "LibraryCall"):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        walk(callee)

    walk(function)
    if len(signs) == 1:
        return next(iter(signs))
    return None


# ---------------------------------------------------------------------------
# Callee-pointer use-link (destination identity, not name strings)
# ---------------------------------------------------------------------------


def pointer_write_targets(ctx: ClaimContext, function: str) -> list[Any]:
    """State variables ``function`` writes that are callable scalar pointers
    (address / contract-typed, hygiene-normal), as Slither ``StateVariable``
    objects for identity comparison."""
    normal_pointer_names = {
        write["var"]
        for write in state_writes(ctx, function)
        if write.get("hygiene_class") == "normal" and _is_scalar_pointer_type(str(write.get("declared_type") or ""))
    }
    if not normal_pointer_names:
        return []
    fn = contract_function(ctx, function)
    if fn is None:
        return []
    from slither.core.variables.state_variable import StateVariable

    out = []
    for var in written_state_variables(fn):
        if isinstance(var, StateVariable) and getattr(var, "name", None) in normal_pointer_names:
            out.append(var)
    return out


def writes_first_time_set_pointer(ctx: ClaimContext, function: str, pointers: list[Any]) -> bool:
    """True if the function gates one of the scalar pointers it writes on a
    zero-address self-check (``require(pointer == address(0))``) — a set-once
    latch that installs the pointer for the first time. Distinguishes an
    initializer's first-time set (setup) from a runtime rotation for the manual
    ``require``-based latches ``tree_is_one_shot`` (OZ initializer-family
    modifiers) does not recognize."""
    if not pointers:
        return False
    fn = contract_function(ctx, function)
    if fn is None:
        return False
    from slither.slithir.operations import Binary

    pointer_names = {name for p in pointers if isinstance((name := getattr(p, "name", None)), str)}
    origins = _operand_origins(fn)
    for node in getattr(fn, "nodes", []) or []:
        for ir in getattr(node, "irs", []) or []:
            if not isinstance(ir, Binary) or getattr(getattr(ir, "type", None), "name", "") != "EQUAL":
                continue
            left = origins.get(id(getattr(ir, "variable_left", None)))
            right = origins.get(id(getattr(ir, "variable_right", None)))
            sides = {left, right}
            if ("zero", None) in sides and any(side == ("state", name) for name in pointer_names for side in sides):
                return True
    return False


def _operand_origins(fn: Any) -> dict[int, tuple[str, str | None]]:
    """``id(ir_value) -> origin`` over the function body, folding
    ``TypeConversion``/``Assignment`` chains so a Binary operand resolves to the
    ``("state", name)`` variable or the ``("zero", None)`` address(0)/0 constant
    it came from (the pieces a ``pointer == address(0)`` latch is built from)."""
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import Assignment, TypeConversion
    from slither.slithir.variables import Constant

    origins: dict[int, tuple[str, str | None]] = {}
    # Fixpoint over the chain length: address(state) and address(0) are single
    # TypeConversions here, but nested casts can stack a few links deep.
    for _ in range(8):
        changed = False
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                lvalue = getattr(ir, "lvalue", None)
                if lvalue is None:
                    continue
                if isinstance(ir, TypeConversion):
                    source = getattr(ir, "variable", None)
                elif isinstance(ir, Assignment):
                    source = getattr(ir, "rvalue", None)
                else:
                    continue
                origin: tuple[str, str | None] | None = None
                if isinstance(source, StateVariable):
                    origin = ("state", getattr(source, "name", None))
                elif isinstance(source, Constant):
                    origin = ("zero", None) if getattr(source, "value", None) in (0, "0", "0x0", False) else None
                elif source is not None:
                    origin = origins.get(id(source))
                if origin is not None and origins.get(id(lvalue)) != origin:
                    origins[id(lvalue)] = origin
                    changed = True
        if not changed:
            break
    return origins


def sibling_invokes_pointer(ctx: ClaimContext, writer: str, pointer: Any) -> str | None:
    """Full-name of an entry-point sibling that (transitively) invokes
    ``pointer`` as a call destination *by identity* and also moves value or
    writes a mapping — the ``transfer``-calls-``hook`` shape. ``None`` if no
    such sibling exists."""
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.operations import HighLevelCall, LowLevelCall

    if not isinstance(pointer, StateVariable):
        return None

    def resolves_to_pointer(destination: Any) -> bool:
        if destination is pointer:
            return True
        origin = getattr(destination, "points_to_origin", None)
        return origin is pointer

    def calls_pointer(fn: Any, seen: set[int]) -> bool:
        if id(fn) in seen:
            return False
        seen.add(id(fn))
        for node in getattr(fn, "nodes", []) or []:
            for ir in getattr(node, "irs", []) or []:
                if isinstance(ir, (HighLevelCall, LowLevelCall)) and resolves_to_pointer(
                    getattr(ir, "destination", None)
                ):
                    return True
                # Body-origin only: a pointer reached only through a modifier
                # (an authority consulted by a guard) is not a runtime code
                # pointer the entry point invokes.
                if type(ir).__name__ in ("InternalCall", "LibraryCall") and not _is_modifier_call(ir):
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None) and calls_pointer(callee, seen):
                        return True
        return False

    for signature in ctx.function_signatures():
        if signature == writer:
            continue
        if not _sibling_moves_value_or_writes_mapping(ctx, signature):
            continue
        if any(calls_pointer(fn, set()) for fn in contract_functions(ctx, signature)):
            return signature
    return None


def _is_modifier_call(ir: Any) -> bool:
    """True iff ``ir`` dispatches a modifier body (a guard), so the walk should
    not follow it into guard-origin territory."""
    if getattr(ir, "is_modifier_call", False):
        return True
    return type(getattr(ir, "function", None)).__name__ == "Modifier"


def _sibling_moves_value_or_writes_mapping(ctx: ClaimContext, signature: str) -> bool:
    if value_flows(ctx, signature):
        return True
    for write in state_writes(ctx, signature):
        if str(write.get("declared_type") or "").startswith("mapping"):
            return True
    return False
