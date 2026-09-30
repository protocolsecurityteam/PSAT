"""The origin/taint engine: value origins, element records, call origins, site classification."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Literal, NamedTuple, TypedDict

from ..predicate_types import TARGET_KIND_STORAGE_NO_SETTER, TARGET_KIND_STORAGE_SETTER
from ..provenance import ProvenanceEngine, is_top
from .selectors import _callee_signature, _selector_for
from .types import KindTier


def _base_name(name: Any) -> str | None:
    """Strip Slither's SSA suffix (``dest_1`` -> ``dest``); the provenance engine keys locals by base name."""
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


class _UnitCtx:
    """Per-unit classification context for value-flow destinations and amounts.

    * ``merged``: local base names a Phi merges across branches. The engine keys locals by base name, so ``d = cond ?
    who : feeSink`` collapses to one origin; anything reaching such a base is ``indeterminate``. Entrypoint Phis on
    state variables are excluded.
    * ``nested``: the unit is an internal callee. A ``parameter`` there is resolved through ``param_bindings`` (the
    argument the single entry path forwarded) and is ``indeterminate`` only when the binding is missing or divergent.
    State vars, ``msg.sender`` and constants are contract-global.
    * ``param_bindings``: formal base name -> neutral origin forwarded at this call site (``None`` on the entry). A
    helper reached with divergent bindings is re-walked so the fold yields ``indeterminate``.
    * ``param_index_bindings``: formal -> entry parameter index, only where the argument is one whole entry parameter;
    threaded like ``param_bindings``.
    """

    def __init__(
        self,
        bundle: _EngineBundle,
        state_vars_by_name: dict[str, Any],
        setters: dict[str, list[str]],
        alias_indeterminate: set[str],
        alias_resolved: set[str],
        setter_scan_complete: bool,
        nested: bool,
        param_bindings: dict[str, tuple[str, ...]] | None = None,
        param_index_bindings: dict[str, int] | None = None,
    ) -> None:
        self.engine = bundle.engine
        self.param_names = bundle.param_names
        self.merged = bundle.merged
        self.def_by_id = bundle.def_by_id
        self.param_indexes = bundle.param_indexes
        self.state_vars_by_name = state_vars_by_name
        self.setters = setters
        self.alias_indeterminate = alias_indeterminate
        self.alias_resolved = alias_resolved
        self.setter_scan_complete = setter_scan_complete
        self.nested = nested
        self.param_bindings = param_bindings
        self.param_index_bindings = param_index_bindings


class _EngineBundle:
    """Context-independent provenance for one function (engine at fixed point, formal names, Phi-merged bases, SSA
    def-use index), memoized across the build pass. Only ``nested`` lives on ``_UnitCtx``.
    """

    __slots__ = ("engine", "param_names", "merged", "def_by_id", "param_indexes")

    def __init__(
        self,
        engine: ProvenanceEngine,
        param_names: set[str],
        merged: set[str],
        def_by_id: dict[int, Any],
        param_indexes: dict[str, int],
    ) -> None:
        self.engine = engine
        self.param_names = param_names
        self.merged = merged
        self.def_by_id = def_by_id
        self.param_indexes = param_indexes


# Scoped to one artifact pass: the bundle references its function, so a process-wide weak map would keep compilation
# units alive.
_ENGINE_BUNDLE_SCOPE: ContextVar[dict[Any, _EngineBundle] | None] = ContextVar(
    "psat_effects_engine_bundle", default=None
)


def _param_indexes_of(unit: Any) -> dict[str, int]:
    """Formal base name -> positional index. Repeated names are dropped: an ambiguous name must address no ABI slot."""
    indexes: dict[str, int] = {}
    ambiguous: set[str] = set()
    for position, param in enumerate(getattr(unit, "parameters", []) or []):
        base = _base_name(getattr(param, "name", None))
        if not base:
            continue
        if base in indexes:
            ambiguous.add(base)
            continue
        indexes[base] = position
    for name in ambiguous:
        indexes.pop(name, None)
    return indexes


def _engine_bundle_for(unit: Any) -> _EngineBundle:
    cache = _ENGINE_BUNDLE_SCOPE.get()
    try:
        cached = cache.get(unit) if cache is not None else None
    except TypeError:  # pragma: no cover — unit not hashable
        cached = None
    if cached is not None:
        return cached
    from slither.core.cfg.node import NodeType
    from slither.core.variables.local_variable import LocalVariable
    from slither.slithir.operations import Phi

    engine = ProvenanceEngine(unit)
    engine.run()
    param_names = {
        base for param in getattr(unit, "parameters", []) or [] if (base := _base_name(getattr(param, "name", None)))
    }
    param_indexes = _param_indexes_of(unit)
    merged: set[str] = set()
    def_by_id: dict[int, Any] = {}
    for node in getattr(unit, "nodes", []) or []:
        # An ENTRYPOINT Phi is Slither's interprocedural parameter binding, not a cross-branch merge; counting it would
        # force every forwarded parameter to indeterminate.
        is_entrypoint = getattr(node, "type", None) == NodeType.ENTRYPOINT
        for ir in getattr(node, "irs_ssa", ()) or ():
            lvalue = getattr(ir, "lvalue", None)
            if lvalue is not None:
                def_by_id[id(lvalue)] = ir
            if isinstance(ir, Phi) and not is_entrypoint:
                nsv = getattr(lvalue, "non_ssa_version", None) or lvalue
                if isinstance(nsv, LocalVariable):
                    base = _base_name(getattr(lvalue, "name", None))
                    if base:
                        merged.add(base)
    bundle = _EngineBundle(engine, param_names, merged, def_by_id, param_indexes)
    if cache is not None:
        try:
            cache[unit] = bundle
        except TypeError:  # pragma: no cover — unit not hashable
            pass
    return bundle


def _build_unit_ctx(
    unit: Any,
    is_entry: bool,
    state_vars_by_name: dict[str, Any],
    setters: dict[str, list[str]],
    alias_indeterminate: set[str],
    alias_resolved: set[str],
    setter_scan_complete: bool,
    param_bindings: dict[str, tuple[str, ...]] | None = None,
    param_index_bindings: dict[str, int] | None = None,
) -> _UnitCtx:
    return _UnitCtx(
        _engine_bundle_for(unit),
        state_vars_by_name,
        setters,
        alias_indeterminate,
        alias_resolved,
        setter_scan_complete,
        not is_entry,
        param_bindings,
        param_index_bindings,
    )


def _ir_source_operands(ir: Any) -> list[Any]:
    """The operands an IR derives its lvalue from (the def-use edges for ``_reaches_merged_local``)."""
    tn = type(ir).__name__
    if tn == "TypeConversion":
        return [getattr(ir, "variable", None)]
    if tn == "Assignment":
        return [getattr(ir, "rvalue", None)]
    if tn == "Phi":
        return list(getattr(ir, "rvalues", ()) or [])
    if tn == "Unpack":
        return [getattr(ir, "tuple", None) or getattr(ir, "rvalue", None)]
    if tn == "Unary":
        return [getattr(ir, "rvalue", None)]
    if tn == "Binary":
        return [getattr(ir, "variable_left", None), getattr(ir, "variable_right", None)]
    if tn == "Member":
        # The field access carries the base local's identity.
        return [getattr(ir, "variable_left", None)]
    if tn == "Index":
        # A merge in either base or key makes the element ambiguous.
        return [getattr(ir, "variable_left", None), getattr(ir, "variable_right", None)]
    return []


def _reaches_merged_local(value: Any, ctx: _UnitCtx) -> bool:
    if value is None or not ctx.merged:
        return False
    seen: set[int] = set()
    stack: list[Any] = [value]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        if _base_name(getattr(v, "name", None)) in ctx.merged:
            return True
        ir = ctx.def_by_id.get(id(v))
        if ir is not None:
            stack.extend(_ir_source_operands(ir))
    return False


# Reassignment chains are a hop or two; deeper is "not proven".
_MERGE_RESOLVE_DEPTH = 4


def _phi_of(value: Any, ctx: _UnitCtx) -> Any:
    """The Phi that defines ``value`` (through copies only), or ``None``."""
    seen: set[int] = set()
    stack: list[Any] = [value]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "Phi":
            return ir
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
    return None


# ``param`` is an entry parameter; ``caller_supplied`` is an already-proven merge of them, so forwards compose.
_CALLER_SUPPLIED_TAGS = ("param", "caller_supplied")


def _is_caller_supplied_leaf(value: Any, ctx: _UnitCtx) -> bool:
    """True when ``value`` is a caller-chosen quantity: ``msg.value``, or a formal the caller-directed origin
    reaches.

    A nested formal is resolved through ``param_bindings`` (the caller may have forwarded storage); a missing binding
    fails closed.
    """
    if value is None:
        return False
    from slither.core.declarations.solidity_variables import SolidityVariable

    if isinstance(value, SolidityVariable) and str(getattr(value, "name", "")) == "msg.value":
        return True
    base = _base_name(getattr(value, "name", None))
    if not base or base not in ctx.param_names:
        return False
    if not ctx.nested:
        return True
    if ctx.param_bindings is None:
        return False
    return ctx.param_bindings.get(base, ("indeterminate",))[0] in _CALLER_SUPPLIED_TAGS


def _merged_caller_supplied(value: Any, ctx: _UnitCtx, depth: int = 0) -> bool:
    """True when every branch of a merged value is caller-supplied (``if (asset == native) amount = msg.value``: both
    are the caller's number, so this is an agreeing disjunction, not "traced nothing"). Not a slot claim: one
    branch has no ABI slot. Anything unproven fails the whole conjunction.
    """
    if depth > _MERGE_RESOLVE_DEPTH:
        return False
    phi = _phi_of(value, ctx)
    if phi is None:
        return False
    inputs = list(getattr(phi, "rvalues", None) or [])
    if not inputs:
        return False
    for rvalue in inputs:
        if _is_caller_supplied_leaf(rvalue, ctx):
            continue
        resolved, _ir = _resolve_copies(rvalue, ctx.def_by_id)
        if _is_caller_supplied_leaf(resolved, ctx):
            continue
        if _merged_caller_supplied(rvalue, ctx, depth + 1):
            continue
        return False
    return True


def _operand_is_direct(value: Any, param_names: set[str]) -> bool:
    """True for a direct AST leaf (Tier 1): a state variable, a Solidity built-in, a literal, or an uncast parameter
    read. Temporaries and references are Tier-2 traces.
    """
    if value is None:
        return False
    tn = type(value).__name__
    if "Temporary" in tn or "Reference" in tn or "Tuple" in tn:
        return False
    from slither.core.declarations.solidity_variables import SolidityVariable
    from slither.core.variables.state_variable import StateVariable
    from slither.slithir.variables import Constant

    if isinstance(value, (StateVariable, SolidityVariable, Constant)):
        return True
    if isinstance(getattr(value, "non_ssa_version", None), StateVariable):
        return True
    base = _base_name(getattr(value, "name", None))
    return bool(base) and base in param_names


def _state_var_target_kind(name: str, ctx: _UnitCtx) -> str:
    var = ctx.state_vars_by_name.get(name)
    if var is None:
        return "indeterminate"
    if getattr(var, "is_constant", False):
        return "constant"
    if getattr(var, "is_immutable", False):
        return "immutable"
    if name in ctx.setters:
        return TARGET_KIND_STORAGE_SETTER
    if name in ctx.alias_indeterminate:
        # Aliased into a callee we couldn't decide writes through, so no-setter is unsound.
        return "indeterminate"
    # Only a complete setter scan proves "fixed"; assembly sstore, delegatecall or unresolved aliases leave it unknown.
    return TARGET_KIND_STORAGE_NO_SETTER if ctx.setter_scan_complete else "indeterminate"


# A neutral origin is the entry-rooted source of a value, independent of whether it's used as destination or amount:
# ``("param",)``, ``("msg_sender",)``, ``("caller_controlled",)`` (tx.origin), ``("self",)``, ``("constant",)``,
# ``("state_variable", name)`` or ``("indeterminate",)``. ``_arg_origin`` computes it for a call-site argument;
# ``_origin_to_*_kind`` maps it back at the use site.


def _single_param_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """A ``parameter`` source's neutral origin: ``("param",)`` on the entry, the forwarded binding in a nested
    callee, else indeterminate.
    """
    if not ctx.nested:
        return ("param",)
    if ctx.param_bindings is None:
        return ("indeterminate",)
    base = _base_name(source.parameter_name) if source.parameter_name else None
    return ctx.param_bindings.get(base, ("indeterminate",)) if base else ("indeterminate",)


def _source_neutral_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """One provenance source's neutral origin; anything not a clean single origin is indeterminate.

    This neutralizes Slither's entrypoint-Phi binding: a nested forwarded param carries its own seed plus the caller's
    argument sources, so requiring all to agree turns a consistent echo into one origin and contamination into
    indeterminate.
    """
    kind = source.kind
    if kind == "parameter":
        return _single_param_origin(source, ctx)
    if kind == "msg_sender":
        return ("msg_sender",)
    if kind == "tx_origin":
        # tx.origin: caller-directed like msg_sender/param, but a distinct fact.
        return ("caller_controlled",)
    if kind == "self_address":
        return ("self",)
    if kind == "constant":
        # Keep the literal so a provably-zero value call is recognized as a non-flow; only ``origin[0]`` is classified.
        return ("constant", source.constant_value or "")
    if kind == "state_variable":
        return ("state_variable", source.state_variable_name) if source.state_variable_name else ("indeterminate",)
    return ("indeterminate",)


def _arg_origin(operand: Any, ctx: _UnitCtx, depth: int = 0) -> tuple[str, ...]:
    """The neutral origin a call-site argument forwards, resolved in the caller's context; all sources must agree,
    else indeterminate.

    A directly read nested parameter drops entrypoint-Phi echoes like the use-site classifiers do, so a two-hop forward
    through a shared helper (Lido ``claimWithdrawalsTo`` -> ``_claim`` -> ``_sendValue``) keeps its binding.
    """
    if operand is None:
        return ("indeterminate",)
    # An element argument (``_execute(targets[i], ...)``) takes its root base's origin.
    elem = _element_origin(operand, ctx)
    if elem is not None:
        return elem
    if _reaches_merged_local(operand, ctx):
        # Only amounts can agree across caller-chosen branches; two caller-chosen destinations are different addresses,
        # and ``_origin_to_target_kind`` has no case for this tag.
        return ("caller_supplied",) if _merged_caller_supplied(operand, ctx) else ("indeterminate",)
    # Amount vocabulary even for destinations: ``param_derived`` has no destination case, so destinations still land on
    # indeterminate, while amounts like ``shareAmount.mulDivDown(rate, ONE)`` forwarded into ``vault.exit`` resolve.
    call = _call_origin(operand, ctx, amount=True, depth=depth)
    if call is not None:
        return call
    srcs = ctx.engine._sources_for_value(operand)
    if not srcs or is_top(srcs):
        return ("indeterminate",)
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        origins = {_single_param_origin(s, ctx) for s in forwarded}
    else:
        origins = {_source_neutral_origin(s, ctx) for s in srcs if s.kind != "computed"}
    if len(origins) == 1 and ("indeterminate",) not in origins:
        return next(iter(origins))
    return ("indeterminate",)


def _source_param_index(source: Any, ctx: _UnitCtx) -> int | None:
    """The entry parameter index one source resolves to, or ``None``."""
    if source.kind != "parameter":
        return None
    base = _base_name(source.parameter_name) if source.parameter_name else None
    if not base:
        return None
    if not ctx.nested:
        return ctx.param_indexes.get(base)
    return ctx.param_index_bindings.get(base) if ctx.param_index_bindings else None


def _reads_element(operand: Any, ctx: _UnitCtx) -> bool:
    """True when the operand is read through an array/mapping/struct access.

    Such a destination is no ABI slot (a probe would have to rewrite inside an encoding), so no index is emitted;
    ``target_kind`` is unaffected.
    """
    seen: set[int] = set()
    stack: list[Any] = [operand]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn in ("Index", "Member"):
            return True
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
    return False


def _operand_param_index(operand: Any, ctx: _UnitCtx) -> int | None:
    """The entry parameter index an operand resolves to (the only producer of ``target_param_index``).

    Emitted only when every source binds to the same entry parameter; otherwise ``None`` and no probe is planted.
    """
    if operand is None or _reads_element(operand, ctx) or _reaches_merged_local(operand, ctx):
        return None
    srcs = ctx.engine._sources_for_value(operand)
    if not srcs or is_top(srcs):
        return None
    forwarded = _forwarded_param_sources(srcs, ctx)
    considered = forwarded if forwarded is not None else [s for s in srcs if s.kind != "computed"]
    if not considered:
        return None
    indexes = {_source_param_index(s, ctx) for s in considered}
    if len(indexes) != 1:
        return None
    return next(iter(indexes))


def _is_zero_literal(value: str) -> bool:
    try:
        return int(value, 0) == 0
    except (TypeError, ValueError):
        return False


def _amount_is_provably_zero(operand: Any, ctx: _UnitCtx) -> bool:
    """True when a value-call's value provably resolves to zero through the caller binding (OZ ``SafeERC20`` calls
    ``functionCallWithValue(token, data, 0)``). A zero-value call moves no ETH.
    """
    origin = _arg_origin(operand, ctx)
    return origin[0] == "constant" and len(origin) > 1 and _is_zero_literal(origin[1])


def _origin_to_target_kind(origin: tuple[str, ...], ctx: _UnitCtx) -> str:
    tag = origin[0]
    if tag == "param":
        return "param"
    if tag == "msg_sender":
        return "msg_sender"
    if tag == "caller_controlled":
        return "caller_controlled"
    if tag == "self":
        return "self"
    if tag == "constant":
        return "constant"
    if tag == "token_owner":
        return "token_owner"
    if tag == "state_variable":
        return _state_var_target_kind(origin[1], ctx)
    return "indeterminate"


def _is_derivation(computed_kind: str | None) -> bool:
    """True for a ``computed`` tag made by arithmetic, as opposed to one naming the value read (``msg.value``,
    ``balance(address)``).
    """
    return computed_kind is not None and computed_kind.startswith(("BinaryType.", "UnaryType."))


def _is_subtraction(computed_kind: str | None) -> bool:
    """True for subtraction, the only op that makes a balance read a delta."""
    return computed_kind == "BinaryType.SUBTRACTION"


def _origin_to_amount_kind(origin: tuple[str, ...]) -> str:
    tag = origin[0]
    if tag == "param":
        return "param"
    if tag == "constant":
        return "fixed_constant"
    if tag == "state_variable":
        return "bounded_by_storage"
    if tag == "param_derived":
        return "param_derived"
    if tag == "caller_supplied":
        return "caller_supplied"
    # An address origin used as an amount bounds nothing.
    return "indeterminate"


# Roots classified from: storage gives the base var's mutability, a parameter gives ``param``, a constant is fixed.
# Anything else (``address(this)``, unresolved or merged bases) falls through to the source-set path.
_ELEMENT_ROOT_TAGS = ("param", "state_variable", "constant")

_ELEMENT_WALK_DEFS = ("TypeConversion", "Assignment", "Index", "Member")


def _single_phi_input(var: Any, ctx: _UnitCtx) -> Any:
    """The single predecessor when ``var``'s def is a single-input body Phi (pure renaming, e.g.

    a storage pointer written through). ``None`` for real merges and ENTRYPOINT binding Phis (following those would
    cross into the caller's SSA).
    """
    from slither.core.cfg.node import NodeType

    ir = ctx.def_by_id.get(id(var))
    if ir is None or type(ir).__name__ != "Phi":
        return None
    if getattr(getattr(ir, "node", None), "type", None) == NodeType.ENTRYPOINT:
        return None
    rvals = {id(rv): rv for rv in (getattr(ir, "rvalues", None) or []) if rv is not None and id(rv) != id(var)}
    return next(iter(rvals.values())) if len(rvals) == 1 else None


def _member_name(ir: Any) -> str:
    """The field a ``Member`` IR selects (``str`` fallback so odd shapes still name themselves)."""
    right = getattr(ir, "variable_right", None)
    name = getattr(right, "name", None)
    return str(name) if name else str(right)


class _ElementRoot(NamedTuple):
    """One root an element walk reached, with its access path.

    ``keys``/``members`` are in walk order, nearest first (``m[a][b].f`` gives ``f``, ``b``, ``a``). ``variable`` is the
    state variable reached; ``merged_base`` marks a multi-input Phi root, which is no record identity.
    """

    origin: tuple[str, ...]
    keys: tuple[Any, ...]
    members: tuple[str, ...]
    merged_base: bool
    variable: Any


def _element_walk(operand: Any, ctx: _UnitCtx) -> list[_ElementRoot] | None:
    """Every root an element read (``a[k]``, ``s.field``, ``map[k].field``, including via storage-pointer locals)
    reaches, with the keys and members selected, or ``None``.

    A positive test for ``Index``/``Member`` IR, which separates real element reads from forwarded params that look
    identical in the source set. Shared by :func:`_element_root_origins` (roots only) and :func:`_element_record_site`
    (path too) so the two can't drift.
    """
    from slither.core.variables.state_variable import StateVariable

    seen: set[int] = set()
    stack: list[tuple[Any, tuple[Any, ...], tuple[str, ...]]] = [(operand, (), ())]
    roots: list[_ElementRoot] = []
    found_access = False
    while stack:
        v, keys, members = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        if isinstance(v, StateVariable) or isinstance(getattr(v, "non_ssa_version", None), StateVariable):
            # A bare state var only counts when reached through an access.
            continue
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "TypeConversion":
            stack.append((getattr(ir, "variable", None), keys, members))
        elif tn == "Assignment":
            stack.append((getattr(ir, "rvalue", None), keys, members))
        elif tn == "Phi":
            # Follow single-input Phis (SSA renames after writing through a storage pointer); a real merge ends the
            # branch.
            nxt = _single_phi_input(v, ctx)
            if nxt is not None:
                stack.append((nxt, keys, members))
        elif tn in ("Index", "Member"):
            found_access = True
            base = getattr(ir, "variable_left", None)
            if tn == "Index":
                keys = (*keys, getattr(ir, "variable_right", None))
            else:
                members = (*members, _member_name(ir))
            base_nsv = getattr(base, "non_ssa_version", None)
            base_var = (
                base if isinstance(base, StateVariable) else base_nsv if isinstance(base_nsv, StateVariable) else None
            )
            if base_var is not None:
                if base_var.name:
                    roots.append(_ElementRoot(("state_variable", base_var.name), keys, members, False, base_var))
            elif type(ctx.def_by_id.get(id(base))).__name__ in _ELEMENT_WALK_DEFS or _single_phi_input(base, ctx):
                # Nested access, aliasing local, or renamed storage pointer: keep walking to the root. Multi-input Phi
                # bases fall to ``_arg_origin``.
                stack.append((base, keys, members))
            else:
                # Parameter, merged or unresolvable root: resolve like a forwarded argument.
                merged = type(ctx.def_by_id.get(id(base))).__name__ == "Phi"
                roots.append(_ElementRoot(_arg_origin(base, ctx), keys, members, merged, None))
    return roots if (found_access and roots) else None


def _element_root_origins(operand: Any, ctx: _UnitCtx) -> set[tuple[str, ...]] | None:
    """Neutral origins of an element read's root bases, or ``None``.

    The key is ignored: every element shares the base's origin. :func:`_element_record_site` reads the key.
    """
    roots = _element_walk(operand, ctx)
    return {root.origin for root in roots} if roots is not None else None


def _element_origin(operand: Any, ctx: _UnitCtx) -> tuple[str, ...] | None:
    """An element read's origin from its root base, never the key; ``None`` when not an element read or the root
    isn't classifiable (the merged-local guard then applies, which also catches multi-root walks).
    """
    roots = _element_root_origins(operand, ctx)
    if roots is None or len(roots) != 1:
        return None
    root = next(iter(roots))
    return root if root[0] in _ELEMENT_ROOT_TAGS else None


class ElementRecordSite(TypedDict):
    """The storage record one element read names: the base declaration (canonical, since two contracts may each
    declare ``bids``), the member, and each key's origin. An identity for joins only.
    """

    base_variable: str
    base_canonical: str
    member_path: tuple[str, ...]
    # Per key level in source order. Only ``param``, ``msg_sender`` or ``indeterminate``; other origins mean no
    # caller-relative slot. ``param`` only where the level is one whole entry argument with ``key_param_indexes`` naming
    # it, so ``bids[a + b]`` never reads as caller-named.
    key_origins: tuple[tuple[str, ...], ...]
    # Entry parameter slot per key level; ``None`` unless the key is one whole argument (see
    # :func:`_key_conversion_is_lossy`).
    key_param_indexes: tuple[int | None, ...]
    key_levels: int


# Past these depths no single guard leaf can name the record, so the site refuses.
_MAX_RECORD_MEMBER_DEPTH = 2
_MAX_RECORD_KEY_LEVELS = 2

_RECORD_KEY_ORIGINS: dict[str, tuple[str, ...]] = {"param": ("param",), "msg_sender": ("msg_sender",)}


def _type_bit_width(declared: Any) -> int | None:
    """Bit width of a value type, or ``None`` when not measurable. Contract references are addresses."""
    from slither.core.declarations.contract import Contract
    from slither.core.solidity_types.elementary_type import ElementaryType
    from slither.core.solidity_types.user_defined_type import UserDefinedType
    from slither.exceptions import SlitherException

    if isinstance(declared, ElementaryType):
        try:
            size_bytes, dynamic = declared.storage_size
        except SlitherException:
            return None
        return None if dynamic else size_bytes * 8
    if isinstance(declared, UserDefinedType) and isinstance(getattr(declared, "type", None), Contract):
        return 160
    return None


def _key_conversion_is_lossy(operand: Any, ctx: _UnitCtx) -> bool:
    """True when the key's def chain has a narrowing or unmeasurable ``TypeConversion``.

    A narrowed key selects a different cell for large arguments while resolving to the same ABI slot, so a guard on
    ``bids[id]`` would falsely join a payout from ``bids[uint128(id)]``.
    """
    seen: set[int] = set()
    stack: list[Any] = [operand]
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "TypeConversion":
            source = getattr(ir, "variable", None)
            source_width = _type_bit_width(getattr(source, "type", None))
            target_width = _type_bit_width(getattr(ir, "type", None))
            if source_width is None or target_width is None or target_width < source_width:
                return True
            stack.append(source)
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
        elif tn == "Phi":
            stack.append(_single_phi_input(v, ctx))
    return False


def _element_record_site(operand: Any, ctx: _UnitCtx) -> ElementRecordSite | None:
    """The record ``operand`` is read from, or ``None`` on any ambiguity: several roots, a non-state-variable root, a
    merged base, a merged key, no key, or excessive depth. Refusal means an absent record, never a weaker one.

    Key origins reuse ``_arg_origin``, so ``_burn(msg.sender, amt)``'s ``_balances[account]`` resolves to the caller's
    own cell.
    """
    roots = _element_walk(operand, ctx)
    if roots is None or len(roots) != 1:
        return None
    root = roots[0]
    if root.merged_base or root.origin[0] not in _ELEMENT_ROOT_TAGS or root.variable is None:
        return None
    name = getattr(root.variable, "name", None)
    canonical = getattr(root.variable, "canonical_name", None)
    if not name or not canonical:
        return None
    member_path = tuple(reversed(root.members))
    keys = tuple(reversed(root.keys))
    if not keys or len(keys) > _MAX_RECORD_KEY_LEVELS or len(member_path) > _MAX_RECORD_MEMBER_DEPTH:
        return None
    key_origins: list[tuple[str, ...]] = []
    key_param_indexes: list[int | None] = []
    for key in keys:
        if key is None or _reaches_merged_local(key, ctx):
            # A merged key selects one of several cells.
            return None
        index = None if _key_conversion_is_lossy(key, ctx) else _operand_param_index(key, ctx)
        origin = _RECORD_KEY_ORIGINS.get(_arg_origin(key, ctx)[0], ("indeterminate",))
        if origin == ("param",) and index is None:
            # Caller-derived isn't caller-named: ``bids[a + b]`` and ``bids[uint128(id)]`` don't say which argument is
            # the key.
            origin = ("indeterminate",)
        key_origins.append(origin)
        key_param_indexes.append(index)
    return ElementRecordSite(
        base_variable=str(name),
        base_canonical=str(canonical),
        member_path=member_path,
        key_origins=tuple(key_origins),
        key_param_indexes=tuple(key_param_indexes),
        key_levels=len(keys),
    )


# ERC-721 ``ownerOf(uint256)``: the current owner of a caller-chosen id. Neither caller-named nor admin-settable, so it
# gets its own kind.
_TOKEN_OWNER_SELECTOR = "0x6352211e"

_CALL_WALK_DEFS = ("TypeConversion", "Assignment")
_CALL_IR_OPS = ("InternalCall", "LibraryCall", "HighLevelCall")


def _call_standard_origin(ir: Any) -> tuple[str, ...]:
    """The origin a recognized standard callee returns; unrecognized callees are indeterminate."""
    if _selector_for(_callee_signature(ir)) == _TOKEN_OWNER_SELECTOR:
        return ("token_owner",)
    return ("indeterminate",)


def _call_param_argument_indexes(ir: Any, ctx: _UnitCtx) -> set[int]:
    """Distinct entry parameter slots of this call's arguments; only whole unambiguous entry parameters count."""
    out: set[int] = set()
    for arg in getattr(ir, "arguments", None) or []:
        index = _operand_param_index(arg, ctx)
        if index is not None:
            out.add(index)
    return out


def _call_amount_origin(ir: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """The origin of an amount read back from a call, including the amount-only ``param_derived``.

    ``param_derived`` means only: the amount is an external call's return value and a caller-supplied entry parameter
    was among its arguments. It is not a bound (the callee's rate can move arbitrarily) and not proof of caller control.
    It covers ubiquitous shapes like ``convertToAssets(shares)`` that were otherwise indistinguishable from "traced
    nothing". A recognized standard callee still wins.
    """
    standard = _call_standard_origin(ir)
    if standard[0] != "indeterminate":
        return standard
    return ("param_derived",) if _call_param_argument_indexes(ir, ctx) else ("indeterminate",)


# Calls whose callee runs against the caller's storage (internal and library). Not ``HighLevelCall``: its state
# variables belong to another contract.
_SAME_CONTEXT_CALL_OPS = ("InternalCall", "LibraryCall")

# Real getter chains are a hop or two.
_RETURN_ORIGIN_DEPTH = 4

# Resolving a return can re-enter the same helper; the build pass is single-threaded and this is cleared in a
# ``finally``.
_RETURN_ORIGIN_ACTIVE: set[int] = set()


def _return_values(callee: Any) -> list[Any] | None:
    """The single value each ``return`` yields, or ``None`` (no explicit return, or a tuple return where the member
    reaching the sink is unknown).
    """
    values: list[Any] = []
    for node in getattr(callee, "nodes", []) or []:
        # ``irs_ssa``: every downstream lookup is keyed on SSA objects, and non-SSA twins fail quietly.
        for ir in getattr(node, "irs_ssa", ()) or ():
            if type(ir).__name__ != "Return":
                continue
            operands = list(getattr(ir, "values", None) or [])
            if len(operands) != 1:
                return None
            values.append(operands[0])
    return values or None


def _callee_return_origin(ir: Any, ctx: _UnitCtx, depth: int) -> tuple[str, ...] | None:
    """The origin of the value an in-contract helper returns, or ``None``.

    Arguments already flow into helpers; this carries answers back out, so ``_send(_governor(), amount)`` resolves to
    the admin-settable state variable. The callee is classified in its own context with the call's arguments bound, so
    returning a parameter resolves to what the caller passed. All returns must agree.

    Element reads are refused: ``return _owners[id]`` would resolve to the base's mutability (``storage_no_setter``,
    provably fixed), but the caller picks the key. Keyed lookups only get a named kind via a standard (``ownerOf`` ->
    ``token_owner``).
    """
    if depth > _RETURN_ORIGIN_DEPTH or type(ir).__name__ not in _SAME_CONTEXT_CALL_OPS:
        return None
    callee = getattr(ir, "function", None)
    if callee is None or not getattr(callee, "nodes", None):
        return None
    key = id(callee)
    if key in _RETURN_ORIGIN_ACTIVE:
        return None
    values = _return_values(callee)
    if values is None:
        return None
    bindings, index_bindings = _bindings_for_call(ir, callee, ctx)
    callee_ctx = _build_unit_ctx(
        callee,
        False,
        ctx.state_vars_by_name,
        ctx.setters,
        ctx.alias_indeterminate,
        ctx.alias_resolved,
        ctx.setter_scan_complete,
        bindings,
        index_bindings,
    )
    _RETURN_ORIGIN_ACTIVE.add(key)
    try:
        if any(_element_origin(value, callee_ctx) is not None for value in values):
            return None
        origins = {_arg_origin(value, callee_ctx, depth + 1) for value in values}
    finally:
        _RETURN_ORIGIN_ACTIVE.discard(key)
    if len(origins) != 1:
        return None
    origin = next(iter(origins))
    return None if origin[0] == "indeterminate" else origin


def _call_irs(operand: Any, ctx: _UnitCtx) -> list[Any]:
    """Every call IR ``operand`` is the return value of, through casts and copies."""
    seen: set[int] = set()
    stack: list[Any] = [operand]
    irs: list[Any] = []
    while stack:
        v = stack.pop()
        if v is None or id(v) in seen:
            continue
        seen.add(id(v))
        ir = ctx.def_by_id.get(id(v))
        if ir is None:
            continue
        tn = type(ir).__name__
        if tn == "TypeConversion":
            stack.append(getattr(ir, "variable", None))
        elif tn == "Assignment":
            stack.append(getattr(ir, "rvalue", None))
        elif tn in _CALL_IR_OPS:
            irs.append(ir)
    return irs


def _param_derived_index(operand: Any, ctx: _UnitCtx) -> int | None:
    """The entry slot of the input that fed a ``param_derived`` amount (the amount itself has no slot).

    Only when exactly one call produced it and its arguments name exactly one entry parameter; a guessed slot is worse
    than none for a prober.
    """
    irs = _call_irs(operand, ctx)
    if len(irs) != 1:
        return None
    indexes = _call_param_argument_indexes(irs[0], ctx)
    return next(iter(indexes)) if len(indexes) == 1 else None


def _one_call_origin(ir: Any, ctx: _UnitCtx, *, amount: bool, depth: int) -> tuple[str, ...]:
    """One call's return origin, best evidence first: a recognized standard callee, then what an in-contract helper
    provably returns, then the amount-only ``param_derived``, then indeterminate. The helper step only answers
    when all returns agree.
    """
    standard = _call_standard_origin(ir)
    if standard[0] != "indeterminate":
        return standard
    traced = _callee_return_origin(ir, ctx, depth)
    if traced is not None:
        return traced
    return _call_amount_origin(ir, ctx) if amount else standard


def _call_origin(operand: Any, ctx: _UnitCtx, *, amount: bool = False, depth: int = 0) -> tuple[str, ...] | None:
    """The origin of an operand that is a call's return value; ``None`` unless it resolves (through casts/copies) to
    exactly one call. ``amount`` enables the amount vocabulary.

    A positive def-use test, not a source-set test: the set would also fire on values merely tainted by a call
    (``ownerOf(id) ^ salt``), and a forwarded parameter can carry a sibling call's tag as an entrypoint-Phi echo. It
    also stops ``ownerOf(id)``, whose sources include the key parameter, from reading as a caller-chosen destination.
    """
    origins: set[tuple[str, ...] | None] = {
        _one_call_origin(ir, ctx, amount=amount, depth=depth) for ir in _call_irs(operand, ctx)
    }
    # Two calls reaching one operand need a Phi: a merge.
    if len(origins) != 1:
        return ("indeterminate",) if origins else None
    return next(iter(origins))


def _element_kind(operand: Any, ctx: _UnitCtx, *, amount: bool) -> str | None:
    """An element read's kind: storage roots give the base's mutability (never ``param``); caller-supplied roots give
    ``param``.
    """
    origin = _element_origin(operand, ctx)
    if origin is None:
        return None
    return _origin_to_amount_kind(origin) if amount else _origin_to_target_kind(origin, ctx)


def _forwarded_param_sources(srcs: Any, ctx: _UnitCtx) -> list[Any] | None:
    """For a directly read nested parameter, the ``parameter`` sources whose bindings decide (other sources can only
    be entrypoint-Phi echoes), or ``None`` when that shortcut is unsound.

    A ``computed`` operand can combine the parameter with a real co-origin without a Phi (``uint160(to) ^
    uint160(owner)``), so it returns ``None`` and uses the agreement path. Call results are intercepted upstream by
    ``_call_origin``.
    """
    if not ctx.nested:
        return None
    if any(s.kind == "computed" for s in srcs):
        return None
    params = [s for s in srcs if s.kind == "parameter"]
    return params or None


def _target_kind_from_sources(srcs: Any, ctx: _UnitCtx) -> str:
    if not srcs or is_top(srcs):
        return "indeterminate"
    # ``computed`` is a wrapper tag, never an origin. A single agreeing origin classifies; any mix is indeterminate.
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        kinds = {_origin_to_target_kind(_single_param_origin(s, ctx), ctx) for s in forwarded}
    else:
        kinds = {_origin_to_target_kind(_source_neutral_origin(s, ctx), ctx) for s in srcs if s.kind != "computed"}
    if len(kinds) == 1 and "indeterminate" not in kinds:
        return next(iter(kinds))
    return "indeterminate"


def _amount_kind_from_sources(srcs: Any, ctx: _UnitCtx) -> str:
    if not srcs or is_top(srcs):
        return "indeterminate"
    computed_kinds = {s.computed_kind for s in srcs if s.kind == "computed"}
    has_value = any(c == "msg.value" for c in computed_kinds)
    has_balance = any(c and "balance" in c for c in computed_kinds)
    if has_balance and not has_value and any(_is_derivation(c) for c in computed_kinds):
        # Arithmetic on a balance read: subtraction is a delta and gets named; other derivations can't be bounded. The
        # other operand must never win alone (``balance - locked`` isn't ``bounded_by_storage``).
        return "balance_delta" if any(_is_subtraction(c) for c in computed_kinds) else "indeterminate"
    meaningful = {s.kind for s in srcs} - {"computed"}
    if not meaningful:
        # Only ``msg.value`` and a bare self-balance read are unambiguous amount origins.
        if has_value and not has_balance:
            # Still bounded by what the caller attached.
            return "msg_value"
        if has_balance and not has_value:
            # Only a bare read can drain everything.
            return "whole_balance"
        return "indeterminate"
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        kinds = {_origin_to_amount_kind(_single_param_origin(s, ctx)) for s in forwarded}
    else:
        kinds = {_origin_to_amount_kind(_source_neutral_origin(s, ctx)) for s in srcs if s.kind != "computed"}
    if len(kinds) == 1 and "indeterminate" not in kinds:
        return next(iter(kinds))
    return "indeterminate"


# Comparisons under which ``cond ? A : B`` returns the smaller operand (how ``min`` compiles).
_MIN_LT_OPS = ("BinaryType.LESS", "BinaryType.LESS_EQUAL")
_MIN_GT_OPS = ("BinaryType.GREATER", "BinaryType.GREATER_EQUAL")


def _resolve_copies(value: Any, def_by_id: dict[int, Any]) -> tuple[Any, Any]:
    """Follow cast and assignment edges to the defining value: ``(value, defining_ir)``, with ``None`` for a leaf.

    Never crosses a Phi or computation.
    """
    seen: set[int] = set()
    v = value
    while v is not None and id(v) not in seen:
        seen.add(id(v))
        ir = def_by_id.get(id(v))
        if ir is None:
            return v, None
        tn = type(ir).__name__
        if tn == "TypeConversion":
            v = getattr(ir, "variable", None)
        elif tn == "Assignment":
            v = getattr(ir, "rvalue", None)
        else:
            return v, ir
    return v, None


def _is_self_balance_read(value: Any, ctx: _UnitCtx) -> bool:
    """``value`` is ``address(this).balance`` (argument identity checked; a foreign ``.balance`` doesn't count)."""
    from slither.core.declarations.solidity_variables import SolidityVariable

    _, ir = _resolve_copies(value, ctx.def_by_id)
    if ir is None or type(ir).__name__ != "SolidityCall":
        return False
    name = getattr(getattr(ir, "function", None), "name", "") or ""
    if "balance" not in name:
        return False
    args = getattr(ir, "arguments", None) or []
    if len(args) != 1:
        return False
    base, _ = _resolve_copies(args[0], ctx.def_by_id)
    return isinstance(base, SolidityVariable) and getattr(base, "name", None) == "this"


def _fn_def_by_id(fn: Any) -> dict[int, Any]:
    """A ``def_by_id`` map for a callee's SSA, outside the entry unit."""
    out: dict[int, Any] = {}
    for node in getattr(fn, "nodes", ()) or ():
        for ir in getattr(node, "irs_ssa", ()) or ():
            lv = getattr(ir, "lvalue", None)
            if lv is not None:
                out[id(lv)] = ir
    return out


def _branch_return_value(node: Any) -> Any:
    """The value a straight-line branch returns, or ``None``."""
    seen: set[int] = set()
    cur = node
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        for ir in getattr(cur, "irs_ssa", ()) or ():
            if type(ir).__name__ == "Return":
                vals = getattr(ir, "values", None) or []
                return vals[0] if len(vals) == 1 else None
        sons = getattr(cur, "sons", None) or []
        cur = sons[0] if len(sons) == 1 else None
    return None


def _callee_is_two_arg_min(fn: Any) -> bool:
    """Prove ``fn`` returns the smaller of its two arguments, by body shape (one comparison, each arm returning one
    parameter), never by name.
    """
    from slither.core.cfg.node import NodeType

    params = getattr(fn, "parameters", None) or []
    if len(params) != 2:
        return False
    d = _fn_def_by_id(fn)
    candidates: list[tuple[Any, Any]] = []
    for node in getattr(fn, "nodes", ()) or ():
        if getattr(node, "type", None) != NodeType.IF:
            continue
        for ir in getattr(node, "irs_ssa", ()) or ():
            if type(ir).__name__ == "Binary" and str(getattr(ir, "type", "")) in (_MIN_LT_OPS + _MIN_GT_OPS):
                candidates.append((node, ir))
    if len(candidates) != 1:
        return False
    cif, cmp = candidates[0]
    tv = _branch_return_value(getattr(cif, "son_true", None))
    fv = _branch_return_value(getattr(cif, "son_false", None))
    if tv is None or fv is None:
        return False

    def pidx(v: Any) -> int | None:
        rv, _ = _resolve_copies(v, d)
        nsv = getattr(rv, "non_ssa_version", None) or rv
        for i, p in enumerate(params):
            if p is nsv:
                return i
        return None

    li, ri = pidx(cmp.variable_left), pidx(cmp.variable_right)
    ti, fi = pidx(tv), pidx(fv)
    if None in (li, ri, ti, fi) or {li, ri} != {0, 1}:
        return False
    op = str(getattr(cmp, "type", ""))
    if op in _MIN_LT_OPS:  # A < B -> take A (left) when smaller
        return ti == li and fi == ri
    return ti == ri and fi == li  # A > B -> take B (right) when smaller


def _capped_ternary(operand: Any, ctx: _UnitCtx) -> bool:
    """Form 1: a hand-written ``bal < X ? bal : X`` (a 2-input Phi under an inequality) over the self-balance read."""
    from slither.core.cfg.node import NodeType

    phi = ctx.def_by_id.get(id(operand))
    if phi is None or type(phi).__name__ != "Phi":
        return False
    inputs = list({id(rv): rv for rv in (getattr(phi, "rvalues", None) or []) if rv is not None}.values())
    if len(inputs) != 2:
        return False
    branch: dict[int, tuple[Any, Any]] = {}
    for p in inputs:
        d = ctx.def_by_id.get(id(p))
        if d is None or type(d).__name__ != "Assignment":
            return False
        branch[id(p)] = (getattr(d, "node", None), getattr(d, "rvalue", None))
    branch_nodes = {id(n) for n, _ in branch.values() if n is not None}
    if len(branch_nodes) != 2:
        return False
    endif = getattr(phi, "node", None)
    fn = getattr(endif, "node_function", None) or getattr(endif, "function", None)
    if fn is None:
        return False
    cif = None
    for node in getattr(fn, "nodes", ()) or ():
        if getattr(node, "type", None) != NodeType.IF:
            continue
        st, sf = getattr(node, "son_true", None), getattr(node, "son_false", None)
        if st is not None and sf is not None and {id(st), id(sf)} == branch_nodes:
            cif = node
            break
    if cif is None:
        return False
    cmp = next(
        (
            ir
            for ir in getattr(cif, "irs_ssa", ()) or ()
            if type(ir).__name__ == "Binary" and str(getattr(ir, "type", "")) in (_MIN_LT_OPS + _MIN_GT_OPS)
        ),
        None,
    )
    if cmp is None:
        return False
    st = getattr(cif, "son_true", None)
    tv = fv = None
    for _, (node, val) in branch.items():
        if st is not None and id(node) == id(st):
            tv = val
        else:
            fv = val
    if tv is None or fv is None:
        return False

    def canon(v: Any) -> int:
        rv, _ = _resolve_copies(v, ctx.def_by_id)
        return id(rv)

    lc, rc, tc, fc = canon(cmp.variable_left), canon(cmp.variable_right), canon(tv), canon(fv)
    op = str(getattr(cmp, "type", ""))
    is_min = (op in _MIN_LT_OPS and tc == lc and fc == rc) or (op in _MIN_GT_OPS and tc == rc and fc == lc)
    if not is_min:
        return False
    return _is_self_balance_read(cmp.variable_left, ctx) or _is_self_balance_read(cmp.variable_right, ctx)


def _capped_min_call(operand: Any, ctx: _UnitCtx) -> bool:
    """Form 2: a proven 2-arg ``min`` call with the self-balance read as an argument."""
    _, ir = _resolve_copies(operand, ctx.def_by_id)
    if ir is None or type(ir).__name__ not in ("LibraryCall", "InternalCall"):
        return False
    fn = getattr(ir, "function", None)
    if fn is None or not _callee_is_two_arg_min(fn):
        return False
    args = getattr(ir, "arguments", None) or []
    if len(args) != 2:
        return False
    return any(_is_self_balance_read(a, ctx) for a in args)


def _is_capped_by_balance(operand: Any, ctx: _UnitCtx) -> bool:
    """An amount provably at most ``address(this).balance`` (either min form). Any doubt stays indeterminate."""
    return _capped_ternary(operand, ctx) or _capped_min_call(operand, ctx)


def _classify_site(operand: Any, ctx: _UnitCtx, *, amount: bool) -> tuple[str, str]:
    """Classify one destination/amount operand at one site -> ``(kind, tier)``.

    Anything that may be a collapsed cross-branch merge is indeterminate.
    """
    if operand is None:
        return ("indeterminate", "static_trace")
    # Elements classify by their root, detected from IR. Before the merged-local guard because that guard also walks the
    # key, and a loop-merged index says nothing about the base; merged bases are still caught via ``_arg_origin``.
    elem = _element_kind(operand, ctx, amount=amount)
    if elem is not None:
        return (elem, "static_trace")
    # Before the merged-local guard (the ternary form is a Phi) and the source path (which declines the call form).
    # Amounts only.
    if amount and _is_capped_by_balance(operand, ctx):
        return ("capped_by_balance", "static_trace")
    if _reaches_merged_local(operand, ctx):
        return ("indeterminate", "static_trace")
    # A call result classifies from the callee's standard identity or a helper's proven return: always a trace.
    call = _call_origin(operand, ctx, amount=amount)
    if call is not None:
        kind = _origin_to_amount_kind(call) if amount else _origin_to_target_kind(call, ctx)
        return (kind, "static_trace")
    srcs = ctx.engine._sources_for_value(operand)
    kind = _amount_kind_from_sources(srcs, ctx) if amount else _target_kind_from_sources(srcs, ctx)
    if kind == "indeterminate":
        return ("indeterminate", "static_trace")
    # A nested parameter was recovered through the call binding: a trace, not an entry-level fact.
    forwarded_param = ctx.nested and any(s.kind == "parameter" for s in srcs)
    direct = _operand_is_direct(operand, ctx.param_names) and not forwarded_param
    tier = "dispositive_ast" if direct else "static_trace"
    return (kind, tier)


# Its only admissible value; typed as a literal so the checker rejects ``True``.
_WRITER_SURFACE_CLOSED: Literal["not_determined"] = "not_determined"


_NO_TARGET_VAR: tuple[str | None, str | None, tuple[str, ...], bool, str | None] = (None, None, (), False, None)


def _target_variable_site(name: str, ctx: _UnitCtx) -> tuple[str | None, str | None, tuple[str, ...], bool, str | None]:
    """One destination site: ``(name, canonical name, writers, scan complete, reason no writer was attributed)``.

    Compared on the canonical name: two contracts may each declare ``recipient``.
    """
    variable = ctx.state_vars_by_name.get(name)
    canonical = getattr(variable, "canonical_name", None) if variable is not None else None
    writers = tuple(ctx.setters.get(name, ()))
    reason: str | None = None
    if not writers and name in ctx.setters:
        # Only setter targets can lack a named writer, and the two reasons carry opposite risk: a declaration
        # initialiser is effectively fixed, an unattributed storage alias is a real writer anyone might reach.
        reason = "alias_unattributed" if name in ctx.alias_resolved else "declaration_initialiser_only"
    return (name, str(canonical) if canonical else None, writers, ctx.setter_scan_complete, reason)


def _target_state_var_name(operand: Any, ctx: _UnitCtx) -> str | None:
    """The one state variable a destination reads, or ``None``, following :func:`_classify_site`'s path exactly so
    the name matches the kind. Element reads decline: the base isn't the destination.
    """
    if operand is None:
        return None
    if _element_kind(operand, ctx, amount=False) is not None:
        return None
    if _reaches_merged_local(operand, ctx):
        return None
    call = _call_origin(operand, ctx, amount=False)
    if call is not None:
        return call[1] if call[0] == "state_variable" and len(call) > 1 else None
    srcs = ctx.engine._sources_for_value(operand)
    if not srcs or is_top(srcs):
        return None
    forwarded = _forwarded_param_sources(srcs, ctx)
    if forwarded is not None:
        origins = {_single_param_origin(s, ctx) for s in forwarded}
    else:
        origins = {_source_neutral_origin(s, ctx) for s in srcs if s.kind != "computed"}
    if len(origins) != 1:
        return None
    origin = next(iter(origins))
    return origin[1] if origin and origin[0] == "state_variable" and len(origin) > 1 else None


def _fold_sites(sites: list[tuple[str, str]]) -> KindTier | None:
    """Collapse all sites' ``(kind, tier)``; the tier is the weakest.

    Agreeing kinds give that kind. Disagreeing but all resolved gives ``several``: we know each destination, so
    ``indeterminate`` would hide it. Any indeterminate member gives ``indeterminate``: the set isn't closed.

    ``several`` is a set, not a sequence or disjunction; the moves may all happen in one call. Consumers read
    ``target_kinds``/``amount_kinds`` and take the worst.
    """
    if not sites:
        return None
    kinds = {kind for kind, _ in sites}
    tier = "static_trace" if any(t == "static_trace" for _, t in sites) else "dispositive_ast"
    if len(kinds) == 1:
        kind = next(iter(kinds))
        return {"kind": kind, "tier": "static_trace" if kind == "indeterminate" else tier}
    if "indeterminate" in kinds:
        return {"kind": "indeterminate", "tier": "static_trace"}
    return {"kind": "several", "tier": tier}


def _site_breakdown(sites: list[tuple[str, str]]) -> list[KindTier] | None:
    """The distinct ``(kind, tier)`` site classifications, published only when sites disagree on kind (when the fold
    loses information), in first-seen order. Indeterminate sites stay listed. Bounded by the vocabularies' size.
    """
    if len({kind for kind, _ in sites}) < 2:
        return None
    ordered: list[KindTier] = []
    seen: set[tuple[str, str]] = set()
    for kind, tier in sites:
        if (kind, tier) in seen:
            continue
        seen.add((kind, tier))
        ordered.append({"kind": kind, "tier": tier})
    return ordered


def _bindings_for_call(ir: Any, callee: Any, ctx: _UnitCtx) -> tuple[dict[str, tuple[str, ...]], dict[str, int]]:
    """The param -> neutral-origin map (and param -> entry-index map) forwarded at one call site, resolved in the
    caller's context so multi-hop forwards stay exact.
    """
    bindings: dict[str, tuple[str, ...]] = {}
    index_bindings: dict[str, int] = {}
    args = list(getattr(ir, "arguments", []) or [])
    for param, arg in zip(getattr(callee, "parameters", []) or [], args):
        base = _base_name(getattr(param, "name", None))
        if not base:
            continue
        bindings[base] = _arg_origin(arg, ctx)
        index = _operand_param_index(arg, ctx)
        if index is not None:
            index_bindings[base] = index
    return bindings, index_bindings
