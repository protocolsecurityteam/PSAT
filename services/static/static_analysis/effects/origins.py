"""The origin/taint engine: value origins, element records, call origins, site classification."""

from __future__ import annotations

from typing import Any, Literal, NamedTuple, TypedDict
from weakref import WeakKeyDictionary

from ..predicate_types import TARGET_KIND_STORAGE_NO_SETTER, TARGET_KIND_STORAGE_SETTER
from ..provenance import ProvenanceEngine, is_top
from .selectors import _callee_signature, _selector_for
from .types import KindTier


def _base_name(name: Any) -> str | None:
    """Strip Slither's SSA version suffix (``dest_1`` -> ``dest``). The
    provenance engine keys locals by their *base* name, so version suffixes
    must be normalized before a set-membership test against it."""
    if not isinstance(name, str):
        return None
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0]
    return name


class _UnitCtx:
    """Per-walked-unit classification context for value-flow destinations and
    amounts. Carries the unit's provenance map plus the two soundness guards:

    * ``merged`` — base names of LOCAL variables that a Phi merges across
      branches. The engine keys locals by base name, so two branch versions of
      ``d`` (``d = cond ? who : feeSink``) collapse to whichever assignment was
      processed last — silently discarding the other origin. Any destination
      that reaches such a base is forced ``indeterminate`` rather than trusting
      the collapsed value. (State-variable entrypoint Phis are excluded: their
      incoming versions are the same origin, not a cross-branch merge.)
    * ``nested`` — True when the unit is an internal callee, not the entry
      point. A ``parameter`` origin inside a callee is not self-evidently
      caller-directed: the entry may forward a fixed state var OR a
      caller-chosen argument into it. But the value-flow walk is rooted at ONE
      external entry, so the argument forwarded at each call site along that
      single path is unambiguous. ``param_bindings`` carries that forwarded
      origin (see below); a nested ``parameter`` is resolved through it to the
      entry-rooted kind, and only degrades to ``indeterminate`` when the
      binding is missing, unresolvable, or divergent across call sites. A state
      var / ``msg.sender`` / constant is contract-global and stays trustworthy
      across the internal-call boundary regardless.
    * ``param_bindings`` — for a nested unit, maps each of the unit's formal
      parameter base names to the *neutral origin* (see ``_arg_origin``) the
      entry-rooted walk forwarded into it at this call site: an entry parameter,
      ``msg.sender``, ``tx.origin``, ``address(this)``, a constant, or a named
      state variable. ``None`` on the entry itself (its own parameters ARE the
      caller-directed origin). Threaded down ``walk`` per call site; a helper
      reached from two sites with divergent bindings is re-walked so the
      cross-site fold collapses the disagreement to ``indeterminate``.
    * ``param_index_bindings`` — the positional half of ``param_bindings``: for a
      nested unit, the ENTRY parameter INDEX each formal binds to, present only
      for the formals whose argument resolved to one unambiguous entry parameter
      (never for a struct member / array element of one). The origin alone says
      *a* parameter; addressing an ABI argument slot needs *which*. Threaded and
      re-walked exactly like ``param_bindings``, so two call sites forwarding
      different parameter positions disagree at the fold instead of one winning."""

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
        # Context-independent, shared across every entry that reaches this unit.
        self.engine = bundle.engine
        self.param_names = bundle.param_names
        self.merged = bundle.merged
        self.def_by_id = bundle.def_by_id
        self.param_indexes = bundle.param_indexes
        # Contract-level (constant within a contract) + the per-context nested flag.
        self.state_vars_by_name = state_vars_by_name
        self.setters = setters
        self.alias_indeterminate = alias_indeterminate
        self.alias_resolved = alias_resolved
        self.setter_scan_complete = setter_scan_complete
        self.nested = nested
        self.param_bindings = param_bindings
        self.param_index_bindings = param_index_bindings


class _EngineBundle:
    """The context-independent provenance artifacts for one function: the SSA
    ``ProvenanceEngine`` (run to fixed point), formal-parameter base names, the
    Phi-merged local bases, and the SSA def-use index. All are pure functions of
    the function's own IR — identical whichever entry point reaches it — so the
    bundle is memoized per function across the whole build pass. Only the
    per-context ``nested`` interpretation lives on ``_UnitCtx``."""

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


# Per-function memo of the context-independent bundle, keyed by the Slither
# function object (weak so it dies with the Slither instance). Collapses the
# prior O(entries × helpers) engine rebuilds to one run per function per pass.
_ENGINE_BUNDLE: WeakKeyDictionary[Any, _EngineBundle] = WeakKeyDictionary()


def _param_indexes_of(unit: Any) -> dict[str, int]:
    """``formal parameter base name -> positional index``. A name that repeats
    (shadowing, an unnamed formal reusing the empty name) is DROPPED: the index
    is used to address an ABI argument slot, so an ambiguous name must resolve to
    nothing rather than to the first match."""
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
    cached = _ENGINE_BUNDLE.get(unit)
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
        # An ENTRYPOINT-node Phi is a parameter-binding phi (Slither's
        # interprocedural SSA linking a callee param to its caller argument), NOT
        # an intra-function cross-branch merge. Counting it as "merged" would
        # spuriously force every forwarded-param destination in an internal
        # helper to indeterminate. A genuine reassignment merge lives at an
        # ENDIF/other body node and is still caught.
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
    try:
        _ENGINE_BUNDLE[unit] = bundle
    except TypeError:  # pragma: no cover — unit not weak-referenceable
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
    """The value operands an IR derives its lvalue from — the edges of the
    def-use backward walk used by ``_reaches_merged_local``."""
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
        # ``s.field`` — the field access carries the base local's identity, so a
        # destination read off a branch-reassigned struct local must reach it.
        return [getattr(ir, "variable_left", None)]
    if tn == "Index":
        # ``arr[k]`` — both the base and the key select the element; a merge in
        # either makes the destination element ambiguous.
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


# How deep to chase nested merges when deciding whether every branch of a value
# is caller-supplied. Reassignment chains are a hop or two (`if native: amount =
# msg.value`); past that the answer is "we did not prove it", which is the safe
# direction anyway.
_MERGE_RESOLVE_DEPTH = 4


def _phi_of(value: Any, ctx: _UnitCtx) -> Any:
    """The Phi IR that defines ``value``, or ``None``. Walks copy edges only, so
    the returned merge IS this value's definition rather than one of its inputs'."""
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


# Neutral-origin tags that ARE a caller-chosen quantity, for the merge proof
# below. ``param`` is an entry parameter; ``caller_supplied`` is an already-proven
# merge of them, so a two-hop forward composes.
_CALLER_SUPPLIED_TAGS = ("param", "caller_supplied")


def _is_caller_supplied_leaf(value: Any, ctx: _UnitCtx) -> bool:
    """True when ``value`` IS a caller-chosen quantity: the ETH attached to the
    call, or a formal parameter that the caller-directed origin actually reaches.

    The parameter half is NOT the bare AST test it looks like. On the entry, a
    formal IS the caller's argument. In a NESTED unit it is only whatever the
    caller bound to it, and the caller may well have forwarded a state variable —
    so the formal is resolved through ``param_bindings`` exactly as
    :func:`_single_param_origin` resolves it. Reading a nested formal as
    self-evidently caller-supplied published ``caller_supplied`` for
    ``_helper(feeAmount)`` merged with ``msg.value``: an assertion that the caller
    picks the magnitude, on a branch where the magnitude is storage they cannot
    influence. A missing binding fails closed."""
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
    """True when EVERY branch of a merged value is caller-supplied.

    ``function deposit(IERC20 asset, uint256 amount) payable`` that does
    ``if (asset == native) amount = msg.value;`` merges an ABI argument with the
    attached ETH. Both are the caller's number, so the merge is not the absence of
    an answer — it is a disjunction whose members agree on the only thing an
    amount kind claims. Collapsing it to ``indeterminate`` published "we traced
    nothing" about a quantity the caller picks outright.

    Deliberately NOT a slot claim: one branch has no ABI slot at all, so no
    ``amount_param_index`` follows from this (see :func:`_fold_param_index`).
    Anything the walk cannot prove caller-supplied — a storage read, a call
    result, a nested merge past the depth bound — fails the whole conjunction, so
    the answer degrades to ``indeterminate`` rather than to a guessed member."""
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
    """True when the operand is a definitive AST leaf (Tier-1 dispositive): a
    StateVariable, a Solidity built-in (``msg.sender``/``msg.value``), a literal
    constant, or a formal-parameter read with no intervening cast/computation.
    Temporaries/references (cast results, computed values) are Tier-2 traces."""
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
        # Aliased into a callee we could not decide writes-through — the
        # no-setter proof for this specific var is unsound.
        return "indeterminate"
    # No attributed setter. Only a *complete* scan makes that a proven negative
    # ("fixed destination"); an assembly-sstore/delegatecall/unresolved-alias
    # blind spot leaves it unknown — never assert immutability we could not prove.
    return TARGET_KIND_STORAGE_NO_SETTER if ctx.setter_scan_complete else "indeterminate"


# A ``neutral origin`` is the entry-rooted source of a value forwarded across an
# internal-call boundary, independent of whether the value is used as a
# destination or an amount. One of: ``("param",)`` (an entry parameter, the
# caller-directed origin), ``("msg_sender",)``, ``("caller_controlled",)``
# (tx.origin), ``("self",)`` (address(this)), ``("constant",)``,
# ``("state_variable", name)``, or ``("indeterminate",)``. ``_arg_origin``
# computes it for a call-site argument (chaining through the caller's own
# bindings); ``_origin_to_*_kind`` translates it back into the destination /
# amount lattice at the use site.


def _single_param_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """The neutral origin one ``parameter`` source resolves to. On the entry its
    own parameter IS the caller-directed origin → ``("param",)``. In a nested
    callee look it up in the forwarded ``param_bindings``; a missing binding →
    ``("indeterminate",)``."""
    if not ctx.nested:
        return ("param",)
    if ctx.param_bindings is None:
        return ("indeterminate",)
    base = _base_name(source.parameter_name) if source.parameter_name else None
    return ctx.param_bindings.get(base, ("indeterminate",)) if base else ("indeterminate",)


def _source_neutral_origin(source: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """One provenance source → its neutral origin. A ``parameter`` chains through
    the entry-rooted binding (``_single_param_origin``); every other kind maps to
    a contract-global origin. Anything not a clean single origin (view/external
    call, block context, signature recovery) → ``("indeterminate",)``.

    This is what neutralizes Slither's entrypoint-Phi parameter binding: a nested
    forwarded param carries BOTH its own ``parameter`` seed AND the caller's
    argument source unioned in by the entry Phi. Resolving every source to a
    neutral origin and demanding they AGREE turns a consistent echo into that one
    origin, and any cross-site contamination into ``indeterminate``."""
    kind = source.kind
    if kind == "parameter":
        return _single_param_origin(source, ctx)
    if kind == "msg_sender":
        return ("msg_sender",)
    if kind == "tx_origin":
        # The transaction origin (an EOA the caller controls) — a proven
        # caller-directed destination, theft-shaped like msg_sender/param, but a
        # distinct address fact so it is not folded into msg_sender.
        return ("caller_controlled",)
    if kind == "self_address":
        return ("self",)
    if kind == "constant":
        # Carry the literal so a provably-zero value call can be recognized as a
        # non-flow. Classification only reads ``origin[0]`` so the extra element
        # is inert for the target/amount lattice.
        return ("constant", source.constant_value or "")
    if kind == "state_variable":
        return ("state_variable", source.state_variable_name) if source.state_variable_name else ("indeterminate",)
    # view_call, external_call, block_context, signature_recovery, top.
    return ("indeterminate",)


def _arg_origin(operand: Any, ctx: _UnitCtx, depth: int = 0) -> tuple[str, ...]:
    """The neutral origin a single call-site argument forwards, resolved in the
    caller's entry-rooted context. Every meaningful source resolves to a neutral
    origin and they must AGREE; any merge / unresolvable / multi-origin shape →
    ``("indeterminate",)`` — never a guessed member.

    A directly-read nested parameter takes the same entrypoint-Phi echo-drop the
    use-site classifiers take (``_forwarded_param_sources``): forwarding a
    parameter ONWARD through a second helper must resolve exactly as reading it
    at the send site would, or a two-hop forward through a helper that other
    entries also call (Lido ``claimWithdrawalsTo`` → ``_claim`` → ``_sendValue``,
    where ``_claim``'s Phi carries the sibling entries' ``msg.sender``) loses its
    binding to a phantom disagreement."""
    if operand is None:
        return ("indeterminate",)
    # An element read forwarded as an argument (``_execute(targets[i], …)``)
    # carries its ROOT base's origin — same rule, and same key-blindness, as
    # classifying it at a send site.
    elem = _element_origin(operand, ctx)
    if elem is not None:
        return elem
    if _reaches_merged_local(operand, ctx):
        # A merge whose every branch is caller-supplied is a known disjunction,
        # not an unknown. It resolves ONLY on the amount side: two caller-chosen
        # QUANTITIES agree on what an amount kind asserts, whereas two caller-
        # chosen DESTINATIONS are two different addresses and must stay
        # indeterminate — which is what ``_origin_to_target_kind`` does with this
        # tag, having no case for it.
        return ("caller_supplied",) if _merged_caller_supplied(operand, ctx) else ("indeterminate",)
    # The AMOUNT vocabulary, deliberately, even though this binding also feeds
    # destination resolution in the callee. ``param_derived`` is the one tag it
    # adds, and ``_origin_to_target_kind`` has no case for it, so a destination
    # resolved through this binding lands on ``indeterminate`` — bit-identical to
    # what the narrower call had already produced for the same operand. What it
    # buys is the amount side: ``vault.exit(to, asset, shareAmount.mulDivDown(
    # rate, ONE), …)`` forwards a scaled caller input, and refusing to name it
    # here made every ERC-4626-style redemption's amount ``indeterminate`` at the
    # sink, one hop from a fact we hold.
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
    """The ENTRY parameter index one provenance source resolves to — the
    positional twin of ``_single_param_origin``. ``None`` for every source that
    is not a parameter reaching one unambiguous entry parameter."""
    if source.kind != "parameter":
        return None
    base = _base_name(source.parameter_name) if source.parameter_name else None
    if not base:
        return None
    if not ctx.nested:
        return ctx.param_indexes.get(base)
    return ctx.param_index_bindings.get(base) if ctx.param_index_bindings else None


def _reads_element(operand: Any, ctx: _UnitCtx) -> bool:
    """True when the operand's value is read THROUGH an array/mapping/struct
    access (``a[k]``, ``s.field``, ``map[k].field``).

    Such a destination is not an ABI argument slot even when its root is a
    parameter: planting a probe address would mean rewriting a field inside an
    encoded struct/array. Index emission bails on this shape entirely — the
    ``target_kind`` (``param`` for a calldata-struct root, the base var's
    mutability for a storage root) is unaffected."""
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
    """The ENTRY parameter index an operand resolves to — the positional twin of
    ``_arg_origin``, and the ONLY producer of ``target_param_index``.

    Emits an index only when EVERY source the origin resolution considered is a
    parameter binding onto the SAME entry parameter, so the operand is that whole
    argument and nothing else. Element reads, merged locals, computed mixes,
    missing bindings and non-parameter origins all yield ``None`` — the caller
    must then plant no probe rather than address a guessed slot."""
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
    """True when a value-call's ``call_value`` provably resolves to constant zero,
    threading the caller binding (OZ ``SafeERC20`` routes token transfers through
    ``Address.functionCallWithValue(token, data, 0)`` — a ``.call{value: value}``
    whose ``value`` param is bound to the literal ``0``). A zero-value call moves
    no ETH, so it is not a value-out flow and must not fold with a real send."""
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
    """True for a ``computed`` tag produced by arithmetic on other operands
    (``BinaryType.SUBTRACTION`` / ``UnaryType.*``) — as opposed to a tag that
    merely names the value read (``msg.value``, ``balance(address)``,
    ``member.<field>``)."""
    return computed_kind is not None and computed_kind.startswith(("BinaryType.", "UnaryType."))


def _is_subtraction(computed_kind: str | None) -> bool:
    """True for the one arithmetic op that makes a balance read a DELTA. A
    comparison (``Math.min``'s ``a < b``) or a scaling (``balance / 2``) is not a
    delta and must not borrow the name."""
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
    # An address origin (msg.sender / tx.origin / self) forwarded as an amount is
    # not a meaningful value bound — stay indeterminate rather than invent one.
    return "indeterminate"


# Element-root origins we classify from. A storage root gives the base var's
# mutability, a parameter root gives ``param`` (an element of a caller-supplied
# array/struct is still caller-chosen), a constant root is fixed. Any other root
# (``address(this)`` — some solc versions lower ``address(this).balance`` to a
# Member — an unresolved local, a merged base) is NOT an element classification;
# the caller falls through to the source-set path instead.
_ELEMENT_ROOT_TAGS = ("param", "state_variable", "constant")

_ELEMENT_WALK_DEFS = ("TypeConversion", "Assignment", "Index", "Member")


def _single_phi_input(var: Any, ctx: _UnitCtx) -> Any:
    """The one distinct predecessor of ``var`` when its SSA def is a SINGLE-input
    body Phi — pure renaming, not a merge (a storage-pointer local given a fresh
    version because the body wrote through it). ``None`` for a non-Phi def, a
    genuine multi-input merge (must NOT be followed to either arm), or an
    ENTRYPOINT parameter-binding Phi (Slither's interprocedural SSA link — following
    it would cross into the caller's SSA and strip a forwarded parameter of the
    binding the nested classifiers resolve it through)."""
    from slither.core.cfg.node import NodeType

    ir = ctx.def_by_id.get(id(var))
    if ir is None or type(ir).__name__ != "Phi":
        return None
    if getattr(getattr(ir, "node", None), "type", None) == NodeType.ENTRYPOINT:
        return None
    rvals = {id(rv): rv for rv in (getattr(ir, "rvalues", None) or []) if rv is not None and id(rv) != id(var)}
    return next(iter(rvals.values())) if len(rvals) == 1 else None


def _member_name(ir: Any) -> str:
    """The field name a ``Member`` IR selects. Slither carries it as a Constant
    whose ``name`` is the identifier; ``str`` is the fallback so an unusual
    right-hand shape names itself rather than vanishing."""
    right = getattr(ir, "variable_right", None)
    name = getattr(right, "name", None)
    return str(name) if name else str(right)


class _ElementRoot(NamedTuple):
    """One ROOT the element walk reached, with the access path taken to it.

    ``keys`` and ``members`` are in WALK order — the access nearest the read
    first, which is the reverse of source order: ``m[a][b].f`` walks ``f``, then
    ``b``, then ``a``. ``variable`` is the state variable the walk actually
    landed on, carried so a reader takes the declaration off the object it
    proved rather than re-resolving a bare name. ``merged_base`` records that
    the root was a multi-input Phi: a genuine cross-branch merge resolved as an
    argument would be, not a base this walk identified, so nothing may be read
    off it as a record identity."""

    origin: tuple[str, ...]
    keys: tuple[Any, ...]
    members: tuple[str, ...]
    merged_base: bool
    variable: Any


def _element_walk(operand: Any, ctx: _UnitCtx) -> list[_ElementRoot] | None:
    """The shared def-edge walk behind every element fact: if ``operand`` reads
    an array/mapping/struct element (``a[k]`` / ``s.field`` / ``map[k].field``,
    possibly via a storage-pointer local ``Req storage rq = _requests[id];
    rq.recipient``), every ROOT base it reaches together with the keys and
    members the access path selected. ``None`` when it is not such an access.

    This is a POSITIVE structural test on the operand's def-use chain — an
    ``Index`` / ``Member`` op — so it distinguishes a genuine element read from
    the source-set-identical shape a forwarded param produces via the entrypoint
    Phi (which has no Index/Member IR).

    One walk, two readers: :func:`_element_root_origins` keeps only the roots
    (the amount/destination LATTICE is decided by the base alone), while
    :func:`_element_record_site` also reads the path (the RECORD identity is the
    base, the member and the key together). Forking the walk would let the two
    drift, and a join across them would then join a record to a different
    record."""
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
            # A bare state-var read only counts as an element base when it was
            # reached THROUGH an Index/Member (found_access) — a whole-var
            # destination stays a plain state_variable classification.
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
            # A single-input Phi is pure SSA renaming — a storage-pointer local
            # (``Bid storage bid = bids[id]``) given a fresh version because the
            # body wrote through it (``bid.isActive = false``). Follow it so the
            # aliased element resolves to the same root a direct read would. A
            # multi-input Phi is a genuine merge and ends this branch; the caller
            # then falls through to the merged-local guard rather than picking one
            # arm. (Reached only for a Phi in the def chain, not a Phi BASE — that
            # case is routed at the Index/Member handler below.)
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
                # A nested access (map[k].field), an aliasing local, or a
                # single-input-Phi storage pointer (``bid.amount`` where ``bid``
                # was SSA-renamed by a write through it) — keep walking to the root
                # rather than reading the intermediate reference's base∪key source
                # union. A multi-input Phi base is NOT walked here; it falls to the
                # ``_arg_origin`` resolution below, exactly as before.
                stack.append((base, keys, members))
            else:
                # A parameter / merged / unresolvable root: resolve it exactly as
                # a forwarded call-site argument would be (binding-chained, with
                # the merged-local guard).
                merged = type(ctx.def_by_id.get(id(base))).__name__ == "Phi"
                roots.append(_ElementRoot(_arg_origin(base, ctx), keys, members, merged, None))
        # An unknown def (call return, etc.) ends this branch.
    return roots if (found_access and roots) else None


def _element_root_origins(operand: Any, ctx: _UnitCtx) -> set[tuple[str, ...]] | None:
    """The set of neutral origins of an element read's ROOT base(s), or ``None``
    when the operand is not an element read.

    The KEY is deliberately ignored here: every element of one base shares that
    base's origin, so the base alone decides the kind and a caller-chosen (or
    loop-merged) index cannot upgrade or degrade it. The key is not lost — it is
    read by :func:`_element_record_site` off the same walk, where identity, not
    kind, is the question."""
    roots = _element_walk(operand, ctx)
    return {root.origin for root in roots} if roots is not None else None


def _element_origin(operand: Any, ctx: _UnitCtx) -> tuple[str, ...] | None:
    """The neutral origin an element read takes from its ROOT base — NEVER from
    the caller-supplied key. ``None`` when the operand is not an element read, or
    when its root is not one we classify from (``address(this)``, a merged or
    unresolvable base). The caller then falls through to the source-set path,
    where the merged-local guard still applies — and that guard is also what
    catches a >1-root walk, since two roots require a Phi between them."""
    roots = _element_root_origins(operand, ctx)
    if roots is None or len(roots) != 1:
        return None
    root = next(iter(roots))
    return root if root[0] in _ELEMENT_ROOT_TAGS else None


class ElementRecordSite(TypedDict):
    """The storage RECORD one element read names, at one IR site.

    Where :func:`_element_origin` answers "what kind of value is this", this
    answers "which cell is it read out of" — the base DECLARATION (canonical,
    because two contracts in one call graph may each declare ``bids``), the
    member selected inside it, and the origin of every key that selected it.
    Identity for a join; it resolves nothing on its own."""

    base_variable: str
    base_canonical: str
    member_path: tuple[str, ...]
    # Per index level in SOURCE order — the first index level written first
    # (``m[a][b]`` gives ``a`` then ``b``). Three tokens only —
    # ``("param",)``, ``("msg_sender",)``, ``("indeterminate",)`` — because the
    # question this answers is "which caller-relative slot names this key", and
    # every other resolved origin (a constant, a state variable) answers "none
    # of them". ``indeterminate`` here is therefore never readable as "no origin
    # exists". ``param`` is EARNED: it rides only where the level is one whole
    # entry argument and ``key_param_indexes`` names its slot, so a consumer
    # reading the kind alone can never take a caller-derived arithmetic mix
    # (``bids[a + b]``) for a cell the caller named.
    key_origins: tuple[tuple[str, ...], ...]
    # The ENTRY parameter slot of each key level, positionally aligned with
    # ``key_origins``. ``None`` where the key is not one whole entry argument —
    # ``msg.sender``, a constant, a merged mix, or a value narrowed on the way
    # in (see :func:`_key_conversion_is_lossy`).
    key_param_indexes: tuple[int | None, ...]
    key_levels: int


# Deep nesting is not this pass's problem: past these depths the record identity
# a join would compare stops being a thing one guard leaf can name, so the site
# refuses instead of publishing a path no consumer is specified to read.
_MAX_RECORD_MEMBER_DEPTH = 2
_MAX_RECORD_KEY_LEVELS = 2

# The key-origin vocabulary — see ``ElementRecordSite.key_origins``.
_RECORD_KEY_ORIGINS: dict[str, tuple[str, ...]] = {"param": ("param",), "msg_sender": ("msg_sender",)}


def _type_bit_width(declared: Any) -> int | None:
    """The width in bits of a value type, or ``None`` when it is not a fixed
    width this pass can measure (a dynamic type, an enum, a struct). A contract
    reference IS an address, which is what lets an ``IERC20(addr)`` /
    ``uint160`` hop keep resolving."""
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
    """True when the key's def chain holds a ``TypeConversion`` this pass cannot
    prove keeps the whole value — a NARROWING cast (``uint128(id)``), or one
    between widths it cannot measure. Widening and same-width casts
    (``uint160`` → ``address``, ``address`` → a contract type) keep resolving.

    The KEY is the cell's identity, and a narrowed key selects a DIFFERENT cell
    for a large argument while still resolving to that argument's ABI slot. The
    guard side reads the slot through this same helper, so without this test a
    guard on ``bids[id]`` and a payout from ``bids[uint128(id)]`` — two cells —
    AGREE on the slot they were keyed by, and that agreement is the whole join.
    So the slot is withheld: the argument was not, in whole, the key."""
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
    """The record ``operand`` is read out of, or ``None`` on any ambiguity.

    Refuses — and a refusal is an absent record downstream, never a weaker one —
    on more than one root, a root that is not a state variable this walk landed
    on (a parameter or constant root — a calldata struct, a literal table — has
    no declaration to compare a guard's against), a merged (multi-input Phi)
    base, a key reaching a cross-branch merge, no key at all (a whole-struct
    read is not a keyed record), and depths past ``_MAX_RECORD_*``.

    The key origins reuse ``_arg_origin``, so a key that is a callee formal
    resolves through the call-site binding the flow walk already threads —
    which is what makes ``_burn(msg.sender, amt)``'s ``_balances[account]``
    resolve to the caller's own cell rather than to an unknown address."""
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
            # The key IS the cell's identity: a merged one selects one of several
            # cells and the walk cannot say which.
            return None
        index = None if _key_conversion_is_lossy(key, ctx) else _operand_param_index(key, ctx)
        origin = _RECORD_KEY_ORIGINS.get(_arg_origin(key, ctx)[0], ("indeterminate",))
        if origin == ("param",) and index is None:
            # Caller-DERIVED is not caller-NAMED: ``bids[a + b]`` and
            # ``bids[uint128(id)]`` both come from the caller's arguments, and
            # neither says which argument IS the key. Publishing ``param`` there
            # would let a consumer reading the kind alone take an unproven slot
            # for a proven one.
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


# ERC-721 ``ownerOf(uint256)``. A destination read back from it is the CURRENT
# owner of the token id the caller passed: the caller chooses the id, the token's
# transfer history chooses the address. That is neither a caller-supplied
# argument (``param`` — the caller cannot name the payee) nor a fixed or
# admin-settable one (``storage_*`` — no setter redirects it), so it gets its own
# kind rather than being folded into a neighbour it would misdescribe.
_TOKEN_OWNER_SELECTOR = "0x6352211e"

# Def-chain edges that preserve "this value IS that call's return value".
_CALL_WALK_DEFS = ("TypeConversion", "Assignment")
_CALL_IR_OPS = ("InternalCall", "LibraryCall", "HighLevelCall")


def _call_standard_origin(ir: Any) -> tuple[str, ...]:
    """The neutral origin a recognized STANDARD callee returns. An unrecognized
    callee is ``("indeterminate",)`` — a return value we cannot name, NOT a value
    to keep resolving from the callee's internals."""
    if _selector_for(_callee_signature(ir)) == _TOKEN_OWNER_SELECTOR:
        return ("token_owner",)
    return ("indeterminate",)


def _call_param_argument_indexes(ir: Any, ctx: _UnitCtx) -> set[int]:
    """The distinct ENTRY parameter slots this call's ARGUMENTS resolve to.

    Each argument goes through :func:`_operand_param_index`, so an argument
    counts only when it IS one whole unambiguous entry parameter — an element
    read, a merged local, a computed mix and a non-parameter origin all
    contribute nothing."""
    out: set[int] = set()
    for arg in getattr(ir, "arguments", None) or []:
        index = _operand_param_index(arg, ctx)
        if index is not None:
            out.add(index)
    return out


def _call_amount_origin(ir: Any, ctx: _UnitCtx) -> tuple[str, ...]:
    """The neutral origin of an AMOUNT read back from a call, which can name one
    shape the destination lattice has no use for: ``param_derived``.

    ``param_derived`` claims EXACTLY this and nothing more, and every consumer
    must read it that way:

    - It is NOT a bound. The callee's rate is state we cannot see and it can
      move arbitrarily, so this kind must never be treated as an upper bound
      nor credited as a mitigation.
    - It is NOT proof of caller control. We cannot see inside the callee, so we
      cannot prove it honors its argument; it must not be read as "the caller
      determines the magnitude".
    - It IS: the amount is an external call's return value, and a caller-supplied
      entry parameter was among that call's arguments — the caller supplied an
      input, an external contract scaled it.

    The shape is ubiquitous (``transfer(receiver, convertToAssets(shares))`` in
    every ERC-4626-style redemption, ``unwrap`` on a rebasing wrapper), and
    collapsing it to ``indeterminate`` made it indistinguishable from "we traced
    nothing". A recognized standard callee still wins: naming what the callee
    returns is strictly more informative than naming what fed it."""
    standard = _call_standard_origin(ir)
    if standard[0] != "indeterminate":
        return standard
    return ("param_derived",) if _call_param_argument_indexes(ir, ctx) else ("indeterminate",)


# Call ops whose callee runs against the CALLER's own contract storage, so the
# caller's state-variable context classifies the callee's body correctly. An
# ``InternalCall`` is the same contract by definition; a library's functions are
# inlined (internal) or delegatecalled (external), and both read the caller's
# storage. A ``HighLevelCall`` is deliberately absent — its callee's state
# variables belong to a DIFFERENT contract, and reusing this context there would
# classify one contract's mutability as another's.
_SAME_CONTEXT_CALL_OPS = ("InternalCall", "LibraryCall")

# Depth bound on chasing helper returns through helpers. Real getter chains are a
# hop or two (``_governorIndirect`` -> ``_governor`` -> the state var); past that
# the answer degrades to "not proven", which is the safe direction.
_RETURN_ORIGIN_DEPTH = 4

# Re-entrancy guard for :func:`_callee_return_origin`. Resolving a helper's
# return value re-enters the general origin machinery, which can reach the same
# helper again (directly recursive, or mutually so through a second helper), and
# the recursion has no natural base case. A module-level set is sound here
# because the whole static build pass is single-threaded, and it is always
# cleared in a ``finally``.
_RETURN_ORIGIN_ACTIVE: set[int] = set()


def _return_values(callee: Any) -> list[Any] | None:
    """The single value each of ``callee``'s ``return`` statements yields, or
    ``None`` when the shape is not one this can reason about.

    ``None`` for a callee with no explicit return at all (it yields the type's
    zero value, which is not an origin), and for any return carrying a number of
    values other than one — a tuple return gives no way to say WHICH member
    reached the sink, and guessing a member is the failure mode this whole
    module is built to avoid."""
    values: list[Any] = []
    for node in getattr(callee, "nodes", []) or []:
        # ``irs_ssa``, NOT ``irs``: every lookup the returned operand then feeds
        # (the def-use index, the provenance engine) is keyed on the SSA objects,
        # so a non-SSA twin of the same variable resolves to nothing. It fails
        # quietly, and only for values whose SSA identity carries the answer — a
        # returned state variable resolves by name either way, a returned call
        # result does not.
        for ir in getattr(node, "irs_ssa", ()) or ():
            if type(ir).__name__ != "Return":
                continue
            operands = list(getattr(ir, "values", None) or [])
            if len(operands) != 1:
                return None
            values.append(operands[0])
    return values or None


def _callee_return_origin(ir: Any, ctx: _UnitCtx, depth: int) -> tuple[str, ...] | None:
    """The neutral origin of the value an in-contract helper RETURNS, or ``None``.

    The lattice already threads a caller's arguments INTO a helper, so a
    destination or amount passed down resolves interprocedurally. Nothing carried
    the answer back OUT, so ``_send(_governor(), amount)`` published
    ``indeterminate`` for a destination the contract states plainly — an
    admin-settable state variable, which is exactly the redirectable-vs-fixed
    distinction a scorer reads. The shape recurs on every diamond-storage getter
    and ``_calculate*`` helper.

    The callee is classified in its OWN context, with the call site's arguments
    bound exactly as ``walk`` binds them, so a helper that returns one of its
    parameters resolves to whatever the caller passed — including ``param``, when
    the caller passed a caller-chosen address. That is a finding, not a leak: the
    destination really is caller-named.

    Every ``return`` must agree on one resolved origin. Two returns naming
    different origins is a genuine disagreement the caller cannot see through
    (``if (flag) return governor; return treasury;``), and picking either member
    would assert a destination the code does not commit to.

    An ELEMENT read is refused outright, and that refusal is the whole safety
    argument. ``function beneficiaryOf(uint256 id) { return _owners[id]; }``
    resolves, by the element rule, to the mutability of the BASE variable — and
    ``_owners`` has no setter function, so the base reads ``storage_no_setter``,
    i.e. *provably fixed*. The destination is nothing of the sort: the caller
    picks the key, and a different key is a different address. Publishing it as
    fixed is the worst over-claim this module can make — it is the benign end of
    the redirectability axis, and §4.2 promotes it to ``immutable_fixed`` on the
    verdict. The base's mutability is simply not a statement about any one entry,
    which is exactly why a keyed lookup earns a named kind only where a published
    standard says what it means (``ownerOf`` -> ``token_owner``) and is otherwise
    left unresolved."""
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
    """Every call IR ``operand`` IS the return value of, walking casts/copies
    only — the def-chain edges that preserve that identity."""
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
        # An unknown def (a Phi, a binary op) ends this branch.
    return irs


def _param_derived_index(operand: Any, ctx: _UnitCtx) -> int | None:
    """The ENTRY parameter slot of the caller INPUT that fed a ``param_derived``
    amount's conversion — NOT the slot of the amount itself (the amount is a call
    return value and occupies no ABI slot).

    Emitted only when exactly ONE call produced the operand and its arguments
    identify exactly ONE unambiguous entry parameter. Two distinct entry params
    feeding the call keep the KIND (it is still param-derived) but emit no index:
    a prober plants a value in the slot, so a guessed one is worse than none."""
    irs = _call_irs(operand, ctx)
    if len(irs) != 1:
        return None
    indexes = _call_param_argument_indexes(irs[0], ctx)
    return next(iter(indexes)) if len(indexes) == 1 else None


def _one_call_origin(ir: Any, ctx: _UnitCtx, *, amount: bool, depth: int) -> tuple[str, ...]:
    """The neutral origin of ONE call's return value, best evidence first.

    1. A recognized STANDARD callee (``ownerOf``) — a published contract, so it
       beats anything read off a body.
    2. What an in-contract helper's body actually RETURNS
       (:func:`_callee_return_origin`). A traced origin outranks
       ``param_derived`` below, which only says a caller input went in somewhere.
    3. The amount-only ``param_derived`` fallback, then ``indeterminate``.

    The order matters in one direction only: step 2 can never turn an
    ``indeterminate`` into a wrong answer, because it declines unless every
    ``return`` agrees on one resolved origin."""
    standard = _call_standard_origin(ir)
    if standard[0] != "indeterminate":
        return standard
    traced = _callee_return_origin(ir, ctx, depth)
    if traced is not None:
        return traced
    return _call_amount_origin(ir, ctx) if amount else standard


def _call_origin(operand: Any, ctx: _UnitCtx, *, amount: bool = False, depth: int = 0) -> tuple[str, ...] | None:
    """The neutral origin of an operand that IS a call's return value. ``None``
    only when the operand does not resolve — through casts/copies alone — to
    exactly one call, in which case the caller falls through to the source set.

    ``amount`` opts into the amount-only vocabulary (:func:`_call_amount_origin`);
    destination resolution is unaffected, so ``param_derived`` can never reach
    :func:`_origin_to_target_kind`.

    A POSITIVE test on the def-use chain, not on the source set, for two reasons.
    A set-membership test would fire on a value merely TAINTED by the call
    (``ownerOf(id) ^ salt``) rather than one that IS its result. And going the
    other way, the source set of a DIRECTLY-READ nested parameter can carry a
    call tag as a Slither entrypoint-Phi echo from a sibling call site — blocking
    on that would degrade a perfectly resolvable forwarded parameter.

    Answering here is what keeps ``_forwarded_param_sources`` honest for call
    results. ``_handle_internal_call`` sets its lvalue to the callee's return
    sources UNIONED with the call tag, so ``ownerOf(id)`` carries
    ``{view_call, state_variable _owners, parameter id}`` — where the parameter
    is the mapping KEY, not the value. Falling through to the source set there
    lets the drop-the-rest shortcut pick ``param`` out of a real union and report
    a token-owner payout as a caller-chosen destination."""
    origins: set[tuple[str, ...] | None] = {
        _one_call_origin(ir, ctx, amount=amount, depth=depth) for ir in _call_irs(operand, ctx)
    }
    # Two calls reaching one operand require a Phi between them, so >1 origin is
    # a merge and must not resolve to either member.
    if len(origins) != 1:
        return ("indeterminate",) if origins else None
    return next(iter(origins))


def _element_kind(operand: Any, ctx: _UnitCtx, *, amount: bool) -> str | None:
    """An element read's destination/amount kind. A storage root yields the base
    var's mutability (``storage_setter`` / ``storage_no_setter`` /
    ``bounded_by_storage``) and can never become ``param``; a caller-supplied
    array/struct root yields ``param``."""
    origin = _element_origin(operand, ctx)
    if origin is None:
        return None
    return _origin_to_amount_kind(origin) if amount else _origin_to_target_kind(origin, ctx)


def _forwarded_param_sources(srcs: Any, ctx: _UnitCtx) -> list[Any] | None:
    """In a nested callee reached through a DIRECT forwarded read, the
    ``parameter`` sources whose bindings are the authoritative single-entry-path
    origin — or ``None`` when the drop-the-rest shortcut is not sound and the
    caller must use the all-sources-agree path instead.

    The other non-parameter sources present alongside a *directly-read* nested
    parameter can only be Slither entrypoint-Phi echoes (the parameter's
    interprocedural binding from OTHER call sites / entries) — a genuine in-body
    second origin needs a body Phi, already caught by ``_reaches_merged_local``.
    So for a direct read those echoes are safely dropped and the binding decides.

    But a ``computed`` operand (``Binary`` / ``Member`` / ``Unary`` / ``Length`` /
    ``SolidityCall`` attach a ``computed`` wrapper alongside ALL of their operand
    sources) can combine the forwarded parameter with a genuine co-origin and no
    Phi — ``dest = uint160(to) ^ uint160(owner)``. Dropping the co-origin there
    would guess the ``param`` member of a real union and make the nested
    classification MORE specific than the byte-identical entry-level code (which
    sees ``{parameter, state_variable}`` and yields indeterminate). So a computed
    operand returns ``None`` and falls through to the agreement path, where the
    disagreement correctly yields indeterminate while a computed-but-single-origin
    shape (a struct-member read of a forwarded param) still recovers.

    A CALL RESULT is the same trap without a ``computed`` wrapper to mark it, but
    it is intercepted upstream by ``_call_origin`` rather than here: the source
    set alone cannot tell a call the operand IS from a call tag echoed onto a
    forwarded parameter by a sibling call site."""
    if not ctx.nested:
        return None
    if any(s.kind == "computed" for s in srcs):
        return None
    params = [s for s in srcs if s.kind == "parameter"]
    return params or None


def _target_kind_from_sources(srcs: Any, ctx: _UnitCtx) -> str:
    if not srcs or is_top(srcs):
        return "indeterminate"
    # ``computed`` is a wrapper tag Binary/Member ops attach alongside the real
    # operand sources; it is never itself a destination origin. Every real source
    # resolves to a neutral origin (a nested forwarded ``parameter`` through its
    # binding); a single agreeing origin classifies, any MIX -> indeterminate.
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
        # Arithmetic ON a balance read. Subtraction is a DELTA
        # (``address(this).balance - prevBalance``, ``balance - locked``) and gets
        # named; any other derivation (``balance / 2``) has no bound we can name.
        # Either way the OTHER operand must not win alone: reporting
        # ``balance - locked`` as ``bounded_by_storage``, or ``balance / 2`` as
        # ``fixed_constant``, credits that operand with bounding an amount that
        # actually tracks the balance. This runs ahead of the meaningful-source
        # split precisely because that operand is usually the only non-``computed``
        # source and would otherwise be the whole answer.
        return "balance_delta" if any(_is_subtraction(c) for c in computed_kinds) else "indeterminate"
    meaningful = {s.kind for s in srcs} - {"computed"}
    if not meaningful:
        # Pure computed: only ``msg.value`` and a bare ``address(this).balance``
        # read are unambiguous amount origins; hash/mixed tags stay indeterminate.
        if has_value and not has_balance:
            # A msg.value derivation (``msg.value - fee``) is still bounded by
            # what the caller attached to THIS call, so the label does not
            # over-claim the way a bare balance read would.
            return "msg_value"
        if has_balance and not has_value:
            # ``whole_balance`` asserts the send can drain everything the contract
            # holds — true only of a bare READ, and every derivation is gone by here.
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


# Inequalities under which a ``cond ? A : B`` returns the SMALLER operand — the
# shape a hand-written or library ``min`` compiles to. ``<``/``<=`` return the
# then-value when it is the left (smaller) operand; ``>``/``>=`` return it when it
# is the right one.
_MIN_LT_OPS = ("BinaryType.LESS", "BinaryType.LESS_EQUAL")
_MIN_GT_OPS = ("BinaryType.GREATER", "BinaryType.GREATER_EQUAL")


def _resolve_copies(value: Any, def_by_id: dict[int, Any]) -> tuple[Any, Any]:
    """Follow copy edges (``TypeConversion`` cast, ``Assignment``) from ``value``
    to the value that actually defines it. Returns ``(value, defining_ir)`` where
    ``defining_ir`` is ``None`` for a leaf (param / constant / state var / call
    argument with no def in this map). A pure identity walk — it never crosses a
    Phi merge or a computation, so the returned value IS the input, just renamed."""
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
    """``value`` (through casts/copies) IS ``address(this).balance`` — the
    ``SOLIDITY_CALL balance(address)`` built-in whose sole argument resolves to the
    ``this`` Solidity variable. An arbitrary ``other.balance`` reads a foreign
    balance and must NOT qualify, so the argument identity is checked."""
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
    """A ``def_by_id`` map for an ARBITRARY function's SSA — needed to inspect a
    call's callee body, which lives outside the entry unit's own map."""
    out: dict[int, Any] = {}
    for node in getattr(fn, "nodes", ()) or ():
        for ir in getattr(node, "irs_ssa", ()) or ():
            lv = getattr(ir, "lvalue", None)
            if lv is not None:
                out[id(lv)] = ir
    return out


def _branch_return_value(node: Any) -> Any:
    """The single value a straight-line branch returns, or ``None`` when the arm is
    not a simple ``return <expr>`` (it splits/merges or returns a tuple)."""
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
    """PROVE ``fn`` computes the minimum of its two arguments — returns ``arg_i``
    when ``arg_i < arg_j`` else ``arg_j`` (the smaller). Keyed on the body's SHAPE,
    never its name: exactly one comparison IF over the two parameters, each arm
    returning one parameter, the smaller taken on the corresponding branch. Any
    other shape (a max, three args, a computed result) fails to ``False``."""
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
    """Form 1: a hand-written ``contractBalance < X ? contractBalance : X`` lowered
    to a 2-input Phi over branch assignments, controlled by an inequality IF, where
    the construct returns the SMALLER value and one compared operand is the
    self-balance read. ``min(self_balance, X) <= self_balance``."""
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
    # Map each branch's assigned value to the true/false side of the condition.
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
    """Form 2: ``operand`` is the result of a 2-argument ``min`` call (a library or
    internal function PROVEN to return the smaller argument) one of whose arguments
    is the self-balance read. ``min(self_balance, X) <= self_balance``."""
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
    """An amount provably ``<= address(this).balance``: the minimum of the
    contract's own balance and some other value. Recognized in the two forms a min
    compiles to (a hand-written ternary, a min-call). Fails to ``False`` on any
    doubt — a MAX, a foreign balance, more than two inputs — so the caller stays
    ``indeterminate`` rather than over-claiming a bound."""
    return _capped_ternary(operand, ctx) or _capped_min_call(operand, ctx)


def _classify_site(operand: Any, ctx: _UnitCtx, *, amount: bool) -> tuple[str, str]:
    """Classify one destination/amount operand at one IR site -> (kind, tier).

    The load-bearing fallback: any operand that could be a collapsed
    cross-branch merge (``_reaches_merged_local``) is ``indeterminate`` — we
    never project a concrete kind the engine's base-name keying might have
    silently picked from an ambiguous set."""
    if operand is None:
        return ("indeterminate", "static_trace")
    # An array/mapping/struct element is classified by its ROOT base, detected
    # positively from the operand IR so it is not confused with a forwarded
    # parameter (source-set-identical via the entrypoint Phi). This runs BEFORE
    # the merged-local guard because the guard also walks the element KEY, and a
    # loop-merged index (``targets[i]``) says nothing about the destination's
    # kind — every element of the base shares its origin. A merged BASE is still
    # caught: the root resolves through ``_arg_origin``, which applies the guard.
    elem = _element_kind(operand, ctx, amount=amount)
    if elem is not None:
        return (elem, "static_trace")
    # An amount that is provably ``min(address(this).balance, X)`` is bounded by
    # the contract's own balance. This runs BEFORE the merged-local guard because
    # the ternary form (Form 1) IS a cross-branch Phi merge the guard would fold to
    # indeterminate, and before the source path because the min-call form (Form 2)
    # otherwise declines there. Amount-only: a destination has no such bound.
    if amount and _is_capped_by_balance(operand, ctx):
        return ("capped_by_balance", "static_trace")
    if _reaches_merged_local(operand, ctx):
        return ("indeterminate", "static_trace")
    # A call's return value classifies from the callee's standard identity, or
    # from what an in-contract helper's body provably returns — a trace through
    # the call either way, never a dispositive AST read.
    call = _call_origin(operand, ctx, amount=amount)
    if call is not None:
        kind = _origin_to_amount_kind(call) if amount else _origin_to_target_kind(call, ctx)
        return (kind, "static_trace")
    srcs = ctx.engine._sources_for_value(operand)
    kind = _amount_kind_from_sources(srcs, ctx) if amount else _target_kind_from_sources(srcs, ctx)
    if kind == "indeterminate":
        return ("indeterminate", "static_trace")
    # A ``parameter`` operand resolved inside a nested callee was recovered by
    # threading the caller's binding across the internal-call boundary — a trace,
    # not a dispositive AST fact at the entry. State-var / msg.sender reads are
    # contract-global and stay dispositive regardless of nesting.
    forwarded_param = ctx.nested and any(s.kind == "parameter" for s in srcs)
    direct = _operand_is_direct(operand, ctx.param_names) and not forwarded_param
    tier = "dispositive_ast" if direct else "static_trace"
    return (kind, tier)


# ``writer_surface_closed`` has exactly one admissible value. Declared as a
# literal-typed constant so the type checker, not a reviewer, is what rejects a
# ``True`` — there is no migration here and so no CHECK constraint to lean on.
_WRITER_SURFACE_CLOSED: Literal["not_determined"] = "not_determined"


# One destination site that named no state variable at all.
_NO_TARGET_VAR: tuple[str | None, str | None, tuple[str, ...], bool, str | None] = (None, None, (), False, None)


def _target_variable_site(name: str, ctx: _UnitCtx) -> tuple[str | None, str | None, tuple[str, ...], bool, str | None]:
    """One destination site: ``(name, canonical name, writers, scan complete,
    reason no writer was attributed)``.

    The CANONICAL name is what sites are compared on. Two contracts in one call
    graph may each declare ``recipient``, with separate setters and separate
    values; agreeing on the bare identifier would publish the scalar — whose
    registered meaning is "every contributing site named the same one" — over
    two different declarations, and silently skip the member list a consumer is
    instructed to read the worst of."""
    variable = ctx.state_vars_by_name.get(name)
    canonical = getattr(variable, "canonical_name", None) if variable is not None else None
    writers = tuple(ctx.setters.get(name, ()))
    reason: str | None = None
    if not writers and name in ctx.setters:
        # Only a SETTER target has an absent-writer question at all: a constant
        # or immutable is not in this map, and its kind already answers it. The
        # two ways a setter target can have no NAMED writer carry opposite risk,
        # so they must not both read as a bare absent key: a declaration-site
        # initialiser is effectively fixed short of an upgrade, while an
        # unattributed storage-pointer alias is a real writer this pass could
        # not name and may be reachable by anyone.
        reason = "alias_unattributed" if name in ctx.alias_resolved else "declaration_initialiser_only"
    return (name, str(canonical) if canonical else None, writers, ctx.setter_scan_complete, reason)


def _target_state_var_name(operand: Any, ctx: _UnitCtx) -> str | None:
    """The ONE state variable a destination operand reads, or ``None``.

    Mirrors :func:`_classify_site`'s decision path exactly, guard for guard, so
    the name can never disagree with the kind published beside it. In
    particular an ELEMENT read declines: ``tokens[id]`` classifies by its base's
    mutability, but the base is not the destination, and publishing its name
    would say one address where there is one per key."""
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
    """Collapse every contributing IR site's (kind, tier) to one classification.
    Tier is the weaker of the contributing sites — one traced site makes the
    whole a ``static_trace``.

    Three outcomes, and the middle one is the point:

    * sites AGREE on one resolved kind — that kind.
    * sites DISAGREE but every member is itself resolved — ``several``. The
      function has several destinations (or several amounts) and we know what
      each of them is; saying ``indeterminate`` there claimed we had traced
      nothing, on flows where we had traced everything. A scorer reading the
      scalar alone would score a function that pays a caller-named address and a
      fixed one identically to a function nothing is known about.
    * any member is itself ``indeterminate`` — ``indeterminate``. One unresolved
      site means the set of destinations is not closed, so the members cannot be
      published as the whole of it.

    The name is deliberately quantitative and says nothing about control flow:
    ``several`` is a set, not a sequence and not a disjunction. The sites may be
    mutually exclusive branches or may all execute in one call, and nothing here
    distinguishes those — a withdrawal that pays the user and then sweeps the
    remainder to a pool makes BOTH moves in the same invocation. A consumer must
    read ``target_kinds``/``amount_kinds`` and take the WORST member — one
    caller-chosen site in the set means the caller can name a destination on some
    path, which is the whole question."""
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
    """The distinct site classifications behind a fold, or ``None`` when the
    fold is already the whole answer.

    ``_fold_sites`` must keep returning one scalar (a scorer reads it), but a
    function with two separately-resolved destinations then publishes only
    ``indeterminate`` — we would be hiding an answer we hold. This publishes the
    contributing sites alongside it, deduplicated by MEANING (the ``(kind,
    tier)`` pair, so provenance is not flattened either) in first-seen order.

    Emitted only when the sites disagree on the KIND, which is exactly when
    ``_fold_sites`` gives up its answer; sites agreeing on a kind are already
    fully described by the fold (which carries their weaker tier), so publishing
    "msg_sender, msg_sender" there would be noise on a flow nothing was hidden
    from. An ``indeterminate`` site stays in the list — the breakdown says why
    the fold is what it is, it never makes it look more resolved.

    Size needs no cap: both lattices are finite closed vocabularies and dedup is
    by lattice member × tier, so the list is bounded by that product (≤20 target,
    ≤14 amount entries) no matter how many IR sites a function has."""
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
    """The param→neutral-origin map forwarded at one internal/library call site,
    resolved in the caller's ``ctx``, plus its param→entry-parameter-INDEX half.
    Each callee formal parameter binds to the entry-rooted origin of its
    positional argument (``_arg_origin``), chaining through the caller's own
    bindings so a multi-hop forward stays exact. The index map carries only the
    formals whose argument is one whole entry parameter."""
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
