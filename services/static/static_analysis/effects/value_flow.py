"""Value-flow facts: direction correction, native transfer/send sinks, attachers."""

from __future__ import annotations

from typing import Any

from ..predicate_types import (
    STATE_VAR_TARGET_KINDS,
    TARGET_KIND_STORAGE_NO_SETTER,
    TARGET_KIND_STORAGE_SETTER,
)
from ..shared import _all_state_variables
from .origins import (
    _NO_TARGET_VAR,
    _WRITER_SURFACE_CLOSED,
    ElementRecordSite,
    _amount_is_provably_zero,
    _bindings_for_call,
    _build_unit_ctx,
    _classify_site,
    _element_record_site,
    _fold_sites,
    _operand_param_index,
    _param_derived_index,
    _site_breakdown,
    _target_state_var_name,
    _target_variable_site,
    _UnitCtx,
)
from .selectors import _callee_signature, _selector_for, _token_first_transfer
from .setters import _aliased_storage_writes, _setter_scan_complete, _setter_state_vars
from .sinks import _bare_callee_name, _is_modifier_call
from .types import (
    _AMBIGUOUS_PULL_SELECTOR,
    _ERC20_PULL_SELECTORS,
    _ERC20_SEND_SELECTORS,
    _ERC721_IDENTITY_SELECTORS,
    _TOKEN_IDENTITY_AMOUNT,
    KindTier,
    ValueFlow,
)

# ---------------------------------------------------------------------------
# Value-flow facts (direction correction + native transfer/send sinks).
# ---------------------------------------------------------------------------


def _arg_is_address_this(arg: Any, this_ids: set[int], this_names: set[str]) -> bool:
    if arg is None:
        return False
    if getattr(arg, "name", None) == "this":
        return True
    if id(arg) in this_ids:
        return True
    name = getattr(arg, "name", None)
    return isinstance(name, str) and name in this_names


# Re-walk insurance: bounds interprocedural recursion when a helper is reached
# with many distinct forwarded-binding signatures (a wide call DAG). Real helper
# chains are a handful of hops deep; a cutoff only drops sends past a depth no
# real destination reaches, in the safe direction (a missing flow, never a
# guessed one). The per-(unit, bindings) ``visited`` set already guarantees
# termination — this is belt-and-suspenders against pathological blow-up.
_VALUE_WALK_DEPTH_CAP = 128


def _value_flow_facts(function: Any, *, zero_value_sinks: set[str] | None = None) -> list[ValueFlow]:
    """Value movement facts, transitively. ``transferFrom`` whose ``from``
    is ``address(this)`` flows *out*; native ``transfer``/``send`` are value
    sinks Slither lowers to their own IR op (not a low-level call).

    ``zero_value_sinks`` collects the flow KINDS this walk reached and dropped
    because their amount is provably zero. Absence of a flow is otherwise
    indistinguishable from never having looked, and the label plane needs the
    difference: only a site the walk saw, resolved through its caller's
    bindings, and proved moves nothing can retract a claim.

    Each flow additionally carries ``target_kind`` (where the funds go) and
    ``amount_kind`` (how much can leave), classified by reusing the SSA
    ``ProvenanceEngine`` per unit. Every IR site contributing to a flow is
    classified and the results are folded per flow key, so distinct
    destinations across branches/sites collapse to ``indeterminate`` instead of
    the first-seen winner — with the contributing sites published alongside as
    ``target_kinds``/``amount_kinds`` when they disagreed."""
    flows: list[ValueFlow] = []
    # Value moves found while CROSSED into a callee contract (``value_router``
    # direction). Collected apart and appended after the primary walk so the
    # same-contract flow list stays in its exact prior order — the parity
    # guarantee — with routed flows strictly after it.
    router_flows: list[ValueFlow] = []
    seen: set[tuple[str, str | None, str, bool, str]] = set()
    # Keyed by (unit id, forwarded-binding signature, crossed): a helper reached
    # with the SAME bindings is deduped, but one reached with DIVERGENT bindings
    # across call sites is re-walked so the cross-site fold collapses to
    # indeterminate. ``crossed`` is part of the identity so a routed walk of a
    # unit can never suppress (or be suppressed by) a same-contract walk of it —
    # the two classify against different contract contexts.
    visited: set[tuple[int, Any, Any, bool]] = set()
    target_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    amount_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    target_indexes: dict[tuple[str, str | None, str, bool, str], list[int | None]] = {}
    amount_indexes: dict[tuple[str, str | None, str, bool, str], list[int | None]] = {}
    # Per amount site: the storage record it is read out of, or None where the
    # site named none. Carried per site — like the destination's variable — so
    # the fold decides agreement instead of a lookup at the end guessing which
    # site's record it holds.
    amount_record_sites: dict[tuple[str, str | None, str, bool, str], list[ElementRecordSite | None]] = {}
    # Per destination site: the state variable it names (or None), the writer
    # signatures for that variable IN THE SITE'S OWN classification context, and
    # that context's scan completeness. Carried per site rather than looked up at
    # the fold because a routed walk classifies against the CALLEE's contract,
    # whose setters are a different set from the entry's.
    target_variable_sites: dict[
        tuple[str, str | None, str, bool, str], list[tuple[str | None, str | None, tuple[str, ...], bool, str | None]]
    ] = {}
    # Per routed-flow key: the ``(selector, bare name)`` identities of the ops
    # that carry the move (see ``ValueFlow.router_ops``). Only ever populated
    # for ``value_router`` flows; identity-less sites simply record nothing,
    # which downstream reads as "router op not determined" (blocks, never
    # proves).
    router_ops_by_key: dict[tuple[str, str | None, str, bool, str], set[tuple[str | None, str | None]]] = {}

    entry_contract = getattr(function, "contract", None)
    # Per-contract classification context (state vars + the setter/alias/scan
    # soundness guards), memoized by contract identity for this build pass. The
    # ENTRY's contract classifies every same-contract unit exactly as before;
    # crossing a HighLevelCall rebuilds it for the CALLEE's contract so
    # ``address(this)``, state-var mutability, and self-detection are read against
    # the contract whose body is actually running, not the router's.
    ctx_tuple_cache: dict[int, tuple[dict[str, Any], dict[str, list[str]], set[str], set[str], bool]] = {}

    def contract_ctx_tuple(
        contract: Any,
    ) -> tuple[dict[str, Any], dict[str, list[str]], set[str], set[str], bool]:
        cache_key = id(contract)
        cached = ctx_tuple_cache.get(cache_key)
        if cached is not None:
            return cached
        state_vars_by_name: dict[str, Any] = {
            getattr(v, "name", "") or "": v for v in (_all_state_variables(contract) if contract is not None else [])
        }
        setters = _setter_state_vars(contract) if contract is not None else {}
        aliased = _aliased_storage_writes(contract) if contract is not None else (set(), set(), False)
        alias_indeterminate = aliased[1]
        alias_resolved = aliased[0]
        scan_complete = _setter_scan_complete(contract) if contract is not None else False
        result = (state_vars_by_name, setters, alias_indeterminate, alias_resolved, scan_complete)
        ctx_tuple_cache[cache_key] = result
        return result

    def unit_ctx(
        unit: Any,
        is_entry: bool,
        param_bindings: dict[str, tuple[str, ...]] | None,
        param_index_bindings: dict[str, int] | None,
        class_contract: Any,
    ) -> _UnitCtx:
        # Fresh per (unit, bindings); the expensive per-unit ProvenanceEngine is
        # memoized inside ``_engine_bundle_for``, so this wrapper is cheap.
        state_vars_by_name, setters, alias_indeterminate, alias_resolved, scan_complete = contract_ctx_tuple(
            class_contract
        )
        return _build_unit_ctx(
            unit,
            is_entry,
            state_vars_by_name,
            setters,
            alias_indeterminate,
            alias_resolved,
            scan_complete,
            param_bindings,
            param_index_bindings,
        )

    def add(
        flow: ValueFlow,
        target: Any,
        amount: Any,
        ctx: _UnitCtx,
        crossed: bool,
        amount_override: tuple[str, str] | None = None,
        identity_possible: bool = False,
        routed_unless_sink_is_self: bool = False,
        router_op: tuple[str | None, str | None] | None = None,
        op_identity: tuple[str | None, str | None] | None = None,
    ) -> None:
        # A move of a provably-zero amount moves nothing — ``transfer(to, 0)``
        # transfers no tokens, and a router handing a callee a literal ``0`` (which
        # the callee then guards with ``if (amount > 0)``) causes no transfer at
        # all. Publishing one names an outflow that CANNOT execute, and the site
        # would additionally fold with any real send on the same key and collapse a
        # resolved destination to ``indeterminate``. Suppressed for every sink kind,
        # because the fact is about the value and not about the call shape.
        #
        # Never applied under ``amount_override``: that slot is a token IDENTITY,
        # and token id 0 is an ordinary NFT. The same reasoning has to reach the
        # AMBIGUOUS selector, which is where the ambiguity actually lives — both
        # ERC-20 and ERC-721 define ``transferFrom(address,address,uint256)``, so
        # a literal ``0`` there is either a zero quantity (moves nothing) or token
        # id 0 (moves an NFT) and nothing in the selector says which. Dropping the
        # site deleted a real transfer, and worse, silently shrank the member set
        # a ``several`` fold then asserts is COMPLETE.
        if _amount_is_provably_zero(amount, ctx):
            if amount_override is not None:
                pass
            elif identity_possible:
                # The move stands, but the amount does NOT: calling a literal
                # zero here ``fixed_constant`` asserts the ERC-20 reading of a
                # slot we just said the selector cannot disambiguate.
                amount_override = ("indeterminate", "static_trace")
            else:
                if zero_value_sinks is not None:
                    zero_value_sinks.add(str(flow["kind"]))
                return
        target_site = _classify_site(target, ctx, amount=False)
        # ``in`` says the funds landed HERE, and only a destination resolved to
        # this contract proves that. A pull whose ``from`` is someone else and
        # whose ``to`` is someone else is a move between two third parties that
        # this function merely caused — the entry is neither source nor sink,
        # which is what ``value_router`` already means. Publishing ``in`` there
        # claimed value entered a contract it never touched (a fee paid by the
        # caller straight to a bridge endpoint reads as a deposit into the
        # bridger). An unresolved destination lands here too: it is not proof the
        # funds arrive, and the weaker routed fact does not assert that they do.
        if routed_unless_sink_is_self and target_site[0] != "self":
            flow = {**flow, "direction": "value_router"}
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        if flow["direction"] == "value_router":
            # A move found beyond a boundary is carried by the call that
            # CROSSED it; a boundary-less routed pull is carried by its own
            # op. Recorded per key so the published flow can name the op(s)
            # whose revert surface IS this effect — and only those.
            identity = router_op if crossed else op_identity
            if identity is not None and (identity[0] or identity[1]):
                router_ops_by_key.setdefault(key, set()).add(identity)
        target_sites.setdefault(key, []).append(target_site)
        # ``amount_override`` is for a sink whose trailing slot the ABI proves is
        # not a quantity at all: tracing its provenance would answer a question
        # nobody asked and publish the answer under the name "amount".
        amount_site = amount_override or _classify_site(amount, ctx, amount=True)
        amount_sites.setdefault(key, []).append(amount_site)
        target_variable_name = _target_state_var_name(target, ctx)
        target_variable_sites.setdefault(key, []).append(
            _target_variable_site(target_variable_name, ctx) if target_variable_name is not None else _NO_TARGET_VAR
        )
        target_indexes.setdefault(key, []).append(_operand_param_index(target, ctx))
        # A ``param_derived`` amount is a call RESULT, so the slot to publish is
        # the one feeding the call, resolved from its arguments instead.
        amount_indexes.setdefault(key, []).append(
            _param_derived_index(amount, ctx)
            if amount_site[0] == "param_derived"
            else _operand_param_index(amount, ctx)
        )
        amount_record_sites.setdefault(key, []).append(_element_record_site(amount, ctx))
        if key in seen:
            return
        seen.add(key)
        (router_flows if crossed else flows).append(flow)

    def walk(
        unit: Any,
        origin: str,
        is_entry: bool,
        param_bindings: dict[str, tuple[str, ...]] | None,
        param_index_bindings: dict[str, int] | None,
        depth: int,
        crossed: bool,
        class_contract: Any,
        # The FIRST boundary-crossing call on this walk path — the entry-side
        # op whose revert surface carries every routed move found below it.
        # ``None`` until a boundary is crossed; never overwritten by a nested
        # crossing (the entry's tree only sees the first one).
        router_op: tuple[str | None, str | None] | None = None,
    ) -> None:
        sig = None if param_bindings is None else frozenset(param_bindings.items())
        # The index half is part of the identity: two sites can forward the same
        # origins from DIFFERENT parameter positions, and deduping those would
        # let the first-walked site's index stand for both.
        index_sig = None if param_index_bindings is None else frozenset(param_index_bindings.items())
        key = (id(unit), sig, index_sig, crossed)
        if key in visited or depth > _VALUE_WALK_DEPTH_CAP:
            return
        visited.add(key)
        ctx: _UnitCtx | None = None  # built lazily only if the unit moves value or forwards args

        def context() -> _UnitCtx:
            nonlocal ctx
            if ctx is None:
                ctx = unit_ctx(unit, is_entry, param_bindings, param_index_bindings, class_contract)
            return ctx

        # A move found across a contract boundary is the ROUTER's effect on a
        # DIFFERENT contract, not the entry's own in/out — it is tagged
        # ``value_router`` regardless of the site's native direction.
        def direction_of(native: str) -> str:
            return "value_router" if crossed else native

        this_ids: set[int] = set()
        this_names: set[str] = set()
        for node in getattr(unit, "nodes", []) or []:
            for ir in getattr(node, "irs_ssa", ()) or ():
                if type(ir).__name__ != "TypeConversion":
                    continue
                source = getattr(ir, "variable", None)
                if getattr(source, "name", None) == "this":
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue is not None:
                        this_ids.add(id(lvalue))
                        name = getattr(lvalue, "name", None)
                        if isinstance(name, str):
                            this_names.add(name)

        for node in getattr(unit, "nodes", []) or []:
            for ir in getattr(node, "irs_ssa", ()) or ():
                op = type(ir).__name__
                if op in ("Transfer", "Send"):
                    add(
                        {
                            "kind": "native_transfer_send",
                            "selector": None,
                            "direction": direction_of("out"),
                            "from_is_self": True,
                            "origin": origin,
                        },
                        getattr(ir, "destination", None),
                        getattr(ir, "call_value", None),
                        context(),
                        crossed,
                        router_op=router_op,
                    )
                elif op == "HighLevelCall":
                    signature = _callee_signature(ir)
                    selector = _selector_for(signature)
                    arguments = list(getattr(ir, "arguments", []) or [])
                    if selector in _ERC20_PULL_SELECTORS:
                        from_arg = arguments[0] if arguments else None
                        from_self = _arg_is_address_this(from_arg, this_ids, this_names)
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out" if from_self else "in"),
                                "from_is_self": from_self,
                                "origin": origin,
                            },
                            arguments[1] if len(arguments) > 1 else None,  # to
                            arguments[2] if len(arguments) > 2 else None,  # amount
                            context(),
                            crossed,
                            _TOKEN_IDENTITY_AMOUNT if selector in _ERC721_IDENTITY_SELECTORS else None,
                            identity_possible=selector == _AMBIGUOUS_PULL_SELECTOR,
                            routed_unless_sink_is_self=not from_self,
                            router_op=router_op,
                            op_identity=(selector, _bare_callee_name(signature)),
                        )
                    elif selector in _ERC20_SEND_SELECTORS:
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out"),
                                "from_is_self": True,
                                "origin": origin,
                            },
                            arguments[0] if arguments else None,  # to
                            arguments[1] if len(arguments) > 1 else None,  # amount
                            context(),
                            crossed,
                            router_op=router_op,
                        )
                elif op == "LowLevelCall" and "value:" in str(ir):
                    # A provably-zero value call (OZ SafeERC20's
                    # ``functionCallWithValue(token, data, 0)``) moves no ETH; it is
                    # dropped by ``add``'s zero-amount guard along with every other
                    # sink kind.
                    add(
                        {
                            "kind": "low_level_value_call",
                            "selector": None,
                            "direction": direction_of("out"),
                            "from_is_self": True,
                            "origin": origin,
                        },
                        getattr(ir, "destination", None),
                        getattr(ir, "call_value", None),
                        context(),
                        crossed,
                        router_op=router_op,
                    )
                # A token-first library/internal transfer (SafeTransferLib /
                # SafeERC20) whose value move is invisible to the selector scan and
                # to the assembly-only callee body. Recognized on the contract's
                # OWN body as well as across a boundary: a contract that reaches
                # for one of these libraries instead of calling ``transfer``
                # directly moves exactly as much value, and publishing nothing for
                # it said "this function moves no funds" about functions that
                # provably do. ``direction_of`` gives the same-contract case its
                # true direction; only a move made across a boundary is routed.
                token_first = _token_first_transfer(ir) if op in ("HighLevelCall", "LibraryCall") else None
                if token_first is not None:
                    signature = _callee_signature(ir)
                    selector = _selector_for(signature)
                    if token_first[0] == "send":
                        _kind, to_arg, amount_arg = token_first
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out"),
                                "from_is_self": True,
                                "origin": origin,
                            },
                            to_arg,
                            amount_arg,
                            context(),
                            crossed,
                            router_op=router_op,
                        )
                    else:  # pull
                        _kind, from_arg, to_arg, amount_arg = token_first
                        from_self = _arg_is_address_this(from_arg, this_ids, this_names)
                        add(
                            {
                                "kind": "callee_erc20_selector",
                                "selector": selector,
                                "direction": direction_of("out" if from_self else "in"),
                                "from_is_self": from_self,
                                "origin": origin,
                            },
                            to_arg,
                            amount_arg,
                            context(),
                            crossed,
                            routed_unless_sink_is_self=not from_self,
                            router_op=router_op,
                            op_identity=(selector, _bare_callee_name(signature)),
                        )
                if op in ("InternalCall", "LibraryCall"):
                    # Descend even into a callee the recognizer just classified.
                    # It cannot double-count: the recognizer only fires when the
                    # callee issues its ERC-20 selector in a form the walk CANNOT
                    # resolve (assembly / ``abi.encodeCall``), which reaches the
                    # walk as a value-less ``LowLevelCall`` and produces no flow.
                    # Skipping the descent instead deleted every OTHER move in
                    # that body — a native ``transfer``, an ERC-721 send, a second
                    # token — from a helper the recognizer happened to match. The
                    # dual-asset payout helper (``if (token == 0) to.call{value:}``
                    # else ``safeTransfer``) lost its whole ETH branch, taking
                    # ``has_native_payout`` with it and silently disabling the
                    # prober's contract-balance seeding.
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
                        child_bindings, child_index_bindings = _bindings_for_call(ir, callee, context())
                        # Internal/library calls stay within the SAME contract
                        # context (and same ``crossed`` state) as their caller.
                        walk(
                            callee,
                            child_origin,
                            False,
                            child_bindings,
                            child_index_bindings,
                            depth + 1,
                            crossed,
                            class_contract,
                            router_op=router_op,
                        )
                elif op == "HighLevelCall":
                    # Route into a RESOLVED in-unit callee that is not itself one
                    # of the already-handled direct value ops — a function whose
                    # BODY moves value (``BoringVault.enter``/``exit``). Crossing
                    # sets ``crossed`` and rebases the classification context onto
                    # the callee's own contract.
                    signature = _callee_signature(ir)
                    selector = _selector_for(signature)
                    is_direct_value = (
                        selector in _ERC20_PULL_SELECTORS
                        or selector in _ERC20_SEND_SELECTORS
                        or _token_first_transfer(ir) is not None
                    )
                    callee = getattr(ir, "function", None)
                    if not is_direct_value and callee is not None and getattr(callee, "nodes", None):
                        child_origin = "guard" if origin == "guard" else "body"
                        child_bindings, child_index_bindings = _bindings_for_call(ir, callee, context())
                        walk(
                            callee,
                            child_origin,
                            False,
                            child_bindings,
                            child_index_bindings,
                            depth + 1,
                            True,
                            getattr(callee, "contract", None),
                            # The op that carries every move found beyond this
                            # boundary. A nested crossing keeps the FIRST one —
                            # the only call the entry's own tree can see.
                            router_op=router_op if crossed else (selector, _bare_callee_name(signature)),
                        )

    walk(function, "body", True, None, None, 0, False, entry_contract)
    # Routed flows come strictly after the same-contract flows, preserving the
    # exact prior ordering of the latter.
    flows.extend(router_flows)
    for flow in flows:
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        if flow["direction"] == "value_router":
            ops = sorted(router_ops_by_key.get(key, ()), key=lambda op: (op[0] or "", op[1] or ""))
            if ops:
                flow["router_ops"] = [{"selector": op_selector, "callee": op_name} for op_selector, op_name in ops]
        target = _fold_sites(target_sites.get(key, []))
        amount = _fold_sites(amount_sites.get(key, []))
        if target is not None:
            flow["target_kind"] = target
            breakdown = _site_breakdown(target_sites.get(key, []))
            if breakdown is not None:
                flow["target_kinds"] = breakdown
            index = _fold_param_index(target, target_indexes.get(key, []))
            if index is not None:
                flow["target_param_index"] = index
            _attach_target_variable(flow, target, target_variable_sites.get(key, []))
        if amount is not None:
            flow["amount_kind"] = amount
            breakdown = _site_breakdown(amount_sites.get(key, []))
            if breakdown is not None:
                flow["amount_kinds"] = breakdown
            index = _fold_param_index(amount, amount_indexes.get(key, []))
            if index is not None:
                flow["amount_param_index"] = index
            _attach_amount_record(flow, amount, amount_record_sites.get(key, []))
    return flows


def _attach_target_variable(
    flow: ValueFlow,
    target: KindTier,
    sites: list[tuple[str | None, str | None, tuple[str, ...], bool, str | None]],
) -> None:
    """Publish the destination's variable identity, its in-unit writers, and
    the two gates that bound what either may be read to mean.

    Requires the folded kind to NAME a state variable at all — a ``param`` or
    ``msg_sender`` destination has no variable, and an ``indeterminate`` fold
    has no single one. Sites naming different DECLARATIONS publish the member
    list and no scalar: two setter-backed variables both fold to
    ``storage_setter``, so agreement on the KIND is not agreement on the
    destination — and two contracts may each declare ``recipient``, so
    agreement on the NAME is not either. The members are canonical
    (``Contract.var``) precisely because bare names cannot tell them apart,
    which is the whole reason the list is published.

    The writer list rides with BOTH its gates or not at all. ``[]`` is emitted
    only under ``storage_no_setter``, where the kind itself is the completed-scan
    negative; where no writer could be NAMED the key is omitted and
    ``target_writer_absent_reason`` says which of the two absences it is."""
    if target["kind"] not in STATE_VAR_TARGET_KINDS or not sites:
        return
    if any(canonical is None for _, canonical, _, _, _ in sites):
        # A site whose declaration could not be identified cannot be shown to
        # agree with anything.
        return
    canonicals = {canonical for _, canonical, _, _, _ in sites if canonical is not None}
    if len(canonicals) > 1:
        flow["target_variables"] = sorted(canonicals)
        return
    flow["target_variable"] = sites[0][0] or ""
    # Never ``true``, and never derived: the closed-surface question is not
    # answerable from one compilation unit. Published wherever the variable is,
    # so even a row carrying no writer list still carries the bound.
    flow["writer_surface_closed"] = _WRITER_SURFACE_CLOSED
    writers = sorted({signature for _, _, signatures, _, _ in sites for signature in signatures})
    if not writers and target["kind"] != TARGET_KIND_STORAGE_NO_SETTER:
        if target["kind"] == TARGET_KIND_STORAGE_SETTER:
            reasons = {reason for _, _, _, _, reason in sites if reason}
            if len(reasons) == 1:
                flow["target_writer_absent_reason"] = next(iter(reasons))
        return
    flow["target_writer_signatures"] = writers
    flow["target_writer_scan_complete"] = all(complete for _, _, _, complete, _ in sites)


def _attach_amount_record(
    flow: ValueFlow,
    amount: KindTier,
    sites: list[ElementRecordSite | None],
) -> None:
    """Publish the record the amount is read out of — the twin of
    :func:`_attach_target_variable`, and held to the same rule.

    Requires the folded kind to BE ``bounded_by_storage``: that is the one kind
    whose value comes out of a storage cell, and a record published beside any
    other kind would name a cell the amount is not read from. One site that
    named no record ⇒ nothing is published at all, because a record assembled
    from the sites that happened to have one is not the record this flow reads.
    Sites naming different DECLARATIONS publish the member list and no scalar.

    The path and the keys ride only where every site agreed on them: two sites
    reading ``bids[a].amount`` and ``bids[b].shares`` agree on the declaration
    and on nothing else, and the first site's path is not the flow's answer."""
    if amount["kind"] != "bounded_by_storage" or not sites:
        return
    if any(site is None for site in sites):
        return
    present = [site for site in sites if site is not None]
    canonicals = {site["base_canonical"] for site in present}
    if len(canonicals) > 1:
        flow["amount_record_variables"] = sorted(canonicals)
        return
    flow["amount_record_variable"] = next(iter(canonicals))
    member_paths = {site["member_path"] for site in present}
    if len(member_paths) == 1:
        flow["amount_record_member_path"] = list(next(iter(member_paths)))
    key_kinds = {tuple(origin[0] for origin in site["key_origins"]) for site in present}
    if len(key_kinds) == 1:
        flow["amount_record_key_kinds"] = list(next(iter(key_kinds)))
    key_indexes = {site["key_param_indexes"] for site in present}
    if len(key_indexes) == 1:
        flow["amount_record_key_param_indexes"] = list(next(iter(key_indexes)))


def _fold_param_index(kind: KindTier, indexes: list[int | None]) -> int | None:
    """The one entry-parameter slot every contributing site resolved to.

    Requires the folded kind to BE ``param`` (so the value is an entry parameter
    at all) and every site to have resolved the same index. A site that resolved
    none, or two sites resolving different positions, yields ``None``: the flow
    still has a ``param`` origin, we just cannot say which slot.

    ``param_derived`` (amounts only) qualifies under the same discipline, with
    the index meaning the slot of the caller INPUT that fed the conversion rather
    than the slot of the value itself — see :func:`_param_derived_index`."""
    if kind["kind"] not in ("param", "param_derived") or not indexes:
        return None
    distinct = set(indexes)
    if len(distinct) != 1:
        return None
    return next(iter(distinct))
