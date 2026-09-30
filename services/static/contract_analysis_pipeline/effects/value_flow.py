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


def _arg_is_address_this(arg: Any, this_ids: set[int], this_names: set[str]) -> bool:
    if arg is None:
        return False
    if getattr(arg, "name", None) == "this":
        return True
    if id(arg) in this_ids:
        return True
    name = getattr(arg, "name", None)
    return isinstance(name, str) and name in this_names


# Bounds recursion when a helper is reached with many distinct bindings; ``visited`` already guarantees termination and
# a cutoff only drops flows.
_VALUE_WALK_DEPTH_CAP = 128


def _value_flow_facts(function: Any, *, zero_value_sinks: set[str] | None = None) -> list[ValueFlow]:
    """Value movement facts, transitively: ``transferFrom`` from ``address(this)`` flows out, and native
    ``transfer``/``send`` are their own IR op.

    ``zero_value_sinks`` records flow kinds dropped because their amount is provably zero, which is the only evidence
    that can retract a label.

    Each flow carries ``target_kind`` and ``amount_kind`` from the SSA provenance engine, folded across sites per flow
    key (with ``target_kinds``/``amount_kinds`` when they disagree).
    """
    flows: list[ValueFlow] = []
    # Routed flows are appended after the walk so same-contract flow order is unchanged.
    router_flows: list[ValueFlow] = []
    seen: set[tuple[str, str | None, str, bool, str]] = set()
    # Keyed by (unit, bindings, crossed): divergent bindings re-walk so the fold sees the disagreement, and routed and
    # same-contract walks classify against different contracts.
    visited: set[tuple[int, Any, Any, bool]] = set()
    target_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    amount_sites: dict[tuple[str, str | None, str, bool, str], list[tuple[str, str]]] = {}
    target_indexes: dict[tuple[str, str | None, str, bool, str], list[int | None]] = {}
    amount_indexes: dict[tuple[str, str | None, str, bool, str], list[int | None]] = {}
    # Per amount site, so the fold decides agreement.
    amount_record_sites: dict[tuple[str, str | None, str, bool, str], list[ElementRecordSite | None]] = {}
    # Per destination site: variable, writers and scan completeness in the site's own context (a routed walk classifies
    # against the callee's contract).
    target_variable_sites: dict[
        tuple[str, str | None, str, bool, str], list[tuple[str | None, str | None, tuple[str, ...], bool, str | None]]
    ] = {}
    # Per routed flow: identities of the ops carrying it. Sites with none record nothing (blocks, never proves).
    router_ops_by_key: dict[tuple[str, str | None, str, bool, str], set[tuple[str | None, str | None]]] = {}

    entry_contract = getattr(function, "contract", None)
    # Classification context per contract; crossing a ``HighLevelCall`` rebuilds it for the callee, so ``address(this)``
    # and mutability are read against the running contract.
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
        # The expensive per-unit engine is memoized in ``_engine_bundle_for``.
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
        # A provably-zero move moves nothing and would also collapse a real send on the same key to indeterminate, so
        # drop it for every sink kind. Never under ``amount_override`` (the slot is a token id and 0 is a real NFT), nor
        # for the ambiguous ``transferFrom`` selector, where 0 may be token id 0.
        if _amount_is_provably_zero(amount, ctx):
            if amount_override is not None:
                pass
            elif identity_possible:
                # The move stands but the amount can't be called ``fixed_constant`` when the selector is ambiguous.
                amount_override = ("indeterminate", "static_trace")
            else:
                if zero_value_sinks is not None:
                    zero_value_sinks.add(str(flow["kind"]))
                return
        target_site = _classify_site(target, ctx, amount=False)
        # ``in`` needs the destination resolved to this contract; a pull between third parties (a fee paid straight to a
        # bridge) is only caused here, and an unresolved destination proves nothing.
        if routed_unless_sink_is_self and target_site[0] != "self":
            flow = {**flow, "direction": "value_router"}
        key = (flow["kind"], flow["selector"], flow["direction"], flow["from_is_self"], flow["origin"])
        if flow["direction"] == "value_router":
            # A move past a boundary is carried by the crossing call; a boundary-less routed pull by its own op.
            identity = router_op if crossed else op_identity
            if identity is not None and (identity[0] or identity[1]):
                router_ops_by_key.setdefault(key, set()).add(identity)
        target_sites.setdefault(key, []).append(target_site)
        # The ABI proves this slot isn't a quantity, so don't trace it as one.
        amount_site = amount_override or _classify_site(amount, ctx, amount=True)
        amount_sites.setdefault(key, []).append(amount_site)
        target_variable_name = _target_state_var_name(target, ctx)
        target_variable_sites.setdefault(key, []).append(
            _target_variable_site(target_variable_name, ctx) if target_variable_name is not None else _NO_TARGET_VAR
        )
        target_indexes.setdefault(key, []).append(_operand_param_index(target, ctx))
        # A ``param_derived`` amount is a call result; publish the slot feeding the call.
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
        # The first boundary-crossing call on this path; nested crossings don't overwrite it (the entry only sees the
        # first).
        router_op: tuple[str | None, str | None] | None = None,
    ) -> None:
        sig = None if param_bindings is None else frozenset(param_bindings.items())
        # Sites can forward the same origins from different positions; don't let the first stand for both.
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

        # A move across a contract boundary is the router's effect on another contract.
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
                    # Dropped by ``add``'s zero-amount guard (OZ SafeERC20's value-0 call).
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
                # Token-first library transfers (SafeTransferLib/SafeERC20) are invisible to the selector scan;
                # recognized in the contract's own body too, with ``direction_of`` giving the real direction.
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
                    # Still descend into a recognized callee: the recognizer only fires where the walk sees no flow, and
                    # skipping the descent lost every other move in that helper (e.g. the ETH branch of a dual-asset
                    # payout).
                    callee = getattr(ir, "function", None)
                    if callee is not None and getattr(callee, "nodes", None):
                        child_origin = "guard" if (origin == "guard" or _is_modifier_call(ir)) else "body"
                        child_bindings, child_index_bindings = _bindings_for_call(ir, callee, context())
                        # Internal/library calls keep the caller's contract context.
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
                    # Route into a resolved in-unit callee whose body moves value (``BoringVault.enter``/``exit``),
                    # rebasing the context onto the callee's contract.
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
                            # Nested crossings keep the first op, the only one the entry's tree sees.
                            router_op=router_op if crossed else (selector, _bare_callee_name(signature)),
                        )

    walk(function, "body", True, None, None, 0, False, entry_contract)
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
    """Publish the destination variable, its in-unit writers and both gates.

    Only when the folded kind names a state variable. Sites naming different declarations publish canonical members and
    no scalar (agreeing on ``storage_setter`` or on a bare name isn't agreeing on the destination). The writer list
    ships with both gates or not at all; ``[]`` only under ``storage_no_setter``, otherwise the key is omitted and
    ``target_writer_absent_reason`` says why.
    """
    if target["kind"] not in STATE_VAR_TARGET_KINDS or not sites:
        return
    if any(canonical is None for _, canonical, _, _, _ in sites):
        # An unidentified declaration can't be shown to agree.
        return
    canonicals = {canonical for _, canonical, _, _, _ in sites if canonical is not None}
    if len(canonicals) > 1:
        flow["target_variables"] = sorted(canonicals)
        return
    flow["target_variable"] = sites[0][0] or ""
    # Never true and never derived; published wherever the variable is.
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
    """Publish the record the amount is read from, under :func:`_attach_target_variable`'s rules.

    Only for ``bounded_by_storage``; one site without a record publishes nothing. Paths and keys only where every site
    agreed.
    """
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
    """The one entry slot every site resolved to, for ``param`` (or ``param_derived``, meaning the input slot); else
    ``None``.
    """
    if kind["kind"] not in ("param", "param_derived") or not indexes:
        return None
    distinct = set(indexes)
    if len(distinct) != 1:
        return None
    return next(iter(distinct))
