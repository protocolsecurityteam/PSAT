"""Predicate-tree evaluator — the bridge from static stage to resolver.

Takes a ``PredicateTree`` (from ``services.static.contract_analysis_pipeline.
predicates.build_predicate_tree``) and produces a ``CapabilityExpr``
describing the principal set / capability shape that gates the
function. Recursive: AND/OR nodes compose via the closed combinators
in ``capabilities.py``.

Per v6 round-5 #3 fix, dispatch order is:
  1. kind == "unsupported"           → CapabilityExpr.unsupported(reason)
  2. authority_role ∈ {reentrancy, pause, business, time} →
     conditional_universal (anyone, with the side condition)
  3. caller_authority / delegated_authority — dispatch on leaf kind:
     - membership   → adapter.enumerate(set_descriptor) → finite_set
     - equality     → resolve operand → finite_set([address])
     - external_bool→ external_check_only
     - signature_auth → signature_witness
     - comparison   → conditional_universal (caller-priority comparisons
                       are exotic; mostly time-gates, already handled)

Adapters are pluggable: the caller passes an ``AdapterRegistry`` (week 5
deliverable). Without adapters, membership leaves return finite_set with
quality=lower_bound and empty members — the structural skeleton is
correct, just unfilled.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Protocol, cast

from eth_utils.crypto import keccak

from services.static.contract_analysis_pipeline.predicate_types import (
    LeafPredicate,
    PredicateTree,
    SetDescriptor,
)

from .capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
    intersect,
    negate,
    union,
)

_CALLER_SOURCES = {"msg_sender", "tx_origin", "signature_recovery", "root_caller"}


def _state_var_lookup_key(operand: dict[str, Any]) -> str | None:
    name = operand.get("state_variable_name")
    if not isinstance(name, str) or not name:
        return None
    member_path = operand.get("member_path")
    if isinstance(member_path, list) and member_path:
        parts = [part for part in member_path if isinstance(part, str) and part]
        if parts:
            return ".".join([name, *parts])
    return name


# ---------------------------------------------------------------------------
# Adapter protocol (placeholder — week-5 fully-typed registry replaces this)
# ---------------------------------------------------------------------------


class SetAdapter(Protocol):
    """Minimal adapter interface for week-4. The full SetAdapter
    Protocol (with EvaluationContext, matches/enumerate/membership)
    lands in week 5 alongside concrete adapters."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr: ...


class _NullAdapter:
    """Fallback when no real adapter is registered. Returns
    finite_set(empty, lower_bound) — the structural skeleton without
    a populated members list."""

    def enumerate(self, descriptor: SetDescriptor, contract_address: str | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class EvaluationContext:
    """Resolver-side context for the simple (week-4) evaluator path.

    The full week-5 ``EvaluationContext`` lives in
    ``services.resolution.adapters`` and carries chain/RPC/repos.
    Use ``evaluate_tree_with_registry`` to dispatch via that fuller
    context.
    """

    def __init__(
        self,
        *,
        contract_address: str | None = None,
        adapter: SetAdapter | None = None,
        block: int | None = None,
        state_var_values: dict[str, str] | None = None,
        call_frame: Any = None,
    ) -> None:
        self.contract_address = contract_address
        self.adapter: SetAdapter = adapter or _NullAdapter()
        self.block = block
        # Persisted state-variable values keyed by storage-var name.
        # Used by ``_resolve_equality_principal`` to enumerate state-variable
        # authority values into concrete addresses.
        self.state_var_values = state_var_values or {}
        self.call_frame = call_frame


def evaluate_tree_with_registry(
    tree: PredicateTree | None,
    registry: Any,  # adapters.AdapterRegistry — typed loosely to avoid circular import
    ctx: Any,  # adapters.EvaluationContext
) -> CapabilityExpr:
    """Like ``evaluate_tree`` but routes membership leaves through the
    week-5 AdapterRegistry. The registry's ``enumerate(descriptor,
    ctx)`` returns a CapabilityExpr that may be a populated
    finite_set, threshold_group, external_check_only, or
    unsupported(no_adapter)."""

    class _RegistryBackedAdapter:
        # ``_outer_ctx`` exposes the full resolver ctx (session, event logs,
        # state_var_values, evaluation_stack, …) to leaf evaluators that
        # need cross-contract inlining. ``_registry`` is the AdapterRegistry
        # the recursive ``evaluate_tree_with_registry`` re-uses when it
        # spawns a child ctx for B's tree.
        _outer_ctx = ctx
        _registry = registry

        def enumerate(self, descriptor, contract_address):  # noqa: ARG002
            return registry.enumerate(descriptor, ctx)

    eval_ctx = EvaluationContext(
        contract_address=getattr(ctx, "contract_address", None),
        adapter=_RegistryBackedAdapter(),
        block=getattr(ctx, "block", None),
        state_var_values=getattr(ctx, "state_var_values", None),
        call_frame=getattr(ctx, "call_frame", None),
    )
    return evaluate_tree(tree, eval_ctx)


def evaluate_tree(
    tree: PredicateTree | None,
    ctx: EvaluationContext | None = None,
) -> CapabilityExpr:
    """Walk a PredicateTree and return its CapabilityExpr.

    None or empty tree → conditional_universal with no conditions
    (i.e., 'public' / no gating).

    AND / OR nodes recurse via closed combinators.

    LEAF nodes dispatch per the v6 order: unsupported first, then
    side-condition roles, then caller/delegated auth.
    """
    if ctx is None:
        ctx = EvaluationContext()
    if tree is None:
        return CapabilityExpr.conditional_universal(
            Condition(kind="business", description="no gating"),
        )
    op = tree.get("op")
    if op == "LEAF":
        leaf = tree.get("leaf")
        if leaf is None:
            return CapabilityExpr.unsupported("empty_leaf")
        return _evaluate_leaf(leaf, ctx)
    children = tree.get("children") or []
    if not children:
        return CapabilityExpr.unsupported("empty_branch")
    evaluated = []
    for child in children:
        side_condition = _side_condition_capability(child) if op == "AND" and len(children) > 1 else None
        evaluated.append(side_condition or evaluate_tree(child, ctx))
    if op == "AND":
        result = evaluated[0]
        for child in evaluated[1:]:
            result = intersect(result, child)
        return result
    if op == "OR":
        result = evaluated[0]
        for child in evaluated[1:]:
            result = union(result, child)
        return result
    return CapabilityExpr.unsupported(f"unknown_op_{op}")


# ---------------------------------------------------------------------------
# Per-leaf dispatch
# ---------------------------------------------------------------------------


def _has_caller_keyed_value_predicate(leaf: LeafPredicate) -> bool:
    """True iff ``leaf.set_descriptor`` carries a ``value_predicate``
    AND at least one ``key_sources`` entry is ``msg_sender`` (i.e. the
    threshold is keyed on the caller). Used to upgrade
    ``business``-flavored thresholds (PR D.1+) into finite-set
    enumerations when the adapter chain has data, while still letting
    pure-business thresholds (``amount > 1000``) fall through to
    ``conditional_universal``.
    """
    descriptor = leaf.get("set_descriptor") or {}
    if not descriptor.get("value_predicate"):
        return False
    keys = descriptor.get("key_sources") or []
    return any(k.get("source") in _CALLER_SOURCES for k in keys)


def _is_opaque_bool_return_predicate(leaf: LeafPredicate) -> bool:
    basis = leaf.get("basis") or []
    if "bool-return predicate" not in basis:
        return False
    if leaf.get("set_descriptor"):
        return False
    if leaf.get("kind") != "equality":
        return False
    return any((op or {}).get("source") in {"computed", "external_call", "top"} for op in leaf.get("operands") or [])


def _evaluate_leaf(leaf: LeafPredicate, ctx: EvaluationContext) -> CapabilityExpr:
    # 0. unsupported is structural — check first (round-5 #3 fix).
    if leaf.get("kind") == "unsupported":
        return CapabilityExpr.unsupported(leaf.get("unsupported_reason") or "unsupported")

    # 1. Non-authority leaves go to side-conditions — UNLESS the
    # descriptor carries a caller-keyed value_predicate (PR D.1+).
    # ``balances[msg.sender] < 10 revert`` is structurally a business
    # threshold but operationally an authority gate over the set of
    # callers whose latest mapping value satisfies the predicate.
    # When the adapter chain has data (durable indexer / on-demand
    # event replay / trace replay) we get a concrete finite_set;
    # otherwise the fallback path produces conditional_universal.
    role = leaf.get("authority_role")
    if role in ("reentrancy", "pause", "business", "time"):
        if _is_opaque_bool_return_predicate(leaf):
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": ["opaque_bool_return_predicate"],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        if _has_caller_keyed_value_predicate(leaf):
            descriptor = leaf.get("set_descriptor")
            if descriptor is not None:
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                # Only return the enumerated capability when it has
                # at least one concrete member. Anything else
                # (``external_check_only``, ``unsupported``, empty
                # ``finite_set`` regardless of quality) means "no
                # useful data" — and a side-condition leaf's
                # description is more informative than an empty
                # principal list. Codex review #3 caught the
                # ``finite_set([], exact)`` case where a genuinely-
                # business predicate could silently lose its
                # description; gating on ``cap.members`` fixes it.
                if cap.kind == "finite_set" and cap.members:
                    return cap
        cond = _condition_from_leaf(leaf)
        return CapabilityExpr.conditional_universal(cond)

    # 2. caller_authority / delegated_authority — dispatch on kind.
    kind = leaf.get("kind")
    operator = leaf.get("operator")

    if kind == "membership":
        descriptor = leaf.get("set_descriptor")
        if descriptor is None:
            return CapabilityExpr.unsupported("membership_without_descriptor")
        cap = _resolve_view_key_membership(descriptor, ctx)
        if cap is None:
            cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
        if operator == "falsy":
            cap = negate(cap)
        return cap

    if kind == "equality":
        if operator in ("eq", "ne"):
            if not _leaf_has_caller_operand(leaf):
                return _resolve_contextual_equality(leaf, ctx, operator)
            base = _resolve_equality_principal(leaf, ctx)
            return base if operator == "eq" else negate(base)
        return CapabilityExpr.unsupported(f"equality_op_{operator}_unsupported")

    if kind == "external_bool":
        descriptor = leaf.get("set_descriptor")
        if descriptor is not None:
            # Cross-contract inlining: when the leaf records an exact
            # callee signature/selector, try evaluating the registry's
            # predicate_trees for that function under the original
            # caller's msg.sender. If it
            # produces a useful capability we use it; otherwise fall
            # through to the adapter-registry path which handles
            # generic event-indexed descriptors.
            inlined = _maybe_inline_cross_contract_call(leaf, descriptor, ctx)
            if inlined is not None:
                if operator == "falsy":
                    inlined = negate(inlined)
                return inlined
            if descriptor.get("kind") == "external_set":
                # Try a named adapter first (e.g. Solmate RolesAuthority resolves
                # canCall via its role events); fall back to the generic
                # external-check materializer only when no adapter produces a
                # concrete set. Previously external_set skipped the registry
                # entirely, so standard authority contracts never resolved.
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                # Fall back to the materializer unless the adapter produced a
                # concrete answer. A non-exact empty finite_set is the _NullAdapter
                # placeholder (or an un-indexed partial) — not a real "nobody";
                # an *exact* empty set IS a real true-negative and is kept.
                if cap.kind in {"unsupported", "external_check_only"} or (
                    cap.kind == "finite_set" and not cap.members and cap.membership_quality != "exact"
                ):
                    cap = _external_check_from_descriptor(leaf, descriptor, ctx)
            else:
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                if cap.kind == "unsupported" and cap.unsupported_reason == "no_adapter":
                    cap = _external_check_from_descriptor(leaf, descriptor, ctx)
            if operator == "falsy":
                cap = negate(cap)
            return cap
        return _resolve_external_bool(leaf, ctx)

    if kind == "signature_auth":
        signer = _resolve_signer_from_leaf(leaf, ctx)
        return CapabilityExpr.signature_witness(signer)

    if kind == "comparison":
        # Caller-authority comparisons are exotic; treat as conditional.
        cond = _condition_from_leaf(leaf)
        return CapabilityExpr.conditional_universal(cond)

    return CapabilityExpr.unsupported(f"unknown_leaf_kind_{kind}")


def _side_condition_capability(tree: PredicateTree) -> CapabilityExpr | None:
    conditions = _side_conditions_from_tree(tree)
    if conditions is None:
        return None
    return CapabilityExpr(
        kind="conditional_universal",
        conditions=conditions,
        confidence="enumerable",
    )


def _side_conditions_from_tree(tree: PredicateTree) -> list[Condition] | None:
    op = tree.get("op")
    if op == "LEAF":
        leaf = tree.get("leaf")
        if not isinstance(leaf, dict):
            return None
        role = leaf.get("authority_role")
        if role in ("reentrancy", "pause", "business", "time") and not leaf.get("references_msg_sender"):
            return [_condition_from_leaf(cast(LeafPredicate, leaf))]
        return None

    children = tree.get("children") or []
    if not children:
        return None

    branch_conditions: list[list[Condition]] = []
    for child in children:
        child_conditions = _side_conditions_from_tree(child)
        if child_conditions is None:
            return None
        branch_conditions.append(child_conditions)

    if op == "AND":
        return [condition for group in branch_conditions for condition in group]
    if op == "OR":
        descriptions = [_condition_group_description(group) for group in branch_conditions]
        description = " OR ".join(description for description in descriptions if description)
        return [Condition(kind="business", description=description or "non-caller side condition")]
    return None


def _condition_group_description(conditions: list[Condition]) -> str:
    descriptions = [condition.description for condition in conditions if condition.description]
    if not descriptions:
        return ""
    if len(descriptions) == 1:
        return descriptions[0]
    return " AND ".join(f"({description})" for description in descriptions)


# ---------------------------------------------------------------------------
# Operand resolution helpers
# ---------------------------------------------------------------------------


def _nullary_getter_selector(name: str | None) -> str | None:
    """4-byte selector for ``<name>()`` — the auto-getter of a public state
    variable. ``None`` for an empty name."""
    if not isinstance(name, str) or not name:
        return None
    return _selector_for_signature(f"{name}()")


# owner() — the canonical OZ Ownable accessor. OZ v4 keeps a plain ``_owner``
# state var; OZ v5 (ERC-7201) keeps it in a namespaced storage struct read via
# assembly. Both expose ``owner()`` identically, so reading it live recovers the
# owner for the v5 case where the operand is the slot-pointer constant.
_OWNER_SELECTOR = "0x8da5cb5b"


def _live_resolve_authority(ctx: EvaluationContext | None, selector: str | None) -> CapabilityExpr | None:
    """Resolve ``msg.sender == X`` by reading ``X`` live when the static
    ``state_var_values`` feed didn't carry it.

    ``msg.sender == owner()`` / ``== governor()`` / ``== <stateVar>`` names a
    single authorized caller; the persisted ``ControllerValue`` feed is the
    only thing :func:`_resolve_equality_principal` consults, so an
    owner()/governor()-gated function whose value was never captured (or was
    captured under a different key) dropped every principal. This reads the
    getter on the contract under analysis and materializes the result.

    Returns ``finite_set([addr], exact)`` for a concrete non-zero address,
    ``finite_set([], exact)`` when the getter returns the zero address
    (genuinely unset / renounced), or ``None`` when nothing could be read — no
    RPC reachable through the outer context, a malformed selector, or a revert
    — in which case the caller keeps the ``lower_bound`` placeholder. Gating on
    a reachable ``rpc_url`` keeps pure-unit evaluations (no RPC) on their
    existing empty-placeholder behaviour."""
    if ctx is None or not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    rpc_url = getattr(outer, "rpc_url", None)
    contract = getattr(outer, "contract_address", None) or ctx.contract_address
    block = getattr(outer, "block", None) if outer is not None else ctx.block
    if not isinstance(rpc_url, str) or not rpc_url:
        return None
    if not isinstance(contract, str) or not contract.startswith("0x") or len(contract) != 42:
        return None
    try:
        from utils.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": contract.lower(), "data": selector}, hex(block) if isinstance(block, int) else "latest"],
            retries=1,
        )
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return None
    addr = "0x" + raw[-40:].lower()
    if _is_zero_address(addr):
        return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
    return CapabilityExpr.finite_set(
        [addr],
        quality="exact",
        confidence="enumerable",
        trace=[{"step": "live_getter_resolution", "selector": selector, "contract": contract.lower()}],
    )


def _resolve_equality_principal(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None = None,
) -> CapabilityExpr:
    """``msg.sender == X`` — resolve X to a CapabilityExpr.

    Per v6 round-5 #2: when X is a function parameter, the result is
    conditional_universal(self_service) — anyone may call but only
    for their own data. State-var operands consult
    ``ctx.state_var_values`` (populated from ``controller_values``);
    when the value isn't there we emit the lower_bound placeholder so
    the FE can still render 'guarded by X' even without enumeration."""
    operands = leaf.get("operands") or []
    other = [op for op in operands if op["source"] not in _CALLER_SOURCES]
    if len(other) != 1:
        return CapabilityExpr.unsupported("equality_operand_ambiguous")
    op = other[0]

    src = op["source"]
    if src == "constant":
        val = op.get("constant_value")
        if isinstance(val, str) and val.startswith("0x") and len(val) == 42:
            if _is_zero_address(val):
                return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
            return CapabilityExpr.finite_set([val])
        return CapabilityExpr.unsupported(f"equality_constant_non_address_{val}")

    if src == "state_variable":
        sv_name = _state_var_lookup_key(cast(dict[str, Any], op))
        if ctx is not None and sv_name and sv_name in ctx.state_var_values:
            value = ctx.state_var_values[sv_name]
            if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
                if _is_zero_address(value):
                    return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
                return CapabilityExpr.finite_set(
                    [value],
                    quality="exact",
                    confidence="enumerable",
                )
        # state_var_values miss. For a bare (non-struct-member) variable the
        # equality ``msg.sender == X`` names X as the sole authorized caller,
        # so reading X's getter live recovers the principal the persisted
        # ControllerValue feed didn't carry (or carried under a different key,
        # e.g. an owner()/governor() gate). Struct members
        # (``accountantState.payoutAddress``) have no nullary getter and
        # describe fund destinations, not callers — left as the placeholder so
        # the FP-only attribution can't re-introduce fee-destination noise.
        if not op.get("member_path"):
            live = _live_resolve_authority(ctx, _nullary_getter_selector(op.get("state_variable_name")))
            if live is not None:
                return live
        elif op.get("member_path") == ["_owner"]:
            # OZ v5 (ERC-7201) Ownable keeps the owner in a namespaced storage
            # struct, so ``msg.sender == OwnableStorageLocation._owner`` arrives
            # as a struct-member operand. Its canonical accessor is the public
            # ``owner()`` getter (identical to v4) — read it live instead of
            # treating the slot-pointer constant as a getter (which reverts, the
            # OZ-v5 owner recall gap). Other struct members (fund destinations
            # like ``accountantState.payoutAddress``) stay placeholders above.
            live = _live_resolve_authority(ctx, _OWNER_SELECTOR)
            if live is not None:
                return live
        # Fallback: we know there's a guarding state-var but haven't
        # enumerated it yet (no ControllerValue row, or non-address
        # value). UI surfaces this as 'guarded but unresolved'.
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )

    if src == "self_address":
        value = ctx.contract_address if ctx is not None else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return CapabilityExpr.finite_set([value.lower()], quality="exact", confidence="enumerable")
        return CapabilityExpr.unsupported("self_address_without_contract")

    if src == "view_call":
        # ``msg.sender == owner()`` / ``== governor()``: the static stage
        # recorded the getter but couldn't read it. Resolve it live against the
        # contract under analysis. This branch previously returned an empty
        # lower_bound placeholder unconditionally, which dropped every
        # owner()/governor()-gated function's principal (the etherfi SyncPool /
        # LRTSquaredCore recall gap). Falls back to the placeholder when no RPC
        # is reachable.
        # Only nullary getters (owner()/governor()) are read live — a view
        # taking args (e.g. roleAdmin(role)) can't be called with empty
        # calldata, so leave it to the placeholder.
        selector = None
        if not op.get("callee_args"):
            selector = op.get("callee_selector")
            if not (isinstance(selector, str) and selector.startswith("0x") and len(selector) == 10):
                signature = op.get("callee_signature")
                selector = (
                    _selector_for_signature(signature)
                    if isinstance(signature, str) and signature.endswith("()")
                    else None
                )
        live = _live_resolve_authority(ctx, selector)
        if live is not None:
            return live
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )

    if src == "parameter":
        # Self-service: anyone, on their own data.
        cond = Condition(
            kind="self_service",
            description=f"caller acting on their own {op.get('parameter_name') or 'arg'}",
            parameter_index=op.get("parameter_index"),
            parameter_name=op.get("parameter_name"),
        )
        return CapabilityExpr.conditional_universal(cond)

    if src == "signature_recovery":
        # Already handled via signature_auth leaf kind, but defensive.
        return CapabilityExpr.signature_witness(CapabilityExpr.unsupported("signer_unresolved"))

    if src == "computed":
        return CapabilityExpr.unsupported(f"equality_operand_computed_{op.get('computed_kind')}")

    return CapabilityExpr.unsupported(f"equality_operand_source_{src}")


def _resolve_view_key_membership(descriptor: SetDescriptor, ctx: EvaluationContext) -> CapabilityExpr | None:
    if descriptor.get("kind") != "mapping_membership":
        return None
    key_sources = list(descriptor.get("key_sources") or [])
    caller_indices = [idx for idx, source in enumerate(key_sources) if source.get("source") in _CALLER_SOURCES]
    view_indices = [idx for idx, source in enumerate(key_sources) if source.get("source") == "view_call"]
    if len(caller_indices) != 1 or len(view_indices) != 1:
        return None

    outer_ctx = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    session = getattr(outer_ctx, "session", None)
    rpc_url = getattr(outer_ctx, "rpc_url", None)
    if session is None or not isinstance(rpc_url, str) or not rpc_url:
        return None

    view_index = view_indices[0]
    view_source = key_sources[view_index]
    selector = view_source.get("callee_selector")
    if not isinstance(selector, str) or not selector.startswith("0x"):
        signature = view_source.get("callee_signature")
        selector = _selector_for_signature(signature) if isinstance(signature, str) else None
    if not selector:
        return None

    event_hints: list[dict[str, Any]] = [
        dict(hint) for hint in (descriptor.get("enumeration_hint") or []) if isinstance(hint, dict)
    ]
    if not event_hints:
        return None
    role_words = _observed_event_key_words(
        session=session,
        outer_ctx=outer_ctx,
        descriptor=descriptor,
        event_hints=event_hints,
        key_index=view_index,
    )
    if not role_words:
        return None

    contract_address = getattr(outer_ctx, "contract_address", None) or ctx.contract_address
    if not isinstance(contract_address, str) or not contract_address.startswith("0x"):
        return None
    admin_words = _call_unary_bytes32_view(
        rpc_url=rpc_url,
        contract_address=contract_address,
        selector=selector,
        args=role_words,
        block=getattr(outer_ctx, "block", None) or ctx.block,
    )
    if not admin_words:
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=contract_address.lower(),
                target_call_selector=selector,
                extra={"basis": ["view_key_membership_unresolved"]},
            )
        )

    result: CapabilityExpr | None = None
    for admin_word in admin_words:
        patched = dict(descriptor)
        patched_keys = [dict(source) for source in key_sources]
        patched_keys[view_index] = {"source": "constant", "constant_value": admin_word}
        patched["key_sources"] = patched_keys
        child = ctx.adapter.enumerate(cast(SetDescriptor, patched), ctx.contract_address)
        result = child if result is None else union(result, child)
    return result


def _observed_event_key_words(
    *,
    session: Any,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
) -> list[str]:
    from sqlalchemy import func, select

    from db.models import IndexedEventLog
    from services.resolution.adapters.event_indexed import _resolve_event_address
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word

    out: set[str] = set()
    for hint in event_hints:
        topic0 = hint.get("topic0")
        if not isinstance(topic0, str):
            continue
        event_address = _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx)
        if event_address is None:
            continue
        stmt = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == getattr(outer_ctx, "chain_id", 1))
            .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
            .where(func.lower(IndexedEventLog.topic0) == topic0.lower())
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        block = getattr(outer_ctx, "block", None)
        if isinstance(block, int):
            stmt = stmt.where(IndexedEventLog.block_number <= block)
        for row in session.execute(stmt).scalars():
            keys = _event_keys(
                row.topics or [],
                row.data_words or [],
                hint.get("topics_to_keys") or {},
                hint.get("data_to_keys") or {},
            )
            word = _normalize_word(keys.get(key_index))
            if word is not None:
                out.add(word)
    if not out:
        out.update(
            _observed_event_key_words_from_hypersync(
                outer_ctx=outer_ctx,
                descriptor=descriptor,
                event_hints=event_hints,
                key_index=key_index,
            )
        )
    return sorted(out)


def _observed_event_key_words_from_hypersync(
    *,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
) -> list[str]:
    import asyncio
    import os
    import time

    from services.resolution.adapters.event_indexed import _resolve_event_address
    from services.resolution.repos.event_logs_hypersync import (
        _data_words_from_log,
        _logs_from_response,
        _topics_from_log,
    )
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word

    token = os.getenv("ENVIO_API_TOKEN") or getattr(outer_ctx, "meta", {}).get("hypersync_token")
    if not token:
        return []
    address_topics: dict[str, set[str]] = {}
    hints_by_address_topic: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for hint in event_hints:
        topic0 = hint.get("topic0")
        if not isinstance(topic0, str):
            continue
        event_address = _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx)
        if event_address is None:
            continue
        address_topics.setdefault(event_address.lower(), set()).add(topic0.lower())
        hints_by_address_topic.setdefault((event_address.lower(), topic0.lower()), []).append(hint)
    if not address_topics:
        return []

    async def _scan() -> list[str]:
        try:
            import hypersync  # type: ignore
        except Exception:
            return []
        url = str(
            getattr(outer_ctx, "meta", {}).get("hypersync_url")
            or os.getenv("PSAT_HYPERSYNC_URL", "https://eth.hypersync.xyz")
        )
        timeout_s = float(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_TIMEOUT_S", "45"))
        max_pages = int(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_MAX_PAGES", "50"))
        client = hypersync.HypersyncClient(hypersync.ClientConfig(url=url, bearer_token=token))
        found: set[str] = set()
        for event_address, topic0s in address_topics.items():
            current_from = 0
            page_count = 0
            started = time.monotonic()
            while True:
                if time.monotonic() - started > timeout_s or page_count >= max_pages:
                    break
                query = hypersync.Query(
                    from_block=current_from,
                    to_block=getattr(outer_ctx, "block", None),
                    logs=[
                        hypersync.LogSelection(
                            address=[event_address],
                            topics=[sorted(topic0s)],
                        )
                    ],
                    field_selection=hypersync.FieldSelection(log=[field.value for field in hypersync.LogField]),
                )
                try:
                    response = await client.get(query)
                except Exception:
                    break
                page_count += 1
                for log in _logs_from_response(response):
                    topics = _topics_from_log(log)
                    if not topics:
                        continue
                    topic0 = topics[0].lower()
                    for hint in hints_by_address_topic.get((event_address, topic0), []):
                        keys = _event_keys(
                            topics,
                            _data_words_from_log(log),
                            hint.get("topics_to_keys") or {},
                            hint.get("data_to_keys") or {},
                        )
                        word = _normalize_word(keys.get(key_index))
                        if word is not None:
                            found.add(word)
                next_block = getattr(response, "next_block", None)
                if next_block is None or next_block <= current_from:
                    break
                block = getattr(outer_ctx, "block", None)
                if isinstance(block, int) and next_block >= block:
                    break
                current_from = next_block
        return sorted(found)

    try:
        return asyncio.run(_scan())
    except Exception:
        return []


def _call_unary_bytes32_view(
    *,
    rpc_url: str,
    contract_address: str,
    selector: str,
    args: list[str],
    block: int | None,
) -> list[str]:
    from services.resolution.repos.event_logs_pg import _normalize_word
    from utils.rpc import rpc_batch_request_with_status

    calls: list[tuple[str, list[Any]]] = []
    for arg in args:
        word = _normalize_word(arg)
        if word is None:
            continue
        calls.append(
            (
                "eth_call",
                [
                    {"to": contract_address.lower(), "data": selector + word[2:]},
                    hex(block) if isinstance(block, int) else "latest",
                ],
            )
        )
    if not calls:
        return []
    out: set[str] = set()
    for raw, had_error in rpc_batch_request_with_status(rpc_url, calls):
        if had_error:
            continue
        word = _normalize_word(raw)
        if word is not None:
            out.add(word)
    return sorted(out)


def _leaf_has_caller_operand(leaf: LeafPredicate) -> bool:
    return any((op.get("source") in _CALLER_SOURCES) for op in (leaf.get("operands") or []))


def _resolve_contextual_equality(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None,
    operator: str,
) -> CapabilityExpr:
    """Evaluate equality leaves whose caller operand was already bound.

    Recursive external-call evaluation intentionally rewrites a callee's
    ``msg.sender`` to the calling contract address. A guard like
    ``msg.sender == liquidityPool`` then becomes a concrete call-edge
    condition, not a root-caller principal. Exact true is no caller
    restriction; exact false means the external call can never authorize
    this edge. Dynamic non-caller checks remain business side-conditions.
    """
    operands = leaf.get("operands") or []
    if len(operands) != 2:
        return CapabilityExpr.conditional_universal(_condition_from_leaf(leaf))

    left = _resolve_operand_static_value(cast(dict[str, Any], operands[0]), ctx)
    right = _resolve_operand_static_value(cast(dict[str, Any], operands[1]), ctx)
    if left is None or right is None:
        return CapabilityExpr.conditional_universal(_condition_from_leaf(leaf))

    matches = left == right
    allowed = matches if operator == "eq" else not matches
    if allowed:
        return CapabilityExpr.conditional_universal(
            Condition(kind="business", description="resolved call-frame equality")
        )
    return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")


def _resolve_operand_static_value(operand: dict[str, Any], ctx: EvaluationContext | None) -> str | None:
    src = operand.get("source")
    if src == "constant":
        value = operand.get("constant_value")
        return value.lower() if isinstance(value, str) else None
    if src == "state_variable":
        sv_name = _state_var_lookup_key(operand)
        values = ctx.state_var_values if ctx is not None else None
        value = values.get(sv_name) if values is not None and isinstance(sv_name, str) else None
        return value.lower() if isinstance(value, str) else None
    if src == "self_address":
        value = ctx.contract_address if ctx is not None else None
        return value.lower() if isinstance(value, str) else None
    return None


def _is_zero_address(value: str) -> bool:
    return value.lower() == "0x" + "0" * 40


def _maybe_inline_cross_contract_call(
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr | None:
    """Try to resolve a delegated external-check leaf by
    evaluating the registry contract's predicate trees under the
    caller's context.

    The leaf must carry:
      * ``set_descriptor.authority_contract.address_source`` — pointing
        at the state-variable that holds the registry address.
      * ``set_descriptor.callee_signature`` or ``callee_selector`` — the
        exact registry function to inline.

    Returns:
      * a ``CapabilityExpr`` from re-evaluating B's tree under A's
        sender, OR
      * ``None`` if any precondition isn't met (no session, no
        state-var resolution, no Job for the registry, no
        predicate_trees artifact, no matching function tree, or the
        recursion guard fires) — caller falls through to the existing
        adapter path.

    The resolver carries an ``evaluation_stack`` set on the context to
    short-circuit cycles: ``(chain_id, address.lower(), function_signature)``
    is added before recursing and removed after. A repeat hit (e.g.
    A→B→A or B→B) returns ``CapabilityExpr.external_check_only`` so
    the leaf still surfaces as 'gated' even if we can't resolve.
    """
    callee_signature = descriptor.get("callee_signature")
    callee_selector = descriptor.get("callee_selector")
    if not isinstance(callee_signature, str):
        callee_signature = None
    if not isinstance(callee_selector, str):
        callee_selector = None
    if not callee_signature and not callee_selector:
        return None
    if callee_selector is None and callee_signature is not None:
        callee_selector = _selector_for_signature(callee_signature)

    # session lives on the OUTER (adapters) context — pulled by the
    # registry-backed adapter wrapper. Fall back to None gracefully.
    outer_ctx = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    if outer_ctx is None:
        return None
    session = getattr(outer_ctx, "session", None)
    if session is None:
        return None

    authority_contract = descriptor.get("authority_contract") or {}
    address_source = authority_contract.get("address_source") or {}
    if address_source.get("source") != "state_variable":
        return None
    sv_name = _state_var_lookup_key(cast(dict[str, Any], address_source))
    if not isinstance(sv_name, str) or not sv_name:
        return None
    state_vars = getattr(outer_ctx, "state_var_values", None) or {}
    registry_addr = state_vars.get(sv_name)
    if not isinstance(registry_addr, str) or not registry_addr.startswith("0x") or len(registry_addr) != 42:
        return None
    registry_addr = registry_addr.lower()

    chain_id = getattr(outer_ctx, "chain_id", 1)
    stack = outer_ctx.evaluation_stack if hasattr(outer_ctx, "evaluation_stack") else set()
    callee_identity = callee_signature or callee_selector or ""
    key = (chain_id, registry_addr, callee_identity)
    if key in stack:
        # Cycle: B's resolution depends on its own gate, or we've already
        # walked through this address+function in this evaluation tree.
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=registry_addr,
                target_call_selector=callee_selector,
                extra={"basis": ["cycle_detected_in_cross_contract_inlining"]},
            )
        )

    # Look up the registry's semantic artifacts. If the registry address is
    # a proxy, predicate_trees live on its implementation child job.
    from db.queue import get_artifact
    from services.resolution.capability_resolver import find_analysis_job_for_address

    lookup = find_analysis_job_for_address(
        session,
        registry_addr,
        required_artifact="predicate_trees",
        completed_only=False,
    )
    if lookup is None:
        return None
    artifact = get_artifact(session, lookup.analysis_job.id, "predicate_trees")
    if not isinstance(artifact, dict):
        return None
    from services.resolution.adapters import CallFrame

    parent_frame = getattr(outer_ctx, "call_frame", None)
    if parent_frame is None:
        parent_frame = CallFrame.root(
            contract_address=getattr(outer_ctx, "contract_address", None),
            function_signature=None,
            function_selector=None,
        )
    call_args = [
        _normalize_operand_for_call_arg(
            arg,
            parent_frame,
            ctx,
            callee_contract_address=registry_addr,
            rpc_url=getattr(outer_ctx, "rpc_url", None),
            block=getattr(outer_ctx, "block", None),
        )
        for arg in _callee_argument_operands(
            leaf,
            callee_signature=callee_signature,
            callee_selector=callee_selector,
        )
    ]

    trees = artifact.get("trees")
    check_trees = artifact.get("check_trees")
    tree_maps = [m for m in (trees, check_trees) if isinstance(m, dict) and m]
    if not tree_maps:
        return _materialize_external_check_from_candidates(
            session=session,
            outer_ctx=outer_ctx,
            chain_id=chain_id,
            registry_addr=registry_addr,
            callee_selector=callee_selector,
            call_args=call_args,
        )

    callee_tree = None
    for tree_map in tree_maps:
        callee_tree = _tree_for_signature_or_selector(
            tree_map,
            callee_signature=callee_signature,
            callee_selector=callee_selector,
        )
        if callee_tree is not None:
            break
    if callee_tree is None:
        return _materialize_external_check_from_candidates(
            session=session,
            outer_ctx=outer_ctx,
            chain_id=chain_id,
            registry_addr=registry_addr,
            callee_selector=callee_selector,
            call_args=call_args,
        )

    callee_tree = _bind_callee_parameters(
        callee_tree,
        call_args,
    )

    # Build a child evaluation context targeting the registry.
    # Parameter arguments are already bound above. Direct Solidity
    # globals inside the callee get the child frame: msg.sender is
    # the calling contract, address(this) is the registry, and
    # msg.sig is the callee selector.
    from services.resolution.capability_resolver import _load_state_var_values

    state_var_values = _load_state_var_values(
        session,
        lookup.analysis_job.address or registry_addr,
        job_id=lookup.analysis_job.id,
    )
    if not state_var_values and lookup.runtime_job.id != lookup.analysis_job.id:
        state_var_values = _load_state_var_values(session, registry_addr, job_id=lookup.runtime_job.id)

    parent_this = getattr(parent_frame, "current_address_this", None) or getattr(
        parent_frame, "executing_contract_address", None
    )
    child_frame = CallFrame(
        protected_contract_address=getattr(parent_frame, "protected_contract_address", None),
        executing_contract_address=registry_addr,
        current_function_signature=callee_signature,
        current_function_selector=callee_selector,
        current_msg_sender=parent_this.lower() if isinstance(parent_this, str) else None,
        current_address_this=registry_addr,
        current_msg_sig=callee_selector,
        bound_parameters=tuple(call_args),
    )
    callee_tree = _normalize_tree_for_frame(callee_tree, child_frame)

    child_outer = type(outer_ctx)(
        chain_id=chain_id,
        rpc_url=getattr(outer_ctx, "rpc_url", None),
        block=getattr(outer_ctx, "block", None),
        finality_depth=getattr(outer_ctx, "finality_depth", 12),
        contract_address=registry_addr,
        event_log_repo=getattr(outer_ctx, "event_log_repo", None),
        bytecode=outer_ctx.bytecode,
        recursive_resolver=outer_ctx.recursive_resolver,
        state_var_values=state_var_values,
        session=session,
        evaluation_stack=stack | {key},
        call_frame=child_frame,
        meta=dict(outer_ctx.meta),
    )

    # Same registry-backed adapter pattern as evaluate_tree_with_registry,
    # just keyed on the child outer ctx.
    from services.resolution.adapters import AdapterRegistry as _Reg

    registry_adapters = (
        ctx.adapter._registry  # type: ignore[attr-defined]
        if hasattr(ctx.adapter, "_registry")
        else _Reg()
    )
    resolved = evaluate_tree_with_registry(callee_tree, registry_adapters, child_outer)
    if _inline_result_needs_materialization(resolved):
        materialized = _materialize_external_check_from_candidates(
            session=session,
            outer_ctx=outer_ctx,
            chain_id=chain_id,
            registry_addr=registry_addr,
            callee_selector=callee_selector,
            call_args=call_args,
        )
        if materialized is not None:
            return materialized
        # Fall through to the caller's adapter dispatch instead of dead-ending.
        # When the inlined delegated check can't be materialized (e.g. canCall's
        # role-mapping join the generic materializer can't express), the caller's
        # external_set path can still try a named adapter — SolmateRolesAuthorityAdapter
        # folds canCall from indexed role events. The old dead-end (an
        # external_check_only with basis=["delegated_check_not_materialized"])
        # returned non-None and pre-empted that adapter for every Solmate-protected
        # contract analyzed alongside its RolesAuthority, so the adapter never ran.
        return None
    return resolved


def _inline_result_needs_materialization(cap: CapabilityExpr) -> bool:
    if cap.kind == "finite_set":
        return not cap.members and cap.membership_quality != "exact"
    if cap.kind in {"external_check_only", "unsupported"}:
        return True
    if cap.kind == "conditional_universal":
        return _conditional_result_needs_materialization(cap)
    if cap.kind == "OR":
        return _or_result_needs_materialization(cap)
    return False


def _conditional_result_needs_materialization(cap: CapabilityExpr) -> bool:
    for condition in cap.conditions:
        description = condition.description or ""
        if description.startswith("return "):
            return True
    return False


def _or_result_needs_materialization(cap: CapabilityExpr) -> bool:
    saw_materializable = False
    for child in cap.children:
        if child.kind == "finite_set":
            if child.members:
                return False
            if child.membership_quality != "exact":
                saw_materializable = True
            continue
        if child.kind in {"external_check_only", "unsupported"}:
            saw_materializable = True
            continue
        if child.kind == "conditional_universal" and _conditional_result_needs_materialization(child):
            saw_materializable = True
            continue
        return False
    return saw_materializable


def _materialize_external_check_from_candidates(
    *,
    session: Any,
    outer_ctx: Any,
    chain_id: int,
    registry_addr: str,
    callee_selector: str | None,
    call_args: list[dict[str, Any]],
) -> CapabilityExpr | None:
    from services.resolution.external_check_materializer import materialize_external_check_from_events

    try:
        return materialize_external_check_from_events(
            session=session,
            rpc_url=getattr(outer_ctx, "rpc_url", None),
            chain_id=chain_id,
            checker_address=registry_addr,
            checker_selector=callee_selector,
            call_args=call_args,
            block=getattr(outer_ctx, "block", None),
        )
    except Exception:
        return None


def _callee_argument_operands(
    leaf: LeafPredicate,
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> list[dict[str, Any]]:
    args: list[dict[str, Any]] = []
    for raw_operand in leaf.get("operands") or []:
        if not isinstance(raw_operand, dict):
            continue
        operand = cast(dict[str, Any], raw_operand)
        if _is_target_call_operand(operand, callee_signature=callee_signature, callee_selector=callee_selector):
            continue
        args.append(deepcopy(operand))
    return args


def _is_target_call_operand(
    operand: dict[str, Any],
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> bool:
    if operand.get("source") != "external_call":
        return False
    op_sig = operand.get("callee_signature")
    if callee_signature and isinstance(op_sig, str) and op_sig == callee_signature:
        return True
    op_selector = operand.get("callee_selector")
    if callee_selector and isinstance(op_selector, str) and op_selector == callee_selector:
        return True
    return False


def _bind_callee_parameters(tree: PredicateTree, call_args: list[dict[str, Any]]) -> PredicateTree:
    bound = _bind_value(deepcopy(tree), call_args)
    return cast(PredicateTree, bound) if isinstance(bound, dict) else tree


def _normalize_operand_for_call_arg(
    operand: dict[str, Any],
    frame: Any,
    ctx: EvaluationContext,
    *,
    callee_contract_address: str | None = None,
    rpc_url: str | None = None,
    block: int | None = None,
) -> dict[str, Any]:
    source = operand.get("source")
    if source in _CALLER_SOURCES:
        return {"source": "root_caller"}
    if source == "external_call":
        constant = _resolve_static_external_call_operand(
            operand,
            callee_contract_address=callee_contract_address,
            rpc_url=rpc_url,
            block=block,
        )
        if constant is not None:
            return constant
    if source == "self_address":
        value = getattr(frame, "current_address_this", None) or getattr(frame, "executing_contract_address", None)
        if isinstance(value, str) and value.startswith("0x"):
            return {"source": "constant", "constant_value": value.lower()}
    if source == "computed" and operand.get("computed_kind") == "msg.sig":
        selector = getattr(frame, "current_msg_sig", None) or getattr(frame, "current_function_selector", None)
        if isinstance(selector, str) and selector.startswith("0x"):
            return {"source": "constant", "constant_value": selector.lower()}
    if source == "parameter":
        bound = _bound_parameter_operand(operand, frame)
        if bound is not None:
            return _normalize_operand_for_call_arg(
                bound,
                frame,
                ctx,
                callee_contract_address=callee_contract_address,
                rpc_url=rpc_url,
                block=block,
            )
    if source == "state_variable":
        name = _state_var_lookup_key(operand)
        value = ctx.state_var_values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) in {42, 66}:
            return {"source": "constant", "constant_value": value.lower()}
    return deepcopy(operand)


def _resolve_static_external_call_operand(
    operand: dict[str, Any],
    *,
    callee_contract_address: str | None,
    rpc_url: str | None,
    block: int | None,
) -> dict[str, Any] | None:
    signature = operand.get("callee_signature")
    selector = operand.get("callee_selector")
    if not isinstance(signature, str) or not signature.endswith("()"):
        return None
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        selector = _selector_for_signature(signature)
    if not selector or not isinstance(callee_contract_address, str) or not callee_contract_address.startswith("0x"):
        return None
    if not rpc_url:
        return None
    block_tag = hex(block) if isinstance(block, int) else "latest"
    try:
        from utils.rpc import rpc_request

        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": callee_contract_address.lower(), "data": selector}, block_tag],
            retries=1,
        )
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return None
    return {"source": "constant", "constant_value": "0x" + raw[-64:].lower()}


def _normalize_tree_for_frame(tree: PredicateTree, frame: Any) -> PredicateTree:
    normalized = _normalize_value_for_frame(deepcopy(tree), frame)
    return cast(PredicateTree, normalized) if isinstance(normalized, dict) else tree


def _normalize_value_for_frame(value: Any, frame: Any, seen_parameters: frozenset[int] = frozenset()) -> Any:
    if isinstance(value, list):
        return [_normalize_value_for_frame(item, frame, seen_parameters) for item in value]
    if not isinstance(value, dict):
        return value

    source = value.get("source")
    if source == "msg_sender":
        sender = getattr(frame, "current_msg_sender", None)
        if isinstance(sender, str) and sender.startswith("0x"):
            return {"source": "constant", "constant_value": sender.lower()}
    if source == "self_address":
        address_this = getattr(frame, "current_address_this", None) or getattr(
            frame, "executing_contract_address", None
        )
        if isinstance(address_this, str) and address_this.startswith("0x"):
            return {"source": "constant", "constant_value": address_this.lower()}
    if source == "computed" and value.get("computed_kind") == "msg.sig":
        selector = getattr(frame, "current_msg_sig", None) or getattr(frame, "current_function_selector", None)
        if isinstance(selector, str) and selector.startswith("0x"):
            return {"source": "constant", "constant_value": selector.lower()}
    if source == "parameter":
        idx = value.get("parameter_index")
        if isinstance(idx, int):
            if idx in seen_parameters:
                return deepcopy(value)
            seen_parameters = seen_parameters | {idx}
        bound = _bound_parameter_operand(value, frame)
        if bound is not None:
            return _normalize_value_for_frame(bound, frame, seen_parameters)

    return {k: _normalize_value_for_frame(v, frame, seen_parameters) for k, v in value.items()}


def _bound_parameter_operand(operand: dict[str, Any], frame: Any) -> dict[str, Any] | None:
    idx = operand.get("parameter_index")
    bound_params = getattr(frame, "bound_parameters", ()) or ()
    if isinstance(idx, int) and 0 <= idx < len(bound_params):
        bound = bound_params[idx]
        return deepcopy(bound) if isinstance(bound, dict) else None
    return None


def _bind_value(value: Any, call_args: list[dict[str, Any]]) -> Any:
    if isinstance(value, list):
        return [_bind_value(item, call_args) for item in value]
    if not isinstance(value, dict):
        return value
    if value.get("source") == "parameter":
        idx = value.get("parameter_index")
        if isinstance(idx, int) and 0 <= idx < len(call_args):
            return deepcopy(call_args[idx])
    out = {k: _bind_value(v, call_args) for k, v in value.items()}
    leaf = out.get("leaf")
    if isinstance(leaf, dict):
        _promote_bound_caller_leaf(leaf)
    return out


def _promote_bound_caller_leaf(leaf: dict[str, Any]) -> None:
    if leaf.get("authority_role") != "business":
        return
    if leaf.get("kind") not in {"equality", "membership", "external_bool"}:
        return
    operands = leaf.get("operands") or []
    key_sources = (leaf.get("set_descriptor") or {}).get("key_sources") or []
    has_caller = any(_is_caller_source(item) for item in [*operands, *key_sources] if isinstance(item, dict))
    if has_caller:
        leaf["authority_role"] = "delegated_authority"
        leaf["references_msg_sender"] = True


def _is_caller_source(item: dict[str, Any]) -> bool:
    return item.get("source") in _CALLER_SOURCES


def _tree_for_signature_or_selector(
    trees: dict[str, Any],
    *,
    callee_signature: str | None,
    callee_selector: str | None,
) -> PredicateTree | None:
    """Find a predicate tree by exact ABI signature or selector."""
    if callee_signature and callee_signature in trees:
        tree = trees[callee_signature]
        return cast(PredicateTree, tree) if isinstance(tree, dict) else None
    if callee_selector:
        for signature, tree in trees.items():
            if not isinstance(signature, str):
                continue
            if _selector_for_signature(signature) == callee_selector and isinstance(tree, dict):
                return cast(PredicateTree, tree)
    return None


def _selector_for_signature(signature: str) -> str | None:
    if "(" not in signature or not signature.endswith(")"):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def _resolve_external_bool(leaf: LeafPredicate, ctx: EvaluationContext | None = None) -> CapabilityExpr:
    """``require(authority.check(...))`` — produces an
    external_check_only capability."""
    selector = None
    for op in leaf.get("operands") or []:
        if op.get("source") == "external_call":
            raw = op.get("callee_selector")
            selector = raw if isinstance(raw, str) else selector
    check = ExternalCheck(
        target_address=None,
        target_call_selector=selector,
        extra={"basis": list(leaf.get("basis", []))},
    )
    cap = CapabilityExpr.external_check_only(check)
    operator = leaf.get("operator")
    if operator == "falsy":
        cap = negate(cap)
    return cap


def _external_check_from_descriptor(
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr:
    target_address = _target_address_from_descriptor(descriptor, ctx)
    selector = descriptor.get("callee_selector")
    check = ExternalCheck(
        target_address=target_address,
        target_call_selector=selector if isinstance(selector, str) else None,
        extra={
            "basis": list(leaf.get("basis", [])),
            "callee_function": descriptor.get("callee_function"),
            "callee_signature": descriptor.get("callee_signature"),
            "topic0": _first_hint_value(descriptor, "topic0"),
            "direction": _first_hint_value(descriptor, "direction"),
        },
    )
    return CapabilityExpr.external_check_only(check)


def _target_address_from_descriptor(descriptor: SetDescriptor, ctx: EvaluationContext) -> str | None:
    authority = descriptor.get("authority_contract") or {}
    raw = authority.get("address")
    if isinstance(raw, str) and raw.startswith("0x") and len(raw) == 42:
        return raw.lower()
    source = authority.get("address_source") or {}
    if source.get("source") == "state_variable":
        name = _state_var_lookup_key(cast(dict[str, Any], source))
        value = ctx.state_var_values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return value.lower()
    return ctx.contract_address.lower() if ctx.contract_address else None


def _first_hint_value(descriptor: SetDescriptor, key: str) -> Any:
    hints = descriptor.get("enumeration_hint") or []
    for hint in hints:
        value = hint.get(key)
        if value is not None:
            return value
    return None


def _resolve_signer_from_leaf(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None = None,
) -> CapabilityExpr:
    """For a signature_auth leaf, the principal is whoever signed.
    Find the operand that's NOT the signature_recovery source — that
    operand identifies the expected signer, which becomes a
    capability that the resolver-side check verifies the signature
    against.

    State-variable signers consult ``ctx.state_var_values`` so persisted
    ``ControllerValue`` rows surface as concrete signers — mirrors the
    sibling ``_resolve_equality_principal`` branch. Without this lookup,
    every signature-gated function whose signer is a state variable
    wraps an empty ``finite_set``, and the writer emits zero
    ``FunctionPrincipal`` rows of ``principal_type=signature_witness``.
    """
    operands = leaf.get("operands") or []
    signers = [op for op in operands if op["source"] != "signature_recovery"]
    if len(signers) != 1:
        return CapabilityExpr.unsupported("signature_signer_ambiguous")
    op = signers[0]

    if op["source"] == "state_variable":
        sv_name = _state_var_lookup_key(cast(dict[str, Any], op))
        if ctx is not None and sv_name and sv_name in ctx.state_var_values:
            value = ctx.state_var_values[sv_name]
            if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
                if _is_zero_address(value):
                    return CapabilityExpr.finite_set([], quality="exact", confidence="enumerable")
                return CapabilityExpr.finite_set(
                    [value],
                    quality="exact",
                    confidence="enumerable",
                )
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
        )
    if op["source"] == "constant":
        val = op.get("constant_value")
        if isinstance(val, str) and val.startswith("0x") and len(val) == 42:
            return CapabilityExpr.finite_set([val])
    return CapabilityExpr.unsupported(f"signature_signer_source_{op['source']}")


def _condition_from_leaf(leaf: LeafPredicate) -> Condition:
    role = leaf.get("authority_role")
    kind: str = role if role in ("time", "pause", "reentrancy", "business") else "business"
    return Condition(
        kind=kind,  # type: ignore[arg-type]
        description=leaf.get("expression") or "",
    )
