"""Public evaluator API, per-leaf dispatch, and cross-contract inlining (kept together because they recurse into each
other).
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.contract_analysis_pipeline.predicate_types import (
    LeafPredicate,
    PredicateTree,
    SetDescriptor,
)

from ..capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
    intersect,
    negate,
    union,
)
from ..permissionless_shapes import (
    caller_gate_basis,
    earned_public_enabled,
    is_caller_keyed_membership_allowlist,
    is_caller_keyed_time_allowlist,
    is_caller_keyed_time_denylist,
    is_permissionless_caller_shape,
    is_public_registration,
    leaf_is_caller_tainted,
)
from .adapters import SetAdapter, _NullAdapter
from .binding import (
    _bind_callee_parameters,
    _callee_argument_operands,
    _normalize_operand_for_call_arg,
    _normalize_tree_for_frame,
    _selector_for_signature,
    _tree_for_signature_or_selector,
)
from .descriptors import (
    _condition_from_leaf,
    _external_check_from_descriptor,
    _normalize_membership_decline_for_negation,
    _resolve_external_bool,
    _resolve_signer_from_leaf,
    _stamp_caller_gate_check,
)
from .equality import (
    _leaf_has_caller_operand,
    _resolve_contextual_equality,
    _resolve_equality_principal,
)
from .materialization import (
    _inline_result_needs_materialization,
    _materialize_external_check_from_candidates,
    _public_without_root_cofinites,
)
from .membership import _resolve_view_key_membership
from .permit import _is_permit_family_signature
from .telemetry import (
    _adapter_declined_external_set,
    _adapter_deferred_pending_index,
    _bump_resolve_counter,
    _record_guard_fire,
    _tag_caller_subject,
)

logger = logging.getLogger("services.resolution.predicate_evaluator")


class EvaluationContext:
    """Context for the simple evaluator path; ``evaluate_tree_with_registry`` uses the fuller
    ``services.resolution.adapters`` context.
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
        # Persisted state-variable values by name, for ``_resolve_equality_principal``.
        self.state_var_values = state_var_values or {}
        self.call_frame = call_frame


def evaluate_tree_with_registry(
    tree: PredicateTree | None,
    registry: Any,  # adapters.AdapterRegistry — typed loosely to avoid circular import
    ctx: Any,  # adapters.EvaluationContext
) -> CapabilityExpr:
    """``evaluate_tree`` routing membership leaves through the AdapterRegistry."""

    class _RegistryBackedAdapter:
        # Exposes the outer resolver ctx to leaves that inline cross-contract calls; ``_registry`` is reused for the
        # child ctx.
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

    A missing or empty tree is public (conditional_universal, no conditions).
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
        cap = _evaluate_leaf(leaf, ctx)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "predicate leaf decision",
                extra={
                    "adapter": "predicate_evaluator",
                    "address": ctx.contract_address,
                    "decision": cap.kind,
                    "reason": leaf.get("authority_role") or leaf.get("kind") or "unknown",
                },
            )
        return cap
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


def _has_caller_keyed_value_predicate(leaf: LeafPredicate) -> bool:
    """Whether the descriptor has a ``value_predicate`` keyed on ``msg_sender``.

    Such business thresholds become enumerations when the adapter has data; pure thresholds (``amount > 1000``) stay
    conditional_universal.
    """
    descriptor = leaf.get("set_descriptor") or {}
    if not descriptor.get("value_predicate"):
        return False
    keys = descriptor.get("key_sources") or []
    return any(k.get("source") in _CALLER_SOURCES for k in keys)


# Aliases kept so legacy call sites stay monkeypatchable under their old names.
_is_caller_keyed_time_allowlist = is_caller_keyed_time_allowlist
_is_caller_keyed_membership_allowlist = is_caller_keyed_membership_allowlist


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
    if _is_recovered_signer_membership(leaf) or (leaf.get("authority_proof") or {}).get("state") == "not_determined":
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=ctx.contract_address,
                target_call_selector=None,
                extra={"basis": ["caller_tainted_authority_unresolved", "signer_authorization_unresolved"]},
            )
        )
    if leaf.get("kind") == "unsupported":
        return CapabilityExpr.unsupported(leaf.get("unsupported_reason") or "unsupported")

    # Non-authority leaves are side conditions, unless keyed on the caller by a value_predicate (``balances[msg.sender]
    # < 10 revert``), which is an authority gate enumerable when the adapter has data.
    role = leaf.get("authority_role")
    if role in ("reentrancy", "pause", "business", "time", "one_shot"):
        if is_public_registration(leaf):
            return CapabilityExpr.conditional_universal(_condition_from_leaf(leaf))
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
                # Only a populated finite_set beats the side-condition description; an empty one would lose it.
                if cap.kind == "finite_set" and cap.members:
                    return cap
        if earned_public_enabled():
            # Caller-taint default: a gate discriminating on caller identity with no known permissionless shape fails
            # closed. Permissionless shapes fall through to open.
            if leaf_is_caller_tainted(leaf) and not is_permissionless_caller_shape(leaf):
                return CapabilityExpr.external_check_only(
                    ExternalCheck(
                        target_address=None,
                        target_call_selector=None,
                        extra={
                            "basis": [caller_gate_basis(leaf)],
                            "expression": leaf.get("expression"),
                        },
                    )
                )
        elif _is_caller_keyed_time_allowlist(leaf):
            # A deny-by-default caller-keyed time allowlist is gated, never public.
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": ["caller_keyed_time_allowlist"],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        elif _is_caller_keyed_membership_allowlist(leaf):
            # ``require(allowed[msg.sender])`` is a positive allowlist: gated. The falsy denylist sibling falls through
            # to open.
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": ["caller_keyed_membership_allowlist"],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        if leaf_is_caller_tainted(leaf) and is_caller_keyed_time_denylist(leaf):
            # A caller-keyed time denylist is public minus a time-bounded exclusion: a root cofinite, which the inline
            # guard's counterfactual spares.
            return CapabilityExpr.cofinite_blacklist(
                [],
                blacklist_quality="lower_bound",
                conditions=[_condition_from_leaf(leaf)],
                subject="root",
            )
        cond = _condition_from_leaf(leaf)
        return CapabilityExpr.conditional_universal(cond)

    kind = leaf.get("kind")
    operator = leaf.get("operator")

    if kind == "membership":
        descriptor = leaf.get("set_descriptor")
        if descriptor is None:
            return CapabilityExpr.unsupported("membership_without_descriptor")
        complement = operator == "falsy"
        predicate = descriptor.get("value_predicate")
        if predicate:
            from services.resolution.mapping_enumerator import _value_predicate_passes

            # Value predicates already express the ALLOWED relation. `!= 0`
            # admits registered keys; negating it again would publish everyone
            # except those keys. Default-allow predicates enumerate the rejected
            # exceptions instead, then take their complement exactly once.
            complement = _value_predicate_passes("0x" + "00" * 32, dict(predicate))
            if complement:
                inverse = {
                    "eq": "ne",
                    "ne": "eq",
                    "lt": "gte",
                    "lte": "gt",
                    "gt": "lte",
                    "gte": "lt",
                    "in": "not_in",
                    "not_in": "in",
                }.get(predicate.get("op"))
                if inverse is None:
                    return CapabilityExpr.unsupported("membership_default_not_determined")
                descriptor = cast(SetDescriptor, {**descriptor, "value_predicate": {**predicate, "op": inverse}})
        cap = _resolve_view_key_membership(descriptor, ctx)
        if cap is None:
            cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
        cap = _tag_caller_subject(cap, ctx)
        if complement:
            # Normalize an un-enumerable falsy membership decline so negate reaches its cofinite arm instead of
            # ``negate_of_no_adapter``.
            cap = _normalize_membership_decline_for_negation(cap, leaf, descriptor, ctx)
            cap = negate(cap)
        return cap

    if kind == "equality":
        if operator in ("eq", "ne"):
            # Tag the subject so an inlined callee's owner-equality (no caller operand after frame rewrite) collapses
            # with its OR sibling into one bound capability; otherwise the intermediate members leak as a competing
            # principal shape.
            if not _leaf_has_caller_operand(leaf):
                return _tag_caller_subject(_resolve_contextual_equality(leaf, ctx, operator), ctx)
            base = _tag_caller_subject(_resolve_equality_principal(leaf, ctx), ctx)
            return base if operator == "eq" else negate(base)
        return CapabilityExpr.unsupported(f"equality_op_{operator}_unsupported")

    if kind == "external_bool":
        if (
            earned_public_enabled()
            and operator == "truthy"
            and leaf.get("callee_state_mutability") == "nonview"
            and leaf_is_caller_tainted(leaf)
            and is_permissionless_caller_shape(leaf)
        ):
            # Value movement: a required effectful external call moving the caller's own assets is open. Usually
            # classified ``business`` upstream; this guards delegated-tagged leaves that still arrive. Library calls and
            # void merkle verifications stay gated.
            if _is_permit_family_signature(leaf.get("callee_signature")):
                # Typed as a permit so the badge says "open via signature".
                return CapabilityExpr.conditional_universal(
                    Condition(
                        kind="permit_sig",
                        description=f"signature authorization (permit family): {leaf.get('expression') or 'call'}",
                    )
                )
            return CapabilityExpr.conditional_universal(
                Condition(
                    kind="self_service",
                    description=f"effectful external call must succeed: {leaf.get('expression') or 'call'}",
                )
            )
        descriptor = leaf.get("set_descriptor")
        if descriptor is not None:
            if descriptor.get("kind") == "external_set":
                from .descriptors import _target_address_from_descriptor

                authority = descriptor.get("authority_contract") or {}
                address_source = authority.get("address_source") or {}
                if address_source.get("source") == "view_call" and address_source.get("storage_slot"):
                    target = _target_address_from_descriptor(descriptor, ctx)
                    if target is None:
                        return _stamp_caller_gate_check(
                            CapabilityExpr.external_check_only(
                                ExternalCheck(
                                    target_address=None,
                                    target_call_selector=descriptor.get("callee_selector"),
                                    extra={"basis": ["authority_slot_unresolved"]},
                                )
                            ),
                            leaf,
                        )
                    descriptor = cast(
                        SetDescriptor, {**descriptor, "authority_contract": {**authority, "address": target}}
                    )
                # Prefer a standard-aware adapter (e.g. Solmate RolesAuthority from role events) before inlining: the
                # generic materializer renders public capabilities as lists and admitted phantom callers for every Veda
                # Teller. A decline falls through to inlining, then a bare external check.
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                if _adapter_declined_external_set(cap):
                    if _adapter_deferred_pending_index(cap):
                        # Keep the cold-index deferral so ``deferred_reconciler`` can re-resolve; the inline probe would
                        # drop the marker and freeze a cold result.
                        cap = _tag_caller_subject(cap, ctx)
                    else:
                        inlined = _maybe_inline_cross_contract_call(leaf, descriptor, ctx)
                        if inlined is not None:
                            # The inline result carries its own subject; don't re-tag.
                            cap = inlined
                        else:
                            cap = _tag_caller_subject(_external_check_from_descriptor(leaf, descriptor, ctx), ctx)
                else:
                    cap = _tag_caller_subject(cap, ctx)
            else:
                # No standard adapter here, so inline first.
                inlined = _maybe_inline_cross_contract_call(leaf, descriptor, ctx)
                if inlined is not None:
                    cap = inlined
                else:
                    cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                    if cap.kind == "unsupported" and cap.unsupported_reason == "no_adapter":
                        cap = _external_check_from_descriptor(leaf, descriptor, ctx)
                    cap = _tag_caller_subject(cap, ctx)
            # Tag unresolved caller-gate checks where the leaf is known; the projection blocker keys on the tag.
            cap = _stamp_caller_gate_check(cap, leaf)
            if operator == "falsy":
                cap = negate(cap)
            return cap
        return _resolve_external_bool(leaf, ctx)

    if kind in ("signature_auth", "authorization"):
        descriptor = leaf.get("set_descriptor")
        if descriptor is not None and descriptor.get("kind") == "state_authority":
            from ..effect_scopes import resolve_state_authority

            return resolve_state_authority(descriptor, ctx)
        if descriptor is not None:
            return ctx.adapter.enumerate(descriptor, ctx.contract_address)
        signer = _resolve_signer_from_leaf(leaf, ctx)
        return CapabilityExpr.signature_witness(signer)

    if kind == "comparison":
        # A comparison leaf here was already judged admin-curated upstream, so it's an authority threshold.
        # ``is_permissionless_caller_shape`` is role-blind and would reopen it.
        if earned_public_enabled() and leaf_is_caller_tainted(leaf):
            descriptor = leaf.get("set_descriptor")
            if descriptor is not None and _has_caller_keyed_value_predicate(leaf):
                cap = ctx.adapter.enumerate(descriptor, ctx.contract_address)
                # Populated or authoritative-empty enumerations stand.
                if cap.kind == "finite_set" and (
                    cap.members or cap.membership_quality == "exact" or cap.empty_reason == "empty_by_design"
                ):
                    return _tag_caller_subject(cap, ctx)
            # No authoritative answer: fail closed.
            return CapabilityExpr.external_check_only(
                ExternalCheck(
                    target_address=None,
                    target_call_selector=None,
                    extra={
                        "basis": [caller_gate_basis(leaf)],
                        "expression": leaf.get("expression"),
                    },
                )
            )
        cond = _condition_from_leaf(leaf)
        return CapabilityExpr.conditional_universal(cond)

    return CapabilityExpr.unsupported(f"unknown_leaf_kind_{kind}")


def _is_recovered_signer_membership(leaf: LeafPredicate) -> bool:
    return leaf.get("kind") == "membership" and any(
        key.get("source") == "signature_recovery" for key in (leaf.get("set_descriptor") or {}).get("key_sources") or []
    )


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
        if (
            _is_recovered_signer_membership(leaf)
            or (leaf.get("authority_proof") or {}).get("state") == "not_determined"
        ):
            return None
        role = leaf.get("authority_role")
        if role in ("reentrancy", "pause", "business", "time", "one_shot") and not leaf.get("references_msg_sender"):
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


def _maybe_inline_cross_contract_call(
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr | None:
    """Resolve a delegated external-check leaf by evaluating the registry contract's predicate trees under the
    caller's context.

    Needs ``set_descriptor.authority_contract.address_source`` and ``callee_signature`` or ``callee_selector``. Returns
    the re-evaluated capability, or ``None`` if a precondition fails so the caller falls back to adapters. Cycles are
    caught via ``evaluation_stack`` keyed on ``(chain_id, address, signature)`` and return ``external_check_only``.
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

    # The session lives on the outer (adapters) context.
    outer_ctx = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    if outer_ctx is None:
        return None
    session = getattr(outer_ctx, "session", None)
    if session is None:
        return None

    from .descriptors import _target_address_from_descriptor

    registry_addr = _target_address_from_descriptor(descriptor, ctx)
    if not isinstance(registry_addr, str) or not registry_addr.startswith("0x") or len(registry_addr) != 42:
        return None
    registry_addr = registry_addr.lower()

    chain_id = getattr(outer_ctx, "chain_id", None)
    if not isinstance(chain_id, int):
        # Chainless inlining can't key the stack or resolve the callee.
        return None
    stack = outer_ctx.evaluation_stack if hasattr(outer_ctx, "evaluation_stack") else set()
    callee_identity = callee_signature or callee_selector or ""
    key = (chain_id, registry_addr, callee_identity)
    if key in stack:
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=registry_addr,
                target_call_selector=callee_selector,
                extra={"basis": ["cycle_detected_in_cross_contract_inlining"]},
            )
        )

    # A proxy registry's predicate_trees live on its implementation job.
    from db.queue import get_artifact
    from services.resolution.capability_resolver import find_analysis_job_for_address
    from utils.chains import UnknownChainError, chain_by_id

    try:
        chain = chain_by_id(chain_id).name
    except UnknownChainError:
        return None

    lookup = find_analysis_job_for_address(
        session,
        registry_addr,
        required_artifact="predicate_trees",
        chain=chain,
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

    # Child frame: msg.sender is the caller contract, address(this) the registry, msg.sig the callee selector.
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

    from services.resolution.adapters import AdapterRegistry as _Reg

    registry_adapters = (
        ctx.adapter._registry  # pyright: ignore[reportAttributeAccessIssue]
        if hasattr(ctx.adapter, "_registry")
        else _Reg()
    )
    _bump_resolve_counter(outer_ctx, "inline_recursions")
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
        # Fall through so a named adapter (e.g. Solmate canCall from role events) can still run; the old dead-end
        # pre-empted it for every Solmate contract.
        return None
    if (
        leaf.get("operator") == "truthy"
        and leaf_is_caller_tainted(leaf)
        and not is_permissionless_caller_shape(leaf)
        and _public_without_root_cofinites(resolved)
    ):
        # Refine-only: an inline result that projects public would un-gate a caller-tainted delegated gate, so keep the
        # outer check. Legitimate deny-by-exception (root cofinites) is exempt.
        cap = _external_check_from_descriptor(leaf, descriptor, ctx)
        if cap.check is not None:
            extra = dict(cap.check.extra or {})
            basis = list(extra.get("basis") or [])
            if "inline_refine_only_guard" not in basis:
                basis.append("inline_refine_only_guard")
            extra["basis"] = basis
            cap = replace(cap, check=replace(cap.check, extra=extra))
        _record_guard_fire(descriptor)
        return cap
    return resolved
