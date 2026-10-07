"""Equality-principal resolution (``msg.sender == X``)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.contract_analysis_pipeline.predicate_types import (
    LeafPredicate,
)

from ..capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
)
from ..permissionless_shapes import (
    earned_public_enabled,
)
from .authority import (
    _OWNER_SELECTOR,
    _canonical_authority_selector_for_slot,
    _is_pending_authority_accessor_operand,
    _live_resolve_authority_slot,
    _nullary_getter_selector,
    _oz_v5_namespaced_authority_selector,
    _pending_ceiling_capability,
    _public_getter_selector_for_internal_accessor,
    _resolve_authority_via_getters,
    _resolve_param_keyed_authority_mapping,
    _view_call_caller_selects_key,
)
from .binding import _selector_for_signature, _stored_dispatch_selector
from .descriptors import _condition_from_leaf
from .telemetry import _is_zero_address, _state_var_lookup_key

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")


def _resolve_equality_principal(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None = None,
) -> CapabilityExpr:
    """``msg.sender == X``: resolve X to a CapabilityExpr.

    A parameter X is self-service (conditional_universal). State vars read ``ctx.state_var_values``, else a lower_bound
    placeholder so the UI can still show "guarded by X".
    """
    operands = leaf.get("operands") or []
    other = [op for op in operands if op["source"] not in _CALLER_SOURCES]
    if len(other) != 1:
        return CapabilityExpr.unsupported("equality_operand_ambiguous")
    op = other[0]

    # ``msg.sender == <mapping>[<param>]`` (claim #3 group C): enumerate the mapping's values from events; there's no
    # getter.
    if op.get("mapping_name") is not None:
        return _resolve_param_keyed_authority_mapping(cast(dict[str, Any], op), ctx)

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
        # Read the variable live, trying in order:
        #   1. ``<name>()``, the public auto-getter;
        #   2. the de-underscored canonical getter (OZ-v4 ``_owner`` → ``owner()``), limited to
        # owner/governor/authority(+pending);
        #   3. the canonical getter behind a slot locator (``_OWNER_SLOT``, ``OwnableStorageLocation``).
        # Struct members are read only for OZ-v5 namespaced ``_owner``; others describe fund destinations, not callers.
        name = op.get("state_variable_name")
        result: CapabilityExpr | None = None
        if not op.get("member_path"):
            result = _resolve_authority_via_getters(
                ctx,
                [
                    _nullary_getter_selector(name),
                    _public_getter_selector_for_internal_accessor(f"{name}()") if name else None,
                    _canonical_authority_selector_for_slot(name, leaf),
                ],
                bases=["abi_auto_getter", "deunderscore_convention", "slot_name_keyword"],
            )
        elif op.get("member_path") == ["_owner"]:
            result = _resolve_authority_via_getters(ctx, [_OWNER_SELECTOR])
        if result is not None and result.membership_quality == "exact":
            return result
        # Non-public address var (e.g. ``MembershipNFT.membershipManager``): read its sequential slot directly. Only
        # bare address scalars carry a slot.
        slot = op.get("storage_slot")
        if isinstance(slot, str) and not op.get("member_path"):
            slot_result = _live_resolve_authority_slot(ctx, slot)
            if slot_result is not None:
                return slot_result
            # Slot present but no RPC.
            return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial", empty_reason="not_read")
        # An empty accept-side 2-step gate is empty-by-design until a transfer is queued.
        if _is_pending_authority_accessor_operand(cast(dict[str, Any], op)):
            return _pending_ceiling_capability(cast(dict[str, Any], op), result)
        if result is not None:
            return result  # carries unreadable_revert / unreadable_empty
        # Guarding var with no getter (struct member, non-address): "guarded but unresolved".
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
            empty_reason="not_read",
        )

    if src == "self_address":
        value = ctx.contract_address if ctx is not None else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return CapabilityExpr.finite_set([value.lower()], quality="exact", confidence="enumerable")
        return CapabilityExpr.unsupported("self_address_without_contract")

    if src == "view_call":
        # Read nullary getters like ``owner()``/``governor()`` live; this used to be an unconditional placeholder that
        # dropped their principals. Arg-taking views can't be called with empty calldata.
        signature = op.get("callee_signature")
        if (
            earned_public_enabled()
            and isinstance(signature, str)
            and "(" in signature
            and not signature.endswith("()")
            and _view_call_caller_selects_key(op)
        ):
            # An arg-taking lookup keyed by the caller (``ownerOf(tokenId)``, ``getApproved(id)``) is self-service:
            # every caller passes for their own key. Fixed authority lookups stay gated. Without this, ERC721
            # transfer/claim functions would be gated.
            cond = Condition(
                kind="self_service",
                description=f"caller matches {signature} for their own key",
            )
            return CapabilityExpr.conditional_universal(cond)
        selector = None
        canonical_selector = None
        canonical_basis = "deunderscore_convention"
        if not op.get("callee_args"):
            signature = op.get("callee_signature")
            selector = op.get("callee_selector")
            if not (isinstance(selector, str) and selector.startswith("0x") and len(selector) == 10):
                selector = (
                    _selector_for_signature(signature)
                    if isinstance(signature, str) and signature.endswith("()")
                    else None
                )
            # Internal accessors have no selector; read the de-underscored public getter instead.
            canonical_selector = _public_getter_selector_for_internal_accessor(signature)
            canonical_basis = "deunderscore_convention"
            # OZ-v5 namespaced ownership accessor, read through ``owner()``.
            if canonical_selector is None:
                canonical_selector = _oz_v5_namespaced_authority_selector(signature)
                canonical_basis = "standard_namespaced_accessor"
        # Canonical getter first, since an internal accessor's own selector is dead.
        candidates = dict.fromkeys((canonical_selector, selector))
        # Publish which name-match produced the selector (``standard_namespaced_accessor`` vs
        # ``deunderscore_convention``); neither outranks the other.
        candidate_basis = {selector: "callee_selector", canonical_selector: canonical_basis}
        result = _resolve_authority_via_getters(
            ctx,
            list(candidates),
            bases=[candidate_basis[c] for c in candidates],
        )
        if result is not None and result.membership_quality == "exact":
            return result
        # Slot-backed accessor with no getter (Governable ``_pendingGovernor``): the slot is authoritative. Zero
        # publishes ``slot_read_zero`` and classification is left to ``_pending_ceiling_capability``; unreadable stays
        # lower_bound.
        slot = op.get("storage_slot")
        if isinstance(slot, str):
            slot_result = _live_resolve_authority_slot(ctx, slot)
            if slot_result is not None:
                return slot_result
            # Slot present but no RPC.
            return CapabilityExpr.finite_set([], quality="lower_bound", confidence="partial", empty_reason="not_read")
        # Getter-less pending accept gate (OZ ``_pendingDefaultAdmin.newAdmin``): empty-by-design.
        if _is_pending_authority_accessor_operand(cast(dict[str, Any], op)):
            return _pending_ceiling_capability(cast(dict[str, Any], op), result)
        if result is not None:
            return result  # carries unreadable_revert / unreadable_empty
        return CapabilityExpr.finite_set(
            [],
            quality="lower_bound",
            confidence="partial",
            empty_reason="not_read",
        )

    if src == "parameter":
        cond = Condition(
            kind="self_service",
            description=f"caller acting on their own {op.get('parameter_name') or 'arg'}",
            parameter_index=op.get("parameter_index"),
            parameter_name=op.get("parameter_name"),
        )
        return CapabilityExpr.conditional_universal(cond)

    if src == "signature_recovery":
        # Normally handled as a signature_auth leaf; defensive.
        return CapabilityExpr.signature_witness(CapabilityExpr.unsupported("signer_unresolved"))

    if src == "external_call":
        # Authority lives in another contract (``PauserRegistry.unpauser()``) whose address we don't have offline. Gated
        # query-only check, never public.
        selector = _stored_dispatch_selector(op.get("callee_selector"), op.get("callee_signature"))
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=None,
                target_call_selector=selector if isinstance(selector, str) else None,
                extra={
                    "basis": ["caller_equals_external_getter"],
                    "callee": op.get("callee"),
                    "callee_signature": op.get("callee_signature"),
                },
            )
        )

    if src == "computed":
        return CapabilityExpr.unsupported(f"equality_operand_computed_{op.get('computed_kind')}")

    return CapabilityExpr.unsupported(f"equality_operand_source_{src}")


def _leaf_has_caller_operand(leaf: LeafPredicate) -> bool:
    return any((op.get("source") in _CALLER_SOURCES) for op in (leaf.get("operands") or []))


def _resolve_contextual_equality(
    leaf: LeafPredicate,
    ctx: EvaluationContext | None,
    operator: str,
) -> CapabilityExpr:
    """Equality leaves whose caller operand was already bound by inlining (``msg.sender`` is the calling contract).

    Exact true means no restriction; exact false means this edge can never authorize; dynamic non-caller checks stay
    business side conditions.
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
