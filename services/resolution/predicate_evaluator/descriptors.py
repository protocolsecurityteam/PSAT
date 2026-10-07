"""External-check descriptors, caller-gate stamping, and leaf conditions."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

from services.static.contract_analysis_pipeline.predicate_types import (
    LeafPredicate,
    SetDescriptor,
)

from ..capabilities import (
    CapabilityExpr,
    Condition,
    ExternalCheck,
    negate,
)
from ..permissionless_shapes import (
    caller_gate_basis,
    earned_public_enabled,
    is_permissionless_caller_shape,
    leaf_is_caller_tainted,
)
from .binding import _stored_dispatch_selector
from .permit import _leaf_is_permit_shape
from .telemetry import _is_zero_address, _record_delegated_gate_unresolved, _state_var_lookup_key

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")


def _stamp_caller_gate_check(cap: CapabilityExpr, leaf: LeafPredicate) -> CapabilityExpr:
    """Tag an unresolvable caller-gate ``external_check_only`` with ``caller_gate_basis``.

    Tagged checks suppress sibling public paths; untagged checks (probes gating an intermediate contract) keep the
    legacy side-condition fold. Decided here, where the leaf is known.
    """
    if cap.kind != "external_check_only" or cap.check is None:
        return cap
    if not earned_public_enabled():
        return cap
    if not (leaf_is_caller_tainted(leaf) and not is_permissionless_caller_shape(leaf)):
        return cap
    tag = caller_gate_basis(leaf)
    extra = dict(cap.check.extra or {})
    basis = list(extra.get("basis") or [])
    if tag not in basis:
        basis.append(tag)
    extra["basis"] = basis
    stamped = replace(cap, check=replace(cap.check, extra=extra))
    # Settled here without a deferral means unresolved for good (the durability tripwire).
    if stamped.check is not None and not extra.get("deferred_pending_index"):
        _record_delegated_gate_unresolved(stamped.check)
    return stamped


def _resolve_external_bool(leaf: LeafPredicate, ctx: EvaluationContext | None = None) -> CapabilityExpr:
    """``require(authority.check(...))``: external_check_only."""
    selector = None
    for op in leaf.get("operands") or []:
        if op.get("source") == "external_call":
            raw = _stored_dispatch_selector(op.get("callee_selector"), op.get("callee_signature"))
            selector = raw if isinstance(raw, str) else selector
    check = ExternalCheck(
        target_address=None,
        target_call_selector=selector,
        extra={"basis": list(leaf.get("basis", []))},
    )
    cap = _stamp_caller_gate_check(CapabilityExpr.external_check_only(check), leaf)
    operator = leaf.get("operator")
    if operator == "falsy":
        cap = negate(cap)
    return cap


def _normalize_membership_decline_for_negation(
    cap: CapabilityExpr,
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr:
    """Turn an un-enumerable membership decline into ``external_check_only`` so a pending falsy negate reaches the
    cofinite arm.

    Otherwise ``unsupported("no_adapter")`` or the null adapter's placeholder negates to ``negate_of_no_adapter`` and
    the denylist is lost. Only that decline is converted; everything else is returned untouched. ``subject`` is
    preserved.
    """
    is_no_adapter = cap.kind == "unsupported" and cap.unsupported_reason == "no_adapter"
    is_null_placeholder = cap.kind == "finite_set" and not cap.members and cap.membership_quality == "lower_bound"
    if not (is_no_adapter or is_null_placeholder):
        return cap
    check = _external_check_from_descriptor(leaf, descriptor, ctx)
    check.subject = cap.subject
    return check


def _external_check_from_descriptor(
    leaf: LeafPredicate,
    descriptor: SetDescriptor,
    ctx: EvaluationContext,
) -> CapabilityExpr:
    target_address = _target_address_from_descriptor(descriptor, ctx)
    selector = _stored_dispatch_selector(descriptor.get("callee_selector"), descriptor.get("callee_signature"))
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
        outer = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
        values = getattr(ctx, "state_var_values", None)
        if values is None:
            values = getattr(outer, "state_var_values", None) or {}
        value = values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return value.lower()
        return None
    if source.get("source") == "view_call" and source.get("storage_slot"):
        from .authority import _live_resolve_authority_slot

        resolved = _live_resolve_authority_slot(ctx, source.get("storage_slot"))
        members = (resolved.members or []) if resolved is not None else []
        if resolved is not None and resolved.membership_quality == "exact" and len(members) == 1:
            return members[0]
        return None
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
    """For a signature_auth leaf the principal is whoever signed: the operand that isn't the recovery source.

    State-variable signers read ``ctx.state_var_values`` so persisted values surface as concrete signers.
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
    kind: str = role if role in ("time", "pause", "reentrancy", "business", "one_shot") else "business"
    if kind == "business" and _leaf_is_permit_shape(leaf):
        # Record the open path as a permit, not a bare open.
        kind = "permit_sig"
    return Condition(
        kind=kind,
        description=leaf.get("expression") or "",
    )
