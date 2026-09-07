"""External-check descriptors, caller-gate stamping, and leaf conditions."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

from services.static.static_analysis.predicate_types import (
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
    is_permissionless_caller_shape,
    leaf_is_caller_tainted,
)
from .permit import _leaf_is_permit_shape
from .telemetry import _is_zero_address, _record_delegated_gate_unresolved, _state_var_lookup_key

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")


def _stamp_caller_gate_check(cap: CapabilityExpr, leaf: LeafPredicate) -> CapabilityExpr:
    """Under the earned-public default, mark an unresolvable
    ``external_check_only`` that IS a caller gate (caller-tainted leaf, no
    permissionless shape) with its ``caller_gate_basis`` tag. The projection
    blocker keys on the tag: a tagged check suppresses a sibling public path
    (the Solmate ``requiresAuth`` decline, a view ACL probe), while an
    untagged check — a downstream statement-call probe whose revert surface
    gates the INTERMEDIATE contract (the un-inlined Veda teller→vault call)
    — keeps the legacy side-condition fold. The decision is made here, where
    the leaf is in hand, never by pattern-matching check dicts downstream."""
    if cap.kind != "external_check_only" or cap.check is None:
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
    # A caller gate that settles here without a pending-index deferral is unresolved
    # for good — the durability tripwire (a transient cold deferral self-heals via
    # the reconciler and is excluded).
    if stamped.check is not None and not extra.get("deferred_pending_index"):
        _record_delegated_gate_unresolved(stamped.check)
    return stamped


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
    """Turn an *un-enumerable* membership decline into an ``external_check_only`` so a
    pending ``falsy`` negate reaches ``negate``'s cofinite arm.

    A ``falsy`` membership leaf (``if (set[caller]) revert``) proceeds for anyone NOT in
    the set, so its faithful resolution is the complement (cofinite/open). But when the
    adapter can't enumerate the set the decline arrives as ``unsupported("no_adapter")``
    (the real ``AdapterRegistry`` has no enumerator for this ``mapping_membership``) or
    as the null adapter's ``finite_set([], lower_bound)`` placeholder — and the raw
    ``unsupported`` would negate to ``unsupported("negate_of_no_adapter")``, discarding
    the denylist. Convert *only* that decline to an ``external_check_only`` describing
    the membership probe; ``negate(external_check_only)`` then yields a lower_bound
    cofinite. ``subject`` is carried through so a bound (inlined-hook) denylist stays a
    side-condition.

    Narrow by construction — a populated/exact ``finite_set``,
    ``membership_without_descriptor``, or any other reason is returned untouched and
    stays gated. Mirrors the external_bool branch's existing ``no_adapter`` handling.
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
    kind: str = role if role in ("time", "pause", "reentrancy", "business", "one_shot") else "business"
    if kind == "business" and _leaf_is_permit_shape(leaf):
        # A signature-witness open path that folded to a side condition (the
        # void EIP-2612 statement call, or a recover-equality that stayed a
        # business leaf): record that this open is a permit, not a bare open.
        kind = "permit_sig"
    return Condition(
        kind=kind,
        description=leaf.get("expression") or "",
    )
