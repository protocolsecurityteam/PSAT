"""Membership probe for semantic predicate trees: is this address in a leaf's set?

``probe_membership`` answers ``yes``, ``no``, or ``unknown`` (e.g. a lower_bound set not containing it, or
external_check_only / signature_witness shapes), based on the resolved CapabilityExpr's quality and confidence.
``unknown`` tells the caller to try an out-of-band probe. Pure over an injected registry and context.
"""

from __future__ import annotations

from typing import Any, Iterator

from .adapters import AdapterRegistry, EvaluationContext
from .capabilities import CapabilityExpr


def probe_membership(
    tree: dict[str, Any],
    *,
    predicate_index: int,
    member: str,
    registry: AdapterRegistry,
    ctx: EvaluationContext,
) -> dict[str, Any]:
    """``{"result": "yes"|"no"|"unknown", ...}`` for the leaf at ``predicate_index``."""
    leaves = list(_walk_leaves(tree))
    if not 0 <= predicate_index < len(leaves):
        return {
            "result": "unknown",
            "reason": "leaf_index_out_of_range",
            "leaf_count": len(leaves),
        }

    leaf = leaves[predicate_index]
    leaf_kind = leaf.get("kind")
    role = leaf.get("authority_role")
    if leaf_kind != "membership":
        return {
            "result": "unknown",
            "reason": "non_membership_leaf",
            "leaf_kind": leaf_kind,
            "authority_role": role,
        }

    descriptor = leaf.get("set_descriptor")
    if not descriptor:
        return {
            "result": "unknown",
            "reason": "no_set_descriptor",
            "leaf_kind": leaf_kind,
            "authority_role": role,
        }

    cap = registry.enumerate(descriptor, ctx)
    answer = _resolve_in_capability(cap, member)
    return {
        **answer,
        "leaf_kind": leaf_kind,
        "authority_role": role,
        "capability_kind": cap.kind,
        "membership_quality": cap.membership_quality,
        "confidence": cap.confidence,
    }


def probe_signature(
    tree: dict[str, Any],
    *,
    predicate_index: int,
    recovered_signer: str,
    registry: AdapterRegistry,
    ctx: EvaluationContext,
) -> dict[str, Any]:
    """``probe_membership`` for ``signature_auth`` leaves: whether an already-recovered signer is in the
    allowed-signer set.

    ECDSA leaves compare against the resolved operand. EIP-1271 leaves wrap an ``external_check_only`` for
    ``isValidSignature``, surfaced via ``unknown``.
    """
    from ..static.contract_analysis_pipeline.predicate_types import make_leaf_node
    from .predicate_evaluator import evaluate_tree_with_registry

    leaves = list(_walk_leaves(tree))
    if not 0 <= predicate_index < len(leaves):
        return {
            "result": "unknown",
            "reason": "leaf_index_out_of_range",
            "leaf_count": len(leaves),
        }

    leaf = leaves[predicate_index]
    leaf_kind = leaf.get("kind")
    role = leaf.get("authority_role")
    if leaf_kind != "signature_auth":
        return {
            "result": "unknown",
            "reason": "non_signature_leaf",
            "leaf_kind": leaf_kind,
            "authority_role": role,
        }

    # Evaluate the leaf alone; the result's ``.signer`` is the allowed set.
    isolated_tree = make_leaf_node(leaf)  # pyright: ignore[reportArgumentType]
    cap = evaluate_tree_with_registry(isolated_tree, registry, ctx)
    if cap.kind == "signature_witness" and cap.signer is not None:
        answer = _resolve_in_capability(cap.signer, recovered_signer)
        answer["capability_kind"] = "signature_witness"
        answer["signer_capability_kind"] = cap.signer.kind
        answer["leaf_kind"] = leaf_kind
        answer["authority_role"] = role
        return answer
    # Not a signature_witness; surface for diagnosis.
    return {
        "result": "unknown",
        "reason": f"unexpected_signature_capability_{cap.kind}",
        "leaf_kind": leaf_kind,
        "authority_role": role,
        "capability_kind": cap.kind,
    }


def _walk_leaves(tree: dict[str, Any] | None) -> Iterator[dict[str, Any]]:
    if tree is None:
        return
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        if leaf is not None:
            yield leaf
        return
    for child in tree.get("children") or []:
        yield from _walk_leaves(child)


def _resolve_in_capability(cap: CapabilityExpr, member: str) -> dict[str, Any]:
    """Project a CapabilityExpr to ``{"result": ..., "reason": ...}`` for ``member``."""
    member_lower = member.lower()

    if cap.kind == "finite_set":
        members = cap.members or []
        in_set = member_lower in {m.lower() for m in members}
        quality = cap.membership_quality
        if quality == "exact":
            return {"result": "yes" if in_set else "no", "reason": "finite_set_exact"}
        if quality == "lower_bound":
            # lower_bound: listed members hold; absence proves nothing.
            if in_set:
                return {"result": "yes", "reason": "finite_set_lower_bound"}
            return {"result": "unknown", "reason": "lower_bound_absent"}
        if quality == "upper_bound":
            # upper_bound: absence is a definite no; presence isn't a definite yes.
            if not in_set:
                return {"result": "no", "reason": "finite_set_upper_bound"}
            return {"result": "unknown", "reason": "upper_bound_present"}
        return {"result": "unknown", "reason": "unknown_quality"}

    if cap.kind == "threshold_group":
        threshold = cap.threshold or (0, [])
        signers = threshold[1]
        if member_lower in {m.lower() for m in signers}:
            # A signer may not sign; the caller decides if potential is enough.
            return {"result": "yes", "reason": "threshold_group_signer"}
        return {"result": "no", "reason": "threshold_group_non_signer"}

    if cap.kind == "cofinite_blacklist":
        blacklist = cap.blacklist or []
        if member_lower in {m.lower() for m in blacklist}:
            return {"result": "no", "reason": "cofinite_blacklisted"}
        return {"result": "yes", "reason": "cofinite_not_blacklisted"}

    if cap.kind == "external_check_only":
        # Not enumerable; surface the probe descriptor for an on-chain check.
        check = cap.check
        return {
            "result": "unknown",
            "reason": "external_check_only",
            "probe_target": getattr(check, "target_address", None) if check else None,
            "probe_selector": getattr(check, "target_call_selector", None) if check else None,
        }

    if cap.kind == "signature_witness":
        return {"result": "unknown", "reason": "signature_witness"}

    if cap.kind == "unsupported":
        return {
            "result": "unknown",
            "reason": "capability_unsupported",
            "capability_unsupported_reason": cap.unsupported_reason,
        }

    if cap.kind in ("AND", "OR"):
        # AND: all yes → yes, any no → no. OR: any yes → yes, all no → no. Otherwise unknown.
        child_results = [_resolve_in_capability(c, member) for c in cap.children]
        statuses = [r["result"] for r in child_results]
        if cap.kind == "AND":
            if all(s == "yes" for s in statuses):
                return {"result": "yes", "reason": "and_all_yes"}
            if any(s == "no" for s in statuses):
                return {"result": "no", "reason": "and_any_no"}
            return {"result": "unknown", "reason": "and_some_unknown"}
        if any(s == "yes" for s in statuses):
            return {"result": "yes", "reason": "or_any_yes"}
        if all(s == "no" for s in statuses):
            return {"result": "no", "reason": "or_all_no"}
        return {"result": "unknown", "reason": "or_some_unknown"}

    if cap.kind == "conditional_universal":
        return {"result": "yes", "reason": "conditional_universal"}

    return {"result": "unknown", "reason": "unrecognized_capability"}
