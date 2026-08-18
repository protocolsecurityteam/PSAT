"""Membership-probe service for semantic predicate trees.

Given a serialized PredicateTree, a leaf index, and a candidate
member address, returns a structured answer to "is this address in
the leaf's set?" The decision relies on the AdapterRegistry to
expand the leaf's set descriptor into a CapabilityExpr.

Three answers ``probe_membership`` returns:

  * ``yes``  — the address is provably allowed by the leaf.
  * ``no``   — the address is provably NOT allowed.
  * ``unknown`` — the adapter resolved the descriptor but the
    answer can't be made definitive (e.g. lower_bound finite_set
    where the address isn't in the partial known list, or
    external_check_only / signature_witness shapes).

The shape of "unknown" matters: it tells the caller whether to fall
back to an out-of-band probe (RPC authority check, EIP-1271
``isValidSignature``) or accept the ambiguity. The membership
quality + confidence on the CapabilityExpr drive the trit.

This is the engine the probe HTTP route (``/api/contract/<addr>/probe/membership``)
will wrap. Keeping it pure-function over an injected registry +
context makes it unit-testable without spinning up FastAPI.
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
    """Return ``{"result": "yes"|"no"|"unknown", ...}`` for the
    leaf at ``predicate_index`` in the predicate tree."""
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
    """Counterpart to ``probe_membership`` for ``signature_auth``
    leaves. The caller has already done ECDSA recovery (or
    EIP-1271 isValidSignature) and supplies the recovered signer
    address; we return whether that address is in the leaf's
    allowed-signer set.

    For ECDSA leaves (``ecrecover(hash, v, r, s) == knownSigner``)
    the signer set is the resolved address-typed operand —
    typically a state-var read or constant. For EIP-1271 leaves,
    the leaf carries a signature_witness shape that wraps an
    ``external_check_only`` indicating the caller must invoke
    ``isValidSignature(hash, sig)`` on the signing contract; we
    surface that probe target+selector via ``unknown``.

    Returns ``{"result": "yes"|"no"|"unknown", ...}`` on the same
    contract as ``probe_membership``.
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

    # Resolve the leaf by itself — wrap in a make_leaf_node so the
    # evaluator handles it cleanly. The evaluator returns a
    # signature_witness whose .signer is the address-set the
    # signature must recover to.
    isolated_tree = make_leaf_node(leaf)  # pyright: ignore[reportArgumentType]
    cap = evaluate_tree_with_registry(isolated_tree, registry, ctx)
    if cap.kind == "signature_witness" and cap.signer is not None:
        answer = _resolve_in_capability(cap.signer, recovered_signer)
        answer["capability_kind"] = "signature_witness"
        answer["signer_capability_kind"] = cap.signer.kind
        answer["leaf_kind"] = leaf_kind
        answer["authority_role"] = role
        return answer
    # Fall-through: leaf resolved to something other than a
    # signature_witness — surface for diagnostic.
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
    """Project a CapabilityExpr into ``{"result": ..., "reason": ...}``
    for a candidate ``member``."""
    member_lower = member.lower()

    if cap.kind == "finite_set":
        members = cap.members or []
        in_set = member_lower in {m.lower() for m in members}
        quality = cap.membership_quality
        if quality == "exact":
            return {"result": "yes" if in_set else "no", "reason": "finite_set_exact"}
        if quality == "lower_bound":
            # Listed members are KNOWN to hold; absence means we
            # haven't observed them — could still hold.
            if in_set:
                return {"result": "yes", "reason": "finite_set_lower_bound"}
            return {"result": "unknown", "reason": "lower_bound_absent"}
        if quality == "upper_bound":
            # Listed members ARE all that could hold; absence is a
            # definitive no, but presence isn't a definitive yes
            # (current state may have evicted them).
            if not in_set:
                return {"result": "no", "reason": "finite_set_upper_bound"}
            return {"result": "unknown", "reason": "upper_bound_present"}
        return {"result": "unknown", "reason": "unknown_quality"}

    if cap.kind == "threshold_group":
        threshold = cap.threshold or (0, [])
        signers = threshold[1]
        if member_lower in {m.lower() for m in signers}:
            # Being a signer doesn't guarantee they'll sign — but
            # they're potentially-allowed. Caller decides whether
            # potential is enough.
            return {"result": "yes", "reason": "threshold_group_signer"}
        return {"result": "no", "reason": "threshold_group_non_signer"}

    if cap.kind == "cofinite_blacklist":
        blacklist = cap.blacklist or []
        if member_lower in {m.lower() for m in blacklist}:
            return {"result": "no", "reason": "cofinite_blacklisted"}
        return {"result": "yes", "reason": "cofinite_not_blacklisted"}

    if cap.kind == "external_check_only":
        # The adapter can't enumerate; the caller needs to invoke
        # the probe interface (e.g. authority check / isValidSignature) at
        # the chain level. Surface the probe descriptor so the
        # caller can do that.
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
        # Compose results of children. AND: every child says yes →
        # yes; any child says no → no; otherwise unknown. OR: any
        # child says yes → yes; every child says no → no; otherwise
        # unknown.
        child_results = [_resolve_in_capability(c, member) for c in cap.children]
        statuses = [r["result"] for r in child_results]
        if cap.kind == "AND":
            if all(s == "yes" for s in statuses):
                return {"result": "yes", "reason": "and_all_yes"}
            if any(s == "no" for s in statuses):
                return {"result": "no", "reason": "and_any_no"}
            return {"result": "unknown", "reason": "and_some_unknown"}
        # OR
        if any(s == "yes" for s in statuses):
            return {"result": "yes", "reason": "or_any_yes"}
        if all(s == "no" for s in statuses):
            return {"result": "no", "reason": "or_all_no"}
        return {"result": "unknown", "reason": "or_some_unknown"}

    if cap.kind == "conditional_universal":
        return {"result": "yes", "reason": "conditional_universal"}

    return {"result": "unknown", "reason": "unrecognized_capability"}
