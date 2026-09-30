"""Leaf confidence derivation."""

from __future__ import annotations

from ..predicate_types import Confidence, LeafPredicate, PredicateTree


def apply_confidence_to_tree(tree: PredicateTree | None) -> None:
    """Stamp ``confidence`` on every leaf in place. Idempotent; re-run after passes that change ``authority_role``."""
    if tree is None:
        return
    op = tree.get("op")
    if op == "LEAF":
        leaf = tree.get("leaf")
        if leaf is not None:
            leaf["confidence"] = _derive_confidence(leaf)
        return
    for child in tree.get("children", []) or []:
        apply_confidence_to_tree(child)


def _derive_confidence(leaf: LeafPredicate) -> Confidence:
    """HIGH/MEDIUM/LOW confidence from a classified leaf's structure.

    HIGH: direct shape matches (caller equality vs an address operand, ``signature_auth``, multi-key caller membership,
    time gates, reentrancy/pause, EIP-1271). MEDIUM: inferred (single-key membership promoted by the writer gate,
    threshold promotion, ``delegated_authority`` via external bool). LOW: business residuals, bare bools, unsupported
    leaves.
    """
    role = leaf.get("authority_role", "business")
    kind = leaf.get("kind")
    operator = leaf.get("operator")
    operands = leaf.get("operands", []) or []
    descriptor = leaf.get("set_descriptor")
    basis_text = " ".join(leaf.get("basis", []) or [])

    if kind == "unsupported" or role == "business":
        return "low"

    if role in ("reentrancy", "pause", "time", "one_shot"):
        return "high"

    if kind == "signature_auth":
        return "high"

    if role == "delegated_authority":
        return "medium"

    if role == "caller_authority":
        if kind == "equality" and operator == "eq":
            non_caller = [
                o for o in operands if o.get("source") not in ("msg_sender", "tx_origin", "signature_recovery")
            ]
            if any(
                o.get("source") in ("state_variable", "view_call", "parameter", "signature_recovery")
                for o in non_caller
            ):
                return "high"
            return "medium"
        if kind == "membership" and descriptor:
            keys = descriptor.get("key_sources", []) or []
            caller_key = any(k.get("source") in ("msg_sender", "tx_origin", "signature_recovery") for k in keys)
            if len(keys) >= 2 and caller_key:
                return "high"
            if len(keys) == 1 and "self-administered" in basis_text:
                # Writer reads the same map (Maker-wards self-admin ACL).
                return "high"
            if len(keys) == 1 and "writers are authority-gated" in basis_text:
                # Writer has other auth: transitive.
                return "medium"
            # Single key with no writer-gate basis could be a member list or a personal flag.
            return "medium"
        if kind == "comparison":
            return "medium"
        return "medium"

    return "low"
