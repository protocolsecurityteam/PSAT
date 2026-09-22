"""Leaf confidence derivation."""

from __future__ import annotations

from ..predicate_types import Confidence, LeafPredicate, PredicateTree

# ---------------------------------------------------------------------------
# Confidence
# ---------------------------------------------------------------------------


def apply_confidence_to_tree(tree: PredicateTree | None) -> None:
    """Walk a PredicateTree in place and stamp ``confidence`` on
    every leaf using ``_derive_confidence``. Idempotent — safe to
    call after every pass that mutates ``authority_role``."""
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
    """Map a fully-classified leaf to HIGH/MEDIUM/LOW confidence.

    Rules (structural):
      HIGH — shape-tight matches with no indirect inference:
        • equality/eq with caller-source operand vs address-typed
          state/view/parameter/sig_recovery operand (Rule A direct).
        • signature_auth (ecrecover-then-equality, shape-tight by
          construction).
        • multi-key (≥2) membership with caller key (Rule B direct
          promote — permission table by structure).
        • time (block_context comparison without caller).
        • reentrancy/pause (cross-referenced via dedicated analyzer).
        • EIP-1271 magic-value match (caller_authority on F3 path).

      MEDIUM — inferred / dependent on writer or
      threshold analysis:
        • 1-key caller-keyed membership promoted by writer-gate
          Path 1 (rules b.i/b.ii — depends on writer side analysis).
        • F2 threshold-promote (comparison kind, authority-derived
          counter inference).
        • delegated_authority via external_bool (depends on the
          oracle resolving correctly at evaluation time).

      LOW — residual / no auth signal:
        • business default for residual leaves.
        • bare-bool truthy leaves with no caller / state context.
        • unsupported leaves (we tried but couldn't classify).
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
                # Multi-key permission table — Rule B direct promote.
                return "high"
            if len(keys) == 1 and "self-administered" in basis_text:
                # Rule b.ii — writer reads the same map (Maker-wards
                # canonical self-admin ACL). Tight structural match.
                return "high"
            if len(keys) == 1 and "writers are authority-gated" in basis_text:
                # Rule b.i — writer has some other auth. Transitive,
                # so the auth signal is weaker than direct shape.
                return "medium"
            # 1-key direct (no writer-gate basis) — could be member /
            # KYC / personal flag. Don't claim HIGH without writer
            # context; codex round on this called it out explicitly.
            return "medium"
        if kind == "comparison":
            # threshold-promote (F2) is an inferred authority signal.
            return "medium"
        return "medium"

    return "low"
