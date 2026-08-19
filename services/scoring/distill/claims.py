"""Claim reads: tiers, flows, shapes."""

from __future__ import annotations

import logging
from typing import Any

from services.scoring import constants as K
from utils.scoring_status import (
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
    WITNESS_TIER_IDIOM_STRUCTURAL,
    WITNESS_TIER_NOT_DETERMINED,
    WITNESS_TIER_POLICY_DERIVED,
    WITNESS_TIER_STANDARD_EXACT,
)

logger = logging.getLogger(__name__)

_TIER_TOKENS = {
    "behavioral_observed": WITNESS_TIER_BEHAVIORAL_OBSERVED,
    "standard_exact": WITNESS_TIER_STANDARD_EXACT,
    "idiom_structural": WITNESS_TIER_IDIOM_STRUCTURAL,
    "policy_derived": WITNESS_TIER_POLICY_DERIVED,
}
# Strongest first. Used only to pick the signal's descriptive tier; the gates
# that matter (a behavioural existence proof, a policy_derived block) are
# applied per claim entry where they arise.
_TIER_RANK = (
    WITNESS_TIER_BEHAVIORAL_OBSERVED,
    WITNESS_TIER_STANDARD_EXACT,
    WITNESS_TIER_IDIOM_STRUCTURAL,
    WITNESS_TIER_POLICY_DERIVED,
    WITNESS_TIER_NOT_DETERMINED,
)

# ---------------------------------------------------------------- claim reads


def _claims(func: Any) -> list[dict[str, Any]]:
    raw = func.claims
    if not isinstance(raw, list):
        return []
    return [c for c in raw if isinstance(c, dict)]


def _claim_ids(func: Any) -> set[str]:
    return {str(c.get("claim_id")) for c in _claims(func) if c.get("claim_id")}


def _tier(claim: dict[str, Any]) -> str:
    return _TIER_TOKENS.get(str(claim.get("tier")), WITNESS_TIER_NOT_DETERMINED)


def _best_tier(tiers: set[str]) -> str:
    for tier in _TIER_RANK:
        if tier in tiers:
            return tier
    return WITNESS_TIER_NOT_DETERMINED


def _target_kinds(flow: dict[str, Any]) -> list[str | None]:
    """A ``several`` target expands to its members; an unreadable member fails closed."""
    target = flow.get("target_kind") or {}
    kind = target.get("kind")
    if kind != "several":
        return [kind]
    members = flow.get("target_kinds") or target.get("kinds") or []
    out: list[str | None] = []
    for member in members:
        if isinstance(member, dict):
            out.append(str(member["kind"]) if member.get("kind") else None)
        elif member:
            out.append(str(member))
    return out or [None]


def _considered_out_flows(claims: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str | None]:
    """Every out-flow entry of the function, or the reason the set cannot be read.

    Two rules, each of which fails OPEN if skipped: ``value_router`` flows are
    inside the conjunction, and a ``flow.out``/``value_router`` claim with no
    ``flows`` key BLOCKS — silence is not evidence. ``policy_derived`` blocks for
    the same reason. A blocked set is returned as a named reason rather than as
    an empty list, so a universal over it cannot come out vacuously true.
    """
    considered: list[dict[str, Any]] = []
    for claim in claims:
        claim_id = str(claim.get("claim_id"))
        if claim_id not in ("flow.out", "value_router"):
            continue
        if claim.get("tier") == "policy_derived":
            return [], "blocked_policy_derived"
        witness = claim.get("witness") or {}
        flows = witness.get("flows")
        if flows is None:
            return [], "blocked_no_flows"
        # ``direction`` lives on the WITNESS. Read off a flow entry it is always
        # absent, which silently empties the conjunction.
        direction = str(witness.get("direction") or ("value_router" if claim_id == "value_router" else "out"))
        if direction not in ("out", "eth_out", "value_router"):
            continue
        considered.extend(f for f in flows if isinstance(f, dict))
    return considered, None


def _static_destination_shape(claims: list[dict[str, Any]]) -> tuple[str | None, str]:
    """Replay of the static lattice over every out-flow of the function.

    ``several`` reduces to its worst member, over the flow set
    ``_considered_out_flows`` closes.
    """
    considered, blocked = _considered_out_flows(claims)
    if blocked is not None:
        return None, blocked
    if not considered:
        return None, "no_out_flows"
    kinds: set[str | None] = set()
    for flow in considered:
        kinds.update(_target_kinds(flow))
    if None in kinds:
        return None, "unreadable_target_kind"
    known = {str(k) for k in kinds}
    if known <= K.FIXED_TARGET_KINDS:
        return "immutable_fixed", "static_conjunction"
    if known <= (K.FIXED_TARGET_KINDS | {K.ADMIN_TARGET_KIND}):
        return "storage_determined", "static_conjunction_admin"
    caller_relative = known & K.CALLER_RELATIVE_TARGET_KINDS
    if caller_relative and known <= (K.FIXED_TARGET_KINDS | K.CALLER_RELATIVE_TARGET_KINDS):
        # A PROVEN kind, not a gap — but not a fixed destination either: the
        # recipient is a known function of the caller / of token ownership. The
        # conjunction still takes the WORST member (``TARGET_KIND_RANK``), so a
        # flow set mixing an immutable payee with a caller payee reduces to the
        # caller one rather than to whichever entry was read last. What the kind
        # is WORTH is decided by the caller gate in ``_flow_destination``;
        # nothing here scores it.
        worst = min(caller_relative, key=lambda kind: K.TARGET_KIND_RANK[kind])
        return worst, f"static_conjunction_{worst}"
    return None, "not_fixed"


def _amount_kinds(claims: list[dict[str, Any]]) -> set[str]:
    kinds: set[str] = set()
    for claim in claims:
        if str(claim.get("claim_id")) != "flow.out":
            continue
        for flow in (claim.get("witness") or {}).get("flows") or []:
            if not isinstance(flow, dict):
                continue
            kind = (flow.get("amount_kind") or {}).get("kind")
            if kind == "several":
                kinds.update(str(m) for m in (flow.get("amount_kinds") or []) if m)
            elif kind:
                kinds.add(str(kind))
    return kinds
