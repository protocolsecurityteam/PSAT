"""Derived views over canonical claims and analysis receipts."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from schemas.assessment import Assessment, Claim


def function_effect_claims(assessment: Assessment, effect_kind: str | None = None) -> list[Claim]:
    claims: list[Claim] = []
    for claim in assessment["claims"].values():
        proposition = claim["proposition"]
        if proposition["kind"] != "function_effect":
            continue
        if effect_kind is not None and proposition["effect"]["kind"] != effect_kind:
            continue
        claims.append(claim)
    return claims


def capability_claims(assessment: Assessment, effect_kind: str | None = None) -> list[Claim]:
    claims: list[Claim] = []
    for claim in assessment["claims"].values():
        proposition = claim["proposition"]
        if proposition["kind"] != "authority_capability":
            continue
        if effect_kind is not None and proposition["effect"]["kind"] != effect_kind:
            continue
        claims.append(claim)
    return claims


def effect_presence(assessment: Assessment, effect_kind: str, *, detector: str | None = None) -> bool | None:
    """Three-state projection without storing uncertainty inside a claim."""

    if function_effect_claims(assessment, effect_kind):
        return True
    detector_name = detector or effect_kind
    receipts = [analysis for analysis in assessment["analyses"] if analysis["detector"] == detector_name]
    if not receipts:
        return None
    receipt = receipts[-1]
    coverage = receipt["coverage"]
    if (
        receipt["status"] == "completed"
        and coverage["targets_completed"] == coverage["targets_total"]
        and not coverage["omissions"]
    ):
        return False
    return None


def effect_matches_by_function(assessment: Assessment) -> dict[str, list[dict[str, Any]]]:
    """Build the compact effect matches used by relational index writers."""

    signatures = {function_id: function["signature"] for function_id, function in assessment["functions"].items()}
    out: dict[str, list[dict[str, Any]]] = {}
    for claim in function_effect_claims(assessment):
        proposition = claim["proposition"]
        if proposition["kind"] != "function_effect":
            continue
        signature = signatures.get(proposition["function_id"])
        if signature is None:
            continue
        rule = claim["basis"]["rule"]
        tier = rule.rsplit("/", 1)[-1]
        if tier not in ("behavioral_observed", "standard_exact", "idiom_structural", "policy_derived"):
            tier = "policy_derived"
        witness: dict[str, Any] = {}
        for evidence_id in claim["basis"]["evidence_ids"]:
            evidence = assessment["evidence"].get(evidence_id)
            if evidence is None or not isinstance(evidence["observation"], dict):
                continue
            # Structural detail is what index writers inspect. Execution
            # evidence strengthens the same claim but stays referenced rather
            # than overwriting the replayable static witness.
            if evidence["method"] != "execution":
                witness.update(evidence["observation"])
            else:
                claim_witness = evidence["observation"].get("claim_witness")
                if isinstance(claim_witness, dict):
                    witness.update(claim_witness)
        witness["evidence_ids"] = list(claim["basis"]["evidence_ids"])
        out.setdefault(signature, []).append(
            {
                "claim_id": proposition["effect"]["kind"],
                "tier": tier,
                "witness": witness,
            }
        )
    for signature in out:
        out[signature].sort(key=lambda item: (str(item["claim_id"]), str(item["tier"])))
    return out


def project_permission_index(assessment: Assessment, permissions: Mapping[str, Any]) -> dict[str, Any]:
    """Attach canonical effect matches to the transient permission rows."""

    projected = copy.deepcopy(dict(permissions))
    claims = effect_matches_by_function(assessment)
    known_signatures = {function["signature"] for function in assessment["functions"].values()}
    functions = projected.get("functions")
    if not isinstance(functions, list):
        return projected
    for function in functions:
        if not isinstance(function, dict):
            continue
        signature = function.get("abi_signature") or function.get("function")
        if isinstance(signature, str) and signature in known_signatures:
            function["claims"] = list(claims.get(signature, []))
    return projected


__all__ = [
    "capability_claims",
    "effect_presence",
    "function_effect_claims",
    "effect_matches_by_function",
    "project_permission_index",
]
