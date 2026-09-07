"""Derived views over canonical claims and analysis receipts."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any, cast

from schemas.assessment import Assessment, Claim


def function_effect_claims(assessment: Assessment, effect_kind: str | None = None) -> list[Claim]:
    claims: list[Claim] = []
    for claim in assessment["claims"].values():
        proposition = claim["proposition"]
        if proposition["kind"] != "function_effect":
            continue
        effect = proposition.get("effect")
        if effect is None or (effect_kind is not None and effect["kind"] != effect_kind):
            continue
        claims.append(claim)
    return claims


def function_authority_claims(assessment: Assessment) -> list[Claim]:
    """Supported answers to who may call a function, independent of its effect."""

    return [claim for claim in assessment["claims"].values() if claim["proposition"]["kind"] == "function_authority"]


def effect_presence(assessment: Assessment, effect_kind: str, *, detector: str | None = None) -> bool | None:
    """Three-state projection without storing uncertainty inside a claim."""

    if function_effect_claims(assessment, effect_kind):
        return True
    detector_name = detector or effect_kind
    receipts = [analysis for analysis in assessment["analyses"] if analysis["detector"] == detector_name]
    if not receipts:
        return None
    receipt = receipts[-1]
    if (
        receipt["status"] == "completed"
        and receipt["targets_completed"] == receipt["targets_total"]
        and not receipt["omissions"]
    ):
        return False
    return None


def effect_matches_by_function(assessment: Assessment) -> dict[str, list[dict[str, Any]]]:
    """Build the compact effect matches used by relational index writers."""

    out: dict[str, list[dict[str, Any]]] = {}
    for claim in function_effect_claims(assessment):
        proposition = claim["proposition"]
        if proposition["kind"] != "function_effect":
            continue
        signature = proposition.get("function")
        effect = proposition.get("effect")
        if signature is None or effect is None:
            continue
        rule = claim["rule"]
        tier = rule.rsplit("/", 1)[-1]
        if tier not in ("behavioral_observed", "standard_exact", "idiom_structural", "policy_derived"):
            tier = "policy_derived"
        witness: dict[str, Any] = {}
        for evidence_key in claim["evidence"]:
            evidence = assessment["evidence"].get(evidence_key)
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
        witness["evidence_ids"] = list(claim["evidence"])
        out.setdefault(signature, []).append(
            {
                "claim_id": effect["kind"],
                "tier": tier,
                "witness": witness,
            }
        )
    for signature in out:
        out[signature].sort(key=lambda item: (str(item["claim_id"]), str(item["tier"])))
    return out


def project_permission_index(assessment: Assessment) -> dict[str, Any]:
    """Rebuild permission rows exclusively from canonical Assessment evidence."""

    claims = effect_matches_by_function(assessment)
    policy_observations = {
        evidence["subject"]: evidence["observation"]
        for evidence in assessment["evidence"].values()
        if evidence["producer"] == "policy.capability"
        and evidence["subject_kind"] == "function"
        and isinstance(evidence["observation"], Mapping)
    }
    functions = []
    for signature, observation in sorted(policy_observations.items()):
        identity = assessment["functions"][signature]
        functions.append(
            {
                **copy.deepcopy(dict(observation)),
                "function": signature,
                "abi_signature": identity["abi_signature"] or signature,
                "selector": identity["selector"],
                "claims": list(claims.get(signature, [])),
            }
        )
    return {
        "schema_version": assessment["schema_version"],
        "contract_address": assessment["contract"]["deployment_address"],
        "contract_name": assessment["contract"]["name"],
        "functions": functions,
    }


def static_index_view(assessment: Assessment) -> dict[str, Any]:
    """Project static relational indexes from validated Assessment evidence."""

    for evidence in assessment["evidence"].values():
        if evidence["producer"] != "static.facts" or not isinstance(evidence["observation"], Mapping):
            continue
        observation = cast(Mapping[str, Any], evidence["observation"])
        static_facts = observation.get("static_facts")
        if not isinstance(static_facts, Mapping):
            continue
        subject_value = static_facts.get("subject")
        summary_value = static_facts.get("summary")
        subject = cast(Mapping[str, Any], subject_value) if isinstance(subject_value, Mapping) else {}
        summary = cast(Mapping[str, Any], summary_value) if isinstance(summary_value, Mapping) else {}
        semantic_control = static_facts.get("semantic_control")
        roles = semantic_control.get("role_definitions") if isinstance(semantic_control, Mapping) else None
        return {
            "contract_name": subject.get("name"),
            "source_verified": subject.get("source_verified"),
            "control_model": summary.get("control_model"),
            "is_upgradeable": summary.get("is_upgradeable"),
            "is_pausable": effect_presence(assessment, "pause.set"),
            "has_timelock": summary.get("has_timelock"),
            "is_factory": summary.get("is_factory"),
            "is_nft": summary.get("is_nft"),
            "standards": list(summary.get("standards") or []),
            "role_definitions": list(roles) if isinstance(roles, list) else [],
        }
    raise ValueError("Assessment has no static.facts evidence")


def static_inputs(assessment: Assessment) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Project the transient semantic inputs embedded in static evidence."""

    for evidence in assessment["evidence"].values():
        observation = evidence["observation"]
        if evidence["producer"] != "static.facts" or not isinstance(observation, Mapping):
            continue
        static_facts = observation.get("static_facts")
        predicate_trees = observation.get("predicate_trees")
        effects = observation.get("effects")
        if all(isinstance(value, Mapping) for value in (static_facts, predicate_trees, effects)):
            return (
                dict(cast(Mapping[str, Any], static_facts)),
                dict(cast(Mapping[str, Any], predicate_trees)),
                dict(cast(Mapping[str, Any], effects)),
            )
    raise ValueError("Assessment has no complete static input evidence")


__all__ = [
    "effect_presence",
    "function_effect_claims",
    "function_authority_claims",
    "effect_matches_by_function",
    "project_permission_index",
    "static_index_view",
    "static_inputs",
]
