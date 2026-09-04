"""Merge behavioral effect verdicts into canonical evidence and claims."""

from __future__ import annotations

import copy
from collections.abc import Iterable, Mapping
from typing import Any, cast

from schemas.assessment import (
    Analysis,
    Assessment,
    Effect,
    EffectFamily,
    EffectKind,
    Evidence,
    Proposition,
)
from services.effects.claims_bridge import verdict_to_claim
from services.effects.config import VERDICT_PROVEN
from services.static.claims.registry import entry_for
from services.static.claims.types import TIER_PRECEDENCE

from .functions import resolve_function
from .keys import content_key
from .keys import json_value as _json
from .slices import remove_analysis_slice
from .validation import checked


def _existing_effect_claim(assessment: Assessment, function: str, kind: str) -> tuple[str, Any] | None:
    for claim_key, claim in assessment["claims"].items():
        proposition = claim["proposition"]
        if (
            proposition["kind"] == "function_effect"
            and proposition.get("function") == function
            and proposition.get("effect", {}).get("kind") == kind
        ):
            return claim_key, claim
    return None


def add_effects(
    assessment: Assessment,
    verdicts: Iterable[Any],
    *,
    signatures_by_function_row: Mapping[int, str],
) -> Assessment:
    """Add proven execution evidence; unknown verdicts become omissions."""

    result = cast(Assessment, copy.deepcopy(assessment))
    remove_analysis_slice(result, "effects.execution")
    tier_rank = TIER_PRECEDENCE
    for claim in result["claims"].values():
        current_proposition = claim["proposition"]
        if current_proposition["kind"] != "function_effect":
            continue
        tiers: list[str] = []
        for evidence_key in claim["evidence"]:
            current_evidence = result["evidence"].get(evidence_key)
            locator = current_evidence["locator"] if current_evidence is not None else None
            tier = locator.get("tier") if isinstance(locator, Mapping) else None
            if isinstance(tier, str) and tier in tier_rank:
                tiers.append(tier)
        if tiers:
            strongest = max(tiers, key=lambda tier: tier_rank[tier])
            current_effect = current_proposition.get("effect")
            if current_effect is not None:
                claim["rule"] = f"{current_effect['kind']}/{strongest}"
    verdict_items = list(verdicts)
    omissions: list[dict[str, str]] = []
    claim_keys: list[str] = []
    evidence_keys: list[str] = []
    completed = 0

    for verdict in verdict_items:
        row_id = getattr(verdict, "function_id", None)
        signature = signatures_by_function_row.get(row_id) if isinstance(row_id, int) else None
        function, _problem = resolve_function(result, {"function": signature, "abi_signature": signature})
        if function is None:
            omissions.append(
                {
                    "target_kind": "contract",
                    "target": result["contract"]["address"],
                    "reason": f"effect_verdict_function_not_in_contract:{row_id}",
                }
            )
            continue

        match = verdict_to_claim(verdict)
        if getattr(verdict, "verdict", None) != VERDICT_PROVEN or match is None:
            witness = getattr(verdict, "witness", None)
            reason = witness.get("reason") if isinstance(witness, Mapping) else None
            omissions.append(
                {
                    "target_kind": "function",
                    "target": function,
                    "reason": str(reason or getattr(verdict, "verdict", None) or "effect_not_proven"),
                }
            )
            continue

        completed += 1
        kind = match["claim_id"]
        observation = _json(
            {
                "effect_class": getattr(verdict, "effect_class", None),
                "verdict": getattr(verdict, "verdict", None),
                "tier": getattr(verdict, "tier", None),
                "behavior_hash": getattr(verdict, "behavior_hash", None),
                "current_check_passed": getattr(verdict, "current_check_passed", None),
                "claim_witness": match["witness"],
                "witness": getattr(verdict, "witness", None),
                "observed_residue": getattr(verdict, "observed_residue", None),
                "transcript_ptr": getattr(verdict, "transcript_ptr", None),
            }
        )
        evidence_key = content_key(
            "evidence",
            {
                "contract": result["contract"],
                "method": "execution",
                "function": function,
                "effect_verdict_id": getattr(verdict, "id", None),
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "method": "execution",
            "subject_kind": "function",
            "subject": function,
            "observation": observation,
            "producer": "effects.execution",
            "version": "effects/1",
            "locator": _json(
                {
                    "effect_verdict_id": getattr(verdict, "id", None),
                    "transcript_ptr": getattr(verdict, "transcript_ptr", None),
                }
            ),
        }
        result["evidence"][evidence_key] = evidence
        evidence_keys.append(evidence_key)

        existing = _existing_effect_claim(result, function, kind)
        if existing is not None:
            claim_key, claim = existing
            if evidence_key not in claim["evidence"]:
                claim["evidence"].append(evidence_key)
            claim["rule"] = f"{kind}/behavioral_observed"
            claim_keys.append(claim_key)
            continue

        entry = entry_for(kind)
        effect: Effect = {
            "kind": cast(EffectKind, kind),
            "family": cast(EffectFamily, entry.consumer_family),
            "targets": [],
            "affected_functions": [],
        }
        proposition: Proposition = {
            "kind": "function_effect",
            "function": function,
            "effect": effect,
        }
        claim_key = content_key("claim", {"contract": result["contract"], "proposition": proposition})
        result["claims"][claim_key] = {
            "proposition": proposition,
            "rule": f"{kind}/behavioral_observed",
            "evidence": [evidence_key],
            "claims": [],
        }
        claim_keys.append(claim_key)

    status = "completed" if not omissions else ("partial" if completed else "failed")
    receipt: Analysis = {
        "detector": "effects.execution",
        "version": "effects/1",
        "status": status,
        "targets_total": len(verdict_items),
        "targets_completed": completed,
        "omissions": omissions,
        "diagnostics": [],
        "claims": sorted(set(claim_keys)),
        "evidence": sorted(set(evidence_keys)),
    }
    result["analyses"].append(receipt)
    return checked(result)


__all__ = ["add_effects"]
