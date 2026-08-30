"""Merge behavioral effect verdicts into canonical evidence and claims."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterable, Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import (
    Analysis,
    Assessment,
    Effect,
    EffectFamily,
    EffectKind,
    Evidence,
    FunctionEffect,
    Omission,
)
from services.effects.claims_bridge import verdict_to_claim
from services.effects.config import VERDICT_PROVEN
from services.static.claims.registry import entry_for

from .ids import stable_id
from .validation import checked


def _json(value: Any) -> JsonValue:
    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))


def _function_ids(assessment: Assessment) -> dict[str, str]:
    return {function["signature"]: function_id for function_id, function in assessment["functions"].items()}


def _existing_effect_claim(assessment: Assessment, function_id: str, kind: str) -> tuple[str, Any] | None:
    for claim_id, claim in assessment["claims"].items():
        proposition = claim["proposition"]
        if (
            proposition["kind"] == "function_effect"
            and proposition["function_id"] == function_id
            and proposition["effect"]["kind"] == kind
        ):
            return claim_id, claim
    return None


def add_effects(
    assessment: Assessment,
    verdicts: Iterable[Any],
    *,
    signatures_by_function_row: Mapping[int, str],
) -> Assessment:
    """Add proven execution evidence; unknown verdicts become omissions."""

    result = cast(Assessment, copy.deepcopy(assessment))
    ids_by_signature = _function_ids(result)
    verdict_items = list(verdicts)
    omissions: list[Omission] = []
    claim_ids: list[str] = []
    evidence_ids: list[str] = []
    completed = 0

    for verdict in verdict_items:
        row_id = getattr(verdict, "function_id", None)
        signature = signatures_by_function_row.get(row_id) if isinstance(row_id, int) else None
        function_id = ids_by_signature.get(signature) if signature is not None else None
        if function_id is None:
            omissions.append(
                {
                    "target_kind": "contract",
                    "target_id": result["contract"]["id"],
                    "reason": f"effect_verdict_function_not_in_contract:{row_id}",
                }
            )
            continue

        legacy_claim = verdict_to_claim(verdict)
        if getattr(verdict, "verdict", None) != VERDICT_PROVEN or legacy_claim is None:
            witness = getattr(verdict, "witness", None)
            reason = witness.get("reason") if isinstance(witness, Mapping) else None
            omissions.append(
                {
                    "target_kind": "function",
                    "target_id": function_id,
                    "reason": str(reason or getattr(verdict, "verdict", None) or "effect_not_proven"),
                }
            )
            continue

        completed += 1
        kind = legacy_claim["claim_id"]
        observation = _json(
            {
                "effect_class": getattr(verdict, "effect_class", None),
                "verdict": getattr(verdict, "verdict", None),
                "tier": getattr(verdict, "tier", None),
                "behavior_hash": getattr(verdict, "behavior_hash", None),
                "current_check_passed": getattr(verdict, "current_check_passed", None),
                "claim_witness": legacy_claim["witness"],
                "witness": getattr(verdict, "witness", None),
                "observed_residue": getattr(verdict, "observed_residue", None),
                "transcript_ptr": getattr(verdict, "transcript_ptr", None),
            }
        )
        evidence_id = stable_id(
            "evidence",
            {
                "scope": result["scope"],
                "method": "execution",
                "function_id": function_id,
                "effect_verdict_id": getattr(verdict, "id", None),
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "id": evidence_id,
            "method": "execution",
            "subject": {"kind": "function", "id": function_id},
            "observation": observation,
            "source": {
                "producer": "effects.execution",
                "version": "effects/1",
                "locator": _json(
                    {
                        "effect_verdict_id": getattr(verdict, "id", None),
                        "transcript_ptr": getattr(verdict, "transcript_ptr", None),
                    }
                ),
            },
            "scope": result["scope"],
        }
        result["evidence"][evidence_id] = evidence
        evidence_ids.append(evidence_id)

        existing = _existing_effect_claim(result, function_id, kind)
        if existing is not None:
            claim_id, claim = existing
            if evidence_id not in claim["basis"]["evidence_ids"]:
                claim["basis"]["evidence_ids"].append(evidence_id)
            claim["basis"]["rule"] = f"{kind}/behavioral_observed"
            claim_ids.append(claim_id)
            continue

        entry = entry_for(kind)
        effect: Effect = {
            "kind": cast(EffectKind, kind),
            "family": cast(EffectFamily, entry.consumer_family),
            "targets": [],
            "affected_functions": [],
        }
        proposition: FunctionEffect = {
            "kind": "function_effect",
            "function_id": function_id,
            "effect": effect,
        }
        claim_id = stable_id("claim", {"scope": result["scope"], "proposition": proposition})
        result["claims"][claim_id] = {
            "id": claim_id,
            "proposition": proposition,
            "basis": {
                "rule": f"{kind}/behavioral_observed",
                "evidence_ids": [evidence_id],
                "claim_ids": [],
            },
            "scope": result["scope"],
        }
        claim_ids.append(claim_id)

    status = "completed" if not omissions else ("partial" if completed else "failed")
    receipt: Analysis = {
        "detector": "effects.execution",
        "version": "effects/1",
        "status": status,
        "coverage": {
            "targets_total": len(verdict_items),
            "targets_completed": completed,
            "omissions": omissions,
        },
        "diagnostics": [],
        "claim_ids": sorted(set(claim_ids)),
        "evidence_ids": sorted(set(evidence_ids)),
    }
    result["analyses"] = [item for item in result["analyses"] if item["detector"] != "effects.execution"]
    result["analyses"].append(receipt)
    return checked(result)


__all__ = ["add_effects"]
