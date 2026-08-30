"""Behavioral verdicts strengthen claims with execution evidence."""

from __future__ import annotations

from types import SimpleNamespace

from pydantic import TypeAdapter

from schemas.assessment import Assessment
from services.assessment import add_effects, build_static_assessment
from services.effects.config import EFFECT_CLASS_FREEZE_PAUSE, VERDICT_PROVEN, VERDICT_UNKNOWN


def _base() -> Assessment:
    return build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        analysis={"controller_tracking": []},
        effects={
            "schema_version": "semantic-2",
            "claims_schema_version": "claims/1",
            "functions": {
                "pause()": {
                    "function": "pause()",
                    "selector": "0x8456cb59",
                    "abi_signature": "pause()",
                    "state_changing": True,
                    "state_writes": [],
                    "effect_targets": ["paused"],
                    "claims": [
                        {
                            "claim_id": "pause.set",
                            "tier": "idiom_structural",
                            "witness": {
                                "kind": "pause_flag",
                                "flags": [{"var": "paused", "member": None}],
                                "polarity": "set",
                                "affected_functions": [],
                            },
                        }
                    ],
                }
            },
            "claim_analyses": {},
            "claim_diagnostics": [],
        },
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )


def _verdict(verdict: str, *, reason: str | None = None) -> SimpleNamespace:
    witness = {"observation": "executed", "pause_effective": verdict == VERDICT_PROVEN}
    if reason is not None:
        witness["reason"] = reason
    return SimpleNamespace(
        id=7,
        function_id=42,
        effect_class=EFFECT_CLASS_FREEZE_PAUSE,
        verdict=verdict,
        tier="fork",
        behavior_hash="behavior:1",
        current_check_passed=True,
        witness=witness,
        observed_residue={"observed_blast_radius": ["withdraw()"]},
        transcript_ptr="job::effect_transcript_pause_1",
    )


def test_proven_verdict_adds_execution_evidence_to_the_effect_claim() -> None:
    assessment = add_effects(_base(), [_verdict(VERDICT_PROVEN)], signatures_by_function_row={42: "pause()"})
    TypeAdapter(Assessment).validate_python(assessment)

    pause_claim = next(
        claim
        for claim in assessment["claims"].values()
        if claim["proposition"]["kind"] == "function_effect" and claim["proposition"]["effect"]["kind"] == "pause.set"
    )
    methods = {assessment["evidence"][evidence_id]["method"] for evidence_id in pause_claim["basis"]["evidence_ids"]}
    assert methods == {"static_ir", "execution"}
    assert pause_claim["basis"]["rule"] == "pause.set/behavioral_observed"


def test_unknown_verdict_is_an_omission_and_mints_no_claim() -> None:
    base = _base()
    before = set(base["claims"])
    assessment = add_effects(
        base,
        [_verdict(VERDICT_UNKNOWN, reason="pause_ineffective")],
        signatures_by_function_row={42: "pause()"},
    )
    assert set(assessment["claims"]) == before
    receipt = assessment["analyses"][-1]
    assert receipt["status"] == "failed"
    assert receipt["coverage"]["omissions"][0]["reason"] == "pause_ineffective"
