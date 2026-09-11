"""Canonical static assessment construction."""

from __future__ import annotations

from pydantic import TypeAdapter

from schemas.assessment import Assessment
from services.assessment import build_static_assessment, effect_presence, static_inputs


def _effect(signature: str, *, state_changing: bool, claims: list[dict] | None = None) -> dict:
    return {
        "function": signature,
        "selector": "0x12345678",
        "abi_signature": signature,
        "state_changing": state_changing,
        "state_writes": [],
        "claims": claims or [],
    }


def _pause_inputs() -> tuple[dict, dict, dict]:
    analysis = {
        "controller_tracking": [
            {
                "controller_id": "owner",
                "label": "owner",
                "kind": "state_variable",
                "confidence": "exact",
                "tracking_mode": "state_only",
                "writer_functions": [],
                "associated_events": [],
                "polling_sources": ["owner"],
                "notes": [],
                "source": "state_variable",
                "read_spec": {"strategy": "getter_call", "target": "owner"},
            }
        ]
    }
    effects = {
        "schema_version": "semantic-2",
        "contract_name": "Vault",
        "claims_schema_version": "claims/1",
        "functions": {
            "pause()": _effect(
                "pause()",
                state_changing=True,
                claims=[
                    {
                        "claim_id": "pause.set",
                        "tier": "idiom_structural",
                        "witness": {
                            "kind": "pause_flag",
                            "flags": [{"var": "paused", "member": None}],
                            "polarity": "set",
                        },
                    }
                ],
            ),
            "withdraw()": _effect("withdraw()", state_changing=True),
            "paused()": _effect("paused()", state_changing=False),
        },
        "claim_analyses": {
            "pause.set": {
                "detector": "pause.set",
                "status": "completed",
                "targets_total": 3,
                "targets_completed": 3,
                "omissions": [],
            }
        },
        "claim_diagnostics": [],
    }
    trees = {
        "schema_version": "semantic",
        "trees": {
            "withdraw()": {
                "op": "LEAF",
                "leaf": {
                    "operands": [{"source": "state_variable", "state_variable_name": "paused"}],
                },
            },
            "paused()": {
                "op": "LEAF",
                "leaf": {
                    "operands": [{"source": "state_variable", "state_variable_name": "paused"}],
                },
            },
        },
    }
    return analysis, effects, trees


def test_pause_claim_has_first_class_evidence_and_state_changing_victim() -> None:
    analysis, effects, trees = _pause_inputs()
    assessment = build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts=analysis,
        effects=effects,
        predicate_trees=trees,
    )

    TypeAdapter(Assessment).validate_python(assessment)
    assert len(assessment["claims"]) == 1
    claim = next(iter(assessment["claims"].values()))
    proposition = claim["proposition"]
    assert proposition["kind"] == "function_effect"
    effect = proposition.get("effect")
    assert effect is not None
    assert effect["kind"] == "pause.set"
    assert effect["affected_functions"] == ["withdraw()"]
    assert len(claim["evidence"]) == 1
    assert claim["evidence"][0] in assessment["evidence"]
    assert next(item for item in assessment["analyses"] if item["detector"] == "pause.set")["status"] == "completed"
    assert effect_presence(assessment, "pause.set") is True


def test_static_assessment_ids_are_deterministic() -> None:
    analysis, effects, trees = _pause_inputs()
    kwargs = {
        "chain_id": 1,
        "address": "0x1111111111111111111111111111111111111111",
        "contract_name": "Vault",
        "code_hash": None,
        "source_hash": "0xsource",
        "static_facts": analysis,
        "effects": effects,
        "predicate_trees": trees,
    }
    assert build_static_assessment(**kwargs) == build_static_assessment(**kwargs)


def test_static_inputs_are_embedded_in_assessment_evidence() -> None:
    static_facts, effects, predicate_trees = _pause_inputs()
    assessment = build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts=static_facts,
        effects=effects,
        predicate_trees=predicate_trees,
    )

    assert static_inputs(assessment) == (static_facts, predicate_trees, effects)


def test_matcher_failure_is_an_analysis_diagnostic_not_a_claim() -> None:
    analysis, effects, trees = _pause_inputs()
    effects["functions"]["pause()"]["claims"] = []
    effects["claim_analyses"]["pause.set"] = {
        "detector": "pause.set",
        "status": "failed",
        "targets_total": 3,
        "targets_completed": 0,
        "omissions": [{"function": "pause()", "reason": "matcher_trigger_failed"}],
    }
    effects["claim_diagnostics"] = [
        {
            "claim_id": "pause.set",
            "function": "pause()",
            "exc_type": "RuntimeError",
            "message": "predicate lowering failed",
        }
    ]

    assessment = build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts=analysis,
        effects=effects,
        predicate_trees=trees,
    )

    assert assessment["claims"] == {}
    receipt = next(item for item in assessment["analyses"] if item["detector"] == "pause.set")
    assert receipt["status"] == "failed"
    assert receipt["diagnostics"][0]["code"] == "RuntimeError"
    assert effect_presence(assessment, "pause.set") is None


def test_complete_empty_detector_projects_false() -> None:
    analysis, effects, trees = _pause_inputs()
    effects["functions"]["pause()"]["claims"] = []
    assessment = build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts=analysis,
        effects=effects,
        predicate_trees=trees,
    )
    assert effect_presence(assessment, "pause.set") is False
