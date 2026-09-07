"""Behavioral verdicts strengthen claims with execution evidence."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any, cast

from pydantic import TypeAdapter

from schemas.assessment import Assessment, assessment_problems
from services.assessment import add_effects, add_policy, build_static_assessment, effect_matches_by_function
from services.effects.config import EFFECT_CLASS_FREEZE_PAUSE, VERDICT_PROVEN, VERDICT_UNKNOWN
from tests.conftest import requires_postgres


def _base() -> Assessment:
    return build_static_assessment(
        chain_id=1,
        address="0x1111111111111111111111111111111111111111",
        contract_name="Vault",
        code_hash=None,
        source_hash="0xsource",
        static_facts={"controller_tracking": []},
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
    witness = {
        "observation": "executed",
        "pause_effective": verdict == VERDICT_PROVEN,
        "observed_blast_radius": ["withdraw()"] if verdict == VERDICT_PROVEN else [],
    }
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
        if claim["proposition"]["kind"] == "function_effect"
        and (effect := claim["proposition"].get("effect")) is not None
        and effect["kind"] == "pause.set"
    )
    methods = {assessment["evidence"][key]["method"] for key in pause_claim["evidence"]}
    assert methods == {"static_ir", "execution"}
    assert pause_claim["rule"] == "pause.set/behavioral_observed"
    projection = effect_matches_by_function(assessment)["pause()"][0]
    assert projection["witness"]["observed"]["observed_blast_radius"] == ["withdraw()"]


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
    assert receipt["omissions"][0]["reason"] == "pause_ineffective"


def test_failed_effect_refresh_retracts_execution_evidence_and_restores_static_basis() -> None:
    observed = add_effects(_base(), [_verdict(VERDICT_PROVEN)], signatures_by_function_row={42: "pause()"})
    refreshed = add_effects(
        observed,
        [_verdict(VERDICT_UNKNOWN, reason="pause_ineffective")],
        signatures_by_function_row={42: "pause()"},
    )
    pause_claim = next(
        claim
        for claim in refreshed["claims"].values()
        if claim["proposition"]["kind"] == "function_effect"
        and (effect := claim["proposition"].get("effect")) is not None
        and effect["kind"] == "pause.set"
    )
    assert pause_claim["rule"] == "pause.set/idiom_structural"
    assert {refreshed["evidence"][key]["method"] for key in pause_claim["evidence"]} == {"static_ir"}


def test_withdrawn_execution_retracts_dependent_capability() -> None:
    base = _base()
    base["claims"].clear()
    for receipt in base["analyses"]:
        receipt["claims"] = []
    observed = add_effects(base, [_verdict(VERDICT_PROVEN)], signatures_by_function_row={42: "pause()"})
    authorized = add_policy(
        observed,
        {
            "functions": [
                {
                    "function": "pause()",
                    "capability_expr": {"kind": "conditional_universal"},
                }
            ]
        },
        chain_id=1,
    )
    assert any(c["proposition"]["kind"] == "authority_capability" for c in authorized["claims"].values())
    refreshed = add_effects(authorized, [_verdict(VERDICT_UNKNOWN)], signatures_by_function_row={42: "pause()"})
    assert {c["proposition"]["kind"] for c in refreshed["claims"].values()} == {"function_authority"}
    assert assessment_problems(refreshed) == []


def test_execution_uses_canonical_function_identity() -> None:
    base = _base()
    identity = base["functions"].pop("pause()")
    identity["abi_signature"] = "pause(address)"
    base["functions"]["pause(Authority)"] = identity
    base["claims"].clear()
    for receipt in base["analyses"]:
        receipt["claims"] = []
    # Remove source-linked evidence for the original spelling in this fixture.
    base["evidence"] = {key: item for key, item in base["evidence"].items() if item["subject_kind"] != "function"}
    for receipt in base["analyses"]:
        receipt["evidence"] = [key for key in receipt["evidence"] if key in base["evidence"]]
    result = add_effects(base, [_verdict(VERDICT_PROVEN)], signatures_by_function_row={42: "pause(address)"})
    assert result["analyses"][-1]["omissions"] == []
    assert effect_matches_by_function(result)["pause(Authority)"][0]["claim_id"] == "pause.set"


@requires_postgres
def test_worker_refresh_preserves_other_functions_and_isolates_deployments(db_session) -> None:
    from db.models import Contract, EffectiveFunction, EffectVerdict, Job, JobStage, JobStatus
    from db.queue import get_artifact, store_artifact
    from workers.effects_worker import EffectsWorker

    address, other_deployment = "0x" + "1" * 40, "0x" + "2" * 40
    job = Job(id=uuid.uuid4(), address=address, chain_id=1, request={}, stage=JobStage.done, status=JobStatus.completed)
    db_session.add(job)
    db_session.flush()
    contract = Contract(address=address, chain="ethereum", job_id=job.id)
    db_session.add(contract)
    db_session.flush()
    rows = []
    for name, abi, selector, deployment in (
        ("pause", "pause(address)", "0x11111111", address),
        ("freeze", "freeze()", "0x22222222", address),
        ("pause", "pause(address)", "0x11111111", other_deployment),
    ):
        row = EffectiveFunction(
            contract_id=contract.id,
            function_name=name,
            abi_signature=abi,
            selector=selector,
            deployment_address=deployment,
            authority_public=False,
            claims=[],
        )
        db_session.add(row)
        db_session.flush()
        db_session.add(
            EffectVerdict(
                function_id=row.id,
                chain_id=1,
                contract_address=deployment,
                selector=selector,
                effect_class=EFFECT_CLASS_FREEZE_PAUSE,
                behavior_hash=f"test:{row.id}",
                verdict=VERDICT_PROVEN,
                tier="fork",
                witness={},
            )
        )
        rows.append(row)
    assessment = build_static_assessment(
        chain_id=1,
        address=address,
        contract_name="Vault",
        code_hash=None,
        source_hash=None,
        static_facts={"controller_tracking": []},
        predicate_trees={"trees": {}},
        effects={
            "functions": {
                "pause(Authority)": {
                    "abi_signature": "pause(address)",
                    "selector": "0x11111111",
                    "state_changing": True,
                },
                "freeze()": {"abi_signature": "freeze()", "selector": "0x22222222", "state_changing": True},
            }
        },
    )
    store_artifact(db_session, job.id, "assessment", data=assessment)
    db_session.commit()
    items = cast(Any, [SimpleNamespace(candidate=SimpleNamespace(function_id=rows[0].id))])
    assert EffectsWorker()._update_assessments(db_session, items) == 1
    result = get_artifact(db_session, job.id, "assessment")
    assert set(effect_matches_by_function(cast(Assessment, result))) == {"pause(Authority)", "freeze()"}
    assert rows[0].claims and rows[1].claims
    assert rows[2].claims == []
