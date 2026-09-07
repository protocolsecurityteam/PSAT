"""Governance updates and scenarios share the temporal Assessment ledger."""

from __future__ import annotations

from sqlalchemy import func, select

from db.models import AssessmentAnalysis, AssessmentAnalysisOutput, AssessmentClaimEvidence
from db.queue import store_artifact
from schemas.temporal_assessment import (
    BindingPhase,
    ConfigurationParameter,
    CorrectionReason,
    CorrectionTargetKind,
)
from services.assessment.governance import (
    ChainPoint,
    record_applied_configuration,
    record_configuration,
    record_scenario_configuration,
)
from services.assessment.impact import build_proposal_impact
from services.assessment.repository import load_temporal_assessment, record_correction
from tests.assessment.test_temporal_repository import ADDRESS, _assessment, _job
from tests.conftest import requires_postgres


def _point(block: int) -> ChainPoint:
    return {"chain_id": 1, "block_number": block, "block_hash": "0x" + f"{block:064x}"}


@requires_postgres
def test_configuration_update_and_proposal_binding_preserve_the_consulted_value(db_session):
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment("0x" + "aa" * 20, 90))
    old_delay = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point=_point(100),
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"adapter": "openzeppelin_timelock"},
    )
    binding = record_applied_configuration(
        db_session,
        job.id,
        governor_address=ADDRESS,
        proposal_id="7",
        point=_point(150),
        phase=BindingPhase.schedule,
        configuration_claim=old_delay,
        source={"method": "hashOperation"},
        implementation={"adapter": "openzeppelin_timelock"},
    )
    new_delay = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point=_point(200),
        parameter=ConfigurationParameter.minimum_delay,
        value="21600",
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"adapter": "openzeppelin_timelock"},
    )
    db_session.commit()

    current = load_temporal_assessment(db_session, job.id)
    at_150 = load_temporal_assessment(db_session, job.id, at_block=150)
    assert current is not None and at_150 is not None
    by_id = {claim["id"]: claim for claim in current["claims"]}
    assert old_delay in by_id and new_delay in by_id and binding in by_id
    assert by_id[binding]["claims"] == [old_delay]
    assert by_id[old_delay]["proposition"]["value"] == "172800"
    assert by_id[new_delay]["proposition"]["value"] == "21600"
    assert new_delay not in {claim["id"] for claim in at_150["claims"]}


@requires_postgres
def test_scenario_update_is_reusable_and_never_becomes_observed_current(db_session):
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment("0x" + "aa" * 20, 90))
    baseline = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point=_point(100),
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"adapter": "openzeppelin_timelock"},
    )
    action = {
        "kind": "call",
        "chain_id": 1,
        "sender": "0x" + "bb" * 20,
        "target": ADDRESS,
        "calldata": "0x",
        "value": "0",
    }
    first_claim, context_id = record_scenario_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        baseline=_point(100),
        step=1,
        parameter=ConfigurationParameter.minimum_delay,
        value="21600",
        unit="seconds",
        actions=[action],
        assumptions=[],
        prerequisite_claims=[baseline],
        implementation={"engine": "anvil", "mode": "fork"},
    )
    analyses_before = db_session.scalar(select(func.count()).select_from(AssessmentAnalysis))
    outputs_before = db_session.scalar(select(func.count()).select_from(AssessmentAnalysisOutput))
    second_claim, second_context = record_scenario_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        baseline=_point(100),
        step=1,
        parameter=ConfigurationParameter.minimum_delay,
        value="21600",
        unit="seconds",
        actions=[action],
        assumptions=[],
        prerequisite_claims=[baseline],
        implementation={"engine": "anvil", "mode": "fork"},
    )
    db_session.commit()

    observed = load_temporal_assessment(db_session, job.id)
    scenario = load_temporal_assessment(db_session, job.id, context_id=context_id)
    assert observed is not None and scenario is not None
    assert first_claim == second_claim
    assert context_id == second_context
    assert first_claim not in {claim["id"] for claim in observed["claims"]}
    assert first_claim in {claim["id"] for claim in scenario["claims"]}
    scenario_claim = next(claim for claim in scenario["claims"] if claim["id"] == first_claim)
    assert scenario_claim["scope"] == {"kind": "scenario", "context": context_id, "step": 1}
    assert db_session.scalar(select(func.count()).select_from(AssessmentAnalysis)) == analyses_before + 1
    assert db_session.scalar(select(func.count()).select_from(AssessmentAnalysisOutput)) == outputs_before + 1


@requires_postgres
def test_correction_of_one_proof_preserves_an_independent_proof(db_session):
    job = _job(db_session)
    store_artifact(db_session, job.id, "assessment", data=_assessment("0x" + "aa" * 20, 90))
    first = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point=_point(100),
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "storage", "slot": "0x01"},
        implementation={"adapter": "openzeppelin_timelock"},
    )
    second = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point=_point(100),
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "getter", "selector": "0xf27a0c92"},
        implementation={"adapter": "openzeppelin_timelock"},
    )
    first_evidence = db_session.scalar(
        select(AssessmentClaimEvidence.evidence_id).where(AssessmentClaimEvidence.claim_id == first)
    )
    assert first_evidence is not None and first != second
    record_correction(
        db_session,
        job.id,
        target_kind=CorrectionTargetKind.evidence,
        target_id=first_evidence,
        reason=CorrectionReason.invalid_observation,
    )
    db_session.commit()

    current = load_temporal_assessment(db_session, job.id)
    assert current is not None
    eligible = {claim["id"] for claim in current["claims"]}
    assert first not in eligible
    assert second in eligible


@requires_postgres
def test_proposal_impact_projects_current_to_scenario_delta(db_session):
    job = _job(db_session)
    job.company = "example"
    store_artifact(db_session, job.id, "assessment", data=_assessment("0x" + "aa" * 20, 90))
    baseline = record_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        point=_point(100),
        parameter=ConfigurationParameter.minimum_delay,
        value="172800",
        unit="seconds",
        clock=None,
        source={"method": "getMinDelay"},
        implementation={"adapter": "openzeppelin_timelock"},
    )
    record_scenario_configuration(
        db_session,
        job.id,
        contract_address=ADDRESS,
        baseline=_point(100),
        step=1,
        parameter=ConfigurationParameter.minimum_delay,
        value="21600",
        unit="seconds",
        actions=[{"kind": "call", "target": ADDRESS, "calldata": "0x", "sender": ADDRESS, "value": "0"}],
        assumptions=[],
        prerequisite_claims=[baseline],
        implementation={"engine": "anvil"},
    )
    db_session.commit()

    impact = build_proposal_impact(db_session, "example", [job])
    assert impact["changes"][0]["before"] == "172800"
    assert impact["changes"][0]["after"] == "21600"
    assert impact["changes"][0]["prerequisites"] == [baseline]
