"""Typed governance, configuration, and scenario publications."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypedDict

from sqlalchemy.orm import Session

from schemas.temporal_assessment import (
    ActionKind,
    AnalysisProducer,
    BindingPhase,
    ClaimKind,
    ClockKind,
    ConfigurationParameter,
    DerivationRule,
    EvidenceKind,
    ProposalState,
    ScopeKind,
    SubjectKind,
    SubjectRole,
)
from services.assessment.repository import publish_scoped_claim


class ChainPoint(TypedDict):
    chain_id: int
    block_number: int
    block_hash: str


def _point_scope(point: ChainPoint) -> dict[str, Any]:
    block_hash = point["block_hash"].lower()
    if not block_hash.startswith("0x") or len(block_hash) != 66:
        raise ValueError("an exact governance update requires a 32-byte block hash")
    if point["chain_id"] <= 0 or point["block_number"] < 0:
        raise ValueError("invalid chain point")
    return {
        "kind": ScopeKind.point.value,
        "at": {
            "chain_id": point["chain_id"],
            "block_number": str(point["block_number"]),
            "block_hash": block_hash,
        },
    }


def record_configuration(
    session: Session,
    job_id: Any,
    *,
    contract_address: str,
    point: ChainPoint,
    parameter: ConfigurationParameter,
    value: Any,
    unit: str | None,
    clock: ClockKind | None,
    source: Mapping[str, Any],
    implementation: Mapping[str, Any],
) -> str:
    """Append a point-in-time configuration value; prior values remain."""
    scope = _point_scope(point)
    _publication, _evidence, claim, _context = publish_scoped_claim(
        session,
        job_id,
        producer=AnalysisProducer.governance,
        subject_kind=SubjectKind.address,
        subject_identity={"chain_id": point["chain_id"], "address": contract_address.lower()},
        subject_role=SubjectRole.entity,
        natural_key=f"configuration:{parameter.value}",
        evidence_kind=EvidenceKind.chain_read,
        evidence_payload={
            "parameter": parameter.value,
            "value": value,
            "unit": unit,
            "clock": clock.value if clock is not None else None,
        },
        evidence_source={"kind": EvidenceKind.chain_read.value, **dict(source)},
        claim_kind=ClaimKind.configuration,
        proposition={
            "kind": ClaimKind.configuration.value,
            "parameter": parameter.value,
            "value": value,
            "unit": unit,
            "clock": clock.value if clock is not None else None,
        },
        scope_kind=ScopeKind.point,
        scope=scope,
        rule=DerivationRule.configuration,
        implementation=implementation,
    )
    return claim


def record_proposal_state(
    session: Session,
    job_id: Any,
    *,
    governor_address: str,
    proposal_id: str,
    point: ChainPoint,
    state: ProposalState,
    source: Mapping[str, Any],
    implementation: Mapping[str, Any],
) -> str:
    scope = _point_scope(point)
    _publication, _evidence, claim, _context = publish_scoped_claim(
        session,
        job_id,
        producer=AnalysisProducer.governance,
        subject_kind=SubjectKind.proposal,
        subject_identity={
            "chain_id": point["chain_id"],
            "governor": governor_address.lower(),
            "proposal_id": str(proposal_id),
        },
        subject_role=SubjectRole.proposal,
        natural_key=f"proposal:{governor_address.lower()}:{proposal_id}",
        evidence_kind=EvidenceKind.chain_read,
        evidence_payload={"state": state.value},
        evidence_source={"kind": EvidenceKind.chain_read.value, **dict(source)},
        claim_kind=ClaimKind.proposal_state,
        proposition={"kind": ClaimKind.proposal_state.value, "state": state.value},
        scope_kind=ScopeKind.point,
        scope=scope,
        rule=DerivationRule.proposal_state,
        implementation=implementation,
    )
    return claim


def record_applied_configuration(
    session: Session,
    job_id: Any,
    *,
    governor_address: str,
    proposal_id: str,
    point: ChainPoint,
    phase: BindingPhase,
    configuration_claim: str,
    source: Mapping[str, Any],
    implementation: Mapping[str, Any],
) -> str:
    """Bind a proposal phase to the exact configuration claim it consulted."""
    scope = _point_scope(point)
    _publication, _evidence, claim, _context = publish_scoped_claim(
        session,
        job_id,
        producer=AnalysisProducer.governance,
        subject_kind=SubjectKind.proposal,
        subject_identity={
            "chain_id": point["chain_id"],
            "governor": governor_address.lower(),
            "proposal_id": str(proposal_id),
        },
        subject_role=SubjectRole.proposal,
        natural_key=f"proposal:{governor_address.lower()}:{proposal_id}:binding:{phase.value}",
        evidence_kind=EvidenceKind.chain_read,
        evidence_payload={"phase": phase.value, "configuration_claim": configuration_claim},
        evidence_source={"kind": EvidenceKind.chain_read.value, **dict(source)},
        claim_kind=ClaimKind.applied_configuration,
        proposition={
            "kind": ClaimKind.applied_configuration.value,
            "phase": phase.value,
            "configuration": configuration_claim,
        },
        scope_kind=ScopeKind.point,
        scope=scope,
        rule=DerivationRule.applied_configuration,
        implementation=implementation,
        prerequisite_claims=[configuration_claim],
    )
    return claim


def record_scenario_configuration(
    session: Session,
    job_id: Any,
    *,
    contract_address: str,
    baseline: ChainPoint,
    step: int,
    parameter: ConfigurationParameter,
    value: Any,
    unit: str | None,
    actions: Sequence[Mapping[str, Any]],
    assumptions: Sequence[Mapping[str, Any]],
    prerequisite_claims: list[str],
    implementation: Mapping[str, Any],
) -> tuple[str, str]:
    """Publish a hypothetical update without making it observed current state."""
    if step < 1 or step > len(actions):
        raise ValueError("scenario step must identify an executed action")
    normalized_actions: list[dict[str, Any]] = []
    for action in actions:
        raw_kind = action.get("kind")
        kind = raw_kind if isinstance(raw_kind, ActionKind) else ActionKind(str(raw_kind))
        normalized_actions.append({**dict(action), "kind": kind.value})
    context = {
        "kind": "scenario",
        "base": _point_scope(baseline)["at"],
        "actions": normalized_actions,
        "assumptions": [dict(item) for item in assumptions],
    }
    scope = {"kind": ScopeKind.scenario.value, "step": step}
    _publication, _evidence, claim, context_id = publish_scoped_claim(
        session,
        job_id,
        producer=AnalysisProducer.scenario,
        subject_kind=SubjectKind.address,
        subject_identity={"chain_id": baseline["chain_id"], "address": contract_address.lower()},
        subject_role=SubjectRole.entity,
        natural_key=f"scenario:configuration:{parameter.value}:step:{step}",
        evidence_kind=EvidenceKind.execution,
        evidence_payload={"parameter": parameter.value, "value": value, "unit": unit, "step": step},
        evidence_source={"kind": EvidenceKind.execution.value, "environment": "fork", "step": step},
        claim_kind=ClaimKind.configuration,
        proposition={
            "kind": ClaimKind.configuration.value,
            "parameter": parameter.value,
            "value": value,
            "unit": unit,
        },
        scope_kind=ScopeKind.scenario,
        scope=scope,
        rule=DerivationRule.scenario_transition,
        implementation=implementation,
        context=context,
        prerequisite_claims=prerequisite_claims,
    )
    return claim, context_id


__all__ = [
    "ChainPoint",
    "record_applied_configuration",
    "record_configuration",
    "record_proposal_state",
    "record_scenario_configuration",
]
