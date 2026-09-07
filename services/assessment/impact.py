"""Proposal/scenario comparison views derived only from temporal Assessment."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sqlalchemy.orm import Session

from db.models import Job
from services.assessment.repository import load_temporal_assessment, publication_history


def _block_number(claim: Mapping[str, Any]) -> int:
    at = claim.get("scope", {}).get("at", {})
    try:
        return int(at.get("block_number", -1))
    except (TypeError, ValueError):
        return -1


def _config_key(claim: Mapping[str, Any]) -> tuple[str, str]:
    return (str(claim.get("subject") or ""), str(claim.get("proposition", {}).get("parameter") or ""))


def _subject_label(subjects: Mapping[str, Mapping[str, Any]], subject_id: str) -> str:
    identity = subjects.get(subject_id, {}).get("identity", {})
    return str(identity.get("address") or identity.get("proposal_id") or identity.get("operation_id") or subject_id)


def _proof(
    claim: Mapping[str, Any],
    claims: Mapping[str, Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "claim": {
            "id": claim["id"],
            "kind": claim["kind"].value,
            "scope": claim["scope"],
            "proposition": claim["proposition"],
        },
        "evidence": [
            {
                "id": evidence_id,
                "kind": evidence[evidence_id]["kind"].value,
                "source": evidence[evidence_id]["source"],
                "block_number": evidence[evidence_id]["block_number"],
                "block_hash": evidence[evidence_id]["block_hash"],
            }
            for evidence_id in claim["evidence"]
            if evidence_id in evidence
        ],
        "prerequisites": [
            {
                "id": claim_id,
                "kind": claims[claim_id]["kind"].value,
                "scope": claims[claim_id]["scope"],
                "proposition": claims[claim_id]["proposition"],
            }
            for claim_id in claim["claims"]
            if claim_id in claims
        ],
    }


def _downstream(root: str, claims: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    reached = {root}
    changed = True
    while changed:
        changed = False
        for claim in claims.values():
            if claim["id"] in reached or not reached.intersection(claim["claims"]):
                continue
            reached.add(claim["id"])
            found.append(
                {
                    "id": claim["id"],
                    "kind": claim["kind"].value,
                    "proposition": claim["proposition"],
                    "scope": claim["scope"],
                }
            )
            changed = True
    return found


def build_proposal_impact(session: Session, company: str, jobs: list[Job]) -> dict[str, Any]:
    """Build table-ready observed/proposal/scenario rows for one protocol."""
    proposals: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    limitations: list[dict[str, Any]] = []
    context_seen: set[str] = set()
    for job in jobs:
        observed = load_temporal_assessment(session, job.id)
        if observed is None:
            continue
        subjects = {row["id"]: row for row in observed["subjects"]}
        evidence_by_id = {row["id"]: row for row in observed["evidence"]}
        claims_by_id = {row["id"]: row for row in observed["claims"]}
        observed_configs = [row for row in observed["claims"] if row["kind"].value == "configuration"]
        current_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
        for claim in sorted(observed_configs, key=_block_number):
            current_by_key[_config_key(claim)] = claim
        for claim in observed["claims"]:
            if claim["kind"].value not in {
                "proposal_contents",
                "proposal_state",
                "proposal_timing",
                "proposal_quorum",
                "applied_configuration",
                "operation_state",
                "operation_timing",
            }:
                continue
            proposals.append(
                {
                    "job_id": str(job.id),
                    "run_name": job.name or str(job.id),
                    "claim_id": claim["id"],
                    "subject": _subject_label(subjects, claim["subject"]),
                    "kind": claim["kind"].value,
                    "proposition": claim["proposition"],
                    "scope": claim["scope"],
                    "evidence": claim["evidence"],
                    "prerequisites": claim["claims"],
                    "proof": _proof(claim, claims_by_id, evidence_by_id),
                }
            )
        for analysis in observed["analyses"]:
            for diagnostic in analysis["diagnostics"]:
                if analysis["producer"].value == "governance":
                    limitations.append(
                        {
                            "job_id": str(job.id),
                            "code": diagnostic["code"].value,
                            "message": diagnostic["message"],
                        }
                    )

        histories = publication_history(session, job.id)
        for publication in histories:
            if publication["context_kind"] != "scenario" or publication["context"] in context_seen:
                continue
            context_id = publication["context"]
            context_seen.add(context_id)
            scenario = load_temporal_assessment(session, job.id, context_id=context_id)
            if scenario is None:
                continue
            scenario_subjects = {row["id"]: row for row in scenario["subjects"]}
            scenario_evidence = {row["id"]: row for row in scenario["evidence"]}
            scenario_claims = {row["id"]: row for row in scenario["claims"]}
            context = next((row["context"] for row in scenario["contexts"] if row["id"] == context_id), {})
            for claim in scenario["claims"]:
                if claim["scope_kind"].value != "scenario" or claim["kind"].value != "configuration":
                    continue
                before = current_by_key.get(_config_key(claim))
                proposition = claim["proposition"]
                changes.append(
                    {
                        "job_id": str(job.id),
                        "run_name": job.name or str(job.id),
                        "context_id": context_id,
                        "step": claim["scope"].get("step"),
                        "subject": _subject_label(scenario_subjects, claim["subject"]),
                        "parameter": proposition.get("parameter"),
                        "before": before["proposition"].get("value") if before else None,
                        "after": proposition.get("value"),
                        "unit": proposition.get("unit") or (before or {}).get("proposition", {}).get("unit"),
                        "claim_id": claim["id"],
                        "evidence": claim["evidence"],
                        "prerequisites": claim["claims"],
                        "baseline": context.get("base"),
                        "actions": context.get("actions") or [],
                        "assumptions": context.get("assumptions") or [],
                        "proof": _proof(claim, scenario_claims, scenario_evidence),
                        "downstream": _downstream(claim["id"], scenario_claims),
                    }
                )
    proposals.sort(key=lambda row: (row["subject"], row["kind"], row["claim_id"]))
    changes.sort(key=lambda row: (row["context_id"], int(row["step"] or 0), row["subject"], row["parameter"]))
    return {
        "company": company,
        "data_origin": "canonical_assessment",
        "proposals": proposals,
        "changes": changes,
        "limitations": limitations,
    }


__all__ = ["build_proposal_impact"]
