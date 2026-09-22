"""Proposal/scenario comparison views derived only from temporal Assessment."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AssessmentPayload, Job
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
    payloads: Mapping[str, Mapping[str, Any]],
    remaining_payload_bytes: list[int] | None = None,
) -> dict[str, Any]:
    # A publication is the eligibility boundary. In particular, a corrected
    # prerequisite absent from this projection must never look like a leaf.
    issues: list[str] = []
    if remaining_payload_bytes is None:
        remaining_payload_bytes = [512 * 1024]
    expanded = 0
    max_claims = 128
    max_depth = 16

    def walk(row: Mapping[str, Any], path: frozenset[str], depth: int) -> dict[str, Any]:
        nonlocal expanded
        claim_id = row["id"]
        expanded += 1
        node: dict[str, Any] = {
            "id": claim_id,
            "kind": row["kind"].value,
            "scope": row["scope"],
            "proposition": row["proposition"],
            "evidence": [],
            "prerequisites": [],
        }
        if not row["evidence"] and not row["claims"]:
            issues.append(f"Claim {claim_id} has no linked evidence or prerequisites")
        for evidence_id in row["evidence"]:
            item = evidence.get(evidence_id)
            if item is None:
                issues.append(f"Evidence {evidence_id} is unavailable in this publication")
                node["evidence"].append({"id": evidence_id, "unavailable": "not in publication"})
                continue
            payload_id = item["payload"]
            payload = payloads.get(payload_id)
            if payload is None:
                issues.append(f"Payload {payload_id} is unavailable")
                payload_view: dict[str, Any] = {"id": payload_id, "unavailable": "not found"}
            else:
                payload_view = dict(payload)
                if "unavailable" in payload_view:
                    issues.append(f"Payload {payload_id} is unavailable: {payload_view['unavailable']}")
                elif payload_view.get("byte_length", 0) > remaining_payload_bytes[0]:
                    payload_view.pop("data", None)
                    payload_view["unavailable"] = "response payload limit reached"
                    issues.append(f"Payload {payload_id} is unavailable: response payload limit reached")
                else:
                    remaining_payload_bytes[0] -= payload_view.get("byte_length", 0)
            node["evidence"].append(
                {
                    "id": evidence_id,
                    "kind": item["kind"].value,
                    "source": item["source"],
                    "block_number": item["block_number"],
                    "block_hash": item["block_hash"],
                    "transaction_hash": item["transaction_hash"],
                    "log_index": item["log_index"],
                    "payload": payload_view,
                }
            )
        for prerequisite_id in row["claims"]:
            if prerequisite_id in path or prerequisite_id == claim_id:
                issues.append(f"Prerequisite cycle at {prerequisite_id}")
                node["prerequisites"].append({"id": prerequisite_id, "unavailable": "cycle"})
            elif prerequisite_id not in claims:
                issues.append(f"Prerequisite {prerequisite_id} is unavailable or correction-ineligible")
                node["prerequisites"].append({"id": prerequisite_id, "unavailable": "not eligible in publication"})
            elif depth >= max_depth or expanded >= max_claims:
                issues.append(f"Prerequisite expansion limit reached at {prerequisite_id}")
                node["prerequisites"].append({"id": prerequisite_id, "unavailable": "expansion limit"})
            else:
                node["prerequisites"].append(walk(claims[prerequisite_id], path | {claim_id}, depth + 1))
        return node

    root = walk(claim, frozenset(), 0)
    return {
        "claim": {key: root[key] for key in ("id", "kind", "scope", "proposition")},
        "evidence": root["evidence"],
        "prerequisites": root["prerequisites"],
        "complete": not issues,
        "issues": issues,
    }


def _payload_views(
    session: Session,
    assessment: Mapping[str, Any],
    cache: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    candidates = [
        row["id"] for row in assessment["payloads"] if row["id"] not in cache and row["byte_length"] <= 32 * 1024
    ]
    fetched = (
        {
            row.id: row
            for row in session.execute(select(AssessmentPayload).where(AssessmentPayload.id.in_(candidates))).scalars()
        }
        if candidates
        else {}
    )
    for metadata in assessment["payloads"]:
        payload_id = metadata["id"]
        if payload_id in cache:
            result[payload_id] = cache[payload_id]
            continue
        view = dict(metadata)
        row = fetched.get(payload_id)
        if metadata["byte_length"] > 32 * 1024:
            view["unavailable"] = "exceeds 32 KiB inline proof limit"
        elif row is None:
            view["unavailable"] = "not found"
        elif row.media_type == "application/json":
            try:
                view["data"] = json.loads(row.data)
            except (UnicodeDecodeError, ValueError):
                view["unavailable"] = "invalid JSON"
        else:
            view["unavailable"] = f"unsupported media type {row.media_type}"
        result[payload_id] = view
        cache[payload_id] = view
    return result


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
    context_seen: set[tuple[Any, str]] = set()
    payload_cache: dict[str, dict[str, Any]] = {}
    remaining_payload_bytes = [512 * 1024]
    for job in jobs:
        observed = load_temporal_assessment(session, job.id)
        if observed is None:
            continue
        subjects = {row["id"]: row for row in observed["subjects"]}
        evidence_by_id = {row["id"]: row for row in observed["evidence"]}
        claims_by_id = {row["id"]: row for row in observed["claims"]}
        payloads_by_id = _payload_views(session, observed, payload_cache)
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
                    "proof": _proof(claim, claims_by_id, evidence_by_id, payloads_by_id, remaining_payload_bytes),
                }
            )
        for analysis in observed["analyses"]:
            for diagnostic in analysis["diagnostics"]:
                if analysis["producer"].value in {"governance", "scenario"}:
                    limitations.append(
                        {
                            "job_id": str(job.id),
                            "code": diagnostic["code"].value,
                            "message": diagnostic["message"],
                        }
                    )

        histories = publication_history(session, job.id)
        for publication in histories:
            if publication["context_kind"] != "scenario" or (job.id, publication["context"]) in context_seen:
                continue
            context_id = publication["context"]
            context_seen.add((job.id, context_id))
            scenario = load_temporal_assessment(session, job.id, context_id=context_id)
            if scenario is None:
                continue
            scenario_subjects = {row["id"]: row for row in scenario["subjects"]}
            scenario_evidence = {row["id"]: row for row in scenario["evidence"]}
            scenario_claims = {row["id"]: row for row in scenario["claims"]}
            scenario_payloads = _payload_views(session, scenario, payload_cache)
            baseline_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
            for baseline_claim in sorted(scenario["claims"], key=_block_number):
                if baseline_claim["kind"].value == "configuration" and baseline_claim["scope_kind"].value != "scenario":
                    baseline_by_key[_config_key(baseline_claim)] = baseline_claim
            context = next((row["context"] for row in scenario["contexts"] if row["id"] == context_id), {})
            for claim in scenario["claims"]:
                if claim["scope_kind"].value != "scenario" or claim["kind"].value != "configuration":
                    continue
                before = baseline_by_key.get(_config_key(claim))
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
                        "proof": _proof(
                            claim, scenario_claims, scenario_evidence, scenario_payloads, remaining_payload_bytes
                        ),
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
