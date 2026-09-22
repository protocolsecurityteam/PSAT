"""The canonical public Assessment view over immutable temporal records."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from schemas.temporal_assessment import TemporalAssessmentDict

Assessment = TemporalAssessmentDict


def assessment_problems(assessment: Assessment) -> list[str]:
    """Check row identities and references in a public Assessment view."""
    problems: list[str] = []
    if "schema_version" in assessment:
        problems.append("schema_version: compact assessment version is not public")
    for collection in (
        "subjects",
        "evidence",
        "claims",
        "analyses",
        "corrections",
        "contexts",
        "implementations",
        "payloads",
    ):
        seen: set[str] = set()
        for row in assessment[collection]:
            identifier = row["id"]
            if not identifier:
                problems.append(f"{collection}.id: identity is empty")
            if identifier in seen:
                problems.append(f"{collection}.{identifier}: duplicate identity")
            seen.add(identifier)
    subjects = {row["id"] for row in assessment["subjects"]}
    payloads = {row["id"] for row in assessment["payloads"]}
    evidence = {row["id"] for row in assessment["evidence"]}
    claims = {row["id"] for row in assessment["claims"]}
    contexts = {row["id"] for row in assessment["contexts"]}
    implementations = {row["id"] for row in assessment["implementations"]}
    analyses = {row["id"] for row in assessment["analyses"]}

    def subject_references(value: Any) -> set[str]:
        if isinstance(value, str):
            return {value} if value.startswith("subject:") else set()
        if isinstance(value, Mapping):
            return {ref for item in value.values() for ref in subject_references(item)}
        if isinstance(value, list):
            return {ref for item in value for ref in subject_references(item)}
        return set()

    for row in assessment["subjects"]:
        for reference in subject_references(row["identity"]):
            if reference not in subjects:
                problems.append(f"subjects.{row['id']}.identity: {reference} is missing")
    for row in assessment["evidence"]:
        if row["subject"] not in subjects:
            problems.append(f"evidence.{row['id']}.subject: subject is missing")
        if row["payload"] not in payloads:
            problems.append(f"evidence.{row['id']}.payload: payload is missing")
    for row in assessment["claims"]:
        if row["subject"] not in subjects:
            problems.append(f"claims.{row['id']}.subject: subject is missing")
        for evidence_id in row["evidence"]:
            if evidence_id not in evidence:
                problems.append(f"claims.{row['id']}.evidence: {evidence_id} is missing")
        for claim_id in row["claims"]:
            if claim_id not in claims:
                problems.append(f"claims.{row['id']}.claims: {claim_id} is missing")
        for reference in subject_references(row["proposition"]):
            if reference not in subjects:
                problems.append(f"claims.{row['id']}.proposition: {reference} is missing")
    for row in assessment["analyses"]:
        if row["context"] not in contexts:
            problems.append(f"analyses.{row['id']}.context: context is missing")
        if row["implementation"] not in implementations:
            problems.append(f"analyses.{row['id']}.implementation: implementation is missing")
    for row in assessment["corrections"]:
        if row["analysis"] not in analyses:
            problems.append(f"corrections.{row['id']}.analysis: analysis is missing")
    return problems


__all__ = ["Assessment", "assessment_problems"]
