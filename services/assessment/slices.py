"""Atomic ownership helpers for replaceable Assessment stages."""

from __future__ import annotations

from collections.abc import Mapping

from schemas.assessment import Assessment


def remove_analysis_slice(assessment: Assessment, detector: str) -> None:
    """Remove the claim/evidence outputs owned by an earlier detector run."""

    prior = [analysis for analysis in assessment["analyses"] if analysis["detector"] == detector]
    if not prior:
        return

    owned_claims = {key for analysis in prior for key in analysis["claims"]}
    owned_evidence = {key for analysis in prior for key in analysis["evidence"]}
    other_receipts = [analysis for analysis in assessment["analyses"] if analysis["detector"] != detector]
    shared_claims = {key for analysis in other_receipts for key in analysis["claims"]}

    for claim in assessment["claims"].values():
        claim["evidence"] = [key for key in claim["evidence"] if key not in owned_evidence]
        claim["claims"] = [key for key in claim["claims"] if key not in owned_claims]

    for key in owned_claims - shared_claims:
        claim = assessment["claims"].get(key)
        if claim is not None and not claim["evidence"]:
            assessment["claims"].pop(key, None)

    referenced_evidence = {key for claim in assessment["claims"].values() for key in claim["evidence"]}
    referenced_evidence.update(key for analysis in other_receipts for key in analysis["evidence"])
    for key in owned_evidence - referenced_evidence:
        assessment["evidence"].pop(key, None)

    assessment["analyses"] = other_receipts


def prune_unreferenced_entities(assessment: Assessment) -> None:
    """Remove entities no current claim or evidence names."""

    contract = assessment["contract"]
    root_addresses = {contract["address"], contract["deployment_address"]}
    referenced = {key for key, entity in assessment["entities"].items() if entity["address"] in root_addresses}

    def add_authority(authority: object) -> None:
        if not isinstance(authority, Mapping):
            return
        kind = authority.get("kind")
        if kind == "entity" and isinstance(authority.get("entity"), str):
            referenced.add(str(authority["entity"]))
        elif kind == "role" and isinstance(authority.get("entities"), list):
            referenced.update(str(key) for key in authority["entities"])
        elif kind in ("any", "all") and isinstance(authority.get("children"), list):
            for child in authority["children"]:
                add_authority(child)

    for claim in assessment["claims"].values():
        proposition = claim["proposition"]
        kind = proposition["kind"]
        if kind == "entity_classification" and isinstance((entity := proposition.get("entity")), str):
            referenced.add(entity)
        elif kind == "authority_relationship":
            target = proposition.get("target")
            if isinstance(target, str):
                referenced.add(target)
            add_authority(proposition.get("authority"))
        elif kind in ("function_authority", "authority_capability"):
            add_authority(proposition.get("authority"))
    for evidence in assessment["evidence"].values():
        if evidence["subject_kind"] == "entity":
            referenced.add(evidence["subject"])

    assessment["entities"] = {key: entity for key, entity in assessment["entities"].items() if key in referenced}


__all__ = ["prune_unreferenced_entities", "remove_analysis_slice"]
