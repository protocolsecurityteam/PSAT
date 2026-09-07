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

    shared_evidence = {key for analysis in other_receipts for key in analysis["evidence"]}
    withdrawn_evidence = owned_evidence - shared_evidence
    for claim in assessment["claims"].values():
        claim["evidence"] = [key for key in claim["evidence"] if key not in withdrawn_evidence]

    removed: set[str] = set()
    for key in owned_claims - shared_claims:
        claim = assessment["claims"].get(key)
        if claim is not None and not claim["evidence"]:
            assessment["claims"].pop(key, None)
            removed.add(key)

    # A derivation requires all of its premises. Retract dependents transitively
    # instead of silently changing their rule by dropping a premise.
    while True:
        dependents = {key for key, claim in assessment["claims"].items() if removed.intersection(claim["claims"])}
        if not dependents:
            break
        for key in dependents:
            assessment["claims"].pop(key)
        removed.update(dependents)
    for receipt in other_receipts:
        if removed.intersection(receipt["claims"]):
            receipt["claims"] = [key for key in receipt["claims"] if key not in removed]
            receipt["status"] = "partial"
            receipt["targets_completed"] = 0
            receipt["omissions"].append(
                {
                    "target_kind": "contract",
                    "target": assessment["contract"]["deployment_address"],
                    "reason": "prerequisite_claim_withdrawn",
                }
            )

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
