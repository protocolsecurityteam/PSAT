"""Persist recursive resolution bundles inside the job's canonical Assessment."""

from __future__ import annotations

import copy
import logging
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.assessment import load_assessment, store_assessment
from db.models import Job
from db.queue import get_artifact, store_artifact
from schemas.assessment import ASSESSMENT_VERSION, Assessment, validate_assessment

logger = logging.getLogger(__name__)

# Retained for callers that use the vocabulary while migrating from recursive.*
# rows. No artifacts are stored under these names anymore.
ARTIFACT_KINDS: tuple[str, ...] = ("snapshot", "effective_permissions")
KEY_PREFIX = "recursive"


def artifact_key(address: str, kind: str) -> str:
    """Legacy deterministic key, retained only for parsing old references."""
    return f"{KEY_PREFIX}.{address.lower()}.{kind}"


def parse_key(name: str) -> tuple[str, str] | None:
    """Parse a legacy recursive artifact key."""
    if not name.startswith(f"{KEY_PREFIX}."):
        return None
    parts = name.split(".", 2)
    if len(parts) != 3:
        return None
    _, address, kind = parts
    return address, kind


def _child_assessment(bundle: Mapping[str, Any], existing: Assessment | None = None) -> Assessment:
    """Merge one recursive bundle without deleting omitted prior sections.

    The former per-kind artifact writer upserted only values present in a
    publication. A later partial bundle therefore left earlier snapshot or
    permission rows intact; the canonical child must preserve that behavior.
    """
    child: dict[str, Any] = (
        copy.deepcopy(dict(existing)) if existing is not None else {"schema_version": ASSESSMENT_VERSION}
    )
    sections = {
        "analysis": "contract_analysis",
        "tracking_plan": "control_tracking_plan",
        "snapshot": "control_snapshot",
        "predicate_trees": "predicate_trees",
        "effective_permissions": "effective_permissions",
    }
    for bundle_name, section_name in sections.items():
        payload = bundle.get(bundle_name)
        if isinstance(payload, dict):
            child[section_name] = copy.deepcopy(payload)
        elif bundle_name in ("analysis", "tracking_plan", "snapshot"):
            logger.warning("Recursive assessment section missing: kind=%s", bundle_name)
    return validate_assessment(child)


def store_bundle(session: Session, job_id: Any, nested: Mapping[str, Mapping[str, Any]]) -> None:
    """Merge address-keyed recursive bundles into the canonical Assessment."""
    if session.execute(select(Job.id).where(Job.id == job_id).with_for_update()).scalar_one_or_none() is None:
        raise ValueError(f"job {job_id} does not exist")
    current = load_assessment(session, job_id, reader=get_artifact)
    assessment: Assessment = copy.deepcopy(current) if current is not None else {"schema_version": ASSESSMENT_VERSION}
    recursive = assessment.setdefault("recursive", {})
    for address, bundle in nested.items():
        key = address.lower()
        recursive[key] = _child_assessment(bundle, recursive.get(key))
    store_assessment(session, job_id, assessment, writer=store_artifact)
