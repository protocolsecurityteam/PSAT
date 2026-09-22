"""Read and update the one canonical Assessment artifact for a job."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Job
from schemas.assessment import (
    ASSESSMENT_SECTIONS,
    ASSESSMENT_VERSION,
    Assessment,
    AssessmentSectionName,
    validate_assessment,
)

ASSESSMENT_ARTIFACT = "assessment"
ArtifactReader = Callable[[Session, Any, str], object]
ArtifactWriter = Callable[..., None]


def _reader(reader: ArtifactReader | None) -> ArtifactReader:
    if reader is not None:
        return reader
    from db.queue.artifacts import get_artifact

    return get_artifact


def _writer(writer: ArtifactWriter | None) -> ArtifactWriter:
    if writer is not None:
        return writer
    from db.queue.artifacts import store_artifact

    return store_artifact


def _lock_job(session: Session, job_id: Any) -> None:
    if session.execute(select(Job.id).where(Job.id == job_id).with_for_update()).scalar_one_or_none() is None:
        raise ValueError(f"job {job_id} does not exist")


def load_assessment(session: Session, job_id: Any, *, reader: ArtifactReader | None = None) -> Assessment | None:
    """Load and validate the canonical artifact; preserve absent as ``None``."""
    value = _reader(reader)(session, job_id, ASSESSMENT_ARTIFACT)
    if value is None:
        return None
    return validate_assessment(value)


def get_assessment_section(
    session: Session,
    job_id: Any,
    name: str,
    *,
    reader: ArtifactReader | None = None,
) -> dict[str, Any] | None:
    """Return one section, preserving the distinction between absent and ``{}``."""
    if name not in ASSESSMENT_SECTIONS:
        raise ValueError(f"unknown assessment section: {name!r}")
    assessment = load_assessment(session, job_id, reader=reader)
    if assessment is None or name not in assessment:
        return None
    return cast(dict[str, Any], assessment.get(cast(AssessmentSectionName, name)))


def store_assessment(
    session: Session,
    job_id: Any,
    assessment: Assessment,
    *,
    writer: ArtifactWriter | None = None,
) -> None:
    """Validate and store the complete canonical artifact without rewriting it."""
    validate_assessment(assessment)
    _writer(writer)(session, job_id, ASSESSMENT_ARTIFACT, assessment)


def store_assessment_section(
    session: Session,
    job_id: Any,
    name: str,
    data: Mapping[str, Any],
    *,
    reader: ArtifactReader | None = None,
    writer: ArtifactWriter | None = None,
) -> Assessment:
    """Atomically merge one stage section into the canonical artifact.

    The job row is locked before the current artifact is read. The existing
    artifact writer commits the transaction, releasing the lock only after the
    merged document is durable.
    """
    if name not in ASSESSMENT_SECTIONS:
        raise ValueError(f"unknown assessment section: {name!r}")
    if not isinstance(data, Mapping):
        raise ValueError(f"assessment.{name} must be an object")
    _lock_job(session, job_id)
    current = load_assessment(session, job_id, reader=reader)
    updated: dict[str, Any] = (
        copy.deepcopy(dict(current)) if current is not None else {"schema_version": ASSESSMENT_VERSION}
    )
    updated[name] = copy.deepcopy(dict(data))
    result = validate_assessment(updated)
    store_assessment(session, job_id, result, writer=writer)
    return result


def get_recursive_assessment(assessment: Assessment, key: str) -> Assessment | None:
    """Read a validated recursive contract assessment by its address key."""
    validate_assessment(assessment)
    child = assessment.get("recursive", {}).get(key)
    return validate_assessment(child) if child is not None else None


__all__ = [
    "ASSESSMENT_ARTIFACT",
    "get_assessment_section",
    "get_recursive_assessment",
    "load_assessment",
    "store_assessment",
    "store_assessment_section",
]
