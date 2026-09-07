"""One-shot, loss-preserving import of pre-cutover analytical artifacts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, cast

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Artifact, AssessmentImportManifest, AssessmentPayload, SessionLocal
from db.queue.artifacts import _artifact_row_to_value
from schemas.assessment import Assessment
from services.assessment.repository import (
    intern_payload,
    load_legacy_assessment,
    load_principal_history,
    publish_legacy_assessment,
    publish_principal_history,
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def _without_transport_version(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "schema_version"}


def _assert_projection(name: str, source: Mapping[str, Any], projected: Mapping[str, Any] | None) -> None:
    if projected is None:
        raise RuntimeError(f"{name} import produced no canonical projection")
    left = dict(source) if name == "assessment" else _without_transport_version(source)
    right = dict(projected) if name == "assessment" else _without_transport_version(projected)
    if _canonical_bytes(left) != _canonical_bytes(right):
        raise RuntimeError(f"{name} canonical projection does not match its source artifact")


def import_legacy_artifacts(session: Session) -> dict[str, Any]:
    """Consume every legacy Assessment/history row in restart-safe transactions.

    Each source body is retained in the content store and named by a durable
    manifest before the mutable Artifact row is removed. A failed comparison
    rolls back the publication, manifest, and deletion together.
    """
    rows = (
        session.execute(
            select(Artifact)
            .where(Artifact.name.in_(("assessment", "principal_history")))
            .order_by(
                # Principal history extends an Assessment publication, so its
                # source must be converted second for every database-wide pass.
                (Artifact.name == "principal_history"),
                Artifact.created_at,
                Artifact.id,
            )
        )
        .scalars()
        .all()
    )
    imported = {"assessment": 0, "principal_history": 0}
    manifests: list[dict[str, Any]] = []
    for artifact in rows:
        source = _artifact_row_to_value(artifact)
        if not isinstance(source, Mapping):
            raise RuntimeError(f"{artifact.name} artifact {artifact.id} is not a JSON object")
        source_value = dict(source)
        source_bytes = _canonical_bytes(source_value)
        digest = hashlib.sha256(source_bytes).hexdigest()

        existing = session.get(AssessmentImportManifest, artifact.id)
        if existing is not None:
            payload = session.get(AssessmentPayload, existing.source_payload_id)
            if existing.source_digest != digest or payload is None or payload.data != source_bytes:
                raise RuntimeError(f"import manifest mismatch for artifact {artifact.id}")
            session.delete(artifact)
            session.commit()
            continue

        source_payload_id = intern_payload(session, source_value)
        if artifact.name == "assessment":
            publication_id = publish_legacy_assessment(
                session,
                artifact.job_id,
                cast(Assessment, source_value),
            )
            projected = load_legacy_assessment(session, artifact.job_id)
        else:
            publication_id = publish_principal_history(session, artifact.job_id, source_value)
            projected = load_principal_history(session, artifact.job_id)
        _assert_projection(artifact.name, source_value, projected)

        source_descriptor = {
            "storage_key": artifact.storage_key,
            "stored_object_size_bytes": artifact.stored_object_size_bytes,
            "content_type": artifact.content_type,
        }
        session.add(
            AssessmentImportManifest(
                artifact_id=artifact.id,
                job_id=artifact.job_id,
                artifact_name=artifact.name,
                source_digest=digest,
                source_payload_id=source_payload_id,
                source_created_at=artifact.created_at,
                publication_id=publication_id,
                source=source_descriptor,
            )
        )
        session.delete(artifact)
        session.commit()
        imported[artifact.name] += 1
        manifests.append(
            {
                "artifact_id": str(artifact.id),
                "job_id": str(artifact.job_id),
                "name": artifact.name,
                "source_digest": digest,
                "publication_id": str(publication_id),
            }
        )
    return {"imported": imported, "manifests": manifests, "remaining": 0}


def main() -> None:
    with SessionLocal() as session:
        result = import_legacy_artifacts(session)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
