"""Writing a :class:`ScoreDocument` to ``protocol_scores``, and reading it back.

Both halves live here so a spill is never written in a shape the reader can't resolve. ``protocol_scores`` is
insert-only.

The document is inline JSONB, spilling to object storage above :data:`INLINE_DOCUMENT_LIMIT_BYTES`;
``ck_protocol_scores_document_exactly_one`` makes them exclusive, so the choice is made once before the INSERT. Storage
is written before the row: a row naming a missing body would look like a lost body, while an orphaned body just costs
bytes (orphan keys are logged).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.schema import ScoreDocument

logger = logging.getLogger(__name__)

# Measured on the serialized bytes, which is what Postgres stores.
INLINE_DOCUMENT_LIMIT_BYTES = 1_000_000


class ScoreDocumentUnavailable(RuntimeError):
    """The row names a body that couldn't be read.

    Distinct from no row (404) and never served as an empty or partial document.
    """


def persist_score_document(session: Session, document: ScoreDocument) -> Any:
    """INSERT one ``protocol_scores`` row for *document*.

    Doesn't commit, so the loop's mark clear lands in the same commit.
    """
    from db.models import ProtocolScore

    # Serialize once and store that result inline too, so both paths fail identically on unencodable values (e.g. a
    # ``default=str`` fallback would stringify a Decimal only when spilled).
    body = json.dumps(document.document(), sort_keys=True).encode("utf-8")
    payload = json.loads(body)

    findings: Any | None = payload
    storage_key: str | None = None
    if len(body) > INLINE_DOCUMENT_LIMIT_BYTES:
        storage_key = _spill(document.protocol_id, body)
        if storage_key is not None:
            findings = None
        else:
            # Storage unconfigured (local dev, offline tests): fall back to inline rather than discard the score.
            logger.warning(
                "protocol score document exceeds the inline limit but object storage is unconfigured; storing inline",
                extra={"protocol_id": document.protocol_id, "document_bytes": len(body)},
            )

    row = ProtocolScore(
        protocol_id=document.protocol_id,
        model_version=document.model_version,
        computed_at=document.computed_at,
        trigger=document.trigger,
        trigger_job_id=document.trigger_job_id,
        grade_state=document.grade_state,
        grade_lambda=document.grade_lambda,
        grade_exposure=document.grade_exposure,
        confidence_pct=document.confidence_pct,
        perimeter_state=document.perimeter_state,
        findings=findings,
        storage_key=storage_key,
        provenance=document.provenance,
        model_parameters=document.model_parameters,
    )
    session.add(row)
    try:
        session.flush()
    except Exception:
        # The row won't exist; log the key so the orphaned body is countable.
        if storage_key:
            logger.warning(
                "protocol score document orphaned in object storage: row insert failed",
                extra={"protocol_id": document.protocol_id, "storage_key": storage_key},
            )
        raise
    return row


def _spill(protocol_id: int, body: bytes) -> str | None:
    from db.storage import JSON_CONTENT_TYPE, get_storage_client, protocol_score_document_key

    client = get_storage_client()
    if client is None:
        return None
    key = protocol_score_document_key(protocol_id, uuid.uuid4().hex)
    client.put(key, body, JSON_CONTENT_TYPE, metadata={"protocol_id": str(protocol_id)})
    return key


def load_score_document(row: Any) -> dict[str, Any]:
    """The document a ``protocol_scores`` row carries, spill reassembled.

    Raises :class:`ScoreDocumentUnavailable` instead of serving ``{}`` on a failed fetch.
    """
    if row.findings is not None:
        return dict(row.findings)
    key = row.storage_key
    if not key:
        raise ScoreDocumentUnavailable(f"protocol score {row.id} carries neither an inline document nor a storage key")

    from db.storage import deserialize_artifact, get_storage_client

    client = get_storage_client()
    if client is None:
        raise ScoreDocumentUnavailable(f"protocol score {row.id} spilled to {key} but object storage is unconfigured")
    try:
        value = deserialize_artifact(client.get(key), "application/json")
    except Exception as exc:
        raise ScoreDocumentUnavailable(f"protocol score {row.id} body at {key} could not be read: {exc}") from exc
    if not isinstance(value, dict):
        raise ScoreDocumentUnavailable(f"protocol score {row.id} body at {key} is not a document")
    return value


__all__ = [
    "INLINE_DOCUMENT_LIMIT_BYTES",
    "ScoreDocumentUnavailable",
    "load_score_document",
    "persist_score_document",
]
