"""Writing a :class:`ScoreDocument` to ``protocol_scores``, and reading it back.

Two halves of one seam, in one module so the spill can never be written in a
shape the reader does not resolve. ``protocol_scores`` is insert-only: a fold
never destroys a row a consumer already read, and the score's movement is free
history for the Activity timeline.

The document is inline JSONB, spilling to object storage only above
:data:`INLINE_DOCUMENT_LIMIT_BYTES` (strategy §7.3). The table's
``ck_protocol_scores_document_exactly_one`` makes the two mutually exclusive, so
a reader is never handed a row carrying both a stale inline copy and a spill —
which is why the size decision is taken here, once, before the INSERT, rather
than by a later mutation.

The write ORDER is storage-then-row on purpose. A row committed before its body
exists names an object a reader would 404 on and would be indistinguishable from
a genuinely lost body; a body written before a row that never lands is an
orphaned object, which costs bytes and claims nothing. Orphans are logged with
their key at both the INSERT and the commit, so they are countable; collecting
them is not this pass's job.

The document is serialized exactly ONCE, and the inline column stores what came
back out of that serialization. Two encoders is how the same document becomes
two different documents.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from services.scoring.schema import ScoreDocument

logger = logging.getLogger(__name__)

# The §7.3 spill threshold. Measured on the serialized body, not the Python
# object, because the bytes are what Postgres stores and what a reader pays for.
INLINE_DOCUMENT_LIMIT_BYTES = 1_000_000


class ScoreDocumentUnavailable(RuntimeError):
    """The row names a body that could not be read.

    Distinct from "no score row" (which is a 404) and from an inline document:
    a spilled body that cannot be fetched is not determined, and the read
    surface must not present it as an empty or a partial document.
    """


def persist_score_document(session: Session, document: ScoreDocument) -> Any:
    """INSERT one ``protocol_scores`` row for *document*. Does not commit.

    Returns the ORM row. The caller commits, so the score lands with whatever
    else that transaction carries (the loop clears the dirty marks it consumed
    in the same commit).
    """
    from db.models import ProtocolScore

    # ONE serialization, and the inline column stores what came back out of it.
    # Two encoders would make the same document two different documents: a
    # ``default=str`` fallback silently turns a Decimal into a string on the
    # spilled path while the inline path hands the raw object to the JSONB
    # serializer, which raises. A value this cannot encode is a producer bug and
    # must fail the same way in both paths, at persist time, with the document
    # in hand.
    body = json.dumps(document.document(), sort_keys=True).encode("utf-8")
    payload = json.loads(body)

    findings: Any | None = payload
    storage_key: str | None = None
    if len(body) > INLINE_DOCUMENT_LIMIT_BYTES:
        storage_key = _spill(document.protocol_id, body)
        if storage_key is not None:
            findings = None
        else:
            # Storage is not configured (local dev, offline tests). Inline is
            # the honest fallback: JSONB holds it, and refusing to persist would
            # discard a computed verdict over a deployment detail.
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
        # The body is already in the bucket and the row that would have named it
        # is not going to exist. No GC here, but the key is logged so an orphan
        # is countable rather than invisible — an unnamed object is otherwise
        # indistinguishable from one nobody ever wrote.
        if storage_key:
            logger.warning(
                "protocol score document orphaned in object storage: row insert failed",
                extra={"protocol_id": document.protocol_id, "storage_key": storage_key},
            )
        raise
    return row


def _spill(protocol_id: int, body: bytes) -> str | None:
    """Write *body* to object storage, returning its key, or ``None`` if unconfigured."""
    from db.storage import JSON_CONTENT_TYPE, get_storage_client, protocol_score_document_key

    client = get_storage_client()
    if client is None:
        return None
    key = protocol_score_document_key(protocol_id, uuid.uuid4().hex)
    client.put(key, body, JSON_CONTENT_TYPE, metadata={"protocol_id": str(protocol_id)})
    return key


def load_score_document(row: Any) -> dict[str, Any]:
    """The document a ``protocol_scores`` row carries, spill reassembled.

    Raises :class:`ScoreDocumentUnavailable` rather than returning a partial or
    an empty document when the spilled body cannot be read — an unreadable
    document is not an empty one, and serving ``{}`` would publish "this
    protocol has no findings" out of a failed fetch.
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
