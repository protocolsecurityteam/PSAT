"""Build the live audit-extraction pipeline view (text + scope workers)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import AuditReport, Protocol
from services.audits.serializers import _pipeline_item

_PIPELINE_FAILED_LOOKBACK_HOURS = 24

_PIPELINE_BUCKET_LIMIT = 50


def build_audits_pipeline(session: Session) -> dict[str, Any]:
    """In-flight audit text + scope extraction per worker: ``processing``, ``pending`` (claimable), ``failed`` (last
    24h). Scope ``pending`` requires successful text extraction.
    """
    now = datetime.now(timezone.utc)
    failed_cutoff = now - timedelta(hours=_PIPELINE_FAILED_LOOKBACK_HOURS)

    protocol_names: dict[int, str] = {
        row.id: row.name for row in session.execute(select(Protocol.id, Protocol.name)).all()
    }

    def _fetch(stmt) -> list[Any]:
        return list(session.execute(stmt).scalars().all())

    text_processing = _fetch(
        select(AuditReport)
        .where(AuditReport.text_extraction_status == "processing")
        .order_by(AuditReport.text_extraction_started_at.asc().nullslast())
        .limit(_PIPELINE_BUCKET_LIMIT)
    )
    text_pending = _fetch(
        select(AuditReport)
        .where(AuditReport.text_extraction_status.is_(None))
        .order_by(AuditReport.discovered_at.asc().nullslast())
        .limit(_PIPELINE_BUCKET_LIMIT)
    )
    text_failed = _fetch(
        select(AuditReport)
        .where(
            AuditReport.text_extraction_status == "failed",
            AuditReport.text_extracted_at >= failed_cutoff,
        )
        .order_by(AuditReport.text_extracted_at.desc().nullslast())
        .limit(_PIPELINE_BUCKET_LIMIT)
    )

    scope_processing = _fetch(
        select(AuditReport)
        .where(AuditReport.scope_extraction_status == "processing")
        .order_by(AuditReport.scope_extraction_started_at.asc().nullslast())
        .limit(_PIPELINE_BUCKET_LIMIT)
    )
    scope_pending = _fetch(
        select(AuditReport)
        .where(
            AuditReport.scope_extraction_status.is_(None),
            AuditReport.text_extraction_status == "success",
        )
        .order_by(AuditReport.text_extracted_at.asc().nullslast())
        .limit(_PIPELINE_BUCKET_LIMIT)
    )
    scope_failed = _fetch(
        select(AuditReport)
        .where(
            AuditReport.scope_extraction_status == "failed",
            AuditReport.scope_extracted_at >= failed_cutoff,
        )
        .order_by(AuditReport.scope_extracted_at.desc().nullslast())
        .limit(_PIPELINE_BUCKET_LIMIT)
    )

    def _shape(rows: list[Any]) -> list[dict[str, Any]]:
        return [_pipeline_item(ar, protocol_names.get(ar.protocol_id), now) for ar in rows]

    return {
        "text_extraction": {
            "processing": _shape(text_processing),
            "pending": _shape(text_pending),
            "failed": _shape(text_failed),
        },
        "scope_extraction": {
            "processing": _shape(scope_processing),
            "pending": _shape(scope_pending),
            "failed": _shape(scope_failed),
        },
        "generated_at": now.isoformat(),
    }
