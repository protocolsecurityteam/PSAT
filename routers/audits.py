"""Audit endpoints: pipeline, fetch, PDF/text/scope, scope re-extraction,
add/delete, refresh-coverage, and per-contract audit timeline."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select

from db.models import AuditReport, Protocol
from schemas.api_requests import AddAuditRequest
from services.aggregations import build_audits_pipeline, build_contract_audit_timeline
from services.audits.serializers import _audit_report_to_dict

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/audits/pipeline", dependencies=[Depends(deps.require_admin_key)])
def audits_pipeline() -> dict[str, Any]:
    """In-flight audit text + scope extraction, grouped by bucket.

    Feeds the monitor page's "Audit Extraction" shelf (parallel to
    ``/api/jobs`` for the job pipeline). Text and scope workers drive a
    column state machine on ``audit_reports`` rather than the ``jobs``
    queue, so they need their own endpoint.

    Each list is capped at ``_PIPELINE_BUCKET_LIMIT`` entries; callers
    should surface an overflow indicator when counts hit the cap.

    Route MUST stay registered before ``/api/audits/{audit_id}`` — FastAPI
    matches in declaration order and the param route would otherwise try to
    parse ``"pipeline"`` as an int and 422.
    """
    with deps.SessionLocal() as session:
        return build_audits_pipeline(session)


@router.get("/api/audits/{audit_id}")
def get_audit(audit_id: int) -> dict[str, Any]:
    """Fetch a single audit report's metadata, including text-extraction state."""
    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")
        return _audit_report_to_dict(ar)


@router.get("/api/audits/{audit_id}/pdf")
def get_audit_pdf(audit_id: int):
    """Proxy an audit's PDF through our origin so the frontend can embed it
    in an iframe. The typical source (GitHub raw content, auditor sites)
    serves PDFs with `X-Frame-Options: deny` and `Content-Type:
    application/octet-stream`, both of which prevent inline rendering — we
    need a passthrough that strips those headers and sets
    `Content-Type: application/pdf`.

    The stored URL is crawler/LLM-sourced, so the fetch is routed through
    ``safe_get`` — the target (and every redirect hop) must resolve to a
    public address, closing the unauthenticated SSRF read.
    """
    import requests

    from services.audits.text_extraction import _ACCEPTED_CONTENT_TYPES, _MAX_PDF_BYTES
    from utils.egress import UnsafeUrlError, safe_get
    from utils.github_urls import github_blob_to_raw

    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")
        url = ar.pdf_url or (ar.url if ar.url and ar.url.lower().endswith(".pdf") else None)
        if not url:
            raise HTTPException(status_code=404, detail="No PDF available for this audit")
        url = github_blob_to_raw(url)
        filename = f"audit-{audit_id}.pdf"

    # This is a PUBLIC, unauthenticated route and ``url`` is crawler/LLM-sourced.
    # Stream with a content-type gate + hard byte cap so a seeded URL pointing at
    # a large or non-PDF public file can't buffer an unbounded body into the
    # 512MB web VM. Mirrors the download discipline in
    # ``services.audits.text_extraction.download_audit_body``.
    try:
        resp = safe_get(url, timeout=30, stream=True)
    except UnsafeUrlError as exc:
        logger.warning("Refused audit PDF fetch for audit %s: %s", audit_id, exc)
        raise HTTPException(status_code=502, detail="Failed to fetch PDF") from exc
    except requests.RequestException as exc:
        logger.warning("Audit PDF fetch failed for audit %s: %s", audit_id, exc)
        raise HTTPException(status_code=502, detail="Failed to fetch PDF") from exc

    try:
        try:
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("Audit PDF fetch failed for audit %s: %s", audit_id, exc)
            raise HTTPException(status_code=502, detail="Failed to fetch PDF") from exc

        content_type = (resp.headers.get("content-type") or "").split(";")[0].strip().lower()
        # Empty content-type is tolerated (some CDNs omit it); a present but
        # non-PDF type means we were served an HTML error page or other body.
        if content_type and content_type not in _ACCEPTED_CONTENT_TYPES:
            logger.warning(
                "Audit PDF fetch for audit %s returned unexpected content-type %r",
                audit_id,
                content_type,
            )
            raise HTTPException(status_code=502, detail="Audit source did not return a PDF")

        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=131_072):
            if not chunk:
                continue
            total += len(chunk)
            if total > _MAX_PDF_BYTES:
                logger.warning(
                    "Audit PDF for audit %s exceeded size cap %d bytes; aborting stream",
                    audit_id,
                    _MAX_PDF_BYTES,
                )
                raise HTTPException(status_code=502, detail="PDF exceeds the maximum allowed size")
            chunks.append(chunk)
        body = b"".join(chunks)
    finally:
        resp.close()

    return Response(
        content=body,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
            "Cache-Control": "public, max-age=3600",
        },
    )


@router.get("/api/audits/{audit_id}/text", response_class=PlainTextResponse)
def get_audit_text(audit_id: int) -> str:
    """Return the extracted plain-text body of an audit report.

    Streams the text directly from object storage. Returns 404 for an
    unknown audit, 409 if extraction hasn't completed successfully yet
    (so the caller knows to retry later), and 503 if object storage is
    unreachable.
    """
    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")

        if ar.text_extraction_status != "success" or not ar.text_storage_key:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "text not available",
                    "status": ar.text_extraction_status,
                    "reason": ar.text_extraction_error,
                },
            )

        storage_key = ar.text_storage_key

    client = deps.get_storage_client()
    if client is None:
        raise HTTPException(status_code=503, detail="object storage not configured")
    try:
        body = client.get(storage_key)
    except deps.StorageUnavailable as exc:
        logger.warning("Audit text storage unavailable for audit %s: %s", audit_id, exc)
        raise HTTPException(status_code=503, detail="storage error") from exc
    except deps.StorageError as exc:
        # Covers StorageKeyMissing — DB says text is available but the object
        # got deleted. Inconsistent state; surface as 500 so ops notice.
        logger.error("Audit text record missing from storage for audit %s: %s", audit_id, exc)
        raise HTTPException(
            status_code=500,
            detail="text record missing from storage",
        ) from exc
    return body.decode("utf-8")


@router.get("/api/audits/{audit_id}/scope")
def get_audit_scope(audit_id: int) -> dict[str, Any]:
    """Return the list of in-scope contracts + date for a completed audit.

    Reads from the denormalized ``scope_contracts`` column — the JSON
    artifact in object storage is source-of-truth but not served here
    (that would be a debug-only endpoint). 404 for unknown audit, 409 if
    scope extraction hasn't completed successfully.
    """
    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")
        if ar.scope_extraction_status != "success":
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "scope not available",
                    "status": ar.scope_extraction_status,
                    "reason": ar.scope_extraction_error,
                },
            )
        return {
            "audit_id": audit_id,
            "auditor": ar.auditor,
            "title": ar.title,
            "date": ar.date,
            "contracts": list(ar.scope_contracts or []),
            "scope_extracted_at": (ar.scope_extracted_at.isoformat() if ar.scope_extracted_at else None),
        }


@router.get("/api/contracts/{contract_id}/audit_timeline")
def contract_audit_timeline(contract_id: int) -> dict[str, Any]:
    """Per-impl audit timeline for a single contract, annotated with coverage."""
    with deps.SessionLocal() as session:
        payload = build_contract_audit_timeline(session, contract_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Contract not found")
        return payload


@router.post(
    "/api/company/{company_name}/refresh_coverage",
    dependencies=[Depends(deps.require_admin_key)],
)
def refresh_company_coverage(
    company_name: str,
    verify_source_equivalence: bool = True,
) -> dict[str, Any]:
    """Rebuild ``audit_contract_coverage`` rows for every scoped audit in a protocol.

    Idempotent backfill. Useful when inventory is updated after audits are
    scoped (new Contract rows match pre-existing audit scope) or when a
    bulk data migration needs to re-seat links without waiting for the
    next scope re-extraction.

    ``verify_source_equivalence`` defaults to true: for each audit with
    reviewed_commits + source_repo, compare the byte content of each
    scope file against Etherscan's verified source. Proven matches
    upgrade to ``match_type='reviewed_commit'`` / ``match_confidence='high'``
    and every row gets an ``equivalence_status`` + ``equivalence_reason``
    stamp so the UI can surface failure modes (hash_mismatch, commit
    not in repo, etc.). Pass ``?verify_source_equivalence=false`` to
    skip the network pass for a fast heuristic-only refresh.
    """
    from services.audits.coverage import upsert_coverage_for_protocol

    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")
        inserted = upsert_coverage_for_protocol(
            session,
            protocol_row.id,
            verify_source_equivalence=verify_source_equivalence,
        )
        session.commit()
        deps.log_admin_mutation("refresh_coverage", id=company_name, count=inserted)
        return {
            "company": company_name,
            "protocol_id": protocol_row.id,
            "coverage_rows": inserted,
            "verify_source_equivalence": verify_source_equivalence,
        }


@router.post(
    "/api/audits/{audit_id}/reextract_scope",
    dependencies=[Depends(deps.require_admin_key)],
)
def reextract_audit_scope(audit_id: int) -> dict[str, Any]:
    """Reset scope-extraction state so the worker picks the row up again.

    Requires that text extraction already succeeded — without the stored
    text body there's nothing to re-scope. Idempotent: a fresh row with
    NULL status is a no-op reset.
    """
    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")
        if ar.text_extraction_status != "success":
            raise HTTPException(
                status_code=409,
                detail="text extraction has not succeeded for this audit",
            )
        ar.scope_extraction_status = None
        ar.scope_extraction_error = None
        ar.scope_extraction_worker = None
        ar.scope_extraction_started_at = None
        session.commit()
    deps.log_admin_mutation("reextract_scope", id=audit_id)
    return {"audit_id": audit_id, "reset": True}


@router.post(
    "/api/company/{company_name}/audits",
    dependencies=[Depends(deps.require_admin_key)],
)
def add_company_audit(company_name: str, req: AddAuditRequest) -> dict[str, Any]:
    """Register a new audit report for a protocol.

    The row is inserted with NULL text/scope extraction status, so the
    standing workers will claim it on their next poll: text extraction
    downloads the PDF, scope extraction parses the contracts + commits,
    and coverage matching wires it to deployed addresses. Duplicates
    (same url on the same protocol) are rejected with 409.
    """
    with deps.SessionLocal() as session:
        protocol_row = session.execute(select(Protocol).where(Protocol.name == company_name)).scalar_one_or_none()
        if protocol_row is None:
            raise HTTPException(status_code=404, detail="Company not found")

        existing = session.execute(
            select(AuditReport).where(
                AuditReport.protocol_id == protocol_row.id,
                AuditReport.url == req.url,
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail=f"Audit with this url already exists (id={existing.id})",
            )

        ar = AuditReport(
            protocol_id=protocol_row.id,
            url=req.url,
            pdf_url=req.pdf_url or req.url,
            auditor=req.auditor,
            title=req.title,
            date=req.date,
            confidence=req.confidence,
            source_repo=req.source_repo,
        )
        session.add(ar)
        session.commit()
        session.refresh(ar)

        # A new audit can adopt orphan contracts into this protocol; enqueue a
        # reconcile so monitoring picks up any newly-owned addresses.
        from services.monitoring.enrollment import mark_enrollment_dirty

        mark_enrollment_dirty(session, protocol_row.id, "audit_added")
        session.commit()

        deps.log_admin_mutation("add_audit", id=ar.id, company=company_name)
        return _audit_report_to_dict(ar)


@router.delete(
    "/api/audits/{audit_id}",
    dependencies=[Depends(deps.require_admin_key)],
)
def delete_audit(audit_id: int) -> dict[str, Any]:
    """Remove an audit report (cascades to coverage rows)."""
    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")
        session.delete(ar)
        session.commit()
    deps.log_admin_mutation("delete_audit", id=audit_id)
    return {"audit_id": audit_id, "deleted": True}
