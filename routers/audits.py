from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import select

from db.models import AuditReport, Protocol
from schemas.api_requests import AddAuditRequest
from schemas.api_responses import (
    AuditReportDict,
    AuditScopeResponse,
    DeleteAuditResponse,
    ReextractScopeResponse,
    RefreshCoverageResponse,
)
from services.aggregations import build_audits_pipeline, build_contract_audit_timeline
from services.audits.serializers import _audit_report_to_dict

from . import deps

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/api/audits/pipeline", dependencies=[Depends(deps.require_admin)])
def audits_pipeline() -> dict[str, Any]:
    """In-flight audit extraction for the monitor page, each list capped at ``_PIPELINE_BUCKET_LIMIT``.

    Must stay registered before ``/api/audits/{audit_id}``, or FastAPI parses "pipeline" as an int and 422s.
    """
    with deps.SessionLocal() as session:
        return build_audits_pipeline(session)


@router.get("/api/audits/{audit_id}", response_model=None)
def get_audit(audit_id: int) -> AuditReportDict:
    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")
        return _audit_report_to_dict(ar)


@router.get("/api/audits/{audit_id}/pdf")
def get_audit_pdf(audit_id: int):
    """Proxy an audit PDF through our origin for iframe embedding: sources send ``X-Frame-Options: deny`` /
    octet-stream. The URL is crawler/LLM-sourced, so it goes through ``safe_get`` (SSRF).
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

    # Public route with an untrusted URL: content-type gate + byte cap so it can't buffer a huge body into the 512MB VM.
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
        # Some CDNs omit content-type; a non-PDF type is an error page.
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
    """Extracted text from storage. 404 unknown audit, 409 not yet extracted, 503 storage unreachable."""
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
        # DB says available but the object is gone; 500 so ops notice.
        logger.error("Audit text record missing from storage for audit %s: %s", audit_id, exc)
        raise HTTPException(
            status_code=500,
            detail="text record missing from storage",
        ) from exc
    return body.decode("utf-8")


@router.get("/api/audits/{audit_id}/scope", response_model=None)
def get_audit_scope(audit_id: int) -> AuditScopeResponse:
    """Scope from the ``scope_contracts`` column. 404 unknown audit, 409 not yet extracted."""
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
    with deps.SessionLocal() as session:
        payload = build_contract_audit_timeline(session, contract_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="Contract not found")
        return payload


@router.post(
    "/api/company/{company_name}/refresh_coverage",
    dependencies=[Depends(deps.require_admin)],
    response_model=None,
)
def refresh_company_coverage(
    company_name: str,
    verify_source_equivalence: bool = True,
) -> RefreshCoverageResponse:
    """Rebuild coverage for every scoped audit in a protocol.

    Idempotent. ``verify_source_equivalence`` defaults to true; pass false for a fast heuristic-only refresh.
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
    dependencies=[Depends(deps.require_admin)],
    response_model=None,
)
def reextract_audit_scope(audit_id: int) -> ReextractScopeResponse:
    """Reset scope extraction so the worker re-claims the row. Requires successful text extraction."""
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
    dependencies=[Depends(deps.require_admin)],
    response_model=None,
)
def add_company_audit(company_name: str, req: AddAuditRequest) -> AuditReportDict:
    """Register an audit; workers claim it via NULL extraction status. Duplicate url on the protocol is 409."""
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

        # A new audit can adopt orphan contracts into this protocol.
        from services.monitoring.enrollment import mark_enrollment_dirty

        mark_enrollment_dirty(session, protocol_row.id, "audit_added")
        session.commit()

        deps.log_admin_mutation("add_audit", id=ar.id, company=company_name)
        return _audit_report_to_dict(ar)


@router.delete(
    "/api/audits/{audit_id}",
    dependencies=[Depends(deps.require_admin)],
    response_model=None,
)
def delete_audit(audit_id: int) -> DeleteAuditResponse:
    with deps.SessionLocal() as session:
        ar = session.get(AuditReport, audit_id)
        if ar is None:
            raise HTTPException(status_code=404, detail="Audit not found")
        session.delete(ar)
        session.commit()
    deps.log_admin_mutation("delete_audit", id=audit_id)
    return {"audit_id": audit_id, "deleted": True}
