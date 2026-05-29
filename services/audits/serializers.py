"""Serialization helpers for audit-report rows.

Mirrors the JSON shapes returned by the audit endpoints — kept here so
routers stay thin and the aggregations layer (``audits_pipeline``,
``contract_audit_timeline``) can reuse the exact same serialization.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _audit_report_to_dict(ar: Any) -> dict[str, Any]:
    """Serialize an AuditReport row, including text- and scope-extraction state."""
    from utils.github_urls import github_blob_to_raw

    scope_contracts = list(ar.scope_contracts or [])
    return {
        "id": ar.id,
        "url": ar.url,
        "pdf_url": github_blob_to_raw(ar.pdf_url) if ar.pdf_url else None,
        "auditor": ar.auditor,
        "title": ar.title,
        "date": ar.date,
        "confidence": float(ar.confidence) if ar.confidence is not None else None,
        "text_extraction_status": ar.text_extraction_status,
        "text_extracted_at": (ar.text_extracted_at.isoformat() if ar.text_extracted_at else None),
        "text_size_bytes": ar.text_size_bytes,
        "text_extraction_error": ar.text_extraction_error,
        "has_text": ar.text_extraction_status == "success",
        "scope_extraction_status": ar.scope_extraction_status,
        "scope_extracted_at": (ar.scope_extracted_at.isoformat() if ar.scope_extracted_at else None),
        "scope_contract_count": len(scope_contracts),
        "scope_extraction_error": ar.scope_extraction_error,
        "has_scope": ar.scope_extraction_status == "success",
        # Commit attribution: `reviewed_commits` is the flat list extracted
        # from the PDF via regex; `classified_commits` is the LLM-labeled
        # richer shape with {sha, label, context}. The frontend prefers the
        # classified list (filtered to label === "reviewed") and falls back
        # to reviewed_commits when the classification pass hasn't run.
        "reviewed_commits": list(ar.reviewed_commits or []),
        "classified_commits": list(ar.classified_commits or []),
        "referenced_repos": list(ar.referenced_repos or []),
    }


def _audit_brief(audit: Any, match: Any | None = None) -> dict[str, Any]:
    """Compact audit-report dict for the coverage/timeline endpoints."""
    out: dict[str, Any] = {
        "audit_id": audit.id,
        "auditor": audit.auditor,
        "title": audit.title,
        "date": audit.date,
    }
    if match is not None:
        out["match_type"] = match.match_type
        out["match_confidence"] = match.match_confidence
        out["covered_from_block"] = match.covered_from_block
        out["covered_to_block"] = match.covered_to_block
        # Source-equivalence verdict — see services.audits.source_equivalence
        # for the status vocabulary. ``proven`` means cryptographically
        # verified (file SHA-256 match between audit's GitHub commit and
        # Etherscan-verified source). Other values describe *why* the
        # check couldn't produce a proof so the UI can badge specifically.
        out["equivalence_status"] = getattr(match, "equivalence_status", None)
        out["equivalence_reason"] = getattr(match, "equivalence_reason", None)
        equivalence_checked_at = getattr(match, "equivalence_checked_at", None)
        out["equivalence_checked_at"] = equivalence_checked_at.isoformat() if equivalence_checked_at else None
        # Phase C: proof_kind is the strength subtype of ``proven`` rows.
        # 'pre_fix_unpatched' gets special treatment in the UI as a RED
        # FLAG — the audit reviewed exactly this code AND the protocol
        # knew of a fix but never shipped it.
        out["proof_kind"] = getattr(match, "proof_kind", None)
        # The specific commit SHA this contract's bytecode matched during
        # source-equivalence verification. NULL on heuristic matches and on
        # rows verified before the column existed; re-running
        # refresh_coverage repopulates.
        out["matched_commit_sha"] = getattr(match, "matched_commit_sha", None)
    return out


def _pipeline_item(ar: Any, protocol_name: str | None, now: datetime) -> dict[str, Any]:
    """Shape one audit row for the monitor page's live timeline."""
    started = ar.text_extraction_started_at or ar.scope_extraction_started_at
    elapsed = int((now - started).total_seconds()) if started else None
    scope_contracts = list(ar.scope_contracts or [])
    reviewed_commits = list(ar.reviewed_commits or [])
    referenced_repos = list(ar.referenced_repos or [])
    scope_entries = list(ar.scope_entries or [])
    classified_commits = list(ar.classified_commits or [])
    return {
        "audit_id": ar.id,
        "protocol_id": ar.protocol_id,
        "company": protocol_name,
        "auditor": ar.auditor,
        "title": ar.title,
        "date": ar.date,
        "pdf_url": ar.pdf_url,
        "worker_id": (
            ar.text_extraction_worker if ar.text_extraction_status == "processing" else ar.scope_extraction_worker
        ),
        "started_at": started.isoformat() if started else None,
        "elapsed_seconds": elapsed,
        "text_extraction_status": ar.text_extraction_status,
        "text_extracted_at": (ar.text_extracted_at.isoformat() if ar.text_extracted_at else None),
        "text_size_bytes": ar.text_size_bytes,
        "scope_extraction_status": ar.scope_extraction_status,
        "scope_extracted_at": (ar.scope_extracted_at.isoformat() if ar.scope_extracted_at else None),
        "scope_contract_count": len(scope_contracts),
        "reviewed_commit_count": len(reviewed_commits),
        "referenced_repo_count": len(referenced_repos),
        "scope_entry_count": len(scope_entries),
        "classified_commit_count": len(classified_commits),
        "error": (
            ar.text_extraction_error
            if ar.text_extraction_status == "failed"
            else ar.scope_extraction_error
            if ar.scope_extraction_status == "failed"
            else None
        ),
    }
