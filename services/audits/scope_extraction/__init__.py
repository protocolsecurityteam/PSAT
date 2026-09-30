"""Extract in-scope contracts from audit PDF text. Helpers are importable without DB or S3.

1. ``locate_scope_section`` — header / content-pattern slices.
2. ``extract_scope_with_llm`` — contract names (and structured entries).
3. ``validate_contracts`` — drop names absent from the raw text (hallucination guard).
4. ``extract_date_from_pdf_text`` — title-page date for backfill.
5. ``extract_scope_via_chunk_scan`` — fallback when no header is found.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from db.storage import StorageUnavailable, get_storage_client
from utils.logging import record_degraded, record_stage_metric

from ._artifact import SCOPE_ARTIFACT_CONTENT_TYPE, _store_artifact, build_artifact_payload
from ._chunk_scan import _split_text_into_chunks, extract_scope_via_chunk_scan
from ._errors import LLMUnavailableError, ScopeExtractionError
from ._llm import PROMPT_VERSION, _build_prompt, _call_llm, extract_scope_with_llm
from ._locate import ScopeSection, locate_scope_section
from ._utils import _normalize_ligatures, _page_of_offset, _page_offsets, scope_artifact_key
from ._validate import (
    extract_contracts_regex_fallback,
    extract_date_from_pdf_text,
    validate_contracts,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScopeExtractionOutcome:
    """Result of ``process_audit_scope``.

    ``status`` mirrors ``scope_extraction_status``. Non-empty ``scope_entries`` are authoritative over the flat
    ``contracts`` list in coverage matching.
    """

    status: str
    contracts: tuple[str, ...] = ()
    storage_key: str | None = None
    extracted_date: str | None = None
    reviewed_commits: tuple[str, ...] = ()
    referenced_repos: tuple[str, ...] = ()
    scope_entries: tuple[dict, ...] = ()
    classified_commits: tuple[dict, ...] = ()
    error: str | None = None
    method: str = "llm"
    raw_response: str | None = field(default=None, repr=False)
    model: str | None = None


def process_audit_scope(
    audit_report_id: int,
    text_storage_key: str,
    text_sha256: str | None,
    audit_title: str,
    auditor: str,
) -> ScopeExtractionOutcome:
    """Full scope pipeline for one audit.

    Never raises: failures are ``status="failed"``, no scope section is ``"skipped"``.
    """
    client = get_storage_client()
    if client is None:
        return ScopeExtractionOutcome(
            status="failed",
            error="object storage not configured (ARTIFACT_STORAGE_* env vars unset)",
        )

    try:
        raw_bytes = client.get(text_storage_key)
    except StorageUnavailable as exc:
        return ScopeExtractionOutcome(status="failed", error=f"storage get failed: {exc}")
    except Exception as exc:
        logger.warning(
            "scope: unexpected storage error for audit %s: %s",
            audit_report_id,
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return ScopeExtractionOutcome(status="failed", error=f"storage: {exc!r}")

    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        return ScopeExtractionOutcome(status="failed", error=f"text decode: {exc}")

    raw_text = _normalize_ligatures(raw_text)
    extracted_date = extract_date_from_pdf_text(raw_text)
    # Referenced repos are fallbacks when discovery recorded the auditor's publication repo.
    from services.audits.source_equivalence import extract_referenced_repos, extract_reviewed_commits

    reviewed_commits = tuple(extract_reviewed_commits(raw_text))
    referenced_repos = tuple(extract_referenced_repos(raw_text))

    sections = locate_scope_section(raw_text)

    method = "llm"
    raw_response: str | None = None
    model: str | None = None
    names: list[str] = []
    scope_entries: list[dict] = []
    classified_commits: list[dict] = []
    # Persisted so debugging can see what the model saw.
    llm_input_text: str | None = None

    if sections:
        llm_input_text = "\n\n===\n\n".join(s.text_slice for s in sections)
        try:
            names, scope_entries, classified_commits, raw_response, model = extract_scope_with_llm(
                sections, audit_title, auditor
            )
        except LLMUnavailableError as exc:
            failure_kind = getattr(exc, "failure_kind", "api")
            logger.warning(
                "scope: LLM unavailable; falling back to regex",
                extra={
                    "audit_report_id": audit_report_id,
                    "exc_type": type(exc).__name__,
                    "failure_kind": failure_kind,
                },
            )
            # ``api`` (402/outage) vs ``parse`` (model/parser bug); conflating them hid the 55→4 collapse.
            record_stage_metric("scope_llm_failure_kind", failure_kind)
            record_degraded(
                phase="scope_llm",
                exc=exc,
                context={"audit_report_id": audit_report_id, "failure_kind": failure_kind},
            )
            combined = "\n".join(s.text_slice for s in sections)
            names = extract_contracts_regex_fallback(combined)
            scope_entries = []
            classified_commits = []
            method = "regex_fallback"
            raw_response = json.dumps(
                {"_fallback": "regex", "error": str(exc)},
                sort_keys=False,
            )

    validated = validate_contracts(names, raw_text)

    # Bounded to 4 chunks and gated by ``_has_scope_signal`` to keep findings pages out.
    if not validated:
        try:
            (
                cs_names,
                cs_entries,
                cs_commits,
                cs_response,
                cs_model,
                chunks_used,
                winning_chunk,
            ) = extract_scope_via_chunk_scan(raw_text, audit_title, auditor)
        except LLMUnavailableError as exc:
            failure_kind = getattr(exc, "failure_kind", "api")
            logger.warning(
                "scope: chunk-scan unavailable",
                extra={
                    "audit_report_id": audit_report_id,
                    "exc_type": type(exc).__name__,
                    "failure_kind": failure_kind,
                },
            )
            record_stage_metric("scope_chunk_scan_failure_kind", failure_kind)
            record_degraded(
                phase="scope_chunk_scan",
                exc=exc,
                context={"audit_report_id": audit_report_id, "failure_kind": failure_kind},
            )
            cs_names, cs_entries, cs_commits, cs_response, cs_model, chunks_used, winning_chunk = (
                [],
                [],
                [],
                "",
                None,
                0,
                None,
            )
        if cs_names:
            validated = validate_contracts(cs_names, raw_text)
            if validated:
                method = "llm_chunk_scan"
                raw_response = cs_response
                model = cs_model
                scope_entries = cs_entries
                classified_commits = cs_commits
                if winning_chunk is not None:
                    llm_input_text = winning_chunk.text_slice
                logger.info(
                    "scope: audit %s recovered via chunk-scan (%d chunks, %d names, %d entries, %d commits)",
                    audit_report_id,
                    chunks_used,
                    len(validated),
                    len(cs_entries),
                    len(cs_commits),
                )

    # Entry names must pass the same raw-text check as plain names.
    validated_lower = {n.lower() for n in validated}
    scope_entries = [e for e in scope_entries if e["name"].lower() in validated_lower]

    # The LLM sometimes constructs SHAs; keep only ones present in the text.
    raw_text_lower = raw_text.lower()
    classified_commits = [c for c in classified_commits if c["sha"][:7] in raw_text_lower]

    if not validated:
        return ScopeExtractionOutcome(
            status="skipped",
            error=(
                "no scope section found: header + content-pattern + chunk-scan all empty"
                if not sections
                else "scope section found but extraction + chunk-scan yielded no valid contracts"
            ),
            method=method,
            raw_response=raw_response,
            model=model,
            extracted_date=extracted_date,
            reviewed_commits=reviewed_commits,
            referenced_repos=referenced_repos,
        )

    payload = build_artifact_payload(
        validated,
        method=method,
        model=model,
        extracted_date=extracted_date,
        raw_response=raw_response,
        scope_section_text=llm_input_text,
        scope_entries=scope_entries,
        classified_commits=classified_commits,
    )
    storage_key = _store_artifact(audit_report_id, payload)

    return ScopeExtractionOutcome(
        status="success",
        contracts=tuple(validated),
        storage_key=storage_key,
        extracted_date=extracted_date,
        reviewed_commits=reviewed_commits,
        referenced_repos=referenced_repos,
        scope_entries=tuple(scope_entries),
        classified_commits=tuple(classified_commits),
        method=method,
        raw_response=raw_response,
        model=model,
    )


__all__ = [
    "PROMPT_VERSION",
    "SCOPE_ARTIFACT_CONTENT_TYPE",
    "LLMUnavailableError",
    "ScopeExtractionError",
    "ScopeExtractionOutcome",
    "ScopeSection",
    "scope_artifact_key",
    "locate_scope_section",
    "extract_scope_with_llm",
    "extract_scope_via_chunk_scan",
    "extract_contracts_regex_fallback",
    "validate_contracts",
    "extract_date_from_pdf_text",
    "build_artifact_payload",
    # Re-exported so tests can monkeypatch them.
    "_build_prompt",
    "_call_llm",
    "_normalize_ligatures",
    "_page_offsets",
    "_page_of_offset",
    "_split_text_into_chunks",
    "process_audit_scope",
]
