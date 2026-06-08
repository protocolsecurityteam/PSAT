"""Extract the list of in-scope contracts from an audit report's PDF text.

Runs after ``services.audits.text_extraction`` puts the parsed PDF body in
object storage. The worker in ``workers.audit_scope_extraction`` drives
``process_audit_scope``; every helper is importable without DB or S3.

Pipeline for one audit:
    1. ``locate_scope_section`` — regex for header / content-pattern
       phrases, return 1-3 page slices.
    2. ``extract_scope_with_llm`` — send slices to Gemini 2.0 Flash via
       OpenRouter, get back a JSON array of contract names.
    3. ``validate_contracts`` — drop names that never appear in the raw
       body (hallucination guard).
    4. ``extract_date_from_pdf_text`` — best-effort title-region date
       pull for backfilling ``AuditReport.date`` when null.
    5. On no-header bodies, ``extract_scope_via_chunk_scan`` walks the
       first ~20 pages in N-page windows as a fallback.

``process_audit_scope`` chains everything and returns a
``ScopeExtractionOutcome`` that the worker persists atomically.
"""

from __future__ import annotations

import json
import logging

from db.storage import StorageUnavailable, get_storage_client
from services.audits.types import ScopeExtractionOutcome

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


def process_audit_scope(
    audit_report_id: int,
    text_storage_key: str,
    text_sha256: str | None,
    audit_title: str,
    auditor: str,
) -> ScopeExtractionOutcome:
    """Full scope-extraction pipeline for one audit.

    Fetches the PDF text from object storage, locates scope sections,
    calls the LLM (falling back to regex / chunk-scan as needed),
    validates results against the raw text, and writes a JSON artifact.

    Never raises: any failure becomes ``status="failed"`` with ``error``
    populated. Bodies with no scope section become ``status="skipped"``.
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
    # Commits pulled from the full text so ``source_equivalence`` can later
    # cross-reference reviewed code against persisted impl source.
    # Referenced repos (Phase D) are fallback candidates for source-
    # equivalence when ``source_repo`` misses — common when discovery
    # recorded the auditor's publication repo instead of the protocol's.
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
    # Text the LLM actually saw — persisted on the artifact so debugging
    # can answer "why did the model extract what it extracted?".
    llm_input_text: str | None = None

    if sections:
        llm_input_text = "\n\n===\n\n".join(s.text_slice for s in sections)
        try:
            names, scope_entries, classified_commits, raw_response, model = extract_scope_with_llm(
                sections, audit_title, auditor
            )
        except LLMUnavailableError as exc:
            logger.warning(
                "scope: LLM unavailable for audit %s (%s); falling back to regex",
                audit_report_id,
                exc,
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

    # Chunk-scan fallback: no structural header, or the located section
    # yielded no valid names. Walks the first ~20 pages asking the LLM
    # per chunk. Bounded to 4 chunks, gated by ``_has_scope_signal`` to
    # keep findings-page extractions out.
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
            logger.warning(
                "scope: chunk-scan unavailable for audit %s: %s",
                audit_report_id,
                exc,
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

    # Hallucination filter on scope_entries: the entry's name must survive
    # the same raw-text-substring check we apply to plain names. Drops
    # entries whose name is a model confabulation. The address + commit
    # fields already passed format-level validation in ``_parse_scope_entry``.
    validated_lower = {n.lower() for n in validated}
    scope_entries = [e for e in scope_entries if e["name"].lower() in validated_lower]

    # Hallucination filter on classified_commits: the SHA (as prefix-match
    # at 7 chars) must appear in the raw PDF text. The LLM sometimes emits
    # SHAs it constructed from context rather than ones actually present;
    # drop those to keep only real citations.
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
    # Versions + constants
    "PROMPT_VERSION",
    "SCOPE_ARTIFACT_CONTENT_TYPE",
    # Errors
    "LLMUnavailableError",
    "ScopeExtractionError",
    # Result types
    "ScopeExtractionOutcome",
    "ScopeSection",
    # Utils
    "scope_artifact_key",
    # Locating + extracting
    "locate_scope_section",
    "extract_scope_with_llm",
    "extract_scope_via_chunk_scan",
    "extract_contracts_regex_fallback",
    "validate_contracts",
    "extract_date_from_pdf_text",
    # Artifact assembly
    "build_artifact_payload",
    # Internal helpers re-exported so tests can monkeypatch them
    "_build_prompt",
    "_call_llm",
    "_normalize_ligatures",
    "_page_offsets",
    "_page_of_offset",
    "_split_text_into_chunks",
    # Orchestration
    "process_audit_scope",
]
