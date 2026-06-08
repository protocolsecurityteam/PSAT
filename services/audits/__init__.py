"""Audit-report post-processing services.

This package holds the pieces that run *after* discovery:
  - ``text_extraction`` — download audit PDFs, extract text, store the text in
    object storage, and update the ``AuditReport`` row's extraction state.
  - ``scope_extraction`` — locate the scope section in the extracted text,
    LLM-extract the list of in-scope contracts, and write a JSON artifact.
  - ``coverage`` — match scope contracts to ``Contract`` rows (proxy-aware
    via ``UpgradeEvent`` history) and persist the link in
    ``audit_contract_coverage``.
"""

from .coverage import (
    GRACE_DAYS,
    CoverageMatch,
    ImplWindow,
    match_audits_for_contract,
    match_contracts_for_audit,
    upsert_coverage_for_audit,
    upsert_coverage_for_contract,
    upsert_coverage_for_protocol,
)
from .scope_extraction import (
    PROMPT_VERSION,
    SCOPE_ARTIFACT_CONTENT_TYPE,
    LLMUnavailableError,
    ScopeExtractionError,
    ScopeExtractionOutcome,
    ScopeSection,
    build_artifact_payload,
    extract_contracts_regex_fallback,
    extract_date_from_pdf_text,
    extract_scope_with_llm,
    locate_scope_section,
    process_audit_scope,
    scope_artifact_key,
    validate_contracts,
)
from .source_equivalence import (
    EquivalenceMatch,
    VerifiedSource,
    check_audit_covers_impl,
    check_audit_row_covers_contract,
    extract_reviewed_commits,
    fetch_contract_source_files,
    fetch_db_source_files,
    fetch_github_source_hash,
)
from .text_extraction import (
    AUDIT_TEXT_CONTENT_TYPE,
    ExtractionOutcome,
    audit_text_key,
    download_audit_body,
    download_pdf,
    download_text,
    extract_text_from_pdf,
    process_audit_report,
    store_audit_text,
)

__all__ = [
    "AUDIT_TEXT_CONTENT_TYPE",
    "ExtractionOutcome",
    "audit_text_key",
    "download_audit_body",
    "download_pdf",
    "download_text",
    "extract_text_from_pdf",
    "process_audit_report",
    "store_audit_text",
    # scope-extraction exports
    "LLMUnavailableError",
    "PROMPT_VERSION",
    "SCOPE_ARTIFACT_CONTENT_TYPE",
    "ScopeExtractionError",
    "ScopeExtractionOutcome",
    "ScopeSection",
    "build_artifact_payload",
    "extract_contracts_regex_fallback",
    "extract_date_from_pdf_text",
    "extract_scope_with_llm",
    "locate_scope_section",
    "process_audit_scope",
    "scope_artifact_key",
    "validate_contracts",
    # coverage exports
    "CoverageMatch",
    "GRACE_DAYS",
    "ImplWindow",
    "match_audits_for_contract",
    "match_contracts_for_audit",
    "upsert_coverage_for_audit",
    "upsert_coverage_for_contract",
    "upsert_coverage_for_protocol",
    # source-equivalence exports
    "EquivalenceMatch",
    "VerifiedSource",
    "check_audit_covers_impl",
    "check_audit_row_covers_contract",
    "extract_reviewed_commits",
    "fetch_contract_source_files",
    "fetch_db_source_files",
    "fetch_github_source_hash",
]
