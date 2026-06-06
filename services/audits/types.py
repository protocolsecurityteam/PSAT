"""Schemas owned by audit services."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypedDict

from typing_extensions import NotRequired

from schemas.common import Address, Contract, JsonObject, ServiceBoundaryMetadata, StageArtifact, StageContext


@dataclass(frozen=True)
class ImplWindow:
    proxy_contract_id: int
    proxy_address: Address
    from_block: int
    to_block: int | None
    from_ts: datetime | None
    to_ts: datetime | None


@dataclass(frozen=True)
class CoverageMatch:
    audit_report_id: int
    contract_id: int
    protocol_id: int
    matched_name: str
    match_type: str
    match_confidence: str
    covered_from_block: int | None = None
    covered_to_block: int | None = None
    bytecode_keccak_at_match: str | None = None
    verified_at: datetime | None = None
    equivalence_status: str | None = None
    equivalence_reason: str | None = None
    equivalence_checked_at: datetime | None = None
    pinned_commit: str | None = None
    proof_kind: str | None = None
    matched_commit_sha: str | None = None


@dataclass(frozen=True)
class _EquivalenceInputs:
    audit_report_id: int
    contract_id: int
    contract_address: Address | None
    reviewed_commits: tuple[str, ...]
    scope_contracts: tuple[str, ...]
    source_repo: str | None
    referenced_repos: tuple[str, ...]
    classified_commits: tuple[dict, ...]
    db_impl_source: Any
    contract: Contract | None = None


@dataclass(frozen=True)
class GithubFetch:
    content: str | None
    status: str
    detail: str


@dataclass(frozen=True)
class VerifiedSource:
    contract_name: str | None
    compiler_version: str | None
    files: dict[str, str]


@dataclass(frozen=True)
class EtherscanFetch:
    source: VerifiedSource | None
    status: str
    detail: str


@dataclass(frozen=True)
class GithubHashResult:
    sha256: str | None
    status: str
    detail: str


@dataclass(frozen=True)
class EquivalenceMatch:
    commit: str
    scope_name: str
    etherscan_path: str
    source_sha256: str


@dataclass(frozen=True)
class EquivalenceOutcome:
    status: str
    reason: str
    matches: tuple[EquivalenceMatch, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ExtractionOutcome:
    status: str
    storage_key: str | None = None
    text_size_bytes: int | None = None
    text_sha256: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class ScopeSection:
    start_page: int
    end_page: int
    header: str
    text_slice: str


@dataclass(frozen=True)
class ScopeExtractionOutcome:
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


class AuditStageRequest(TypedDict, total=False):
    context: StageContext
    metadata: ServiceBoundaryMetadata
    contract: Contract | None
    audit_report_id: int | None
    protocol_id: int | None
    url: str | None
    source_repo: str | None
    scope: JsonObject


class AuditPayload(TypedDict):
    contract: NotRequired[Contract | None]
    coverage_matches: list[JsonObject]
    extraction: NotRequired[ExtractionOutcome | None]
    scope_extraction: NotRequired[ScopeExtractionOutcome | None]
    equivalence: NotRequired[EquivalenceOutcome | None]


AuditArtifact = StageArtifact[AuditPayload]


__all__ = [
    "AuditArtifact",
    "AuditPayload",
    "AuditStageRequest",
    "CoverageMatch",
    "EquivalenceMatch",
    "EquivalenceOutcome",
    "EtherscanFetch",
    "ExtractionOutcome",
    "GithubFetch",
    "GithubHashResult",
    "ImplWindow",
    "ScopeExtractionOutcome",
    "ScopeSection",
    "VerifiedSource",
    "_EquivalenceInputs",
]
