"""Response TypedDicts for ``routers/`` handler return types, checked by pyright only.

Not wired as ``response_model=``, which would prune undeclared keys the SPA reads. FastAPI infers a model from a bare
return annotation, so every annotated route must pass ``response_model=None``.

Fields are typed only as precisely as the producer proves; dynamic interiors stay ``dict[str, Any]``.
"""

from __future__ import annotations

from typing import Any

# pydantic refuses typing.TypedDict below 3.12, and FastAPI feeds these to pydantic for docs.
from typing_extensions import NotRequired, TypedDict


class JobDict(TypedDict):
    job_id: str
    address: str | None
    company: str | None
    name: str | None
    status: str
    stage: str
    detail: str | None
    request: dict[str, Any] | None
    error: str | None
    worker_id: str | None
    trace_id: str | None
    is_proxy: bool
    retry_count: int
    next_attempt_at: str | None
    last_failure_kind: str | None
    created_at: str
    updated_at: str


class QueuedJobRef(TypedDict):
    job_id: str
    address: str | None


class AnalyzeRemainingResponse(TypedDict):
    queued: int
    jobs: list[QueuedJobRef]


class CancelQueuedJobsResponse(TypedDict):
    company: str
    cancelled: int
    job_ids: list[str]


class DeleteCompanyAddressResponse(TypedDict):
    company: str
    address: str
    chain: str
    deleted: bool


class JobStageTimingsResponse(TypedDict):
    job_id: str
    stage_timings: dict[str, Any]


class TvlSummary(TypedDict):
    holdings_observed_at: str | None
    holdings_partial: bool | None
    valuation_partial: bool | None
    total_usd: float | None
    defillama_tvl: float | None
    source: str | None
    timestamp: str | None


class ReachBlock(TypedDict):
    model: str
    entities: dict[str, dict[str, Any]]


class CompanyOverviewResponse(TypedDict):
    """The four governance lists are dynamic and stay untyped."""

    company: str
    protocol_id: int | None
    contract_count: int
    tvl: NotRequired[TvlSummary | None]
    analysis_pending_balance_effects: NotRequired[dict[str, int]]
    contracts: list[dict[str, Any]]
    principals: list[dict[str, Any]]
    ownership_hierarchy: list[dict[str, Any]]
    fund_flows: list[dict[str, Any]]
    reach: ReachBlock
    all_addresses_count: int


class CompanyAddressesResponse(TypedDict):
    all_addresses: list[dict[str, Any]]


class CompanyFunctionsResponse(TypedDict):
    functions: dict[str, list[dict[str, Any]]]


class CompanyScoreResponse(TypedDict):
    """Score-document passthrough; consumers branch on ``grade_state``/``perimeter_state``."""

    company: str
    protocol_id: int
    score_id: int
    model_version: str
    computed_at: str | None
    trigger: str
    trigger_job_id: str | None
    grade_state: Any
    grade_lambda: Any
    grade_exposure: Any
    confidence_pct: Any
    perimeter_state: Any
    findings: Any
    earned_negatives: Any
    warnings: Any
    model_parameters: Any
    uncalibrated_arms: Any
    provenance: Any


class AuditReportDict(TypedDict):
    id: int
    url: str
    pdf_url: str | None
    auditor: str
    title: str
    date: str | None
    confidence: float | None
    text_extraction_status: str | None
    text_extracted_at: str | None
    text_size_bytes: int | None
    text_extraction_error: str | None
    has_text: bool
    scope_extraction_status: str | None
    scope_extracted_at: str | None
    scope_contract_count: int
    scope_extraction_error: str | None
    has_scope: bool
    reviewed_commits: list[Any]
    classified_commits: list[Any]
    referenced_repos: list[Any]


class AuditBrief(TypedDict):
    """Match keys appear together iff a coverage row was supplied; the ``coverage_source`` trio only on inherited
    rows.
    """

    audit_id: int
    auditor: str
    title: str
    date: str | None
    match_type: NotRequired[str | None]
    match_confidence: NotRequired[str | None]
    covered_from_block: NotRequired[int | None]
    covered_to_block: NotRequired[int | None]
    equivalence_status: NotRequired[str | None]
    equivalence_reason: NotRequired[str | None]
    equivalence_checked_at: NotRequired[str | None]
    proof_kind: NotRequired[str | None]
    matched_commit_sha: NotRequired[str | None]
    coverage_source: NotRequired[str]
    inherited_from_protocol: NotRequired[str | None]
    inherited_contract_address: NotRequired[str | None]
    # Only from services/aggregations/contract_audit_timeline.py.
    impl_address: NotRequired[str | None]
    bytecode_keccak_at_match: NotRequired[str | None]
    bytecode_keccak_now: NotRequired[str | None]
    bytecode_drift: NotRequired[bool | None]
    verified_at: NotRequired[str | None]
    live_findings: NotRequired[list[dict[str, Any]]]


class CompanyAuditsResponse(TypedDict):
    company: str
    protocol_id: int
    audit_count: int
    audits: list[AuditReportDict]


class AuditCoverageEntry(TypedDict):
    address: str | None
    chain: str | None
    contract_name: str | None
    audit_count: int
    last_audit: AuditBrief | None
    audits: list[AuditBrief]


class CompanyAuditCoverageResponse(TypedDict):
    company: str
    protocol_id: int
    contract_count: int
    audit_count: int
    scoped_audit_count: int
    coverage: list[AuditCoverageEntry]


class AuditScopeResponse(TypedDict):
    audit_id: int
    auditor: str
    title: str
    date: str | None
    contracts: list[Any]
    scope_extracted_at: str | None


class RefreshCoverageResponse(TypedDict):
    company: str
    protocol_id: int
    coverage_rows: int
    verify_source_equivalence: bool


class ReextractScopeResponse(TypedDict):
    audit_id: int
    reset: bool


class DeleteAuditResponse(TypedDict):
    audit_id: int
    deleted: bool


class MonitoredContractItem(TypedDict):
    """Shared by routers/monitored.py and the protocols listing."""

    id: str
    address: str
    chain: str
    contract_type: str
    protocol_id: int | None
    contract_id: int | None
    monitoring_config: dict[str, Any] | None
    last_known_state: dict[str, Any] | None
    last_poll_status: dict[str, Any] | None
    last_scanned_block: int
    enrollment_block: int | None
    needs_polling: bool
    is_active: bool
    enrollment_source: str | None
    created_at: str | None
    updated_at: str | None


class MonitoredEventItem(TypedDict):
    id: str
    monitored_contract_id: str
    event_type: str
    block_number: int
    tx_hash: str
    data: dict[str, Any] | None
    detected_at: str | None


class EnrolledContractBrief(TypedDict):
    id: str
    address: str
    contract_type: str
    monitoring_config: dict[str, Any] | None
    needs_polling: bool
    is_active: bool


class ReEnrollResponse(TypedDict):
    status: str
    protocol_id: int
    contracts_enrolled: int
    contracts: list[EnrolledContractBrief]


class SubscriptionItem(TypedDict):
    id: str
    protocol_id: int
    discord_webhook_url: str | None
    label: str | None
    event_filter: dict[str, Any] | None
    created_at: str | None
    # None for admin-created rows.
    owner_email: str | None


class TvlPoint(TvlSummary):
    pass


class TvlCurrent(TvlSummary):
    contract_breakdown: dict[str, Any] | None
    chain_breakdown: dict[str, Any] | None


class ProtocolTvlResponse(TypedDict):
    protocol_id: int
    protocol_name: str
    current: TvlCurrent
    history: list[TvlPoint]


class FleetStatusResponse(TypedDict):
    """Per-process entries are heterogeneous and stay untyped."""

    now: str
    # Status -> count, plus a nested "by_stage" dict.
    jobs: dict[str, Any]
    daemons: list[dict[str, Any]]
    watchers: dict[str, Any]


class PipelineStatsResponse(TypedDict):
    unique_addresses: int
    total_jobs: int
    completed_jobs: int
    failed_jobs: int


class AnalysisListEntry(TypedDict):
    """``display_name`` on every entry; ``proxy_*_display`` only on merged proxy rows."""

    run_name: str
    job_id: str
    address: str | None
    chain: str | None
    company: str | None
    parent_job_id: Any
    rank_score: float | None
    is_proxy: bool
    proxy_type: str | None
    implementation_address: str | None
    proxy_address: Any
    available_artifacts: list[str]
    contract_name: NotRequired[str]
    display_name: NotRequired[str]
    proxy_address_display: NotRequired[str | None]
    proxy_type_display: NotRequired[str | None]


class AddressLabelView(TypedDict):
    name: str
    note: str | None
    updated_at: str | None


class AddressLabelsResponse(TypedDict):
    labels: dict[str, AddressLabelView]
    chain_labels: dict[str, dict[str, AddressLabelView]]


class AddressLabelUpsertResponse(TypedDict):
    address: str
    chain: str | None
    name: str
    note: str | None
    updated_at: str | None


class AddressLabelDeleteResponse(TypedDict):
    address: str
    chain: str | None
    deleted: bool


class AddressTouch(TypedDict):
    address: str | None
    label: str | None
    function_count: int


class AddressTouchesResponse(TypedDict):
    address: str
    touches: list[AddressTouch]
