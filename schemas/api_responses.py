"""Static response shapes for the JSON endpoints in ``routers/``.

Checking-only: these annotate handler RETURN TYPES so pyright verifies what a
handler builds. They are deliberately NOT wired as FastAPI ``response_model=``
— that would prune undeclared keys from the wire at runtime, and the SPA reads
these payloads as-is. FastAPI also INFERS a response model from a bare return
annotation, so every route annotated with one of these types must pass
``response_model=None`` in its decorator — without it the framework validates
and prunes exactly as if the model had been declared.

Depth is honest, not aspirational: a field is typed only as precisely as the
producing code proves. Interior payloads assembled dynamically elsewhere stay
``dict[str, Any]``; a wrong deep shape would be worse than an absent one.
"""

from __future__ import annotations

from typing import Any

# typing_extensions (not typing): pydantic refuses typing.TypedDict on
# Python < 3.12, and FastAPI feeds these to pydantic when building docs.
from typing_extensions import NotRequired, TypedDict

# ---------------------------------------------------------------------------
# Jobs (db.models.Job.to_dict)
# ---------------------------------------------------------------------------


class JobDict(TypedDict):
    """Serialized Job row — the shape of ``Job.to_dict()``."""

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


# ---------------------------------------------------------------------------
# Company overview + sub-payloads (routers/company.py)
# ---------------------------------------------------------------------------


class TvlSummary(TypedDict):
    total_usd: float | None
    defillama_tvl: float | None
    source: str | None
    timestamp: str


class ReachBlock(TypedDict):
    model: str
    entities: dict[str, dict[str, Any]]


class CompanyOverviewResponse(TypedDict):
    """Top level of ``assemble_company_payload``. The four governance lists are
    dynamic aggregations (``GovernanceView``) and stay untyped inside."""

    company: str
    protocol_id: int | None
    contract_count: int
    tvl: TvlSummary | None
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
    """Score-ledger passthrough: the ``grade_*``/finding fields come verbatim
    from the persisted score document and are consumed by branching on
    ``grade_state``/``perimeter_state`` — no shape promise beyond presence."""

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


# ---------------------------------------------------------------------------
# Audits (services/audits/serializers + routers/audits.py, routers/company.py)
# ---------------------------------------------------------------------------


class AuditReportDict(TypedDict):
    """Serialized AuditReport row — the shape of ``_audit_report_to_dict``."""

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
    """Compact audit dict from ``_audit_brief``. The match keys appear
    together iff a coverage row was supplied; the ``coverage_source`` trio is
    stamped only on inherited rows (routers/company.py)."""

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


# ---------------------------------------------------------------------------
# Monitoring (routers/monitored.py, routers/protocols.py)
# ---------------------------------------------------------------------------


class MonitoredContractBrief(TypedDict):
    """The per-row keys ``/api/protocols/{id}/monitoring`` serializes."""

    id: str
    address: str
    chain: str
    contract_type: str
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


class MonitoredContractItem(MonitoredContractBrief):
    """``routers/monitored.py``'s serializer — the brief plus row linkage.

    Two serializers exist for the same row type; see LANE_API notes on the
    key-set divergence before unifying."""

    protocol_id: int | None
    contract_id: int | None


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


class TvlPoint(TypedDict):
    timestamp: str
    total_usd: float | None
    defillama_tvl: float | None
    source: str | None


class TvlCurrent(TypedDict):
    total_usd: float | None
    defillama_tvl: float | None
    source: str | None
    timestamp: str | None
    contract_breakdown: dict[str, Any] | None
    chain_breakdown: dict[str, Any] | None


class ProtocolTvlResponse(TypedDict):
    protocol_id: int
    protocol_name: str
    current: TvlCurrent
    history: list[TvlPoint]


# ---------------------------------------------------------------------------
# Fleet / stats (routers/fleet.py, routers/meta.py)
# ---------------------------------------------------------------------------


class FleetStatusResponse(TypedDict):
    """Top level of ``build_fleet_status``; the per-process entries are
    heterogeneous operator telemetry and stay untyped inside."""

    now: str
    jobs: dict[str, int]
    daemons: list[dict[str, Any]]
    watchers: dict[str, Any]


class PipelineStatsResponse(TypedDict):
    unique_addresses: int
    total_jobs: int
    completed_jobs: int
    failed_jobs: int


# ---------------------------------------------------------------------------
# Analyses listing (routers/analyses.py)
# ---------------------------------------------------------------------------


class AnalysisListEntry(TypedDict):
    """One row of ``/api/analyses`` after the proxy/impl merge.

    ``display_name`` is stamped by ``_merge_proxy_impl_entries`` on every
    entry; the ``proxy_*_display`` pair only on merged proxy rows."""

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


# ---------------------------------------------------------------------------
# Address labels (routers/address_labels.py)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Agent sidebar (routers/agent.py)
# ---------------------------------------------------------------------------


class AddressTouch(TypedDict):
    address: str | None
    label: str | None
    function_count: int


class AddressTouchesResponse(TypedDict):
    address: str
    touches: list[AddressTouch]
