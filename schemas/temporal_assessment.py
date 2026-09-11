"""Enums and row-shaped transport records for the temporal Assessment store.

The database migration is the schema authority.  These declarations deliberately
carry no schema-version field.  Every controlled category is an enum; addresses,
hashes, timestamps, messages, and identifiers remain data.
"""

from __future__ import annotations

import enum
from typing import Any, TypedDict


class StringEnum(str, enum.Enum):
    """A JSON- and SQL-friendly enum with stable explicit values."""


class SubjectKind(StringEnum):
    address = "address"
    code = "code"
    function = "function"
    controller = "controller"
    role = "role"
    proposal = "proposal"
    operation = "operation"


class SubjectRole(StringEnum):
    contract = "contract"
    function = "function"
    controller = "controller"
    entity = "entity"
    role = "role"
    proposal = "proposal"
    operation = "operation"


class EvidenceKind(StringEnum):
    chain_read = "chain_read"
    chain_event = "chain_event"
    artifact = "artifact"
    execution = "execution"
    external = "external"


class ExecutionEnvironment(StringEnum):
    chain = "chain"
    fork = "fork"
    model = "model"


class ScopeKind(StringEnum):
    code = "code"
    point = "point"
    interval = "interval"
    scenario = "scenario"
    reported = "reported"  # imported report lacks a canonical block hash


class ClaimKind(StringEnum):
    function_effect = "function_effect"
    function_authority = "function_authority"
    authority_capability = "authority_capability"
    authority_relationship = "authority_relationship"
    entity_classification = "entity_classification"
    deployment_code = "deployment_code"
    implementation = "implementation"
    role_membership = "role_membership"
    configuration = "configuration"
    proposal_contents = "proposal_contents"
    proposal_state = "proposal_state"
    proposal_timing = "proposal_timing"
    proposal_quorum = "proposal_quorum"
    operation_state = "operation_state"
    operation_timing = "operation_timing"
    applied_configuration = "applied_configuration"
    dependency = "dependency"


class AnalysisProducer(StringEnum):
    static = "static"
    observation = "observation"
    resolution = "resolution"
    policy = "policy"
    principal = "principal"
    execution = "execution"
    governance = "governance"
    scenario = "scenario"
    correction = "correction"
    migration = "migration"


class AnalysisOutcome(StringEnum):
    completed = "completed"
    partial = "partial"
    failed = "failed"


class ContextKind(StringEnum):
    observed = "observed"
    scenario = "scenario"


class CoverageKind(StringEnum):
    code = "code"
    state_reads = "state_reads"
    events = "events"
    authority = "authority"
    effects = "effects"
    configuration = "configuration"
    proposal_lifecycle = "proposal_lifecycle"
    operation_lifecycle = "operation_lifecycle"
    scenario_actions = "scenario_actions"


class CoverageCompleteness(StringEnum):
    complete = "complete"
    partial = "partial"
    unknown = "unknown"


class DiagnosticSeverity(StringEnum):
    info = "info"
    degraded = "degraded"
    error = "error"


class DiagnosticCode(StringEnum):
    invalid_input = "invalid_input"
    missing_evidence = "missing_evidence"
    unsupported_code = "unsupported_code"
    unsupported_parameter = "unsupported_parameter"
    unsupported_clock = "unsupported_clock"
    unresolved_identity = "unresolved_identity"
    unresolved_authority = "unresolved_authority"
    unresolved_target = "unresolved_target"
    incomplete_coverage = "incomplete_coverage"
    conflicting_evidence = "conflicting_evidence"
    rpc_failure = "rpc_failure"
    source_unavailable = "source_unavailable"
    execution_failure = "execution_failure"
    analysis_failure = "analysis_failure"
    scope_mismatch = "scope_mismatch"
    stale_baseline = "stale_baseline"
    orphaned_block = "orphaned_block"
    pipeline_diagnostic = "pipeline_diagnostic"


class CorrectionTargetKind(StringEnum):
    evidence = "evidence"
    claim = "claim"


class CorrectionReason(StringEnum):
    reorg = "reorg"
    invalid_observation = "invalid_observation"
    wrong_subject = "wrong_subject"
    rule_error = "rule_error"
    incomplete_basis = "incomplete_basis"


class ConfigurationParameter(StringEnum):
    owner = "owner"
    pending_owner = "pending_owner"
    minimum_delay = "minimum_delay"
    voting_delay = "voting_delay"
    voting_period = "voting_period"
    proposal_threshold = "proposal_threshold"
    quorum_rule = "quorum_rule"
    safe_signers = "safe_signers"
    safe_threshold = "safe_threshold"
    role_access = "role_access"


class ClockKind(StringEnum):
    block_number = "block_number"
    timestamp = "timestamp"
    custom = "custom"


class QuorumRuleKind(StringEnum):
    absolute = "absolute"
    fraction = "fraction"
    function = "function"


class BindingPhase(StringEnum):
    creation = "creation"
    snapshot = "snapshot"
    schedule = "schedule"
    execution = "execution"


class ProposalState(StringEnum):
    pending = "pending"
    active = "active"
    succeeded = "succeeded"
    defeated = "defeated"
    queued = "queued"
    executed = "executed"
    cancelled = "cancelled"
    expired = "expired"
    vetoed = "vetoed"


class OperationState(StringEnum):
    scheduled = "scheduled"
    ready = "ready"
    executed = "executed"
    cancelled = "cancelled"
    expired = "expired"


class SetCompleteness(StringEnum):
    exact = "exact"
    lower_bound = "lower_bound"


class ActionKind(StringEnum):
    call = "call"
    deploy = "deploy"


class DerivationRule(StringEnum):
    function_effect = "function_effect"
    function_authority = "function_authority"
    authority_capability = "authority_capability"
    authority_relationship = "authority_relationship"
    entity_classification = "entity_classification"
    deployment_code = "deployment_code"
    implementation_binding = "implementation_binding"
    role_membership = "role_membership"
    configuration = "configuration"
    proposal_contents = "proposal_contents"
    proposal_state = "proposal_state"
    proposal_timing = "proposal_timing"
    proposal_quorum = "proposal_quorum"
    operation_state = "operation_state"
    operation_timing = "operation_timing"
    applied_configuration = "applied_configuration"
    dependency = "dependency"
    historical_interval = "historical_interval"
    scenario_transition = "scenario_transition"
    imported = "imported"


class TemporalSubjectDict(TypedDict):
    id: str
    recorded_at: str
    kind: SubjectKind
    identity: dict[str, Any]


class TemporalEvidenceDict(TypedDict):
    id: str
    recorded_at: str
    subject: str
    kind: EvidenceKind
    source: dict[str, Any]
    payload: str
    obtained_at: str
    chain_id: int | None
    block_number: str | None
    block_hash: str | None
    transaction_hash: str | None
    transaction_index: int | None
    log_index: int | None


class TemporalClaimDict(TypedDict):
    id: str
    recorded_at: str
    subject: str
    kind: ClaimKind
    proposition: dict[str, Any]
    scope_kind: ScopeKind
    scope: dict[str, Any]
    rule: DerivationRule
    evidence: list[str]
    claims: list[str]


class TemporalAnalysisDict(TypedDict):
    id: str
    recorded_at: str
    producer: AnalysisProducer
    implementation: str
    context: str
    started_at: str
    finished_at: str
    outcome: AnalysisOutcome
    receipt: dict[str, Any]
    inputs: dict[str, list[str]]
    outputs: list[str]
    coverage: list[dict[str, Any]]
    diagnostics: list[dict[str, Any]]


class TemporalCorrectionDict(TypedDict):
    id: str
    recorded_at: str
    analysis: str
    target_kind: CorrectionTargetKind
    target: str
    reason: CorrectionReason
    detail: dict[str, Any]


class TemporalContextDict(TypedDict):
    id: str
    recorded_at: str
    kind: ContextKind
    context: dict[str, Any]


class TemporalImplementationDict(TypedDict):
    id: str
    recorded_at: str
    producer: AnalysisProducer
    manifest: dict[str, Any]


class TemporalPayloadDict(TypedDict):
    id: str
    recorded_at: str
    media_type: str
    byte_length: int


class TemporalAssessmentDict(TypedDict):
    view: dict[str, Any]
    subjects: list[TemporalSubjectDict]
    evidence: list[TemporalEvidenceDict]
    claims: list[TemporalClaimDict]
    analyses: list[TemporalAnalysisDict]
    corrections: list[TemporalCorrectionDict]
    contexts: list[TemporalContextDict]
    implementations: list[TemporalImplementationDict]
    payloads: list[TemporalPayloadDict]


__all__ = [
    "AnalysisOutcome",
    "AnalysisProducer",
    "ActionKind",
    "BindingPhase",
    "ClaimKind",
    "ClockKind",
    "ConfigurationParameter",
    "ContextKind",
    "CorrectionReason",
    "CorrectionTargetKind",
    "CoverageCompleteness",
    "CoverageKind",
    "DerivationRule",
    "DiagnosticCode",
    "DiagnosticSeverity",
    "EvidenceKind",
    "ExecutionEnvironment",
    "OperationState",
    "ProposalState",
    "QuorumRuleKind",
    "ScopeKind",
    "StringEnum",
    "SetCompleteness",
    "SubjectKind",
    "SubjectRole",
    "TemporalAnalysisDict",
    "TemporalAssessmentDict",
    "TemporalClaimDict",
    "TemporalCorrectionDict",
    "TemporalContextDict",
    "TemporalEvidenceDict",
    "TemporalImplementationDict",
    "TemporalPayloadDict",
    "TemporalSubjectDict",
]
