"""Typed schemas for contract analysis output."""

from __future__ import annotations

from typing import Literal, TypedDict

from typing_extensions import NotRequired

ControlModel = Literal["ownable", "role_control", "auth", "governance", "custom", "unknown"]
RiskLevel = Literal["low", "medium", "high", "unknown"]
UpgradeabilityPattern = Literal["uups", "transparent", "beacon", "custom", "none", "unknown"]
TimelockPattern = Literal["oz_timelock", "governor_timelock", "custom", "none", "unknown"]
CurrentHoldersStatus = Literal["unknown_static_only"]
ControllerTrackingMode = Literal["event_plus_state", "state_only", "manual_review"]
ControllerKind = Literal[
    "state_variable",
    "mapping_membership",
    "external_contract",
    "role_identifier",
    "singleton_slot",
    "external_policy",
    "computed",
    "unknown",
]
GuardKind = Literal[
    "caller_equals_storage",
    "caller_in_mapping",
    "external_authority_check",
    "role_membership_check",
    "caller_via_helper_function",
    "unknown",
]
SinkKind = Literal["state_write", "contract_creation", "external_call", "delegatecall", "selfdestruct"]
ControllerReadStrategy = Literal["getter_call", "storage_slot", "mapping_lookup", "event_reconstruction", "unknown"]
ControllerConfidence = Literal["exact", "high", "medium", "low", "unknown"]


class Evidence(TypedDict, total=False):
    file: str
    line: int
    detail: str


class Subject(TypedDict):
    address: str
    name: str
    compiler_version: str
    source_verified: bool


class AnalysisStatus(TypedDict):
    static_analysis_completed: bool
    slither_completed: bool
    errors: list[str]


class Summary(TypedDict):
    # Every evidence field here is nullable, and ``None`` always means the
    # detector did not run — never "it ran and found nothing", which is
    # ``False`` / ``[]``. ``contract_summaries`` has been nullable on all of
    # them since the baseline migration; the producer is what emitted a
    # proven-absence on 100% of rows regardless.
    control_model: ControlModel
    is_upgradeable: bool
    is_pausable: bool | None
    has_timelock: bool | None
    static_risk_level: RiskLevel | None
    standards: list[str] | None
    is_factory: bool | None
    is_nft: bool | None


class ContractClassification(TypedDict):
    standards: list[str]
    is_erc20: bool
    is_erc721: bool
    is_erc1155: bool
    is_nft: bool
    is_factory: bool
    factory_functions: list[str]
    evidence: list[Evidence]


class RoleDefinition(TypedDict):
    role: str
    declared_in: str
    evidence: list[Evidence]


class SemanticFunctionSummary(TypedDict):
    contract: str
    function: str
    visibility: str
    guards: list[str]
    guard_kinds: list[GuardKind]
    controller_refs: list[str]
    controller_ids: NotRequired[list[str]]
    sink_ids: list[str]
    effects: list[str]
    effect_targets: list[str]
    effect_labels: list[str]
    action_summary: str


class CurrentHolders(TypedDict):
    status: CurrentHoldersStatus


class SemanticControlAnalysis(TypedDict):
    pattern: ControlModel
    owner_variables: list[str]
    admin_variables: list[str]
    role_definitions: list[RoleDefinition]
    semantic_functions: list[SemanticFunctionSummary]
    current_holders: CurrentHolders
    # WriterEventSpec entries (shape in mapping_events.py). Kept as
    # list[dict] because TypedDict can't forward-ref a sibling module.
    mapping_writer_events: NotRequired[list[dict]]


class UpgradeabilityAnalysis(TypedDict):
    is_upgradeable: bool
    is_upgradeable_proxy: bool
    pattern: UpgradeabilityPattern
    upgradeable_version: str | None
    implementation_slots: list[str]
    admin_paths: list[str]
    evidence: list[Evidence]


class PausabilityAnalysis(TypedDict):
    # ``None`` = not determined (the claims plane, the only detector that
    # resolves a struct-member / namespaced latch, did not run). Distinct from
    # ``False``, which is a proven absence.
    is_pausable: bool | None
    pause_functions: list[str]
    unpause_functions: list[str]
    gating_modifiers: list[str]
    pause_variables: list[str]
    authorized_roles: list[str]
    evidence: list[Evidence]


class TimelockAnalysis(TypedDict):
    # ``None`` = not determined (no IR to walk). Never ``False`` for "we did
    # not look".
    has_timelock: bool | None
    pattern: TimelockPattern
    # The delay VALUE is a live read (``getMinDelay()``) and this module has no
    # chain: ``delay`` is always ``None`` with ``delay_source: "not_read"``
    # until one is threaded. A defaulted delay would fabricate a protective
    # credit. ``delay_variables`` names where the value lives, which is what
    # source alone can prove.
    delay: int | None
    delay_source: Literal["not_read", "chain_read"]
    delay_variables: list[str]
    queue_execute_functions: list[str]
    authorized_roles: list[str]
    evidence: list[Evidence]


class AuditAlignment(TypedDict):
    status: str
    bytecode_match: str
    notes: list[str]


class SlitherFinding(TypedDict):
    check: str
    impact: str
    confidence: str
    description: str


class SlitherSummary(TypedDict):
    detector_counts: dict[str, int]
    key_findings: list[SlitherFinding]


class TrackingHint(TypedDict):
    kind: str
    label: str
    source: str


class AssociatedEventInput(TypedDict):
    name: str
    type: str
    indexed: bool


class EffectTags(TypedDict, total=False):
    """Structural side-effect summary for the union of functions that emit
    an event. Populated by ``_writer_records_from_effects`` from the
    ``effects`` artifact.

    The watcher uses these tags to classify events without relying on a
    controller_id → event_type lookup. ``writes`` is the union of
    state-variable names mutated by any emitter; ``delegates`` is True
    when any emitter contains a DELEGATECALL sink (i.e. the event signals
    a delegate-target swap). ``is_initializer`` flags the OZ
    Initializable pattern — any emitter modified by ``initializer`` /
    ``reinitializer`` — so the watcher can fire reanalysis on unexpected
    re-inits without a hand-rolled Initialized topic.
    """

    writes: list[str]
    delegates: bool
    is_initializer: bool


class AssociatedEventRequired(TypedDict):
    name: str
    signature: str
    topic0: str
    inputs: list[AssociatedEventInput]


class AssociatedEvent(AssociatedEventRequired, total=False):
    effect_tags: EffectTags


class ControllerTypeComponent(TypedDict):
    name: str
    type: str
    abi_type: str
    type_kind: str


class ControllerReadSpecRequired(TypedDict):
    strategy: ControllerReadStrategy
    target: str


class ControllerReadSpec(ControllerReadSpecRequired, total=False):
    kind: str
    state_variable_name: str
    type: str
    type_kind: str
    parent_type: str
    member_path: list[str]
    components: list[ControllerTypeComponent]


class ControllerWriterFunction(TypedDict):
    contract: str
    function: str
    visibility: str
    writes: list[str]
    associated_events: list[AssociatedEvent]
    evidence: list[Evidence]


class ControllerTrackingTarget(TypedDict):
    controller_id: str
    label: str
    source: str
    kind: ControllerKind
    read_spec: ControllerReadSpec | None
    confidence: ControllerConfidence | None
    tracking_mode: ControllerTrackingMode
    writer_functions: list[ControllerWriterFunction]
    associated_events: list[AssociatedEvent]
    polling_sources: list[str]
    notes: list[str]


class SecondaryImplPointer(TypedDict):
    """A storage slot the primary impl's fallback/receive delegatecalls the value
    of — the split-proxy / admin-impl pattern (e.g. LRTSquared's ``adminImpl``).
    ``slot``/``offset`` locate it in the proxy's storage so the value (the
    secondary impl address) can be read from there. ``slot`` is an ``int``: a
    small sequential layout slot for a named ``address`` var, or the full 256-bit
    constant for an unstructured (EIP-1967-style) slot. See
    services/static/contract_analysis_pipeline/secondary_impl.py."""

    name: str
    slot: int
    offset: int


class ContractAnalysis(TypedDict):
    schema_version: str
    subject: Subject
    analysis_status: AnalysisStatus
    summary: Summary
    contract_classification: ContractClassification
    semantic_control: SemanticControlAnalysis
    upgradeability: UpgradeabilityAnalysis
    pausability: PausabilityAnalysis
    timelock: TimelockAnalysis
    audit_alignment: AuditAlignment
    slither: SlitherSummary
    tracking_hints: list[TrackingHint]
    controller_tracking: list[ControllerTrackingTarget]
    # Split-proxy secondary-impl pointers detected on the primary impl. Optional
    # (present only for the rare fallback-delegatecall-to-state-var shape);
    # consumed by the static worker to analyse those logic contracts against
    # proxy storage.
    secondary_impl_pointers: NotRequired[list[SecondaryImplPointer]]
