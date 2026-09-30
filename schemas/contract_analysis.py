from __future__ import annotations

from typing import Any, Literal, TypedDict

from typing_extensions import NotRequired

ControlModel = Literal["ownable", "role_control", "auth", "governance", "custom", "unknown"]
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
# Why an address is attached to a contract; only ``caller_gate`` is a control claim.
#
#   caller_gate  — a predicate requires the caller to equal / be in this address, or delegates its check to it.
#   call_target  — an ``external_call`` sink invokes it. Not proof it isn't a gate.
#
# Absent is not determined; never read it as either value.
ControllerProvenance = Literal["caller_gate", "call_target"]
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
    # Three states: ``None`` means the fetch fact didn't reach this run, which differs from ``False``. Flows to
    # ``contract_summaries.source_verified`` and the company API.
    source_verified: bool | None


class AnalysisStatus(TypedDict):
    static_analysis_completed: bool
    errors: list[str]


class Summary(TypedDict):
    # ``None`` = the detector didn't run or ran on emptied inputs. ``False``/``[]`` is a proven absence only as far as
    # the producer's ran-check covers every plane (per field; see ``_detect_pausability``).
    control_model: ControlModel
    is_upgradeable: bool
    is_pausable: bool | None
    has_timelock: bool | None
    standards: list[str] | None
    is_factory: bool | None
    is_nft: bool | None


class ContractClassification(TypedDict):
    # IR-derived and run on every parse, so ``[]``/``False`` are measured absences.
    standards: list[str]
    is_erc20: bool
    is_erc721: bool
    is_erc1155: bool
    is_nft: bool
    # ``None`` when the effects artifact is degraded.
    is_factory: bool | None
    factory_functions: list[str] | None
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
    # TypedDict can't forward-ref a sibling module.
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
    # ``None`` when the claims plane (the only detector for struct/namespaced latches) didn't run.
    is_pausable: bool | None
    pause_functions: list[str]
    unpause_functions: list[str]
    gating_modifiers: list[str]
    pause_variables: list[str]
    authorized_roles: list[str]
    evidence: list[Evidence]


class TimelockAnalysis(TypedDict):
    # ``None`` when there's no IR; never ``False`` for "didn't look".
    has_timelock: bool | None
    pattern: TimelockPattern
    # The value is a live read and this module has no chain, so always ``None`` with ``delay_source: "not_read"``; a
    # default would fabricate a protective credit.
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


class TrackingHint(TypedDict):
    kind: str
    label: str
    source: str


class AssociatedEventInput(TypedDict):
    name: str
    type: str
    indexed: bool


class EffectTags(TypedDict, total=False):
    """Structural side-effects over every emitter of an event, so the watcher classifies events without a
    controller_id lookup. ``delegates``: some emitter delegatecalls. ``is_initializer``: some emitter is
    ``initializer``/``reinitializer``, so unexpected re-inits trigger reanalysis.
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
    # Both absent unless proven (writer_openness.py):
    #
    #   member_witness   — proves the event's args carry the written entry's key (and value/direction if stated).
    #   writer_openness  — ``"restricted"`` when every path emitting it restricts the caller. Never ``"open"``: that
    # needs the resolution plane's earned-public projection.
    #
    # Together they let the watcher publish ``member_changed:<mapping_var>`` instead of bare activity.
    member_witness: dict[str, Any]
    writer_openness: str


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
    authority_provenance: NotRequired[ControllerProvenance]


class SecondaryImplPointer(TypedDict):
    """A proxy-storage slot the primary impl's fallback delegatecalls to (split-proxy, e.g.

    LRTSquared's ``adminImpl``). ``slot`` is a sequential layout slot or a full 256-bit unstructured constant. See
    secondary_impl.py.
    """

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
    tracking_hints: list[TrackingHint]
    controller_tracking: list[ControllerTrackingTarget]
    # Present only for the rare fallback-delegatecall-to-state-var shape.
    secondary_impl_pointers: NotRequired[list[SecondaryImplPointer]]
