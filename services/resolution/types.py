"""Schemas owned by resolution services."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Protocol, TypeAlias, TypedDict

from typing_extensions import NotRequired

from db.models import Job
from schemas.common import (
    Address,
    CapabilityKind,
    CapabilityMembershipQuality,
    ChainId,
    Contract,
    ContractStageRequest,
    JsonObject,
    StageArtifact,
)
from schemas.common import (
    CapabilityConfidence as SharedCapabilityConfidence,
)
from schemas.common import (
    CapabilitySubject as SharedCapabilitySubject,
)
from schemas.control_tracking import ControlSnapshot, ResolvedControllerType
from services.static.contract_analysis_pipeline.pipeline_types import PredicateSetDescriptor, StaticAnalysisArtifact
from utils.rpc import require_configured_erpc_url, require_supported_chain_id

ResolvedNodeType = Literal["contract", "principal"]
ResolvedEdgeRelation = Literal[
    "controller_value",
    "role_principal",
    "safe_owner",
    "timelock_owner",
    "proxy_admin_owner",
    "mapping_member",
]


class ResolvedGraphNode(TypedDict):
    id: str
    address: Address
    node_type: ResolvedNodeType
    resolved_type: ResolvedControllerType
    label: str
    contract_name: str | None
    contract: NotRequired[Contract | None]
    depth: int
    analyzed: bool
    details: dict[str, object]
    artifacts: dict[str, str]


class ResolvedGraphEdge(TypedDict):
    from_id: str
    to_id: str
    relation: ResolvedEdgeRelation
    label: str
    source_controller_id: str | None
    notes: list[str]


class ResolvedControlGraph(TypedDict):
    schema_version: str
    root_contract_address: Address
    max_depth: int
    nodes: list[ResolvedGraphNode]
    edges: list[ResolvedGraphEdge]


CapKind: TypeAlias = CapabilityKind
MembershipQuality: TypeAlias = CapabilityMembershipQuality
CapabilityConfidence: TypeAlias = SharedCapabilityConfidence
CapabilitySubject: TypeAlias = SharedCapabilitySubject


@dataclass(frozen=True)
class Condition:
    kind: Literal["time", "pause", "reentrancy", "business", "self_service"]
    description: str = ""
    parameter_index: int | None = None
    parameter_name: str | None = None


@dataclass(frozen=True)
class ExternalCheck:
    target_address: Address | None
    target_call_selector: str | None
    extra: dict[str, Any] = field(default_factory=dict)


def _canon_addresses(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in sorted(values, key=lambda item: item.lower() if isinstance(item, str) else str(item)):
        key = value.lower() if isinstance(value, str) else str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


@dataclass
class CapabilityExpr:
    kind: CapKind
    members: list[str] | None = None
    threshold: tuple[int, list[str]] | None = None
    blacklist: list[str] | None = None
    signer: "CapabilityExpr | None" = None
    check: ExternalCheck | None = None
    conditions: list[Condition] = field(default_factory=list)
    unsupported_reason: str | None = None
    children: list["CapabilityExpr"] = field(default_factory=list)
    membership_quality: MembershipQuality = MembershipQuality.EXACT
    confidence: CapabilityConfidence = CapabilityConfidence.ENUMERABLE
    last_indexed_block: int | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)
    subject: CapabilitySubject = "root"

    @classmethod
    def finite_set(
        cls,
        members: list[str],
        *,
        quality: MembershipQuality = MembershipQuality.EXACT,
        confidence: CapabilityConfidence = CapabilityConfidence.ENUMERABLE,
        conditions: list[Condition] | None = None,
        last_indexed_block: int | None = None,
        trace: list[dict[str, Any]] | None = None,
        subject: CapabilitySubject = "root",
    ) -> "CapabilityExpr":
        return cls(
            kind=CapKind.FINITE_SET,
            members=_canon_addresses(members),
            membership_quality=quality,
            confidence=confidence,
            conditions=list(conditions or []),
            last_indexed_block=last_indexed_block,
            trace=list(trace or []),
            subject=subject,
        )

    @classmethod
    def threshold_group(
        cls,
        m: int,
        signers: list[str],
        *,
        confidence: CapabilityConfidence = CapabilityConfidence.ENUMERABLE,
        conditions: list[Condition] | None = None,
    ) -> "CapabilityExpr":
        return cls(
            kind=CapKind.THRESHOLD_GROUP,
            threshold=(m, _canon_addresses(signers)),
            confidence=confidence,
            conditions=list(conditions or []),
        )

    @classmethod
    def cofinite_blacklist(
        cls,
        blacklist: list[str],
        *,
        confidence: CapabilityConfidence = CapabilityConfidence.ENUMERABLE,
        conditions: list[Condition] | None = None,
        subject: CapabilitySubject = "root",
    ) -> "CapabilityExpr":
        return cls(
            kind=CapKind.COFINITE_BLACKLIST,
            blacklist=_canon_addresses(blacklist),
            confidence=confidence,
            conditions=list(conditions or []),
            subject=subject,
        )

    @classmethod
    def signature_witness(
        cls,
        signer: "CapabilityExpr",
        *,
        conditions: list[Condition] | None = None,
    ) -> "CapabilityExpr":
        return cls(
            kind=CapKind.SIGNATURE_WITNESS,
            signer=signer,
            conditions=list(conditions or []),
            confidence=CapabilityConfidence.CHECK_ONLY,
        )

    @classmethod
    def external_check_only(
        cls,
        check: ExternalCheck,
        *,
        conditions: list[Condition] | None = None,
    ) -> "CapabilityExpr":
        return cls(
            kind=CapKind.EXTERNAL_CHECK_ONLY,
            check=check,
            confidence=CapabilityConfidence.CHECK_ONLY,
            conditions=list(conditions or []),
        )

    @classmethod
    def conditional_universal(cls, condition: Condition) -> "CapabilityExpr":
        return cls(
            kind=CapKind.CONDITIONAL_UNIVERSAL,
            conditions=[condition],
            confidence=CapabilityConfidence.ENUMERABLE,
        )

    @classmethod
    def unsupported(cls, reason: str) -> "CapabilityExpr":
        return cls(kind=CapKind.UNSUPPORTED, unsupported_reason=reason, confidence=CapabilityConfidence.CHECK_ONLY)

    @classmethod
    def structural_and(cls, children: list["CapabilityExpr"]) -> "CapabilityExpr":
        if len(children) == 1:
            return children[0]
        return cls(kind=CapKind.AND, children=list(children))

    @classmethod
    def structural_or(cls, children: list["CapabilityExpr"]) -> "CapabilityExpr":
        if len(children) == 1:
            return children[0]
        return cls(kind=CapKind.OR, children=list(children))


class Trit(Enum):
    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AdapterEnumerationResult:
    members: list[str] = field(default_factory=list)
    confidence: CapabilityConfidence = CapabilityConfidence.ENUMERABLE
    partial_reason: str | None = None
    last_indexed_block: int | None = None


@dataclass(frozen=True)
class CallFrame:
    protected_contract_address: Address | None = None
    executing_contract_address: Address | None = None
    current_function_signature: str | None = None
    current_function_selector: str | None = None
    current_msg_sender: str | None = None
    current_address_this: Address | None = None
    current_msg_sig: str | None = None
    bound_parameters: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def root(
        cls,
        *,
        contract_address: Address | None,
        function_signature: str | None,
        function_selector: str | None,
    ) -> "CallFrame":
        normalized = contract_address.lower() if isinstance(contract_address, str) else None
        return cls(
            protected_contract_address=normalized,
            executing_contract_address=normalized,
            current_function_signature=function_signature,
            current_function_selector=function_selector,
            current_msg_sender=None,
            current_address_this=normalized,
            current_msg_sig=function_selector,
        )


class EventLogRepo(Protocol):
    def fold_event_writes(
        self,
        *,
        chain_id: ChainId,
        event_address: Address,
        topic0: str,
        topics_to_keys: dict[int, int],
        data_to_keys: dict[int, int],
        key_sources: list[dict[str, Any]],
        direction: str,
        block: int | None = None,
    ) -> AdapterEnumerationResult: ...


class BytecodeRepo(Protocol):
    def has_selector(self, *, chain_id: ChainId, contract_address: Address, selector: str) -> bool: ...

    def declares_event(self, *, chain_id: ChainId, contract_address: Address, topic0: str) -> bool: ...


@dataclass
class EvaluationContext:
    chain_id: ChainId
    rpc_url: str
    block: int | None = None
    finality_depth: int = 12
    contract_address: Address | None = None
    event_log_repo: EventLogRepo | None = None
    bytecode: BytecodeRepo | None = None
    recursive_resolver: Any = None
    state_var_values: dict[str, str] | None = None
    session: Any = None
    evaluation_stack: set[tuple[int, str, str]] = field(default_factory=set)
    call_frame: CallFrame | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.chain_id = require_supported_chain_id(chain_id=self.chain_id, context="evaluation context")
        self.rpc_url = require_configured_erpc_url(
            self.rpc_url,
            context=f"evaluation context chain_id={self.chain_id}",
            chain_id=self.chain_id,
        )


AdapterSetDescriptor: TypeAlias = dict[Any, Any]


class SetAdapter(Protocol):
    @classmethod
    def matches(cls, descriptor: AdapterSetDescriptor, ctx: EvaluationContext) -> int: ...

    @classmethod
    def supports_external_check_only(cls) -> bool: ...

    def enumerate(self, descriptor: AdapterSetDescriptor, ctx: EvaluationContext) -> CapabilityExpr: ...


@dataclass
class AdapterRegistry:
    adapters: list[type[SetAdapter]] = field(default_factory=list)

    def register(self, adapter_cls: type[SetAdapter]) -> None:
        if adapter_cls in self.adapters:
            return
        self.adapters.append(adapter_cls)

    def pick(self, descriptor: AdapterSetDescriptor, ctx: EvaluationContext) -> type[SetAdapter] | None:
        best: tuple[int, type[SetAdapter]] | None = None
        for cls in self.adapters:
            score = cls.matches(descriptor, ctx)
            if score <= 0:
                continue
            if best is None or score > best[0]:
                best = (score, cls)
        return best[1] if best is not None else None

    def enumerate(self, descriptor: AdapterSetDescriptor, ctx: EvaluationContext) -> CapabilityExpr:
        adapter_cls = self.pick(descriptor, ctx)
        counters = ctx.meta.get("resolve_counters") if isinstance(ctx.meta, dict) else None
        if isinstance(counters, dict):
            name = adapter_cls.__name__ if adapter_cls is not None else "no_adapter"
            bucket = counters.setdefault("adapter_match", {})
            bucket[name] = bucket.get(name, 0) + 1
        if adapter_cls is None:
            return CapabilityExpr.unsupported("no_adapter")
        adapter = adapter_cls()
        return adapter.enumerate(descriptor, ctx)


@dataclass(frozen=True)
class AnalysisJobLookup:
    runtime_job: Job
    analysis_job: Job


class EnumeratedPrincipal(TypedDict):
    address: Address
    mapping_name: str
    direction_history: list[str]
    last_seen_block: int


class MappingEnumerationResult(TypedDict):
    principals: list[EnumeratedPrincipal]
    status: str
    pages_fetched: int
    last_block_scanned: int
    error: str | None


class EnumeratedKeyValue(TypedDict):
    key: str
    mapping_name: str
    value_hex: str
    last_block: int
    last_log_index: int


class EnumerationValueResult(TypedDict):
    entries: list[EnumeratedKeyValue]
    status: str
    pages_fetched: int
    last_block_scanned: int
    error: str | None


class PredicateEvaluatorSetAdapter(Protocol):
    def enumerate(self, descriptor: PredicateSetDescriptor, contract_address: Address | None) -> CapabilityExpr: ...


class _NullPredicateEvaluatorAdapter:
    def enumerate(self, descriptor: PredicateSetDescriptor, contract_address: Address | None) -> CapabilityExpr:
        return CapabilityExpr.finite_set(
            [],
            quality=MembershipQuality.LOWER_BOUND,
            confidence=CapabilityConfidence.PARTIAL,
        )


class PredicateEvaluationContext:
    def __init__(
        self,
        *,
        contract_address: Address | None = None,
        adapter: PredicateEvaluatorSetAdapter | None = None,
        block: int | None = None,
        state_var_values: dict[str, str] | None = None,
        call_frame: Any = None,
    ) -> None:
        self.contract_address = contract_address
        self.adapter: PredicateEvaluatorSetAdapter = adapter or _NullPredicateEvaluatorAdapter()
        self.block = block
        self.state_var_values = state_var_values or {}
        self.call_frame = call_frame


class LoadedArtifacts(TypedDict):
    analysis: JsonObject
    tracking_plan: JsonObject
    snapshot: ControlSnapshot
    predicate_trees: NotRequired[JsonObject | None]
    effective_permissions: NotRequired[JsonObject | None]


class AddressClassification(TypedDict):
    resolved_type: ResolvedControllerType
    details: JsonObject


class ResolutionRequest(TypedDict):
    static_analysis: StaticAnalysisArtifact
    block_number: NotRequired[int | None]


class ResolutionPayload(TypedDict):
    control_snapshot: ControlSnapshot
    resolved_control_graph: ResolvedControlGraph
    nested_artifacts: dict[Address, LoadedArtifacts]
    classified_addresses: NotRequired[dict[Address, AddressClassification]]


ResolutionStageRequest = ContractStageRequest[ResolutionRequest]
ResolutionArtifact = StageArtifact[ResolutionPayload]


class PendingContract(TypedDict):
    address: Address
    depth: int
    contract: NotRequired[Contract]
    artifacts: NotRequired[LoadedArtifacts]


class RolePrincipalAccumulator(TypedDict):
    address: Address
    resolved_type: str
    details: dict[str, object]
    roles: set[int]
    functions: set[str]


class RolePrincipal(TypedDict):
    address: Address
    resolved_type: str
    details: dict[str, object]
    roles: list[int]
    functions: list[str]


@dataclass(frozen=True)
class FetchedEventLog:
    tx_hash: bytes
    log_index: int
    block_number: int
    block_hash: bytes
    transaction_index: int
    topics: list[str]
    data_words: list[str]


__all__ = [
    "AdapterEnumerationResult",
    "AdapterRegistry",
    "AdapterSetDescriptor",
    "AddressClassification",
    "AnalysisJobLookup",
    "BytecodeRepo",
    "CallFrame",
    "CapKind",
    "CapabilityConfidence",
    "CapabilityExpr",
    "CapabilitySubject",
    "Condition",
    "EnumeratedKeyValue",
    "EnumeratedPrincipal",
    "EnumerationValueResult",
    "EvaluationContext",
    "EventLogRepo",
    "ExternalCheck",
    "FetchedEventLog",
    "LoadedArtifacts",
    "MappingEnumerationResult",
    "MembershipQuality",
    "PendingContract",
    "PredicateEvaluationContext",
    "PredicateEvaluatorSetAdapter",
    "ResolutionArtifact",
    "ResolutionPayload",
    "ResolutionRequest",
    "ResolutionStageRequest",
    "RolePrincipal",
    "RolePrincipalAccumulator",
    "ResolvedControlGraph",
    "ResolvedEdgeRelation",
    "ResolvedGraphEdge",
    "ResolvedGraphNode",
    "ResolvedNodeType",
    "SetAdapter",
    "Trit",
]
