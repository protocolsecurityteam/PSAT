"""Schemas owned by policy services."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal, TypeAlias, TypedDict

from typing_extensions import NotRequired

from schemas.common import (
    Address,
    Capability,
    Contract,
    ContractStageRequest,
    FunctionSurface,
    JsonObject,
    OnChainPrincipalType,
    StageArtifact,
)
from schemas.control_tracking import ResolvedControllerType

if TYPE_CHECKING:
    from services.resolution.types import ResolutionArtifact, ResolvedControlGraph
    from services.static.contract_analysis_pipeline.pipeline_types import StaticAnalysisArtifact

ResolvedAddressType: TypeAlias = OnChainPrincipalType
EffectiveFunctionStatus = Literal["public", "unsupported", "resolved_empty"]
CapabilityResolverOutput: TypeAlias = dict[str, Capability]
CapabilityCondition: TypeAlias = JsonObject
PrincipalResolutionStatus = Literal[
    "complete",
    "no_authority",
    "no_authority_snapshot",
]


class PrincipalResolution(TypedDict):
    status: PrincipalResolutionStatus
    reason: str


class ResolvedPrincipal(TypedDict):
    address: Address
    resolved_type: ResolvedAddressType
    details: dict[str, object]
    source_contract: NotRequired[str]
    source_controller_id: NotRequired[str]
    principal_type: NotRequired[str]


class AuthorityRoleGrant(TypedDict):
    role: int
    principals: list[ResolvedPrincipal]


class ResolvedControllerGrant(TypedDict):
    controller_id: str
    label: str
    source: str
    kind: str
    principals: list[ResolvedPrincipal]
    notes: list[str]


class EffectiveFunctionPermission(FunctionSurface):
    direct_owner: ResolvedPrincipal | None
    authority_public: bool
    authority_roles: list[AuthorityRoleGrant]
    controllers: list[ResolvedControllerGrant]
    notes: list[str]
    capability_expr: NotRequired[Capability]
    conditions: NotRequired[list[CapabilityCondition]]
    status: NotRequired[EffectiveFunctionStatus]
    signature_witnesses: NotRequired[list[ResolvedPrincipal]]


class EffectivePermissions(TypedDict):
    schema_version: str
    contract: Contract
    contract_address: Address
    contract_name: str
    authority_contract: Address | None
    principal_resolution: PrincipalResolution
    artifacts: dict[str, str]
    functions: list[EffectiveFunctionPermission]


LabelConfidence = Literal["high", "medium", "low"]


class PrincipalPermission(TypedDict):
    function: str
    effect_labels: list[str]
    role: int | None
    authority_public: bool
    controller: NotRequired[str]


class PrincipalProfile(TypedDict):
    address: Address
    resolved_type: ResolvedControllerType
    display_name: str
    labels: list[str]
    confidence: LabelConfidence
    details: dict[str, object]
    graph_context: list[str]
    controller_context: list[str]
    permissions: list[PrincipalPermission]


class PrincipalLabels(TypedDict):
    schema_version: str
    contract: Contract
    contract_address: Address
    contract_name: str
    principals: list[PrincipalProfile]


class PolicyRequest(TypedDict):
    static_analysis: StaticAnalysisArtifact
    resolution: ResolutionArtifact
    capability_resolver_output: NotRequired[CapabilityResolverOutput | None]


class PolicyPayload(TypedDict):
    effective_permissions: EffectivePermissions
    principal_labels: PrincipalLabels
    resolved_control_graph: ResolvedControlGraph | None
    principal_history: NotRequired[JsonObject | None]


PolicyStageRequest = ContractStageRequest[PolicyRequest]
PolicyArtifact = StageArtifact[PolicyPayload]


@dataclass
class CapabilitySurface:
    principal_rows: list[dict[str, Any]] = field(default_factory=list)
    public_paths: list[list[dict[str, Any]]] = field(default_factory=list)
    residual: list[dict[str, Any]] = field(default_factory=list)

    @property
    def authority_public(self) -> bool:
        return bool(self.public_paths)

    @property
    def conditions(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for row in self.principal_rows:
            details = row.get("details")
            if isinstance(details, dict):
                out.extend(_capability_surface_condition_dicts(details.get("conditions")))
        for path in self.public_paths:
            out.extend(path)
        return _capability_surface_unique_conditions(out)


def _capability_surface_condition_dicts(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [{key: value for key, value in item.items() if value is not None} for item in raw if isinstance(item, dict)]


def _capability_surface_unique_conditions(conditions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for condition in conditions:
        key = repr(sorted(condition.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(condition))
    return out


__all__ = [
    "AuthorityRoleGrant",
    "CapabilityResolverOutput",
    "CapabilitySurface",
    "EffectiveFunctionPermission",
    "EffectiveFunctionStatus",
    "EffectivePermissions",
    "LabelConfidence",
    "PrincipalLabels",
    "PrincipalPermission",
    "PrincipalProfile",
    "PrincipalResolution",
    "PrincipalResolutionStatus",
    "PolicyArtifact",
    "PolicyPayload",
    "PolicyRequest",
    "PolicyStageRequest",
    "ResolvedAddressType",
    "ResolvedControllerGrant",
    "ResolvedPrincipal",
]
