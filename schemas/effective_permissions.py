"""Typed schemas for resolved effective-permission outputs."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from typing_extensions import NotRequired

ResolvedAddressType = Literal[
    "zero", "eoa", "safe", "timelock", "proxy_admin", "contract", "unknown", "cross_chain_authority"
]
EffectiveFunctionStatus = Literal["public", "unsupported", "resolved_empty"]
PrincipalResolutionStatus = Literal[
    "complete",
    "no_authority",
    "no_authority_snapshot",
]


class PrincipalResolution(TypedDict):
    status: PrincipalResolutionStatus
    reason: str


class ResolvedPrincipal(TypedDict):
    address: str
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


class EffectiveFunctionPermission(TypedDict):
    function: str
    abi_signature: str
    selector: str
    direct_owner: ResolvedPrincipal | None
    authority_public: bool
    authority_roles: list[AuthorityRoleGrant]
    controllers: list[ResolvedControllerGrant]
    effect_targets: list[str]
    effect_labels: list[str]
    # Plane-1 claims dual-written alongside effect_labels: {claim_id, tier, witness}.
    claims: NotRequired[list[dict[str, Any]]]
    action_summary: str
    notes: list[str]
    capability_expr: NotRequired[dict[str, Any]]
    conditions: NotRequired[list[dict[str, Any]]]
    status: NotRequired[EffectiveFunctionStatus]
    signature_witnesses: NotRequired[list[ResolvedPrincipal]]


class EffectivePermissions(TypedDict):
    schema_version: str
    contract_address: str
    contract_name: str
    authority_contract: str | None
    principal_resolution: PrincipalResolution
    artifacts: dict[str, str]
    functions: list[EffectiveFunctionPermission]
