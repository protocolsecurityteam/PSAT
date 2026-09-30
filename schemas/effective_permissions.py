from __future__ import annotations

from typing import Any, Literal, TypedDict

from typing_extensions import NotRequired

from .control_tracking import ResolvedControllerType

# One vocabulary with ``schemas.control_tracking``: persisted rows carry ``off_chain_witness``.
ResolvedAddressType = ResolvedControllerType
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
    # ``None`` when the signature couldn't be fully lowered; a hash of an unlowered type is no selector.
    selector: str | None
    direct_owner: ResolvedPrincipal | None
    authority_public: bool
    # Absent (producer couldn't say) is a fourth state; don't fold it into ``not_determined``.
    authority_openness: NotRequired[str]
    # Non-empty = witnessed; ``None`` = role-gated, role undetermined; ``[]`` = proven not role-gated. ``or []`` erases
    # the middle state. See ``capability_role_grants``.
    authority_roles: list[AuthorityRoleGrant] | None
    controllers: list[ResolvedControllerGrant]
    effect_targets: list[str]
    effect_labels: list[str]
    claims: NotRequired[list[dict[str, Any]]]
    action_summary: str
    notes: list[str]
    capability_expr: NotRequired[dict[str, Any]]
    conditions: NotRequired[list[dict[str, Any]]]
    status: NotRequired[EffectiveFunctionStatus]
    signature_witnesses: NotRequired[list[ResolvedPrincipal]]
    # ``None`` on any of the four means not determined, distinct from ``false``/``[]``. See ``_mutability_fields``.
    state_changing: NotRequired[bool | None]
    state_writes: NotRequired[list[dict[str, Any]] | None]
    sinks: NotRequired[list[dict[str, Any]] | None]
    writer_selectors: NotRequired[list[str] | None]


class EffectivePermissions(TypedDict):
    schema_version: str
    contract_address: str
    contract_name: str
    authority_contract: str | None
    principal_resolution: PrincipalResolution
    artifacts: dict[str, str]
    functions: list[EffectiveFunctionPermission]
