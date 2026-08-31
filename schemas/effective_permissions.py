"""Typed schemas for resolved effective-permission outputs."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from typing_extensions import NotRequired

from .control_tracking import ResolvedControllerType

# One vocabulary with ``schemas.control_tracking``: persisted rows carry
# ``off_chain_witness`` (the PR #48 sink bridge wrote it), so the narrower
# 8-member copy this alias used to be was a lie at the cast sites.
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
    source: NotRequired[str]
    kind: str
    principals: list[ResolvedPrincipal]
    notes: list[str]


class EffectiveFunctionPermission(TypedDict):
    function: str
    abi_signature: str
    # ``None`` when the signature could not be fully lowered to elementary ABI
    # types: a hash of a string still naming a user-defined type is not a
    # selector the chain dispatches on, and no answer beats a wrong one.
    selector: str | None
    direct_owner: ResolvedPrincipal | None
    authority_public: bool
    # Three-state counterpart to ``authority_public``, whose ``False`` reports a
    # WITNESSED caller restriction and "the authority could not be determined"
    # with the same value: 'open' | 'restricted' | 'not_determined'. Absent on a
    # record built by a caller that does not carry the distinction — which is a
    # fourth state ("this producer could not say") and must not be folded into
    # ``not_determined``.
    authority_openness: NotRequired[str]
    # Three states, and a consumer must tell them apart (see
    # ``capability_surface.capability_role_grants``): a non-empty list is a
    # WITNESSED role requirement; ``None`` is role-gated with the role NOT
    # determined (the enumerable role-store dissolves role identity by design,
    # and a multi-role capability cannot say which role a member holds); ``[]``
    # is proven not role-gated. It was the literal ``[]`` on every row before
    # this split, so ``authority_roles or []`` at a consumer erases the middle
    # state.
    authority_roles: list[AuthorityRoleGrant] | None
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
    # State-mutability witness carried from the effects stage. Always present,
    # and ``None`` on any of the four means NOT DETERMINED — a state the reader
    # must keep distinct from ``false`` / ``[]`` ("the stage looked and proved
    # none"). See ``services.policy.effective_permissions._mutability_fields``
    # for which record shapes yield which state.
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
