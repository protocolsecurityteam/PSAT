"""Typed schemas for resolved effective-permission outputs."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from typing_extensions import NotRequired

from .observations import ResolvedControllerType

# One vocabulary with ``schemas.observations``: persisted rows carry
# ``off_chain_witness`` (the PR #48 sink bridge wrote it), so the narrower
# 8-member copy this alias used to be was a lie at the cast sites.
PermissionStatus = Literal["public", "unsupported", "resolved_empty"]


class ResolvedPrincipal(TypedDict):
    address: str
    resolved_type: ResolvedControllerType
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


class PermissionRow(TypedDict):
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
    # Supported claims: {claim_id, tier, witness}.
    claims: NotRequired[list[dict[str, Any]]]
    notes: list[str]
    capability_expr: NotRequired[dict[str, Any]]
    conditions: NotRequired[list[dict[str, Any]]]
    status: NotRequired[PermissionStatus]
    signature_witnesses: NotRequired[list[ResolvedPrincipal]]
    # State-mutability witness carried from the effects stage. Always present,
    # and ``None`` on any of the four means NOT DETERMINED — a state the reader
    # must keep distinct from ``false`` / ``[]`` ("the stage looked and proved
    # none"). See ``services.policy.permission_index._mutability_fields``
    # for which record shapes yield which state.
    state_changing: NotRequired[bool | None]
    state_writes: NotRequired[list[dict[str, Any]] | None]
    sinks: NotRequired[list[dict[str, Any]] | None]
    writer_selectors: NotRequired[list[str] | None]


class PermissionIndex(TypedDict):
    schema_version: str
    contract_address: str
    contract_name: str
    functions: list[PermissionRow]


def role_number(value: Any) -> int | None:
    """Parse a numeric role, leaving named or structured roles unresolved."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
