"""Role-membership claims: ``roles.grant`` / ``roles.revoke`` /
``roles.configure``.

Standard-exact, selector-canonical — the only 100%-correct tier in the current
system. Role *membership* is matched on the selector plus a contract-level
standard gate, never on "writes a caller-authority membership var": a
caller-keyed *data* map (LayerZero ``composeQueue`` on ``sendCompose`` /
``lzCompose``) is structurally indistinguishable from a caller-keyed ACL, so the
gate is what keeps those out.

Standards covered:
  * OZ AccessControl ``grantRole`` / ``revokeRole`` (gate: ``hasRole`` +
    ``getRoleAdmin`` siblings);
  * Solady ``EnumerableRoles`` behind OZ-named ``grantRole`` / ``revokeRole``
    wrappers (gate: ``setRole`` + ``hasRole(address,uint256)`` + ``roleHolders``)
    — a flat ``uint256`` role set publishes no per-role admin, so the OZ gate
    alone leaves these registries unlabelled;
  * Maker ``wards`` ``rely`` / ``deny`` (gate: ``rely`` + ``deny`` + a ``wards``
    write) — today mislabeled ``hook_update``;
  * Solmate RolesAuthority ``setUserRole`` / ``setRoleCapability`` /
    ``setPublicCapability`` (gate: those setters + ``canCall``).

Maker wards is the one arm that mints at ``idiom_structural`` rather than
``standard_exact``: there is no published wards standard, and the ACL half of its
gate can only be recognized by the variable's name (see ``maker_wards_gate``), so
the claim is honest as an idiom and overclaimed as a standard proof.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import MatchedEvidence
from . import _authcommon as ac


def _roles_present(ctx: ClaimContext) -> bool:
    return (
        ac.oz_access_control_gate(ctx)
        or ac.solady_enumerable_roles_gate(ctx)
        or ac.maker_wards_gate(ctx)
        or ac.solmate_roles_gate(ctx)
    )


def _evidence(standard: str, selector: str) -> MatchedEvidence:
    return MatchedEvidence(
        tier="standard_exact",
        witness={"kind": "selector", "selector": selector, "standard": standard},
    )


def _wards_evidence(selector: str) -> MatchedEvidence:
    return MatchedEvidence(
        tier="idiom_structural",
        witness={"kind": "selector+wards_idiom", "selector": selector, "standard": "maker_wards"},
    )


@claim_matcher(
    claim_id="roles.grant",
    sentence="grants membership in a role-based access-control scheme (per a recognized standard)",
    consumer_family="control_plane",
    gate=_roles_present,
)
def roles_grant(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    selector = ac.canonical_selector(ctx, function)
    if selector is None:
        return None
    if selector == ac.GRANT_ROLE and ac.oz_access_control_gate(ctx):
        return _evidence("oz_access_control", selector)
    if selector == ac.GRANT_ROLE and ac.solady_enumerable_roles_gate(ctx):
        return _evidence("solady_enumerable_roles", selector)
    if selector == ac.RELY and ac.maker_wards_gate(ctx):
        return _wards_evidence(selector)
    return None


@claim_matcher(
    claim_id="roles.revoke",
    sentence="revokes membership in a role-based access-control scheme (per a recognized standard)",
    consumer_family="control_plane",
    gate=_roles_present,
)
def roles_revoke(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    selector = ac.canonical_selector(ctx, function)
    if selector is None:
        return None
    if selector == ac.REVOKE_ROLE and ac.oz_access_control_gate(ctx):
        return _evidence("oz_access_control", selector)
    if selector == ac.REVOKE_ROLE and ac.solady_enumerable_roles_gate(ctx):
        return _evidence("solady_enumerable_roles", selector)
    if selector == ac.DENY and ac.maker_wards_gate(ctx):
        return _wards_evidence(selector)
    return None


@claim_matcher(
    claim_id="roles.configure",
    sentence="configures role or capability membership in a Solmate RolesAuthority scheme",
    consumer_family="control_plane",
    gate=ac.solmate_roles_gate,
)
def roles_configure(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    selector = ac.canonical_selector(ctx, function)
    if selector is None:
        return None
    if selector in (ac.SET_USER_ROLE, ac.SET_ROLE_CAPABILITY, ac.SET_PUBLIC_CAPABILITY):
        return _evidence("solmate_roles", selector)
    return None
