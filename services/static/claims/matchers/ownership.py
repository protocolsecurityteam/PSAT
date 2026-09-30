"""``ownership.transfer`` / ``renounce`` / ``accept``.

Keyed on canonical ownership selectors plus corroboration, never on writes: on OZ v5 namespaced storage Slither
attributes the owner slot as written by every touching function. Corroboration: an ``owner()`` sibling, a write to a
caller-authority scalar (Solmate Auth, with ``owner`` as a public var), or a two-step standard gate.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _authcommon as ac


def _ownership_present(ctx: ClaimContext) -> bool:
    return (
        ac.is_ownable(ctx)
        or ac.solady_handover_gate(ctx)
        or ac.default_admin_rules_gate(ctx)
        or (ctx.has_selectors(ac.TRANSFER_OWNERSHIP) and bool(ac.caller_authority_scalar_vars(ctx)))
    )


def _evidence(standard: str, selector: str, corroboration: str) -> ClaimEvidence:
    return ClaimEvidence(
        tier="standard_exact",
        witness={
            "kind": "selector",
            "selector": selector,
            "standard": standard,
            "corroboration": corroboration,
        },
    )


@claim_matcher(
    claim_id="ownership.transfer",
    sentence="transfers contract ownership to a new principal (per a recognized ownership standard)",
    legacy_projection="ownership_transfer",
    consumer_family="control_plane",
    gate=_ownership_present,
)
def ownership_transfer(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    selector = ac.canonical_selector(ctx, function)
    if selector is None:
        return None
    if selector == ac.TRANSFER_OWNERSHIP:
        if ac.is_ownable(ctx):
            return _evidence("ownable", selector, "owner_getter_sibling")
        if ac.writes_owner_scalar(ctx, function):
            return _evidence("dsauth_style", selector, "owner_var_write_identity")
    elif selector == ac.COMPLETE_HANDOVER and ac.solady_handover_gate(ctx):
        return _evidence("solady_handover", selector, "handover_gate")
    elif selector == ac.BEGIN_DEFAULT_ADMIN and ac.default_admin_rules_gate(ctx):
        return _evidence("default_admin_rules", selector, "default_admin_gate")
    return None


@claim_matcher(
    claim_id="ownership.renounce",
    sentence="renounces contract ownership, leaving the contract unowned (per a recognized ownership standard)",
    legacy_projection="ownership_transfer",
    consumer_family="control_plane",
    gate=_ownership_present,
)
def ownership_renounce(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    selector = ac.canonical_selector(ctx, function)
    if selector is None:
        return None
    if selector != ac.RENOUNCE_OWNERSHIP:
        return None
    if ac.is_ownable(ctx):
        return _evidence("ownable", selector, "owner_getter_sibling")
    if ac.writes_owner_scalar(ctx, function):
        return _evidence("dsauth_style", selector, "owner_var_write_identity")
    return None


@claim_matcher(
    claim_id="ownership.accept",
    sentence="accepts or requests a pending ownership transfer (per a recognized two-step ownership standard)",
    legacy_projection="ownership_transfer",
    consumer_family="control_plane",
    gate=_ownership_present,
)
def ownership_accept(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    selector = ac.canonical_selector(ctx, function)
    if selector is None:
        return None
    if selector == ac.ACCEPT_OWNERSHIP and ac.is_ownable(ctx):
        return _evidence("ownable2step", selector, "owner_getter_sibling")
    if selector == ac.ACCEPT_DEFAULT_ADMIN and ac.default_admin_rules_gate(ctx):
        return _evidence("default_admin_rules", selector, "default_admin_gate")
    if selector == ac.REQUEST_HANDOVER and ac.solady_handover_gate(ctx):
        return _evidence("solady_handover", selector, "handover_gate")
    return None
