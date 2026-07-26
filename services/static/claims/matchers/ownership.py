"""Contract-ownership claims: ``ownership.transfer`` / ``ownership.renounce`` /
``ownership.accept``.

Standard-exact and ghost-immune: each claim keys on a canonical ownership
selector plus a sibling/standard corroboration, never on which var a function
"writes". On OZ v5 namespaced storage Slither mis-attributes the
``OwnableStorageLocation`` slot constant as written by every touching function
(including the ``owner()`` view), so a write-identity design would tag
``setPeer`` / ``sweep`` / ``owner()`` as ownership changes. Keying on
``transferOwnership`` (``0xf2fde38b``) + an ``owner()`` sibling keeps
``transferOwnership`` and drops the ghosts.

Corroboration paths, any one of which proves the standard:
  * an ``owner()`` getter sibling (OZ Ownable / Ownable2Step / Solady);
  * owner-var write identity — the function writes a hygiene-clean caller-
    authority scalar — for a Solmate-style Auth whose ``owner`` is a public var
    with no ``owner()`` in the ABI set;
  * a two-step standard gate (Solady handover, DefaultAdminRules) for the
    handover / staged-transfer selectors.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _authcommon as ac


def _ownership_present(ctx: ClaimContext) -> bool:
    """Coarse gate: some recognized ownership standard is on the contract."""
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
