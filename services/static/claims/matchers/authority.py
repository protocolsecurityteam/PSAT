"""``authority.replace``: swapping the external authority contract.

Requires the canonical ``setAuthority(address)`` selector and a write to the variable a ``delegated_authority`` gate
leaf consults, so data-freshness calls in modifiers (``registerLibrary``) don't match.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _authcommon as ac


@claim_matcher(
    claim_id="authority.replace",
    sentence="replaces the external authority contract consulted for permission checks",
    legacy_projection="authority_update",
    consumer_family="control_plane",
)
def authority_replace(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if ac.canonical_selector(ctx, function) != ac.SET_AUTHORITY:
        return None
    replaced = sorted(ac.clean_scalar_writes(ctx, function) & ac.delegated_authority_vars(ctx))
    if not replaced:
        return None
    return ClaimEvidence(
        tier="standard_exact",
        witness={
            "kind": "selector",
            "selector": ac.SET_AUTHORITY,
            "standard": "solmate_auth",
            "write_target": replaced[0],
            "authority_gate_vars": replaced,
        },
    )
