"""``authority.replace`` — swapping the external authority contract.

Standard-exact: the canonical ``setAuthority(address)`` selector (``0x7a9e5e4b``,
computed from the *canonical* signature so a ``setAuthority(Authority)``
interface param still resolves) plus the authority write-target gate — the
function writes the ``authority`` state var the permission checks consult.

The gate is what keeps this off the retired ``dest:{name}`` substring detector's
false positives (a data-freshness call inside a modifier, e.g.
``registerEth2DepositContract`` / LayerZero ``registerLibrary``): those never
bear the ``setAuthority`` selector.
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
    if not ac.writes_state_var(ctx, function, "authority"):
        return None
    return ClaimEvidence(
        tier="standard_exact",
        witness={
            "kind": "selector",
            "selector": ac.SET_AUTHORITY,
            "standard": "solmate_auth",
            "write_target": "authority",
        },
    )
