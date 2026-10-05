"""Claims minted after ``build_claims``, by a stage with facts one contract's analysis lacks. Registered with the
matchers so every reader sees the whole vocabulary; their gates never fire on single-contract facts.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence


def _never(_ctx: ClaimContext) -> bool:
    return False


@claim_matcher(
    claim_id="transfer_policy.configure",
    sentence="changes another contract's transfer gating",
    legacy_projection=None,
    consumer_family="control_plane",
    grant_class="control.config",
    gate=_never,
)
def transfer_policy_configure(_ctx: ClaimContext, _function: str) -> ClaimEvidence | None:
    """Minted by the policy stage's cross-contract pass (``services.static.cross_contract``)."""
    return None


# The authority-change recipe proves only that calling F opens a gate to previously rejected callers. No static
# authority claim says exactly that (``roles.grant``, ``authority.replace``, ``authorized_caller.rotate`` each assert a
# mechanism), so it gets its own id.
@claim_matcher(
    claim_id="authority.grant",
    sentence="lets a caller pass a permission gate that previously rejected it",
    legacy_projection="authority_update",
    consumer_family="control_plane",
    grant_class="control.gate",
    gate=_never,
)
def authority_grant(_ctx: ClaimContext, _function: str) -> ClaimEvidence | None:
    """Minted only by the effects bridge (``services.effects.claims_bridge``) from a proven fork verdict."""
    return None
