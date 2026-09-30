"""``authorized_caller.rotate``: rotating a non-owner caller-authority scalar (FiatToken
``updatePauser``/``updateMasterMinter``...), which would otherwise be mislabeled an ownership transfer.

The var must be a scalar ``address`` compared to ``msg.sender`` by an equality leaf (excluding membership leaves and
namespaced-slot ghosts), the writer must be caller-gated (excluding latched initializers), and it must not be the owner
pointer.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from . import _authcommon as ac


def _has_rotatable_scalar(ctx: ClaimContext) -> bool:
    return bool(set(ac.caller_authority_scalar_vars(ctx)) - ac.canonical_owner_vars(ctx))


@claim_matcher(
    claim_id="authorized_caller.rotate",
    sentence="rotates a non-owner scalar address that authorizes callers of specific gated functions",
    legacy_projection=None,
    consumer_family="control_plane",
    gate=_has_rotatable_scalar,
)
def authorized_caller_rotate(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if not ctx.effect_record(function).get("state_changing"):
        return None
    if not ac.function_has_caller_authority_leaf(ctx, function):
        return None

    scalar_vars = ac.caller_authority_scalar_vars(ctx)
    rotatable = set(scalar_vars) - ac.canonical_owner_vars(ctx)
    rotated = sorted(ac.clean_scalar_writes(ctx, function) & rotatable)
    if not rotated:
        return None
    return ClaimEvidence(
        tier="idiom_structural",
        witness={
            "kind": "caller_authority_rotate",
            "vars": rotated,
            # The functions whose equality leaf established each rotated var (replay anchor).
            "established_by": {var: scalar_vars[var] for var in rotated},
        },
    )
