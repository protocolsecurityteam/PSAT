"""``authorized_caller.rotate`` — rotating a non-owner caller-authority scalar.

The idiom that ends the false "Transfers contract ownership" sentence on the
FiatToken ``updatePauser`` / ``updateMasterMinter`` / ``updateBlacklister`` /
``updateRescuer`` class (the ownership post-pass tags them because they write a
caller-authority scalar) while keeping their admin weight under a truthful claim.

Structural, ghost-immune requirements (idiom_structural tier):
  * the written var is a *scalar* ``address`` compared to ``msg.sender`` by a
    caller-authority **equality** leaf somewhere in the contract — membership
    leaves (LayerZero ``composeQueue``) and the OZ v5 / Solady slot ghosts are
    excluded because they are never a clean address scalar;
  * the writer is itself gated by a caller-authority leaf (access-controlled) —
    this excludes a one-shot ``initialize`` that seeds the very same scalars but
    is latched, not caller-gated;
  * the var is not the canonical-owner pointer (``ownership.*`` carries that).
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import MatchedEvidence
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
def authorized_caller_rotate(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    if not ctx.effect_record(function).get("state_changing"):
        return None
    if not ac.function_has_caller_authority_leaf(ctx, function):
        return None

    scalar_vars = ac.caller_authority_scalar_vars(ctx)
    rotatable = set(scalar_vars) - ac.canonical_owner_vars(ctx)
    rotated = sorted(ac.clean_scalar_writes(ctx, function) & rotatable)
    if not rotated:
        return None
    return MatchedEvidence(
        tier="idiom_structural",
        witness={
            "kind": "caller_authority_rotate",
            "vars": rotated,
            # The functions whose ``msg.sender == var`` equality leaf established
            # each rotated var as a caller-authority scalar (replay anchor).
            "established_by": {var: scalar_vars[var] for var in rotated},
        },
    )
