"""``contract_deployment``: a reachable ``contract_creation`` sink proves the function deploys a contract.

The reference matcher.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence


@claim_matcher(
    claim_id="contract_deployment",
    sentence="deploys a new contract",
    legacy_projection="contract_deployment",
    consumer_family="exec",
    grant_class="operational",
)
def contract_deployment(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    sink_ids = ctx.sink_ids(function, "contract_creation")
    if not sink_ids:
        return None
    return ClaimEvidence(
        tier="standard_exact",
        witness={"kind": "sink", "sink_kind": "contract_creation", "sink_ids": sink_ids},
    )
