"""``contract_deployment`` — the reference matcher.

Deterministic and exact: a ``contract_creation`` sink reachable from a function
is machine-checkable proof the function deploys a contract. Ships as the
add-a-module pattern later matcher stages copy; its evidence is a single sink,
so it needs no contract-level gate.
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
)
def contract_deployment(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    sink_ids = ctx.sink_ids(function, "contract_creation")
    if not sink_ids:
        return None
    return ClaimEvidence(
        tier="standard_exact",
        witness={"kind": "sink", "sink_kind": "contract_creation", "sink_ids": sink_ids},
    )
