"""``upgrade.implementation``: changes which code runs behind a deployment.

Standard-gated (UUPS, 1967 ``Upgraded`` marker, or delegatecall-fallback shell), so a bespoke ``upgradeTo(address)``
that only rotates a pointer earns no claim.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from ._gates import UPGRADE_SELECTORS, is_upgrade_gate, is_uups_gate


@claim_matcher(
    claim_id="upgrade.implementation",
    sentence="changes which code executes behind this deployment",
    legacy_projection="implementation_update",
    consumer_family="control_plane",
    gate=is_upgrade_gate,
)
def upgrade_implementation(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    selector = ctx.canonical_selector(function)
    if selector not in UPGRADE_SELECTORS:
        return None
    # Lets the projection suppress the standalone ``delegatecall_execution`` emphasis on this entry.
    explained = ctx.sink_ids(function, "delegatecall")
    return ClaimEvidence(
        tier="standard_exact",
        witness={
            "kind": "selector+gate",
            "selector": selector,
            "gate": "uups" if is_uups_gate(ctx) else "proxy_1967",
            "explained_delegatecall_sink_ids": explained,
        },
    )
