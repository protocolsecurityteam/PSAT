"""``upgrade.implementation`` — changes which code executes behind a deployment.

Standard-gated only: the never-fired same-contract dataflow detectors are
retired. Recovers UUPS (EETH-class ``upgradeToAndCall``), 1967
``Upgraded``-marker impls, and delegatecall-fallback proxy shells (wBETH-class
``upgradeTo``) — all invisible to the legacy detector, which emitted 0 of 2,182.
The near-miss guard: a bespoke ``upgradeTo(address)`` that merely rotates a
pointer carries the selector but qualifies for no upgrade gate, so no claim.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import MatchedEvidence
from ._gates import UPGRADE_SELECTORS, is_upgrade_gate, is_uups_gate


@claim_matcher(
    claim_id="upgrade.implementation",
    sentence="changes which code executes behind this deployment",
    consumer_family="control_plane",
    gate=is_upgrade_gate,
)
def upgrade_implementation(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    selector = ctx.canonical_selector(function)
    if selector not in UPGRADE_SELECTORS:
        return None
    # Record the delegatecall sink(s) this claim explains so the projection
    # layer can suppress the standalone delegatecall_execution emphasis on the
    # same entry.
    explained = ctx.sink_ids(function, "delegatecall")
    return MatchedEvidence(
        tier="standard_exact",
        witness={
            "kind": "selector+gate",
            "selector": selector,
            "gate": "uups" if is_uups_gate(ctx) else "proxy_1967",
            "explained_delegatecall_sink_ids": explained,
        },
    )
