"""``proxy.admin_change`` — changes the proxy admin who can upgrade a deployment.

New claim (no legacy equivalent). Gate: the ``AdminChanged`` marker event or a
delegatecall-fallback proxy shell; trigger: the fixed ``changeAdmin(address)``
selector. FiatTokenProxy.changeAdmin (today: nothing) and transparent-proxy
changeAdmin (today: only a "delegatecall path" fact) get their exact claim.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from ._gates import CHANGE_ADMIN, is_admin_change_gate


@claim_matcher(
    claim_id="proxy.admin_change",
    sentence="changes the proxy admin who can upgrade this deployment",
    legacy_projection=None,
    consumer_family="control_plane",
    gate=is_admin_change_gate,
)
def proxy_admin_change(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if ctx.selector(function) != CHANGE_ADMIN:
        return None
    explained = ctx.sink_ids(function, "delegatecall")
    return ClaimEvidence(
        tier="standard_exact",
        witness={
            "kind": "selector+gate",
            "selector": CHANGE_ADMIN,
            "explained_delegatecall_sink_ids": explained,
        },
    )
