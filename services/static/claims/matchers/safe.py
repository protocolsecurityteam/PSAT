"""Gnosis Safe control-plane claims: signer-set, module, and guard management.

All three ride the Safe gate (getThreshold + getOwners + execTransaction), which
h3sim measured at 0 false claims. Within that gate each trigger matches the
published Safe selector for its entry, so a same-named sibling with a different
argument list is not a Safe operation. Safe's ``execTransaction`` / module-exec
entries are handled by the ``exec.arbitrary`` matcher.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import MatchedEvidence
from ._gates import SAFE_MODULE_SELECTORS, SAFE_SET_GUARD, SAFE_SIGNER_SELECTORS, is_safe_gate


def _safe_evidence(selector: str) -> MatchedEvidence:
    return MatchedEvidence(
        tier="standard_exact",
        witness={"kind": "selector+gate", "standard": "safe", "selector": selector},
    )


@claim_matcher(
    claim_id="safe.signer_mgmt",
    sentence="changes the Safe signer set or approval threshold",
    consumer_family="control_plane",
    gate=is_safe_gate,
)
def safe_signer_mgmt(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    selector = ctx.canonical_selector(function)
    if selector is None or selector not in SAFE_SIGNER_SELECTORS:
        return None
    return _safe_evidence(selector)


@claim_matcher(
    claim_id="safe.module_mgmt",
    sentence="grants or revokes Safe module execution rights",
    consumer_family="control_plane",
    gate=is_safe_gate,
)
def safe_module_mgmt(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    selector = ctx.canonical_selector(function)
    if selector is None or selector not in SAFE_MODULE_SELECTORS:
        return None
    return _safe_evidence(selector)


@claim_matcher(
    claim_id="safe.set_guard",
    sentence="sets the Safe transaction guard hook",
    consumer_family="control_plane",
    gate=is_safe_gate,
)
def safe_set_guard(ctx: ClaimContext, function: str) -> MatchedEvidence | None:
    if ctx.canonical_selector(function) != SAFE_SET_GUARD:
        return None
    return _safe_evidence(SAFE_SET_GUARD)
