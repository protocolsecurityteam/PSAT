"""Gnosis Safe control-plane claims: signer-set, module, and guard management.

All three ride the Safe gate (getThreshold + getOwners + execTransaction), which
h3sim measured at 0 false claims. Within that gate the canonical entry names are
unambiguous, so each trigger matches by name. Safe's ``execTransaction`` /
module-exec entries are handled by the ``exec.arbitrary`` matcher.
"""

from __future__ import annotations

from ..context import ClaimContext
from ..decorator import claim_matcher
from ..types import ClaimEvidence
from ._gates import function_name, is_safe_gate

_SIGNER_FUNCTIONS = frozenset({"addOwnerWithThreshold", "removeOwner", "swapOwner", "changeThreshold"})
_MODULE_FUNCTIONS = frozenset({"enableModule", "disableModule"})


def _safe_evidence(function: str) -> ClaimEvidence:
    return ClaimEvidence(
        tier="standard_exact",
        witness={"kind": "selector+gate", "standard": "safe", "function": function_name(function)},
    )


@claim_matcher(
    claim_id="safe.signer_mgmt",
    sentence="changes the Safe signer set or approval threshold",
    legacy_projection=None,
    consumer_family="control_plane",
    gate=is_safe_gate,
)
def safe_signer_mgmt(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function_name(function) not in _SIGNER_FUNCTIONS:
        return None
    return _safe_evidence(function)


@claim_matcher(
    claim_id="safe.module_mgmt",
    sentence="grants or revokes Safe module execution rights",
    legacy_projection=None,
    consumer_family="control_plane",
    gate=is_safe_gate,
)
def safe_module_mgmt(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function_name(function) not in _MODULE_FUNCTIONS:
        return None
    return _safe_evidence(function)


@claim_matcher(
    claim_id="safe.set_guard",
    sentence="sets the Safe transaction guard hook",
    legacy_projection=None,
    consumer_family="control_plane",
    gate=is_safe_gate,
)
def safe_set_guard(ctx: ClaimContext, function: str) -> ClaimEvidence | None:
    if function_name(function) != "setGuard":
        return None
    return _safe_evidence(function)
