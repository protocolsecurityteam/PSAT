"""Self-service (W1 AND W2) bound reads."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from schemas.contract_analysis import ControllerProvenance
from services.scoring import constants as K
from utils.scoring_status import (
    SELF_SERVICE_BASIS_BOUNDED,
    SELF_SERVICE_DISCLOSE_SIBLING,
    SELF_SERVICE_DISCLOSE_UPGRADE,
    SELF_SERVICE_STATE_PROVEN,
)

from .claims import _considered_out_flows, _target_kinds

logger = logging.getLogger("services.scoring.distill")


# Consumes U5's per-flow ``self_service_payout``: W1 (amount from a caller-owned cell) and W2 (cleared before external
# calls, or a verified reentrancy guard). Replayed as a universal over out-flows, never re-derived.
SELF_SERVICE_BASIS = SELF_SERVICE_BASIS_BOUNDED
SELF_SERVICE_UNCHARGED_NOTE = "self_service_uncharged_product_surface"
_SELF_SERVICE_PROVEN_STATE = SELF_SERVICE_STATE_PROVEN

_PROVENANCE_CALLER_GATE: ControllerProvenance = "caller_gate"
_SS_REFUSAL_PREFIX = "self_service_bound_refused"
_SS_UNREAD_FLOW = "unread_out_flow"
_SS_PAYEE_NOT_CALLER_RELATIVE = "payee_not_caller_relative"
_SS_SOURCE_NOT_SELF = "flow_source_not_self"


@dataclass(frozen=True)
class _SelfServiceBound:
    """Proven (with U5's disclosures), a named failing conjunct, or not asked (no out-flow raises the question).

    Mirrors ``_MsgValueReturn``.
    """

    proven: bool
    refusal: str | None
    disclosures: tuple[str, ...] = ()

    @property
    def notes(self) -> tuple[str, ...]:
        """Tokens a proven verdict publishes; the withhold reads :attr:`refusal_note` instead."""
        if self.proven:
            return (SELF_SERVICE_UNCHARGED_NOTE, *self.disclosures)
        return ()

    @property
    def refusal_note(self) -> str | None:
        return f"{_SS_REFUSAL_PREFIX}:{self.refusal}" if self.refusal is not None else None


_SELF_SERVICE_NOT_ASKED = _SelfServiceBound(proven=False, refusal=None)


def _self_service_bound(claims: list[dict[str, Any]]) -> _SelfServiceBound:
    """Universal over every out-flow: the full W1 and W2 conjunction, or a named refusal.

    No storage-read flow means not asked. Otherwise one unproven flow refuses the whole function, so a sibling flow
    can't ride on a proven one.
    """
    considered, blocked = _considered_out_flows(claims)
    # Blocked flows are not asked (no fact was attachable) and fail closed on the grade without a refusal note.
    if blocked is not None or not considered:
        return _SELF_SERVICE_NOT_ASKED
    if not any(isinstance(f.get("self_service_payout"), dict) for f in considered):
        return _SELF_SERVICE_NOT_ASKED

    disclosures: set[str] = set()
    for flow in considered:
        fact = flow.get("self_service_payout")
        if not isinstance(fact, dict):
            # C4: a sibling flow without the fact is unread, not benign.
            return _SelfServiceBound(proven=False, refusal=_SS_UNREAD_FLOW)
        if fact.get("state") != _SELF_SERVICE_PROVEN_STATE:
            # C1/C2: the producer's named failing conjunct passes through.
            return _SelfServiceBound(proven=False, refusal=str(fact.get("reason") or _SS_UNREAD_FLOW))
        # C3: U5 proves the amount; the contract being the source is checked here. A fixed payee paid from the caller's
        # balance isn't self-service.
        if flow.get("from_is_self") is not True:
            return _SelfServiceBound(proven=False, refusal=_SS_SOURCE_NOT_SELF)
        kinds = set(_target_kinds(flow))
        if not kinds or not kinds <= K.CALLER_RELATIVE_TARGET_KINDS:
            return _SelfServiceBound(proven=False, refusal=_SS_PAYEE_NOT_CALLER_RELATIVE)
        disclosures.update(str(d) for d in (fact.get("disclosures") or []))

    # The G7 pair is always published so an excluded row's earned negative is legible.
    disclosures.update({SELF_SERVICE_DISCLOSE_UPGRADE, SELF_SERVICE_DISCLOSE_SIBLING})
    return _SelfServiceBound(proven=True, refusal=None, disclosures=tuple(sorted(disclosures)))


def _flow_asset_class(claims: list[dict[str, Any]]) -> str | None:
    """native / ERC-20 partition of the out-flows. An absent ``from_is_self`` isn't treated as true."""
    native = erc20 = other = False
    for claim in claims:
        if str(claim.get("claim_id")) != "flow.out":
            continue
        for flow in (claim.get("witness") or {}).get("flows") or []:
            if not isinstance(flow, dict) or flow.get("from_is_self") is not True:
                continue
            kind = flow.get("kind")
            if kind in K.NATIVE_FLOW_KINDS:
                native = True
            elif kind in K.ERC20_FLOW_KINDS:
                erc20 = True
            elif kind:
                other = True
    if other or (native and erc20):
        return "mixed"
    if native:
        return "native_only"
    if erc20:
        return "erc20_only"
    return None
