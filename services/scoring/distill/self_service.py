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

# ---------------------------------------------------------- self-service (W1∧W2)

# The consumer of U5's per-flow ``self_service_payout`` fact: W1 (the paid amount
# is read from a storage cell the caller is proven to own) ∧ W2 (that cell is
# cleared before any external call, or a verified reentrancy guard stands in for
# that order). U5 computed the conjunction; this replays it as a UNIVERSAL over
# the function's out-flows and never re-derives the proof (inv. 9 — the scorer
# consumes published witnesses, it does not recompute them).
SELF_SERVICE_BASIS = SELF_SERVICE_BASIS_BOUNDED
SELF_SERVICE_UNCHARGED_NOTE = "self_service_uncharged_product_surface"
_SELF_SERVICE_PROVEN_STATE = SELF_SERVICE_STATE_PROVEN

# The one provenance value that proves a caller gate (schema vocabulary; the
# annotation pins the spelling).
_PROVENANCE_CALLER_GATE: ControllerProvenance = "caller_gate"
_SS_REFUSAL_PREFIX = "self_service_bound_refused"
_SS_UNREAD_FLOW = "unread_out_flow"
_SS_PAYEE_NOT_CALLER_RELATIVE = "payee_not_caller_relative"
_SS_SOURCE_NOT_SELF = "flow_source_not_self"


@dataclass(frozen=True)
class _SelfServiceBound:
    """Three states, the third being silence — the mirror of ``_MsgValueReturn``.

    PROVEN carries the disclosures U5 stamped on the conjunction; a refusal NAMES
    the conjunct that failed; NOT-ASKED is "no out-flow of this function even
    raises the self-service question", where publishing a refusal would hang a
    reason off a payout the witness was never about.
    """

    proven: bool
    refusal: str | None
    disclosures: tuple[str, ...] = ()

    @property
    def notes(self) -> tuple[str, ...]:
        """The tokens a PROVEN verdict publishes; empty when not proven — the
        withhold reads :attr:`refusal_note`, never these."""
        if self.proven:
            return (SELF_SERVICE_UNCHARGED_NOTE, *self.disclosures)
        return ()

    @property
    def refusal_note(self) -> str | None:
        return f"{_SS_REFUSAL_PREFIX}:{self.refusal}" if self.refusal is not None else None


_SELF_SERVICE_NOT_ASKED = _SelfServiceBound(proven=False, refusal=None)


def _self_service_bound(claims: list[dict[str, Any]]) -> _SelfServiceBound:
    """UNIVERSAL over every out-flow: the full W1 ∧ W2 conjunction, or a named refusal.

    U5 attaches ``self_service_payout`` per flow only where the amount is read out
    of storage — the one place the "is this the caller's own cell" question is
    even asked. So a function with NO such flow is NOT-ASKED (no note, exactly as
    ``_msg_value_return`` is silent on a function that mentions no ``msg.value``).
    Once ANY out-flow raises the question the conjunction is universal: one flow
    whose witness is absent or refused refuses the whole function — a sibling flow
    the caller does not own would otherwise let a proven one buy the 0.0 for both.
    """
    considered, blocked = _considered_out_flows(claims)
    # A blocked out-flow set (policy_derived, or a claim with no flows key) is
    # NOT-ASKED, exactly as in ``_msg_value_return``: the producer could not read
    # the flows, so no ``self_service_payout`` fact was ever attachable and the
    # question was never put. It fails closed on the GRADE regardless — a
    # not-asked witness proves nothing, so no 0.0 is granted — and stamping a
    # refusal here would hang a reason off every unreadable payout in the corpus.
    if blocked is not None or not considered:
        return _SELF_SERVICE_NOT_ASKED
    if not any(isinstance(f.get("self_service_payout"), dict) for f in considered):
        return _SELF_SERVICE_NOT_ASKED

    disclosures: set[str] = set()
    for flow in considered:
        fact = flow.get("self_service_payout")
        if not isinstance(fact, dict):
            # C4: a sibling out-flow whose amount is not read from a caller-owned
            # cell (no W1∧W2 fact attached) is an UNREAD flow, not a benign one.
            return _SelfServiceBound(proven=False, refusal=_SS_UNREAD_FLOW)
        if fact.get("state") != _SELF_SERVICE_PROVEN_STATE:
            # C1/C2: W1 (amount) or W2 (ordering/verified-guard) refused; the
            # producer named which conjunct fell short, and it rides through.
            return _SelfServiceBound(proven=False, refusal=str(fact.get("reason") or _SS_UNREAD_FLOW))
        # C3: the payee is the caller and the contract is the source. U5 proves the
        # AMOUNT is the caller's own position; that the PAYEE is the caller too is
        # a structural fact about the flow, read here directly rather than
        # re-derived — a fixed payee paid out of the caller's recorded balance is
        # NOT a self-service payout and refuses.
        if flow.get("from_is_self") is not True:
            return _SelfServiceBound(proven=False, refusal=_SS_SOURCE_NOT_SELF)
        kinds = set(_target_kinds(flow))
        if not kinds or not kinds <= K.CALLER_RELATIVE_TARGET_KINDS:
            return _SelfServiceBound(proven=False, refusal=_SS_PAYEE_NOT_CALLER_RELATIVE)
        disclosures.update(str(d) for d in (fact.get("disclosures") or []))

    # The two G7 tokens ride every proof: a missing disclosure never downgrades a
    # proof, but the canonical pair is always published so the earned negative an
    # excluded row leaves behind is legible without them.
    disclosures.update({SELF_SERVICE_DISCLOSE_UPGRADE, SELF_SERVICE_DISCLOSE_SIBLING})
    return _SelfServiceBound(proven=True, refusal=None, disclosures=tuple(sorted(disclosures)))


def _flow_asset_class(claims: list[dict[str, Any]]) -> str | None:
    """native / ERC-20 partition of the out-flows, gated on ``from_is_self``.

    An absent ``from_is_self`` is not "this contract is the source": defaulting
    it true would mint a positive fact from a missing key on the gate that
    decides whether the per-asset value substitution runs at all.
    """
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
