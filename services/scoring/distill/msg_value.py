"""The msg_value return witness."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .claims import _considered_out_flows

logger = logging.getLogger("services.scoring.distill")

# ------------------------------------------------------------------ msg_value

# The two arms of the ``msg_value`` witness, each named for what it PROVES. They
# are disjoint by construction and carry separate tokens so the owner can rule on
# them one at a time: the self-return arm is the caller getting back the value it
# just attached; the pass-through arm is that same value reaching a payee no
# caller can name.
MSG_VALUE_ARM_SELF_RETURN = "proven_msg_value_self_return"
MSG_VALUE_ARM_PASSTHROUGH = "proven_msg_value_passthrough"
# What the proven arm did NOT look at, travelling with it. ``_fold_sites``
# collapses agreeing IR sites into one entry and publishes no count, so "each
# payment is bounded by the value attached to this call" is the whole of the
# claim: how many such payments one call makes is unwitnessed, and a bound with
# no repetition count is not a bound on the call.
MSG_VALUE_REPETITION_RESIDUAL = "msg_value_self_return_repetition_not_witnessed"
_MSG_VALUE_REFUSAL_PREFIX = "msg_value_return_refused"
_AMOUNT_TIER_DISPOSITIVE = "dispositive_ast"
_MSG_VALUE_TARGET_ARMS = {"msg_sender": MSG_VALUE_ARM_SELF_RETURN, "immutable": MSG_VALUE_ARM_PASSTHROUGH}


@dataclass(frozen=True)
class _MsgValueReturn:
    """Three states, and the third one is silence.

    An arm PROVEN, a refusal NAMED, or neither — the last being "no out-flow of
    this function mentions ``msg.value`` at all", where the question does not
    arise. Publishing a refusal there would hang a reason off every payout in the
    corpus and say nothing about any of them; publishing the arm off an
    unanswered question is the defect this scorer exists to avoid.
    """

    arm: str | None
    refusal: str | None

    @property
    def notes(self) -> tuple[str, ...]:
        if self.arm is not None:
            return (self.arm,)
        if self.refusal is not None:
            return (f"{_MSG_VALUE_REFUSAL_PREFIX}:{self.refusal}",)
        return ()


_MSG_VALUE_NOT_ASKED = _MsgValueReturn(arm=None, refusal=None)


def _mentions_msg_value(flow: dict[str, Any]) -> bool:
    """Whether the question arises on this flow — the fold's scalar OR any member
    of its breakdown, because a ``several`` is the fold declining to answer, not
    the absence of a ``msg.value`` site."""
    amount = flow.get("amount_kind")
    if isinstance(amount, dict) and amount.get("kind") == "msg_value":
        return True
    for member in flow.get("amount_kinds") or []:
        if (member.get("kind") if isinstance(member, dict) else member) == "msg_value":
            return True
    return False


def _msg_value_return(claims: list[dict[str, Any]]) -> _MsgValueReturn:
    """W3: whether what leaves is the value the caller just attached, and who gets it.

    UNIVERSAL over every out-flow the way ``_static_destination_shape`` is: one
    flow paying anything other than the caller's own ``msg.value``, or paying it
    to a third kind of payee, refuses the whole function rather than being
    outvoted by its siblings.

    One further structural refusal, and it is not a technicality: each entry is
    bounded by ``msg.value``, the SET is bounded by nothing, so a function with
    more than one out-flow entry can move a multiple of what the caller attached
    — the surplus coming out of a balance somebody else funded. What survives
    inside a single entry is the fold's own residual (agreeing IR sites collapse
    with no count), which the proven arm discloses rather than hides.

    Two readings this arm may not take. The amount must be read straight off the
    AST — a ``static_trace`` ``msg.value`` is that the tracer arrived at the
    opcode, not that the amount IS the attached value. And the fold's scalar is
    read together with its breakdown: ``amount_kinds``/``target_kinds`` are
    emitted exactly where the contributing sites DISAGREED
    (``effects._site_breakdown``), so a ``several`` carrying a ``msg_value``
    member proves nothing about the members beside it — ``effects._fold_sites``
    instructs its consumers to take the worst, and the worst here is unproven.
    """
    considered, blocked = _considered_out_flows(claims)
    if blocked is not None or not considered:
        return _MSG_VALUE_NOT_ASKED
    if not any(_mentions_msg_value(flow) for flow in considered):
        return _MSG_VALUE_NOT_ASKED

    targets: set[str] = set()
    for flow in considered:
        amount = flow.get("amount_kind")
        target = flow.get("target_kind")
        if not isinstance(amount, dict) or not isinstance(target, dict) or not target.get("kind"):
            return _MsgValueReturn(arm=None, refusal="flow_kind_unreadable")
        if flow.get("amount_kinds"):
            return _MsgValueReturn(arm=None, refusal="amount_fold_disagreed")
        if amount.get("kind") != "msg_value":
            return _MsgValueReturn(arm=None, refusal="amount_not_msg_value")
        if amount.get("tier") != _AMOUNT_TIER_DISPOSITIVE:
            return _MsgValueReturn(arm=None, refusal="amount_not_dispositive_ast")
        # An absent ``from_is_self`` is not "this contract is the source": the
        # amount can only bound what the CONTRACT pays out if the contract is
        # what pays.
        if flow.get("from_is_self") is not True:
            return _MsgValueReturn(arm=None, refusal="flow_source_not_self")
        if flow.get("target_kinds"):
            return _MsgValueReturn(arm=None, refusal="target_fold_disagreed")
        targets.add(str(target["kind"]))

    if len(considered) > 1:
        # Each entry is bounded by ``msg.value``; the SET is bounded by nothing.
        # Two entries paying the caller move twice what the caller attached, and
        # the second one comes out of a balance somebody else funded — so a flow
        # set with more than one entry refuses rather than being read as one
        # payment repeated in the witness's favour.
        return _MsgValueReturn(arm=None, refusal="multiple_out_flow_entries")
    if len(targets) != 1:
        return _MsgValueReturn(arm=None, refusal="target_not_a_witnessed_arm")
    arm = _MSG_VALUE_TARGET_ARMS.get(next(iter(targets)))
    if arm is None:
        return _MsgValueReturn(arm=None, refusal="target_not_a_witnessed_arm")
    return _MsgValueReturn(arm=arm, refusal=None)
