from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .claims import _considered_out_flows

logger = logging.getLogger("services.scoring.distill")


# The two ``msg_value`` arms, disjoint and separately ruled on: self-return (the caller gets its attached value back)
# and pass-through (that value goes to a payee no caller names).
MSG_VALUE_ARM_SELF_RETURN = "proven_msg_value_self_return"
MSG_VALUE_ARM_PASSTHROUGH = "proven_msg_value_passthrough"
# ``_fold_sites`` collapses agreeing sites without a count, so repetition per call is unwitnessed.
MSG_VALUE_REPETITION_RESIDUAL = "msg_value_self_return_repetition_not_witnessed"
_MSG_VALUE_REFUSAL_PREFIX = "msg_value_return_refused"
_AMOUNT_TIER_DISPOSITIVE = "dispositive_ast"
_MSG_VALUE_TARGET_ARMS = {"msg_sender": MSG_VALUE_ARM_SELF_RETURN, "immutable": MSG_VALUE_ARM_PASSTHROUGH}


@dataclass(frozen=True)
class _MsgValueReturn:
    """Proven arm, named refusal, or silence (no out-flow mentions ``msg.value``, so the question doesn't arise)."""

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
    """Whether the question arises: the scalar or any breakdown member, since ``several`` is the fold declining to
    answer.
    """
    amount = flow.get("amount_kind")
    if isinstance(amount, dict) and amount.get("kind") == "msg_value":
        return True
    for member in flow.get("amount_kinds") or []:
        if (member.get("kind") if isinstance(member, dict) else member) == "msg_value":
            return True
    return False


def _msg_value_return(claims: list[dict[str, Any]]) -> _MsgValueReturn:
    """W3: whether what leaves is the value the caller just attached, and who gets it.

    Universal over every out-flow, like ``_static_destination_shape``. More than one out-flow entry refuses, since each
    is bounded by ``msg.value`` but the set isn't. The amount must be read off the AST (``static_trace`` doesn't count),
    and the scalar is read with its breakdown: a ``several`` with a ``msg_value`` member proves nothing about the
    others.
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
        # The amount bounds the contract's payout only if the contract pays.
        if flow.get("from_is_self") is not True:
            return _MsgValueReturn(arm=None, refusal="flow_source_not_self")
        if flow.get("target_kinds"):
            return _MsgValueReturn(arm=None, refusal="target_fold_disagreed")
        targets.add(str(target["kind"]))

    if len(considered) > 1:
        # Each entry is bounded by ``msg.value`` but the set isn't; two entries could pay twice what was attached.
        return _MsgValueReturn(arm=None, refusal="multiple_out_flow_entries")
    if len(targets) != 1:
        return _MsgValueReturn(arm=None, refusal="target_not_a_witnessed_arm")
    arm = _MSG_VALUE_TARGET_ARMS.get(next(iter(targets)))
    if arm is None:
        return _MsgValueReturn(arm=None, refusal="target_not_a_witnessed_arm")
    return _MsgValueReturn(arm=arm, refusal=None)
