"""Executor-call synthesis (exec.arbitrary / low-level value call)."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass


from typing import TYPE_CHECKING

from services.resolution.differential_probe import (
    _is_address_type,
)

from .encoding import _RESOLVED_ADDRESS, _array_shape, _element_type
from .plans import ARG_AMOUNT
from .roles import _declared_param_names

if TYPE_CHECKING:
    from .facts import FunctionFacts

logger = logging.getLogger(__name__)


# Executor synthesis. ``exec.arbitrary`` is the static claim for "this
# function forwards a caller-supplied destination together with a caller-supplied
# calldata blob", proven off the IR read set of a body call op; its witness names
# the two PARAMETERS. ``low_level_value_call`` + a ``param`` destination is the
# flow lattice making the first half of the same statement.
_EXEC_ARBITRARY_CLAIM = "exec.arbitrary"
_LOW_LEVEL_CALL_KIND = "low_level_value_call"
# transfer(address,uint256) — the ERC-20 standard, not a name guess.
_ERC20_TRANSFER_SELECTOR = "0xa9059cbb"


@dataclass(frozen=True)
class ExecutorCall:
    """An inner call synthesized for an arbitrary-call executor.

    ``slots`` is ``(destination_index, calldata_index)`` — the two parameters
    static proved carry the forwarded call. ``values`` holds the scalar value for
    each of those slots, and is EMPTY when the acting deployment holds no asset to
    build an inner call from: the shape is still known (so the encoder can say the
    payload slot was left at its default), but nothing is claimed about it."""

    slots: tuple[int, int]
    values: Mapping[int, Any] = field(default_factory=dict)


def _forwards_param_destination(fn: "FunctionFacts") -> bool:
    """Does the flow lattice say a low-level call in F's body sends to a
    destination the CALLER named? The index need not have resolved — a loop over
    an array of targets leaves the slot unnamed while still proving the kind."""
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if str(flow.get("kind")) != _LOW_LEVEL_CALL_KIND:
            continue
        kind = flow.get("target_kind")
        if isinstance(kind, dict) and kind.get("kind") == "param":
            return True
    return False


def _named_executor_slots(fn: "FunctionFacts", types: Sequence[str]) -> tuple[int, int] | None:
    """The two slots the ``exec.arbitrary`` witness PROVES, when both name a
    parameter of the right shape.

    A name counts only when its ``*_kind`` is ``param`` — i.e. the IR put that
    parameter in the call's destination / calldata operand position. The other
    kinds publish no name, and a witness written before those kinds existed
    carries a name with no kind at all: that is an unread question, not a proof,
    so it falls through to the ABI-uniqueness reasoning below exactly as a
    ``not_determined`` would."""
    names = _declared_param_names(fn, len(types))
    for claim in fn.effect_info.get("claims") or []:
        if not isinstance(claim, dict) or claim.get("claim_id") != _EXEC_ARBITRARY_CLAIM:
            continue
        witness = claim.get("witness")
        if not isinstance(witness, dict):
            continue
        if witness.get("destination_kind") != "param" or witness.get("calldata_kind") != "param":
            continue
        destination, payload = witness.get("destination_param"), witness.get("calldata_param")
        if not isinstance(destination, str) or not isinstance(payload, str) or not destination or not payload:
            continue
        try:
            dest_idx, data_idx = names.index(destination), names.index(payload)
        except ValueError:
            continue
        if _executor_slot_shapes_agree(types, dest_idx, data_idx):
            return dest_idx, data_idx
    return None


def _executor_slot_shapes_agree(types: Sequence[str], destination: int, payload: int) -> bool:
    """A destination and a payload describe ONE forwarded call only if they have
    the same arity: two scalars, or two arrays walked in step."""
    dest_shape, data_shape = _array_shape(types[destination]), _array_shape(types[payload])
    if (dest_shape is None) != (data_shape is None):
        return False
    return _is_address_type(_element_type(types[destination])) and _element_type(types[payload]) == "bytes"


def _unique_executor_slots(types: Sequence[str]) -> tuple[int, int] | None:
    """The only destination/payload pair the ABI admits, or ``None``.

    Read alone this proves nothing — it is used only where static has ALREADY
    proven the function forwards a caller-named destination, to say WHICH slots
    carry it. Ambiguity yields nothing rather than a positional guess: an executor
    whose destination the probe picked wrong simply reverts, but one whose payload
    slot the probe picked wrong could write a transfer into an argument that is
    not calldata at all."""
    scalar_dest = [i for i, t in enumerate(types) if _is_address_type(t)]
    scalar_data = [i for i, t in enumerate(types) if t.strip() == "bytes"]
    array_dest = [i for i, t in enumerate(types) if t.strip() == "address[]"]
    array_data = [i for i, t in enumerate(types) if t.strip() == "bytes[]"]
    if len(scalar_dest) == 1 and len(scalar_data) == 1 and not array_dest and not array_data:
        return scalar_dest[0], scalar_data[0]
    if len(array_dest) == 1 and len(array_data) == 1 and not scalar_dest and not scalar_data:
        return array_dest[0], array_data[0]
    return None


def executor_call(
    fn: "FunctionFacts", types: Sequence[str], *, held_tokens: Sequence[str], recipient: str
) -> ExecutorCall | None:
    """The inner call to synthesize for an arbitrary-call executor, or ``None``
    when F is not one.

    An executor forwards caller-supplied calldata to a caller-supplied target, so
    the encoder's default leaves it calling nothing with nothing: the probe
    executes, moves no value, and that non-observation gets published — and cached
    — about a function that is by construction able to move everything the
    contract holds. What it takes to observe the real behaviour is one honest
    inner call, and the only honest one is an ERC-20 transfer of an asset the
    acting deployment PROVABLY holds (``contract_balances``, richest first). The
    asset never comes from a list of known tokens: on the next protocol that list
    is empty and the probe would be back to sending nothing.

    Soundness is the argument the stage already makes for token-arg substitution:
    a probe input is a CANDIDATE, not a claim. Writing an address and a payload
    into calldata witnesses nothing by itself — the witness is the ``Transfer``
    the execution actually emitted, and if F does not forward the payload the call
    simply reverts."""
    slots = _named_executor_slots(fn, types)
    if slots is None:
        slots = _unique_executor_slots(types) if _forwards_param_destination(fn) else None
    if slots is None:
        return None
    destination, payload = slots
    token = next((t for t in held_tokens if isinstance(t, str) and _RESOLVED_ADDRESS.match(t)), None)
    inner = _erc20_transfer_calldata(recipient, ARG_AMOUNT)
    if token is None or inner is None:
        return ExecutorCall(slots=slots)
    return ExecutorCall(slots=slots, values={destination: token.lower(), payload: inner})


def _erc20_transfer_calldata(recipient: str, amount: int) -> bytes | None:
    """``transfer(recipient, amount)``, or ``None`` on an unencodable recipient."""
    try:
        from eth_abi.abi import encode as abi_encode

        return bytes.fromhex(_ERC20_TRANSFER_SELECTOR[2:]) + abi_encode(["address", "uint256"], [recipient, amount])
    except Exception:
        return None
