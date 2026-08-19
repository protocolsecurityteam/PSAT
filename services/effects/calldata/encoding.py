"""ABI calldata encoding and argument synthesis."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass


from typing import TYPE_CHECKING

from services.resolution.differential_probe import (
    _default_value_for_type,
    _is_address_type,
    _parse_arg_types,
)

from .plans import ARG_IDENTIFIER, ROLE_AMOUNT, ROLE_IDENTIFIER

if TYPE_CHECKING:
    from .executor import ExecutorCall

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def encode_calldata(
    selector: str,
    canonical_signature: str | None,
    *,
    substitutions: Mapping[int, Any] | None = None,
) -> str | None:
    """``selector ++ abi.encode(args)`` with per-index overrides.

    Argument defaults and type parsing come from ``differential_probe`` (one
    encoder for the codebase); this wrapper adds positional substitution for any
    type, which the effect probes need (an amount, a recipient, a sentinel).
    Returns ``None`` — never raises — when the signature is unparseable or a value
    does not encode, so callers fail closed."""
    if not isinstance(selector, str) or not selector.startswith("0x") or len(selector) != 10:
        return None
    types = _parse_arg_types(canonical_signature)
    if types is None:
        return None
    subs = {int(k): v for k, v in (substitutions or {}).items()}
    try:
        from eth_abi.abi import encode as abi_encode

        values = [subs[i] if i in subs else _default_value_for_type(t) for i, t in enumerate(types)]
        encoded = abi_encode(types, values).hex() if types else ""
    except Exception as exc:
        logger.debug(
            "effects calldata: encode failed",
            extra={
                "selector": selector,
                "canonical_signature": canonical_signature,
                "arg_count": len(types),
                "substituted_indices": sorted(subs),
                "exc_type": type(exc).__name__,
            },
        )
        return None
    return selector + encoded


_INTEGER_TYPE = re.compile(r"u?int\d*")
_ARRAY_TYPE = re.compile(r"^(?P<element>.+)\[(?P<size>\d*)\]$")
_RESOLVED_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _array_shape(type_str: str) -> tuple[str, int | None] | None:
    """``(element_type, fixed_length)`` for an ABI array, ``None`` for a scalar.
    ``fixed_length`` is ``None`` on a dynamic array."""
    match = _ARRAY_TYPE.match(type_str.strip())
    if match is None:
        return None
    size = match.group("size")
    return match.group("element").strip(), (int(size) if size else None)


def _element_type(type_str: str) -> str:
    """The type a substitution has to satisfy for this slot: the element type of
    an array, the type itself otherwise. A parameter's ROLE belongs to what it
    carries, not to its arity — ``uint256[] amounts`` is as much a quantity slot
    as ``uint256 amount``."""
    shape = _array_shape(type_str)
    return shape[0] if shape is not None else type_str.strip()


def _arg_values(
    types: Sequence[str],
    *,
    identity: str | None,
    amount: int,
    integer_roles: Mapping[int, str] | None = None,
    executor: "ExecutorCall | None" = None,
) -> "ProbeArgs":
    """The substitution policy for a value-moving probe: address params get the
    caller identity (so a mint/transfer has a real recipient); an integer param
    takes ``amount`` only where :func:`integer_param_roles` proved it is a
    quantity, the small id filler where it proved an identifier, and the encoder's
    default where the role is unproven.

    A token slot gets the identity here too, and it is deliberate that it stays
    that way until a REAL token is known. Measured on the three etherfi
    BoringVaults (2026-07-25, mainnet fork): ``enter`` with the encoder's default
    ``address(0)`` in its ``asset`` slot SUCCEEDS — a call to a codeless address
    is a no-op success inside ``SafeTransferLib`` — and mints shares against a
    pull that never happened. That is a fabricated ``supply.mint`` with a
    fabricated "no inflow", i.e. exactly the witness this stage must never
    produce. The identity keeps the slot occupied by something the probe never
    claims is a token; the seeded retry then writes a proven one
    (:func:`substitute_address_arg`), and the recipe withholds the backing
    witness entirely when it could not.

    An ARRAY parameter is encoded at length ONE, its element carrying whatever the
    scalar policy proves for the element type. The encoder's own default for a
    dynamic array is empty, and an empty array is a loop body that never runs: the
    batch form of a function then executes, moves nothing, and publishes — and
    CACHES — "this function moves no value" about a body no probe ever entered. A
    length-1 array whose element is itself unproven is not a witness either, but
    it is an honest attempt that the contract's own check gets to reject.

    An ``executor`` (:func:`executor_call`) overrides its own two slots with the
    inner call it synthesized, and SUPPRESSES the integer roles: every remaining
    numeric argument of an arbitrary-call executor is a per-call native value, a
    gas budget or an operation mode, and the probe can prove the contract can
    satisfy none of them. Zero is both the encoder's default and the only value
    that asks the executor to forward the call and nothing else — a quantity there
    would make the vault attach ETH it does not hold and revert the very call this
    synthesis exists to observe.

    Slots the policy could NOT fill are reported as :attr:`ProbeArgs.vacuous` —
    see that class for why one predicate covers both mechanisms."""
    roles = {} if executor is not None else (integer_roles or {})
    overrides = executor.values if executor is not None else {}
    executor_slots = set(executor.slots) if executor is not None else set()
    subs: dict[int, Any] = {}
    vacuous: list[int] = []
    for idx, type_str in enumerate(types):
        shape = _array_shape(type_str)
        value = overrides.get(idx)
        if value is None:
            value = _scalar_arg_value(
                shape[0] if shape else type_str, idx, identity=identity, amount=amount, roles=roles
            )
        if value is None:
            # A slot of the forwarded call the synthesis could not build is vacuous
            # whatever its type: an executor handed empty calldata calls nothing,
            # and "called nothing, moved nothing" is not a fact about F. The
            # executor's OTHER zeros are not vacuous — they are the deliberate
            # "forward this call and nothing else" the synthesis chose.
            if idx in executor_slots:
                vacuous.append(idx)
            elif executor is None and (shape is not None or _INTEGER_TYPE.fullmatch(type_str.strip())):
                vacuous.append(idx)
        if shape is None:
            if value is not None:
                subs[idx] = value
            continue
        element, length = shape
        if value is None:
            try:
                value = _default_value_for_type(element)
            except Exception:
                # An element type the encoder can build no value for at all —
                # leaving the slot to the encoder is the only honest option.
                continue
        subs[idx] = [value] * (1 if length is None else length)
    return ProbeArgs(substitutions=subs, vacuous=tuple(vacuous))


@dataclass(frozen=True)
class ProbeArgs:
    """An encoded argument vector, plus the slots the policy could not fill.

    ``vacuous`` is ONE predicate, not two detectors that would drift apart: *an
    argument the effect depends on was left at the encoder's default*. It covers
    an integer whose role never resolved (a zero-amount call that mints nothing
    and moves nothing), an array whose element is unproven (a loop that runs over
    filler), and a forwarded-call slot with no inner call to put in it. All three
    produce the same false statement downstream — the call RAN and observed
    nothing, which reads as a structural fact about the function while being a
    fact about the arguments this prober chose.

    It is a FACT rather than a guess: the synthesizer knows the ABI types and
    which roles it resolved, so it knows exactly which slots it filled. The
    consumer's job is to keep such a non-observation out of the behaviour cache —
    a code-plane cache entry travels to bytecode twins that were never probed."""

    substitutions: dict[int, Any]
    vacuous: tuple[int, ...] = ()


def _scalar_arg_value(
    type_str: str,
    index: int,
    *,
    identity: str | None,
    amount: int,
    roles: Mapping[int, str],
) -> Any | None:
    """The value :func:`_arg_values` PROVES for one scalar slot, or ``None`` when
    it proves nothing and the encoder's own default has to stand."""
    t = type_str.strip()
    if _is_address_type(t):
        return identity.lower() if identity else None
    if _INTEGER_TYPE.fullmatch(t):
        role = roles.get(index)
        if role == ROLE_AMOUNT:
            return amount
        if role == ROLE_IDENTIFIER:
            return ARG_IDENTIFIER
    return None
