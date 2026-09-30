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

logger = logging.getLogger("services.effects.calldata")


def encode_calldata(
    selector: str,
    canonical_signature: str | None,
    *,
    substitutions: Mapping[int, Any] | None = None,
) -> str | None:
    """``selector ++ abi.encode(args)`` with per-index overrides.

    Defaults and parsing come from ``differential_probe``. Returns ``None`` on an unparseable signature or unencodable
    value.
    """
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
    """``(element_type, fixed_length)`` for an ABI array (``None`` length if dynamic), ``None`` for a scalar."""
    match = _ARRAY_TYPE.match(type_str.strip())
    if match is None:
        return None
    size = match.group("size")
    return match.group("element").strip(), (int(size) if size else None)


def _element_type(type_str: str) -> str:
    """The type a substitution must satisfy: the element type for arrays, else the type itself."""
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
    """Argument policy for a value-moving probe.

    Address params get the caller identity so transfers have a real recipient. Integer params get ``amount`` only where
    :func:`integer_param_roles` proved a quantity, the id filler for identifiers, else the encoder default.

    Token slots also get the identity until a real token is known: with ``address(0)`` a vault's ``enter`` succeeds
    (codeless calls no-op in ``SafeTransferLib``) and mints against a pull that never happened. The seeded retry writes
    a proven token (:func:`substitute_address_arg`), or the recipe withholds backing.

    Arrays are encoded at length one; an empty array runs no loop and would publish (and cache) "moves no value".

    An ``executor`` (:func:`executor_call`) fills its two slots with the synthesized inner call and suppresses integer
    roles: its other numbers are native value, gas or mode, and zero is the only value that just forwards the call.

    Unfilled slots are reported as :attr:`ProbeArgs.vacuous`.
    """
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
            # A forwarded-call slot with no inner call is vacuous (calls nothing); the executor's deliberate zeros
            # aren't.
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
                # No buildable value; leave it to the encoder.
                continue
        subs[idx] = [value] * (1 if length is None else length)
    return ProbeArgs(substitutions=subs, vacuous=tuple(vacuous))


@dataclass(frozen=True)
class ProbeArgs:
    """An encoded argument vector plus the slots the policy couldn't fill.

    ``vacuous`` is one predicate: an argument the effect depends on was left at the encoder default (an unresolved
    integer role, an array of unproven elements, an empty forwarded call). Each makes "ran and observed nothing" a fact
    about our arguments, so consumers keep it out of the behaviour cache.
    """

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
    """The value :func:`_arg_values` proves for one scalar slot, or ``None`` (encoder default)."""
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
