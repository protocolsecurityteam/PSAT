"""Shared canonical ABI identity for analyzer, policy, and Assessment consumers."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Any

from eth_utils.crypto import keccak


def _lower_type_to_abi(t: Any, ancestors: tuple[Any, ...]) -> str:
    """Lower one Slither parameter ``Type`` to its EVM-canonical ABI string:
    contract/interface → ``address``, enum → its ``uint<N>`` width, struct →
    a parenthesised tuple of lowered members, type-alias → its underlying
    elementary type, array → the lowered element with its ``[]``/``[N]`` suffix.

    ``ancestors`` is the chain of struct types enclosing ``t`` on the current
    path; a struct that recurses into itself stops there (its name is kept,
    matching a non-lowerable param so the caller drops it). Tracking the path —
    not every type seen anywhere — means a user-defined type that appears more
    than once across sibling fields lowers at every occurrence."""
    from slither.core.declarations import Contract, Enum, Structure
    from slither.core.solidity_types import ArrayType, UserDefinedType
    from slither.core.solidity_types.type_alias import TypeAlias

    if isinstance(t, ArrayType):
        element = _lower_type_to_abi(t.type, ancestors)
        if t.length is None:
            return element + "[]"
        return f"{element}[{t.length_value}]"

    if isinstance(t, TypeAlias):
        return str(t.type)

    if isinstance(t, UserDefinedType):
        underlying = t.type
        if isinstance(underlying, Contract):
            return "address"
        if isinstance(underlying, Enum):
            count = len(underlying.values)
            width = 8 if count <= 256 else (16 if count <= 65536 else int(math.log2(count)))
            return f"uint{width}"
        if isinstance(underlying, Structure):
            if underlying in ancestors:
                # Self-recursive struct (legal only off the external ABI):
                # un-lowerable, so surface the raw name and let the caller drop it.
                return str(t)
            members = ",".join(_lower_type_to_abi(e.type, ancestors + (underlying,)) for e in underlying.elems_ordered)
            return f"({members})"

    return str(t)


def _canonical_signature(fn: Any) -> str | None:
    """EVM-canonical ABI signature for ``fn`` — contract/interface params
    lowered to ``address``, enums to ``uint<N>``, structs to their tuple form,
    arrays preserving their suffix — or ``None`` when it can't be fully lowered.

    The trees here are keyed on Slither ``full_name``, which keeps user-defined
    parameter type names (``addAsset(ERC20)``,
    ``executeTasks(IEtherFiOracle.OracleReport)``). The real EVM selector can't
    be recovered from that string downstream: a struct's field layout and an
    enum's ``uint8`` width are already gone, and the name alone can't tell a
    struct/enum apart from a contract. We walk the parameter ``Type`` objects
    directly while Slither is live, lowering every occurrence of a user-defined
    type. A self-recursive struct (legal only off the external ABI) leaves a
    residual non-elementary token; the identity remains unknown rather than
    being guessed from that name."""
    try:
        parameters = fn.parameters
        name = fn.name
    except (AttributeError, KeyError, TypeError):
        return None
    if parameters is None or not isinstance(name, str):
        return None
    try:
        lowered = [_lower_type_to_abi(p.type, ()) for p in parameters]
    except (ValueError, AttributeError, KeyError, TypeError):
        return None
    signature = f"{name}({','.join(lowered)})"
    # A user-defined name surviving the walk means a non-lowerable (recursive)
    # struct: reject so the selector derivation uses the string fallback rather
    # than keccak'ing a name that has no on-chain selector.
    if any(seg and not _is_elementary_token(seg) for seg in _split_top_level(",".join(lowered))):
        return None
    return signature


def _is_elementary_token(token: str) -> bool:
    """True when ``token`` (one top-level tuple member, suffix-stripped) is an
    EVM elementary type or a tuple thereof — i.e. carries no residual
    user-defined type name."""
    token = token.strip()
    while token.endswith("]"):
        suffix = re.search(r"\[(?:[1-9][0-9]*)?\]$", token)
        if suffix is None:
            return False
        token = token[: suffix.start()]
    if token.startswith("(") and token.endswith(")"):
        return all(_is_elementary_token(s) for s in _split_top_level(token[1:-1]))
    if token in {"address", "bool", "string", "bytes", "function"}:
        return True
    integer = re.fullmatch(r"u?int([0-9]+)", token)
    if integer:
        width = int(integer[1])
        return str(width) == integer[1] and 8 <= width <= 256 and width % 8 == 0
    fixed_bytes = re.fullmatch(r"bytes([0-9]+)", token)
    if fixed_bytes:
        width = int(fixed_bytes[1])
        return str(width) == fixed_bytes[1] and 1 <= width <= 32
    fixed = re.fullmatch(r"u?fixed([0-9]+)x([0-9]+)", token)
    if fixed:
        width, decimals = int(fixed[1]), int(fixed[2])
        return (
            str(width) == fixed[1]
            and str(decimals) == fixed[2]
            and 8 <= width <= 256
            and width % 8 == 0
            and 1 <= decimals <= 80
        )
    return False


# Slither renders the two selectorless entry points as ordinary zero-argument
# signatures, so every string-level canonicality test passed them and hashed
# them: ``keccak("fallback()")[:4] = 0x552079dc``, ``keccak("receive()")[:4] =
# 0xa3e76c0f``. Neither is a dispatch — a fallback is reached by calldata that
# matches nothing, and a contract that really declared ``function fallback()``
# would own 0x552079dc itself.
SELECTORLESS_SIGNATURES = frozenset({"fallback()", "receive()"})


def has_no_selector(signature: str | None) -> bool:
    """True for the signatures that PROVABLY have no 4-byte selector.

    Distinct from ``not is_canonical_abi_signature(...)``, which means "this
    string was never lowered, so we cannot say". Consumers that need three
    states publish ``""`` here (the ``effect_verdicts`` identity sentinel in
    ``db/effect_cache.py``) and ``None`` for the unlowered case."""
    return signature in SELECTORLESS_SIGNATURES


def is_canonical_abi_signature(signature: str) -> bool:
    """True when every parameter token of ``signature`` is an EVM elementary type
    — i.e. ``keccak(signature)[:4]`` really is the function's ``msg.sig``.

    A residual user-defined name (``setAuthority(Authority)``,
    ``f(IFoo.PermitInput)``) means the signature was never lowered, so its hash
    names a dispatch that does not exist. This is the same rejection
    :func:`_canonical_signature` applies to its own output, shared so that every
    consumer deriving a selector from a *string* can fail closed the same way.

    ``fallback()`` / ``receive()`` are rejected for the same reason: they parse
    as canonical zero-argument signatures but their hash is not reachable."""
    if has_no_selector(signature):
        return False
    if "(" not in signature or not signature.endswith(")"):
        return False
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", signature[: signature.index("(")]):
        return False
    body = signature[signature.index("(") + 1 : -1]
    return not body or all(_is_elementary_token(token) for token in _split_top_level(body))


def _split_top_level(s: str) -> list[str]:
    """Split a comma-joined tuple body at depth-0 commas only."""
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(s):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


def selector_for_signature(signature: str | None) -> str | None:
    """Return a dispatch selector only for a known canonical ABI signature."""
    if not isinstance(signature, str) or not is_canonical_abi_signature(signature):
        return None
    return "0x" + keccak(text=signature).hex()[:8]


def canonical_signature(signature: str | None, known: Mapping[str, str] | None = None) -> str | None:
    """Known ABI spelling or no answer; never infer a type from its name."""
    if not isinstance(signature, str):
        return None
    for candidate in ((known or {}).get(signature), signature):
        if isinstance(candidate, str) and is_canonical_abi_signature(candidate):
            return candidate
    return None


def function_identity(signature: str | None, known: Mapping[str, str] | None = None) -> tuple[str | None, str | None]:
    canonical = canonical_signature(signature, known)
    return canonical, selector_for_signature(canonical)
