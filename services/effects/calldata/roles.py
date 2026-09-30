"""Param-role vocabularies: amounts, identifiers, tokens, recipients."""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass


from typing import TYPE_CHECKING

from services.resolution.differential_probe import (
    _is_address_type,
)

from .encoding import _INTEGER_TYPE, _element_type
from .flows import _lattice_taint_index
from .plans import ROLE_AMOUNT, ROLE_IDENTIFIER, ROLE_RECIPIENT, ROLE_TOKEN
from .trees import _param_index_by_name

if TYPE_CHECKING:
    from .facts import FunctionFacts

logger = logging.getLogger("services.effects.calldata")


# Semantic word vocabularies for integer param roles: ``assetAmount``/``wad`` are quantities, ``tokenId``/``deadline``
# aren't.
_AMOUNT_WORDS = frozenset(
    {"amount", "amounts", "value", "values", "qty", "quantity", "share", "shares", "wad", "fee", "fees", "assets"}
)
# Handles to stored things; they take the id filler, which is also where ownership seeds write.
_IDENTIFIER_WORDS = frozenset({"id", "ids", "index", "indexes", "indices", "idx", "key", "position", "slot"})
# Neither quantities nor handles (clocks, nonces, versions); no honest filler, so they get zero.
_NON_QUANTITY_WORDS = frozenset(
    {"deadline", "timestamp", "expiry", "expiration", "nonce", "epoch", "round", "version", "salt"}
)
# Split on separators and camelCase humps.
_NAME_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _name_words(name: str) -> set[str]:
    return {word.lower() for word in _NAME_SPLIT.split(name or "") if word}


def _declared_param_names(fn: "FunctionFacts", count: int) -> list[str]:
    """Declared parameter names by position: the artifact's ``parameter_names``, gaps filled from predicate trees.

    Unnamed slots are ``""``.
    """
    raw = fn.effect_info.get("parameter_names")
    names = [str(n) for n in raw] if isinstance(raw, list) and len(raw) == count else [""] * count
    for name, idx in _param_index_by_name(fn.tree).items():
        if 0 <= idx < count and not names[idx]:
            names[idx] = name
    return names


def _lattice_amount_indexes(fn: "FunctionFacts", types: Sequence[str], directions: frozenset[str] | None) -> set[int]:
    """Slots the flow lattice resolved as a flow's amount.

    ``param_derived`` counts: it's the input converted into the amount (the ``shares`` in ``transfer(receiver,
    convertToAssets(shares))``). Absent on older artifacts.
    """
    out: set[int] = set()
    for flow in fn.effect_info.get("value_flows") or []:
        if not isinstance(flow, dict) or flow.get("origin") == "guard":
            continue
        if directions is not None and str(flow.get("direction")) not in directions:
            continue
        kind = flow.get("amount_kind")
        kind_name = kind.get("kind") if isinstance(kind, dict) else None
        index = flow.get("amount_param_index")
        if kind_name not in ("param", "param_derived") or not isinstance(index, int) or isinstance(index, bool):
            continue
        if 0 <= index < len(types) and _INTEGER_TYPE.fullmatch(_element_type(types[index])):
            out.add(index)
    return out


def integer_param_roles(
    fn: "FunctionFacts", types: Sequence[str], directions: frozenset[str] | None = None
) -> dict[int, str]:
    """``index -> ROLE_AMOUNT | ROLE_IDENTIFIER`` for integer params with a nameable role.

    Absent means no substitution: filling every integer with an amount made ``requestId`` and ``deadline`` args revert
    on their own input.
    """
    lattice = _lattice_amount_indexes(fn, types, directions)
    names = _declared_param_names(fn, len(types))
    roles: dict[int, str] = {}
    for idx, type_str in enumerate(types):
        if not _INTEGER_TYPE.fullmatch(_element_type(type_str)):
            continue
        words = _name_words(names[idx])
        # Negative vocabularies first: an ambiguous name fails away from the amount.
        if words & _IDENTIFIER_WORDS:
            roles[idx] = ROLE_IDENTIFIER
        elif words & _NON_QUANTITY_WORDS:
            continue
        elif idx in lattice or words & _AMOUNT_WORDS:
            roles[idx] = ROLE_AMOUNT
    return roles


# Address-param roles by word: ``asset``/``tokenIn`` name a dereferenced contract; ``to``/``receiver`` name where value
# lands.
_TOKEN_WORDS = frozenset({"token", "tokens", "asset", "collateral", "underlying", "currency", "erc20", "erc721", "nft"})
_RECIPIENT_WORDS = frozenset({"to", "recipient", "receiver", "beneficiary", "destination", "dst", "payee", "refund"})

# Token-only ERC-20/721 methods (and the common wrapper libraries). A sink calling one on a parameter proves it's a
# token; selectors can't, since library wrappers have their own.
_TOKEN_METHOD_WORDS = frozenset(
    {
        "transfer",
        "transferfrom",
        "safetransfer",
        "safetransferfrom",
        "approve",
        "safeapprove",
        "increaseallowance",
        "decreaseallowance",
        "balanceof",
        "allowance",
        "burn",
        "burnfrom",
        "mint",
        "permit",
    }
)


def _token_method_targets(fn: "FunctionFacts") -> set[str]:
    """Dotted-target heads of body sinks calling a token-only method (``asset.safeTransferFrom`` ⇒ ``asset``)."""
    heads: set[str] = set()
    for sink in fn.effect_info.get("sinks") or []:
        if not isinstance(sink, dict) or sink.get("kind") != "external_call" or sink.get("origin") != "body":
            continue
        target = str(sink.get("target") or "")
        head, _, method = target.rpartition(".")
        if head and method.lower() in _TOKEN_METHOD_WORDS:
            heads.add(head)
    return heads


def address_param_roles(
    fn: "FunctionFacts", types: Sequence[str], directions: frozenset[str] | None = None
) -> dict[int, str]:
    """``index -> ROLE_RECIPIENT | ROLE_TOKEN`` for address params with a nameable role; absent keeps the principal.

    Token slots take no principal (an EOA there reverts the first line); the seeded retry writes a real token
    (:func:`substitute_address_arg`). Recipient is a veto: a name matching both vocabularies, or a lattice-resolved
    payout slot, is never demoted to token.
    """
    names = _declared_param_names(fn, len(types))
    lattice_target = _lattice_taint_index(fn, types, directions) if directions is not None else None
    called_on = _token_method_targets(fn)
    roles: dict[int, str] = {}
    for idx, type_str in enumerate(types):
        if not _is_address_type(type_str.strip()):
            continue
        name = names[idx]
        words = _name_words(name)
        is_recipient = bool(words & _RECIPIENT_WORDS) or idx == lattice_target
        is_token = bool(words & _TOKEN_WORDS) or (bool(name) and name in called_on)
        # Both vocabularies is no evidence; keep the payout observable.
        if is_recipient:
            roles[idx] = ROLE_RECIPIENT
        elif is_token:
            roles[idx] = ROLE_TOKEN
    return roles


def substitute_address_arg(calldata: str, index: int, address: str) -> str | None:
    """Rewrite top-level argument ``index`` of encoded calldata to ``address``.

    Exact because address is a static type at a fixed offset; done post-encoding because the token is only known on the
    wire. ``None`` if too short or malformed.
    """
    if not isinstance(calldata, str) or not calldata.startswith("0x") or index < 0:
        return None
    body = calldata[2:]
    start = 8 + index * 64
    if len(body) < start + 64:
        return None
    raw = address[2:] if address.startswith("0x") else address
    if len(raw) != 40:
        return None
    try:
        int(raw, 16)
    except ValueError:
        return None
    return "0x" + body[:start] + raw.rjust(64, "0").lower() + body[start + 64 :]
