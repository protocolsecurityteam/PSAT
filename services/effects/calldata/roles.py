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

logger = logging.getLogger(__name__)


# Word vocabulary for the ROLE of an integer parameter. Both sets are semantic,
# not protocol-specific: a name is split into words and classified by what the
# word MEANS in ABI usage, so ``assetAmount``/``_amount``/``wad`` are quantities
# and ``tokenId``/``requestId``/``index``/``deadline`` are not, on any contract.
_AMOUNT_WORDS = frozenset(
    {"amount", "amounts", "value", "values", "qty", "quantity", "share", "shares", "wad", "fee", "fees", "assets"}
)
# Names that denote a HANDLE to something the contract stores — a token id, a
# queue position. These take the small id filler, which is also the key the
# ownership seed writes at (:func:`_seed_fixture_for_role`), so a probe and its
# seed agree on which entry they mean.
_IDENTIFIER_WORDS = frozenset({"id", "ids", "index", "indexes", "indices", "idx", "key", "position", "slot"})
# Names that are demonstrably NOT quantities but are no kind of handle either: a
# clock value, a replay counter, a version. There is no honest filler for these —
# a made-up deadline is a guess about the chain's time — so they take the
# encoder's zero and the contract's own check decides.
_NON_QUANTITY_WORDS = frozenset(
    {"deadline", "timestamp", "expiry", "expiration", "nonce", "epoch", "round", "version", "salt"}
)
# Split on separators AND camelCase humps: ``assetAmount`` → asset, amount.
_NAME_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def _name_words(name: str) -> set[str]:
    return {word.lower() for word in _NAME_SPLIT.split(name or "") if word}


def _declared_param_names(fn: "FunctionFacts", count: int) -> list[str]:
    """Declared parameter names by position, best-effort.

    Two sources, both from the static plane: the effects artifact's own
    ``parameter_names`` (complete, but absent on artifacts written before it
    existed), and the predicate trees, which record ``parameter_name`` beside
    ``parameter_index`` for every parameter some gate reads. The tree fills gaps
    on an older artifact; an unnamed slot stays the empty string, which classifies
    as no evidence rather than as a guess."""
    raw = fn.effect_info.get("parameter_names")
    names = [str(n) for n in raw] if isinstance(raw, list) and len(raw) == count else [""] * count
    for name, idx in _param_index_by_name(fn.tree).items():
        if 0 <= idx < count and not names[idx]:
            names[idx] = name
    return names


def _lattice_amount_indexes(fn: "FunctionFacts", types: Sequence[str], directions: frozenset[str] | None) -> set[int]:
    """Parameter slots the static flow lattice resolved as the AMOUNT of a value
    flow — the dispositive "this argument is the quantity" fact (the value-out
    mirror of :func:`_lattice_taint_index`). Absent on artifacts predating the field.

    ``param_derived`` counts alongside ``param``: its index is the slot of the
    caller input the contract converted into the amount (``transfer(receiver,
    convertToAssets(shares))`` — the ``shares`` slot), which is exactly the slot a
    probe must fill for the redemption to move anything. It says nothing about
    how much leaves, and nothing here reads it that way."""
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
    """``index -> ROLE_AMOUNT | ROLE_IDENTIFIER`` for the integer params whose role
    the static plane can actually name. An index ABSENT from the result has no
    evidence either way and takes NO substitution.

    That absence is the point. The previous policy pushed the probe amount into
    every integer slot, so a redemption's ``requestId`` and a swap's ``deadline``
    received a quantity — the seeded retry escalated that to one whole token unit
    and the call reverted on its own input before reaching any effect. A probe
    argument nobody can justify is better left at the encoder's zero: the call
    still runs, and a revert that follows is the contract's, not the prober's."""
    lattice = _lattice_amount_indexes(fn, types, directions)
    names = _declared_param_names(fn, len(types))
    roles: dict[int, str] = {}
    for idx, type_str in enumerate(types):
        if not _INTEGER_TYPE.fullmatch(_element_type(type_str)):
            continue
        words = _name_words(names[idx])
        # The two negative vocabularies are checked FIRST and beat every other
        # signal: writing a quantity into a slot that is not one is the failure
        # being fixed, so an ambiguous name fails away from the amount.
        if words & _IDENTIFIER_WORDS:
            roles[idx] = ROLE_IDENTIFIER
        elif words & _NON_QUANTITY_WORDS:
            continue
        elif idx in lattice or words & _AMOUNT_WORDS:
            roles[idx] = ROLE_AMOUNT
    return roles


# Word vocabulary for the ROLE of an ADDRESS parameter, same mechanism-first
# shape as the integer one: split the declared name into words and classify by
# what the word MEANS in ABI usage. ``asset``/``depositAsset``/``tokenIn`` name a
# contract the function dereferences; ``to``/``receiver``/``beneficiary`` name
# somewhere value lands.
_TOKEN_WORDS = frozenset({"token", "tokens", "asset", "collateral", "underlying", "currency", "erc20", "erc721", "nft"})
_RECIPIENT_WORDS = frozenset({"to", "recipient", "receiver", "beneficiary", "destination", "dst", "payee", "refund"})

# Method names, from the ERC-20/721 ABI and the two ubiquitous wrapper libraries
# over it, that only ever appear on a TOKEN. A body sink calling one of these on
# a parameter proves that parameter is a token, whatever it is named — the
# selector-keyed :data:`_PULL_SELECTORS` cannot see it, because a library wrapper
# (``SafeTransferLib.safeTransferFrom(ERC20,...)``) has a selector of its own.
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
    """Dotted-target HEADS of body sinks calling a token-only method
    (``asset.safeTransferFrom`` ⇒ ``asset``). The head is either a declared
    parameter or a state variable; the caller decides which it is looking at."""
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
    """``index -> ROLE_RECIPIENT | ROLE_TOKEN`` for the address params whose role
    the static plane can name. An index ABSENT from the result keeps the probe's
    default (the acting principal).

    The ROLE_TOKEN half is what this exists for. The encoder used to write the
    principal into every address arg, so a deposit-shaped function received an
    EOA where it expected an ERC-20 and reverted on its own first line — the
    whole gated-deposit population landed ``unknown`` with no backing witness. A
    token slot therefore takes no principal; the seeded retry writes a REAL token
    there (:func:`substitute_address_arg`) or the slot stays at the encoder's
    default and the resulting revert is the contract's, not the prober's.

    ROLE_RECIPIENT is a veto, not a substitution change: it already gets the
    principal. It exists so a name carrying BOTH vocabularies, or a slot the
    value-flow lattice resolved as the payout destination, can never be demoted
    to a token slot and lose the identity that makes the payout observable."""
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
        # Both vocabularies on one name is no evidence at all: demoting a payout
        # destination to a token slot costs the observation the probe exists for.
        if is_recipient:
            roles[idx] = ROLE_RECIPIENT
        elif is_token:
            roles[idx] = ROLE_TOKEN
    return roles


def substitute_address_arg(calldata: str, index: int, address: str) -> str | None:
    """Rewrite top-level argument ``index`` of an encoded call to ``address``.

    An ``address`` is a static ABI type, so its head word IS its value and lives
    at a fixed offset whatever follows it — the rewrite is exact, and it is done
    here rather than by re-encoding because the identity of the token is only
    known on the wire (the seeder resolves it), while the calldata is built
    offline. Returns ``None`` when the calldata is too short for that slot or the
    address is malformed, so the caller fails closed."""
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
