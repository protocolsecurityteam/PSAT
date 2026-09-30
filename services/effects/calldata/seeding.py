"""Token-precondition and input-asset seeding."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass

from typing import TYPE_CHECKING

from eth_utils.crypto import keccak
from sqlalchemy.orm import Session

from services.effects.anvil import ForkFixture
from services.effects.seeding import SEED_UNIT_DECIMALS
from services.effects.selection import Candidate
from services.resolution.differential_probe import (
    _parse_arg_types,
)

from .encoding import _RESOLVED_ADDRESS, _arg_values, encode_calldata
from .facts import ContractFacts, FunctionFacts
from .flows import _selector_of
from .pause_window import (
    _claim_latch_pairs,
    _entry_point_for,
    _latch_pairs,
    _pauser_identity_probes,
    _principals_by_selector,
    _state_changing_functions,
    read_max_pause_duration,
)
from .plans import (
    ARG_IDENTIFIER,
    FIXTURE_BALANCE_WEI,
    SEED_AMOUNT,
    SENTINEL_ADDRESS,
    PausePlanInputs,
)
from .roles import _declared_param_names, _token_method_targets, integer_param_roles
from .trees import _gate_ref, guarded_functions

if TYPE_CHECKING:
    from .executor import ExecutorCall

logger = logging.getLogger("services.effects.calldata")


def _word_hex(value: int) -> str:
    return "0x" + format(value & (2**256 - 1), "064x")


def _mapping_entry_slot(base_slot: str, keys: Sequence[int]) -> str | None:
    """Storage slot of a nested mapping entry, outermost key first: ``m[k1][k2] = keccak(pad32(k2) ++
    keccak(pad32(k1) ++ base))``. ``None`` if ``base_slot`` isn't a ≤32-byte word.
    """
    try:
        raw = base_slot[2:] if base_slot.lower().startswith("0x") else base_slot
        slot = bytes.fromhex(raw)
    except ValueError:
        return None
    if len(slot) > 32:
        return None
    slot = slot.rjust(32, b"\x00")
    for key in keys:
        slot = keccak(key.to_bytes(32, "big") + slot)
    return "0x" + slot.hex()


def _seed_fixture_for_role(entry: Mapping[str, Any], caller: str, target: str) -> ForkFixture | None:
    """One read-back-verified fixture seeding ``caller``'s precondition for one token_slots ``entry`` on ``target``.

    ``None`` on malformed fields (a dropped seed only shrinks the lower bound).
    """
    role = entry.get("role")
    key_kind = entry.get("key_kind")
    base_slot = entry.get("base_slot")
    getter = entry.get("getter")
    if not isinstance(base_slot, str) or not isinstance(getter, str):
        logger.debug("effects calldata: token_slots entry missing base_slot/getter: %r", entry)
        return None
    getter_selector = _selector_of(getter)
    if getter_selector is None:
        logger.debug("effects calldata: token_slots getter not a canonical signature: %r", getter)
        return None

    caller = caller.lower()
    try:
        caller_key = int(caller, 16)
    except ValueError:
        logger.debug("effects calldata: token_slots caller not an address: %r", caller)
        return None

    # Probes put the caller in every address arg and ARG_IDENTIFIER in id-shaped uints, so seeds must use those keys.
    if role in ("balance", "shares") and key_kind == "address":
        keys, subs, value = [caller_key], {0: caller}, _word_hex(SEED_AMOUNT)
    elif role == "allowance" and key_kind == "address_address":
        keys, subs, value = [caller_key, caller_key], {0: caller, 1: caller}, _word_hex(SEED_AMOUNT)
    elif role == "owner" and key_kind == "uint256":
        # ``ownerOf(tokenId)`` must return the prober.
        keys, subs, value = [ARG_IDENTIFIER], {0: ARG_IDENTIFIER}, _word_hex(caller_key)
    else:
        logger.debug("effects calldata: token_slots role/kind unsupported: role=%r kind=%r", role, key_kind)
        return None

    slot = _mapping_entry_slot(base_slot, keys)
    verify_calldata = encode_calldata(getter_selector, getter, substitutions=subs)
    if slot is None or verify_calldata is None:
        logger.debug("effects calldata: token_slots slot/getter unencodable: %r", entry)
        return None
    return ForkFixture(
        kind="set_storage_at",
        address=target,
        value=value,
        slot=slot,
        verify_to=target,
        verify_calldata=verify_calldata,
        verify_expected=value,
    )


def _token_seed_fixtures(
    token_slots: Sequence[Mapping[str, Any]], callers: Sequence[str], target: str
) -> tuple[ForkFixture, ...]:
    """Seed each prober's token preconditions on ``target``, deterministically.

    ``owner`` is seeded for the first caller only: the slot is keyed by tokenId, so per-caller seeds would overwrite
    each other while every read-back said ok. Other callers' NFT entry points just stay invisible (a smaller lower
    bound).
    """
    fixtures: list[ForkFixture] = []
    for entry in token_slots:
        entry_callers = callers[:1] if entry.get("role") == "owner" else callers
        for caller in entry_callers:
            fx = _seed_fixture_for_role(entry, caller, target)
            if fx is not None:
                fixtures.append(fx)
    return tuple(fixtures)


# Directions whose asset the principal must already hold: a pull or a burn of its own holding.
_INPUT_DIRECTIONS = frozenset({"in", "burn"})

# Selectors that pull from the caller; the sink's dotted target names the input asset.
_PULL_SELECTORS = frozenset(
    {
        "0x23b872dd",  # transferFrom(address,address,uint256)
        "0x42842e0e",  # safeTransferFrom(address,address,uint256)
        "0xb88d4fde",  # safeTransferFrom(address,address,uint256,bytes)
        "0x9dc29fac",  # burn(address,uint256)
        "0x79cc6790",  # burnFrom(address,uint256)
    }
)

# Balance-read selectors whose sink head also names the input asset (a share-accounted wrap reads
# ``eETH.shares(caller)`` first). Hint source only: ``shares(address)`` collides with ``PaymentSplitter.shares``.
_TOKEN_READ_SELECTORS = frozenset(
    {
        "0xce7c2ac2",  # shares(address)
        "0xf5eb42dc",  # sharesOf(address)
        "0x70a08231",  # balanceOf(address)
    }
)

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# ERC-4626's required input-asset getter; a wrong candidate only fails to unblock.
_ERC4626_ASSET_GETTER = "asset()"

# The probe target itself (a withdrawal burning the caller's holding of it).
SELF_TOKEN_HINT = "__self__"


def input_token_hints(fn: FunctionFacts, *, token_addresses: Sequence[str] = ()) -> tuple[str, ...]:
    """Candidate input assets for the seeded retry, most specific first, :data:`SELF_TOKEN_HINT` last.

    Each is a zero-arg getter on the target or a resolved address.

    Getters come from sinks with a pull selector (``eETH.transferFrom`` ⇒ ``eETH()``), sinks calling a token-only method
    (library-wrapped pulls), and ``token_var`` of pull/burn value flows. Parameter heads have no getter;
    ``token_addresses`` covers those via :func:`substitute_address_arg`.

    Candidates, not claims: identity is confirmed by storage read-back and the verdict by an observed transfer.
    """
    names: list[str] = []
    params = set(_declared_param_names(fn, len(_parse_arg_types(fn.canonical_signature) or ())))

    def _add(raw: Any) -> None:
        name = str(raw or "").strip()
        # Slither temporaries aren't getters; drop them.
        if name.startswith(("TMP_", "REF_", "TUPLE_")):
            return
        # Parameters live in calldata, not storage.
        if name and name not in params and _IDENTIFIER.match(name) and name not in names:
            names.append(name)

    for sink in fn.effect_info.get("sinks") or []:
        if not isinstance(sink, dict) or sink.get("kind") != "external_call" or sink.get("origin") != "body":
            continue
        if str(sink.get("selector") or "").lower() not in (_PULL_SELECTORS | _TOKEN_READ_SELECTORS):
            continue
        _add(str(sink.get("target") or "").split(".")[0])
    for head in sorted(_token_method_targets(fn)):
        _add(head)
    for flow in fn.legacy_value_flows:
        if str(flow.get("direction")) not in _INPUT_DIRECTIONS or flow.get("is_parameter"):
            continue
        _add(flow.get("token_var"))

    hints = [f"{name}()" for name in names]
    hints.append(_ERC4626_ASSET_GETTER)
    hints.extend(addr.lower() for addr in token_addresses if _RESOLVED_ADDRESS.match(addr or ""))
    hints.append(SELF_TOKEN_HINT)
    return tuple(dict.fromkeys(hints))


def seeded_calldata(
    fn: FunctionFacts,
    principal: str,
    *,
    sentinel_index: int | None = None,
    directions: frozenset[str] | None = None,
    executor: "ExecutorCall | None" = None,
) -> dict[int, str]:
    """``token decimals -> calldata`` for the seeded retry.

    Once seeded, 1 unit becomes the failure mode (``WeETH.wrap(1)`` rounds to a zero mint and reverts), so send one
    whole unit, pre-encoded per common scale since decimals are only known after discovery. ``sentinel_index`` keeps the
    sentinel variant meaningful.
    """
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return {}
    roles = integer_param_roles(fn, types, directions)
    out: dict[int, str] = {}
    for decimals in SEED_UNIT_DECIMALS:
        subs = dict(
            _arg_values(
                types, identity=principal, amount=10**decimals, integer_roles=roles, executor=executor
            ).substitutions
        )
        if sentinel_index is not None:
            if not (0 <= sentinel_index < len(types)):
                return {}
            subs[sentinel_index] = SENTINEL_ADDRESS
        encoded = encode_calldata(fn.selector, fn.canonical_signature, substitutions=subs)
        if encoded is None:
            return {}
        out[decimals] = encoded
    return out


def synthesize_pause(
    session: Session, candidate: Candidate, facts: ContractFacts, fn: FunctionFacts
) -> PausePlanInputs | None:
    """Applicable when F writes a latch-shaped variable.

    ``predicted_guard_set`` is static's read set and the scored denominator, even when empty. When static predicts
    nothing, every state-changing entry point is probed instead. The radius is a lower bound either way; unpredicted
    observed members become ``observed_guard_not_predicted`` discrepancies.
    """
    latch = _claim_latch_pairs(session, candidate.function_id) or _latch_pairs(fn)
    if not latch:
        return None
    latch_vars = {var for var, _member in latch}
    predicted = [name for name in guarded_functions(facts.trees, latch) if name != fn.full_name]
    probe_names = predicted or [name for name in _state_changing_functions(facts) if name != fn.full_name]
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        return None
    pause_calldata = encode_calldata(fn.selector, fn.canonical_signature)
    if pause_calldata is None:
        return None

    principals = _principals_by_selector(session, candidate.contract_id)
    entry_points = [ep for ep in (_entry_point_for(facts, name, principals) for name in probe_names) if ep is not None]
    if not entry_points:
        return None
    # Also probe predicted victims without a principal from the pause principal (see :func:`_pauser_identity_probes`).
    entry_points = [*entry_points, *_pauser_identity_probes(facts, predicted, principals, principal)]

    # One flat fixture list: gas for the pause principal plus per-prober token seeds, on the state-bearing deployment.
    # The seeds are visible to the pause tx too; the verdict binds gate structure, not current funding.
    callers = sorted({ep.from_addr for ep in entry_points if ep.from_addr})
    token_fixtures = _token_seed_fixtures(facts.token_slots, callers, candidate.probe_target)
    fixtures = (ForkFixture(kind="set_balance", address=principal, value=hex(FIXTURE_BALANCE_WEI)), *token_fixtures)
    duration, duration_source = read_max_pause_duration(facts, latch_vars)
    return PausePlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        pause_calldata=pause_calldata,
        entry_points=tuple(entry_points),
        predicted_guard_set=tuple(predicted),
        max_pause_duration=duration,
        duration_bound_source=duration_source,
        gate_ref=_gate_ref(fn.tree),
        fixtures=fixtures,
    )
