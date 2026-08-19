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

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Token-precondition seeding (blast-radius honesty)
# ---------------------------------------------------------------------------


def _word_hex(value: int) -> str:
    """A 32-byte big-endian EVM word as ``0x`` + 64 hex."""
    return "0x" + format(value & (2**256 - 1), "064x")


def _mapping_entry_slot(base_slot: str, keys: Sequence[int]) -> str | None:
    """Storage slot of a (possibly nested) mapping entry, folding keys OUTERMOST
    first: ``m[k1][k2] = keccak(pad32(k2) ++ keccak(pad32(k1) ++ base))``. ``keys``
    is ``[k1, k2, ...]`` in declaration order. ``None`` when ``base_slot`` is not a
    parseable ≤32-byte word."""
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
    """One read-back-verified storage fixture seeding ``caller``'s precondition for
    a single token_slots ``entry`` on ``target`` (the state-bearing deployment).
    ``None`` on any malformed field or role/kind mismatch — a dropped seed only
    shrinks the observed lower bound, never manufactures a witness."""
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

    # The synthesizer substitutes identity=caller for every address arg (see
    # ``_arg_values``), so in a probe an allowance is m[owner=caller][spender=caller];
    # an id-shaped uint arg carries ARG_IDENTIFIER, so a uint-keyed owner mapping is
    # read at exactly that token id — the seeds MUST match those keys.
    if role in ("balance", "shares") and key_kind == "address":
        keys, subs, value = [caller_key], {0: caller}, _word_hex(SEED_AMOUNT)
    elif role == "allowance" and key_kind == "address_address":
        keys, subs, value = [caller_key, caller_key], {0: caller, 1: caller}, _word_hex(SEED_AMOUNT)
    elif role == "owner" and key_kind == "uint256":
        # The stored word IS the caller: ownerOf(tokenId) must return the prober.
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
    """Seed each distinct prober's token preconditions on ``target``. Deterministic
    over (entry order, sorted callers).

    An ``owner`` seed is emitted for the FIRST caller only: its slot is keyed by
    the tokenId (``ARG_AMOUNT``), not the caller, so per-caller seeds would all
    write the same slot last-writer-wins — leaving every earlier caller's probe
    precondition silently unmet while its read-back transcript said ok. One
    deterministic owner keeps the transcript truthful; other callers' NFT entry
    points stay invisible to the diff, which only shrinks the observed lower
    bound."""
    fixtures: list[ForkFixture] = []
    for entry in token_slots:
        entry_callers = callers[:1] if entry.get("role") == "owner" else callers
        for caller in entry_callers:
            fx = _seed_fixture_for_role(entry, caller, target)
            if fx is not None:
                fixtures.append(fx)
    return tuple(fixtures)


# ---------------------------------------------------------------------------
# Input-asset seeding (value-out / supply preconditions) — Tier 1
# ---------------------------------------------------------------------------

# Directions whose asset the ACTING PRINCIPAL must already hold for the call to
# get past its first line: a pull (``in``) and a burn of the caller's own
# holding. An ``out`` flow is what the function produces, never its precondition.
_INPUT_DIRECTIONS = frozenset({"in", "burn"})

# ERC-20/721 selectors that PULL from the caller. A body sink bearing one of
# these names the input asset in its dotted target (``eETH.transferFrom``).
_PULL_SELECTORS = frozenset(
    {
        "0x23b872dd",  # transferFrom(address,address,uint256)
        "0x42842e0e",  # safeTransferFrom(address,address,uint256)
        "0xb88d4fde",  # safeTransferFrom(address,address,uint256,bytes)
        "0x9dc29fac",  # burn(address,uint256)
        "0x79cc6790",  # burnFrom(address,uint256)
    }
)

# View selectors that only ever READ a per-holder token balance, so a body sink
# bearing one names the input asset in its dotted head just as a PULL selector
# does — a share-accounted wrap reads ``eETH.shares(caller)`` before it moves the
# asset, and that read is the only NAMED head when the transfer itself is
# library-wrapped behind a temporary. Selector-keyed, not name-keyed:
# ``shares(address)`` shares its selector with ``PaymentSplitter.shares``, so this
# is a hint source only, never a token-role assertion (see ``_TOKEN_METHOD_WORDS``
# which deliberately excludes ``shares`` for that reason).
_TOKEN_READ_SELECTORS = frozenset(
    {
        "0xce7c2ac2",  # shares(address)
        "0xf5eb42dc",  # sharesOf(address)
        "0x70a08231",  # balanceOf(address)
    }
)

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A token hint that is already an address needs no getter call to resolve.

# Zero-arg getter every ERC-4626 vault must expose for its input asset. A
# standard, not a name guess — and a wrong candidate can only fail to unblock the
# call, never fabricate an inflow.
_ERC4626_ASSET_GETTER = "asset()"

# The probe target itself, as a token-hint sentinel: a withdrawal/unwrap burns
# the caller's holding of the very contract under probe.
SELF_TOKEN_HINT = "__self__"


def input_token_hints(fn: FunctionFacts, *, token_addresses: Sequence[str] = ()) -> tuple[str, ...]:
    """Candidate input assets for the seeded retry, most specific first, plus
    :data:`SELF_TOKEN_HINT` last. An entry is either a zero-arg getter signature
    to call on the probe target or an already-resolved token ADDRESS.

    Getter sources, no name invention: the dotted target of a body sink carrying
    an ERC-20 PULL selector (``eETH.transferFrom`` ⇒ ``eETH()``); the dotted
    target of a body sink calling a token-only METHOD, which is how a
    library-wrapped pull surfaces (``nativeWrapper.safeApprove`` ⇒
    ``nativeWrapper()``, whose selector belongs to the library, not to ERC-20);
    and the ``token_var`` of a ``contract_analysis`` value flow whose direction is
    a pull or burn. A head that is a declared PARAMETER names no getter — there is
    no state variable behind it — which is what ``token_addresses`` is for: the
    caller supplies the assets the acting deployment provably holds, and
    :func:`substitute_address_arg` writes one of them into that parameter.

    These are CANDIDATES, not claims. Identity is settled on the wire (the getter
    must return an address whose storage read-back confirms a balance mapping),
    and the verdict is settled by an observed transfer — a wrong candidate simply
    leaves the call reverting exactly as it does today."""
    names: list[str] = []
    params = set(_declared_param_names(fn, len(_parse_arg_types(fn.canonical_signature) or ())))

    def _add(raw: Any) -> None:
        name = str(raw or "").strip()
        # A Slither synthetic (``TMP_1127``/``REF_5``/``TUPLE_2``) is not a getter:
        # it is an unresolved cast/index temporary, and calling it as ``TMP_1127()``
        # seeds nothing. Static resolution now recovers the state var behind most
        # of these; whatever survives here (a mapping element, a computed value) has
        # no getter to name and is dropped rather than emitted as junk.
        if name.startswith(("TMP_", "REF_", "TUPLE_")):
            return
        # A parameter is not a getter: the value lives in calldata, not storage.
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
    """``token decimals -> calldata`` for the SEEDED retry of a value/supply probe.

    The unseeded probe sends :data:`ARG_AMOUNT` (1 unit) — the amount that slips
    under rate limiters when the caller already holds the asset. Once the input is
    seeded that amount becomes the new failure mode: a conversion rounds 1 unit to
    a zero-sized mint (measured: ``WeETH.wrap(1)`` reverts on
    ``require(weEthAmount > 0)``), which is a non-observation, not a witness. So
    the seeded retry sends ONE WHOLE UNIT of the input token, pre-encoded per
    common token scale because the encoder runs offline and the decimals are only
    known once the discovery block has read them back.

    ``sentinel_index`` re-points the taint-identified address param at the
    attacker sentinel, so a seeded sentinel probe keeps its meaning."""
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
    """Applicable when F writes a latch-shaped state variable.

    ``predicted_guard_set`` is static's read-set for that latch and remains the
    SCORED denominator even when empty. The entry points PROBED are a separate
    thing: when static predicts nothing (no trees for the readers, an
    unsupported guard leaf), we fall back to probing every state-changing entry
    point rather than skipping the class. The observed radius is a lower bound
    either way, and an observed member static did not predict is routed as the
    ``observed_guard_not_predicted`` vocabulary-growth discrepancy — which is
    exactly what that channel is for."""
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
    # Unresolved-victim recovery: also probe each predicted victim that has no resolved
    # principal from the pause principal, so a freeze a foreign caller can't reach
    # pre-pause is still witnessed. Only over the PREDICTED set (not the fallback),
    # union semantics keep the observed radius a sound lower bound.
    entry_points = [*entry_points, *_pauser_identity_probes(facts, predicted, principals, principal)]

    # The pause principal needs gas of its own; the per-entry-point fixtures cover
    # the probers. Kept flat here so the recipe applies one list, while each
    # EntryPoint still carries its own for inspection. Token-precondition seeds
    # (balance/allowance/shares/owner) go here too, one per distinct prober, so a
    # token check can never hide an entry point from the diff; each carries its own
    # getter read-back and lands on the state-bearing deployment, never the impl.
    # The seeds are visible to the pause tx itself (a pause gated on the
    # principal's token stake succeeds on the fork regardless of live holdings) —
    # same gate-relative semantics as the ETH balance seed above: the verdict binds
    # the gate structure, not the principal's current funding.
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
