"""Value-out / supply / timelock plan synthesis."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # typing-only: the effects plane stays off static's runtime import graph
    pass

from eth_utils.crypto import keccak
from sqlalchemy.orm import Session

from services.effects.anvil import ForkFixture
from services.effects.selection import Candidate
from services.resolution.differential_probe import (
    _default_value_for_type,
    _parse_arg_types,
)

from .encoding import _arg_values, _array_shape, encode_calldata
from .executor import executor_call
from .facts import ContractFacts, FunctionFacts
from .flows import (
    _OUT_DIRECTIONS,
    _flow_directions,
    _selector_of,
    _taint_index,
    function_payable,
    has_native_payout,
    static_destination_shape,
)
from .pause_window import _principals_by_selector
from .plans import (
    ARG_AMOUNT,
    FIXTURE_BALANCE_WEI,
    NEUTRAL_CALLER,
    ROLE_TOKEN,
    SENTINEL_ADDRESS,
    SupplyPlanInputs,
    TimelockPlanInputs,
    ValueOutPlanInputs,
)
from .roles import _declared_param_names, address_param_roles, integer_param_roles
from .seeding import input_token_hints, seeded_calldata
from .trees import _gate_ref

logger = logging.getLogger("services.effects.calldata")

# ---------------------------------------------------------------------------
# value-out / supply
# ---------------------------------------------------------------------------

_SUPPLY_DIRECTIONS = frozenset({"mint", "burn"})
# Directions the SUPPLY plan reads its lattice facts through, which are not the
# directions that make the class applicable. ``mint``/``burn`` is a legacy
# ``semantic_control`` vocabulary the effects artifact never emits as a flow
# DIRECTION — measured over the 80 frozen artifacts, every non-guard flow is
# ``out`` (97), ``value_router`` (38) or ``in`` (33), and none is mint/burn — so
# filtering the lattice by it rejected every flow and left the whole class with no
# amount index, no taint index and no lattice recipient, running on the name
# vocabulary alone. A mint/burn function's own value movement is recorded by the
# lattice as the inbound pull it takes (``in``) or the outbound payout it makes
# (``out``); that is where its quantity and its recipient live. Applicability is
# still decided by :data:`_SUPPLY_DIRECTIONS` and supported supply claims
# — those DO carry mint/burn.
_SUPPLY_LATTICE_DIRECTIONS = frozenset({"in", "out"})


@dataclass(frozen=True)
class _ProbeInputs:
    """What the value-out and supply synthesizers both need out of one pass."""

    calldata: str
    taint_param_reaches_sink: bool
    sentinel_calldata: str | None
    token_param_indexes: tuple[int, ...]
    inputs_vacuous: bool
    sentinel_param: str | None = None


def _sentinel_param_name(fn: "FunctionFacts", types: Sequence[str], index: int) -> str | None:
    """The declared name of slot ``index``, or ``None`` when it has none.

    The sentinel proof is a proof about ONE parameter, and the prober is the only
    thing that can state WHICH — a consumer joining on it (``distill
    ._fork_caller_arbitrary_param``) has no other way to tell a sentinel that rode
    the call target from one that rode an executor payload. A slot the static
    plane never named is published as nothing rather than as a positional token:
    ``arg3`` is not a name anything else in the pipeline speaks, so a join on it
    would be a join on this function's own invention.
    """
    names = _declared_param_names(fn, len(types))
    if not (0 <= index < len(names)):
        return None
    return names[index] or None


def _value_probe_inputs(
    fn: FunctionFacts, principal: str, directions: frozenset[str], held_tokens: Sequence[str] = ()
) -> _ProbeInputs | None:
    """The probe inputs shared by the value-out and supply synthesizers."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return None
    roles = integer_param_roles(fn, types, directions)
    addr_roles = address_param_roles(fn, types, directions)
    executor = executor_call(fn, types, held_tokens=held_tokens, recipient=principal)
    base = _arg_values(types, identity=principal, amount=ARG_AMOUNT, integer_roles=roles, executor=executor)
    calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=base.substitutions)
    if calldata is None:
        return None
    taint_idx = _taint_index(fn, types, directions)
    sentinel_calldata = None
    sentinel_param = None
    if executor is not None and executor.values:
        # The executor owns its own sentinel variant, and it supersedes the taint
        # slot: what the caller redirects here is the DESTINATION INSIDE the
        # payload, so the sentinel has to be written there. A sentinel in the
        # target slot would only prove the executor can call the sentinel, which
        # is not the same claim as the funds landing on it.
        sentinel_exec = executor_call(fn, types, held_tokens=held_tokens, recipient=SENTINEL_ADDRESS)
        if sentinel_exec is not None and sentinel_exec.values:
            sentinel_subs = _arg_values(
                types, identity=principal, amount=ARG_AMOUNT, integer_roles=roles, executor=sentinel_exec
            ).substitutions
            sentinel_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=sentinel_subs)
            # The PAYLOAD slot, and saying so is the whole point of the field: an
            # executor's sentinel rides the inner call inside the payload while
            # the outer target keeps whatever the base probe passed, so a
            # consumer that read this proof as being about the call target would
            # be reading it about a parameter the sentinel never touched.
            sentinel_param = _sentinel_param_name(fn, types, sentinel_exec.slots[1])
    elif taint_idx is not None:
        sentinel_subs = dict(base.substitutions)
        sentinel_subs[taint_idx] = SENTINEL_ADDRESS
        sentinel_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=sentinel_subs)
        sentinel_param = _sentinel_param_name(fn, types, taint_idx)
    tokens = tuple(sorted(idx for idx, role in addr_roles.items() if role == ROLE_TOKEN))
    return _ProbeInputs(
        calldata=calldata,
        taint_param_reaches_sink=taint_idx is not None,
        sentinel_calldata=sentinel_calldata,
        token_param_indexes=tokens,
        inputs_vacuous=bool(base.vacuous),
        # Never survives a calldata that failed to encode: the field names the
        # subject of a sentinel probe, so it is only set beside the calldata that
        # actually carries the sentinel.
        sentinel_param=sentinel_param if sentinel_calldata else None,
    )


def synthesize_value_out(candidate: Candidate, fn: FunctionFacts) -> ValueOutPlanInputs | None:
    """Applicable when static says the function moves value OUT. A gated
    function needs a resolved principal — a probe from the zero address only ever
    proves that the gate rejected it — but a PUBLIC function has no principal to
    resolve, so it is probed from :data:`NEUTRAL_CALLER`, an arbitrary non-zero
    identity that is a valid, productive probe of a permissionless mover."""
    if not _flow_directions(fn) & _OUT_DIRECTIONS:
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        if not candidate.authority_public:
            return None
        principal = NEUTRAL_CALLER
    built = _value_probe_inputs(fn, principal, frozenset(_OUT_DIRECTIONS), candidate.input_token_addresses)
    if built is None:
        return None
    calldata, sentinel_calldata = built.calldata, built.sentinel_calldata
    token_params = built.token_param_indexes
    seeded, seeded_sentinel = _seeded_probe_calldata(
        fn, principal, frozenset(_OUT_DIRECTIONS), candidate.input_token_addresses
    )
    return ValueOutPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        calldata=calldata,
        gate_ref=_gate_ref(fn.tree),
        taint_param_reaches_sink=built.taint_param_reaches_sink,
        sentinel_address=SENTINEL_ADDRESS if sentinel_calldata else None,
        sentinel_calldata=sentinel_calldata,
        value_holders=candidate.value_holders,
        acting_balance_usd=candidate.acting_balance_usd,
        protocol_tvl_usd=candidate.protocol_tvl_usd,
        input_token_hints=input_token_hints(fn, token_addresses=_token_arg_candidates(candidate, token_params)),
        token_param_indexes=token_params,
        seeded_calldata=seeded,
        seeded_sentinel_calldata=seeded_sentinel if sentinel_calldata else {},
        target_payable=function_payable(fn),
        native_payout=has_native_payout(fn),
        static_shape=static_destination_shape(fn, frozenset(_OUT_DIRECTIONS)),
        inputs_vacuous=built.inputs_vacuous,
        # Measured holdings only — the seed derives its token from what
        # the deployment provably holds, never a hardcoded asset.
        contract_holdings=tuple(candidate.input_token_addresses),
        sentinel_param=built.sentinel_param,
    )


def synthesize_supply(candidate: Candidate, fn: FunctionFacts) -> SupplyPlanInputs | None:
    """Applicable when static says the function mints or burns."""
    claim_ids = {
        str(claim.get("claim_id")) for claim in fn.effect_info.get("claims") or [] if isinstance(claim, Mapping)
    }
    if not (_flow_directions(fn) & _SUPPLY_DIRECTIONS or claim_ids & {"supply.mint", "supply.burn"}):
        return None
    principal = candidate.principal_addresses[0] if candidate.principal_addresses else None
    if not principal:
        if not candidate.authority_public:
            return None
        principal = NEUTRAL_CALLER
    built = _value_probe_inputs(fn, principal, _SUPPLY_LATTICE_DIRECTIONS, candidate.input_token_addresses)
    if built is None:
        return None
    calldata, sentinel_calldata = built.calldata, built.sentinel_calldata
    token_params = built.token_param_indexes
    seeded, seeded_sentinel = _seeded_probe_calldata(
        fn, principal, _SUPPLY_LATTICE_DIRECTIONS, candidate.input_token_addresses
    )
    return SupplyPlanInputs(
        # The candidate's own probe target. A candidate that is not an ERC-20
        # simply fails the pre-read and lands ``unknown`` — that is the honest
        # answer, not an error to engineer around.
        token_address=candidate.probe_target,
        principal=principal,
        mint_calldata=calldata,
        gate_ref=_gate_ref(fn.tree),
        taint_param_reaches_sink=built.taint_param_reaches_sink,
        sentinel_address=SENTINEL_ADDRESS if sentinel_calldata else None,
        sentinel_calldata=sentinel_calldata,
        input_token_hints=input_token_hints(fn, token_addresses=_token_arg_candidates(candidate, token_params)),
        token_param_indexes=token_params,
        seeded_calldata=seeded,
        seeded_sentinel_calldata=seeded_sentinel if sentinel_calldata else {},
        target_payable=function_payable(fn),
        native_payout=has_native_payout(fn),
        inputs_vacuous=built.inputs_vacuous,
        contract_holdings=tuple(candidate.input_token_addresses),
    )


# The zero-arg getter for a delayed executor's own minimum delay. A canonical
# signature, not a name guess, and the value is READ rather than assumed: OZ
# rejects a schedule below it, and it is per-deployment (measured 432000s and
# 864000s on the two mainnet timelocks this corpus carries).
_MIN_DELAY_SIGNATURE = "getMinDelay()"
# ERC-20 balanceOf(address) — the published standard, used to read the witness.
_ERC20_BALANCE_OF_SIGNATURE = "balanceOf(address)"


def _schedule_sibling(facts: ContractFacts, fn: FunctionFacts, types: Sequence[str]) -> tuple[str, str] | None:
    """``(selector, signature)`` of the function that SCHEDULES what ``fn``
    executes, or ``None``.

    Found by ABI shape rather than by name: the scheduling half of a delayed
    executor takes the executed tuple plus a trailing ``uint256`` delay. Both
    arities fall out of the same rule, and a contract exposing two such siblings
    yields nothing rather than a pick."""
    wanted = [t.strip() for t in types] + ["uint256"]
    found: list[tuple[str, str]] = []
    for name in facts.effects:
        signature = facts.canonical_signature(name)
        if signature == fn.canonical_signature:
            continue
        candidate_types = _parse_arg_types(signature)
        if candidate_types is None or [t.strip() for t in candidate_types] != wanted:
            continue
        selector = _selector_of(signature)
        if selector is not None:
            found.append((selector, signature))
    return found[0] if len(found) == 1 else None


def _dual_role_principal(session: Session, candidate: Candidate, schedule_selector: str) -> str | None:
    """The address that can drive BOTH halves of the sequence.

    Scheduling and executing are separately gated (OZ's ``PROPOSER_ROLE`` and
    ``EXECUTOR_ROLE``), so the probe needs a principal the resolution plane put
    behind both. Preferring the intersection is what keeps this honest: the
    alternative — writing the role into storage so the gate passes — is exactly
    what a probe may not do, because it would revert on the gate, not on a missing
    asset. When the two do not intersect we still probe as the executor and let
    the contract reject the schedule, which the recipe records verbatim."""
    principals = [p.lower() for p in candidate.principal_addresses if isinstance(p, str) and p]
    scheduler = _principals_by_selector(session, candidate.contract_id).get(schedule_selector.lower())
    if scheduler and scheduler.lower() in principals:
        return scheduler.lower()
    return principals[0] if principals else None


def _probe_salt(candidate: Candidate) -> bytes:
    """A deterministic per-(function, contract) operation salt, derived exactly as
    the differential probe derives its identities so a replay reuses it. Its only
    job is to keep the probe's operation distinct from one the timelock already
    has pending — a collision would revert the schedule for a reason that has
    nothing to do with the capability under test."""
    return keccak(text=f"timelock-probe:{candidate.selector or ''}:{candidate.contract_address}")


def synthesize_timelock(
    session: Session, candidate: Candidate, facts: ContractFacts, fn: FunctionFacts
) -> TimelockPlanInputs | None:
    """Applicable when F is a proven arbitrary-call executor whose contract
    also exposes the scheduling half and its own minimum delay.

    The operation scheduled is an ERC-20 transfer to the sentinel of an asset the
    timelock PROVABLY holds. Where it holds nothing — the normal case, since a
    timelock holds authority rather than funds — the operation is a bare call to
    the sentinel: still an operation the proposer chose, which proves the delayed
    execution path runs, while the value question is answered honestly by the
    recipe as "there was no asset to witness" rather than as "moved nothing"."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return None
    executor = executor_call(fn, types, held_tokens=candidate.input_token_addresses, recipient=SENTINEL_ADDRESS)
    if executor is None:
        return None
    sibling = _schedule_sibling(facts, fn, types)
    if sibling is None:
        return None
    schedule_selector, schedule_signature = sibling
    if _MIN_DELAY_SIGNATURE not in facts.effects:
        return None
    delay_calldata = encode_calldata(_selector_of(_MIN_DELAY_SIGNATURE) or "", _MIN_DELAY_SIGNATURE)
    if delay_calldata is None:
        return None
    principal = _dual_role_principal(session, candidate, schedule_selector)
    if not principal:
        # A probe from an address behind neither role only ever proves the gate
        # rejected it — the same rule the value-out plan applies.
        return None

    destination, payload = executor.slots
    witness_token = executor.values.get(destination)
    target = witness_token if witness_token is not None else SENTINEL_ADDRESS
    inner = executor.values.get(payload, b"")
    salt_index = max((i for i, t in enumerate(types) if t.strip() == "bytes32"), default=-1)
    arguments: dict[int, Any] = {}
    for idx, type_str in enumerate(types):
        shape = _array_shape(type_str)
        if idx == destination:
            value: Any = target
        elif idx == payload:
            value = inner
        elif idx == salt_index:
            value = _probe_salt(candidate)
        else:
            # Everything else takes the encoder's own zero: the per-call native
            # value the timelock does not hold, and the predecessor that OZ reads
            # as "this operation depends on nothing".
            try:
                value = _default_value_for_type(shape[0] if shape else type_str)
            except Exception:
                return None
        arguments[idx] = [value] if shape else value

    execute_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=arguments)
    schedule_zero = encode_calldata(schedule_selector, schedule_signature, substitutions={**arguments, len(types): 0})
    if execute_calldata is None or schedule_zero is None:
        return None
    witness_calldata = (
        encode_calldata(
            _selector_of(_ERC20_BALANCE_OF_SIGNATURE) or "",
            _ERC20_BALANCE_OF_SIGNATURE,
            substitutions={0: SENTINEL_ADDRESS},
        )
        if witness_token is not None
        else None
    )
    return TimelockPlanInputs(
        contract_address=candidate.probe_target,
        principal=principal,
        execute_calldata=execute_calldata,
        schedule_selector=schedule_selector,
        schedule_signature=schedule_signature,
        schedule_arguments=arguments,
        delay_index=len(types),
        schedule_calldata_zero=schedule_zero,
        delay_calldata=delay_calldata,
        gate_ref=_gate_ref(fn.tree),
        sentinel_address=SENTINEL_ADDRESS,
        witness_token=witness_token if isinstance(witness_token, str) else None,
        witness_calldata=witness_calldata,
        # Gas only: an impersonated proposer that cannot pay would revert the
        # schedule for a reason that is the harness's, not the contract's.
        fixtures=(ForkFixture(kind="set_balance", address=principal, value=hex(FIXTURE_BALANCE_WEI)),),
    )


def _token_arg_candidates(candidate: Candidate, token_params: Sequence[int]) -> tuple[str, ...]:
    """Assets the acting deployment PROVABLY holds, offered only to a function
    that actually has a token parameter.

    They exist because a caller-supplied token slot has no getter behind it: the
    identity has to come from somewhere, and the only honest "somewhere" is real
    on-chain state. ``contract_balances`` is a measurement of this deployment at
    this block, ordered by USD, and :func:`selection.select_candidates` keeps only
    the PRICED entries — an unpriced holding is usually an airdropped spam token,
    and a mint witnessed against one would read as backed while being worthless.

    A candidate that the function does not accept can only make the call revert.
    It can never invent a witness: backing is counted from Transfers the
    execution EMITTED, and writing an address into calldata emits nothing."""
    return tuple(candidate.input_token_addresses) if token_params else ()


def _seeded_probe_calldata(
    fn: FunctionFacts, principal: str, directions: frozenset[str], held_tokens: Sequence[str] = ()
) -> tuple[dict[int, str], dict[int, str]]:
    """``(base, sentinel)`` whole-unit calldata for the seeded retry, keyed by
    token decimals. Empty dicts when the signature will not encode — the probe
    then simply never retries."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return {}, {}
    executor = executor_call(fn, types, held_tokens=held_tokens, recipient=principal)
    base = seeded_calldata(fn, principal, directions=directions, executor=executor)
    if executor is not None and executor.values:
        # The retry has to keep the synthesized inner call. Falling back to the
        # plain vector here would re-send the empty payload whenever the first
        # probe reverted, and the verdict is read off whichever call executed.
        sentinel_exec = executor_call(fn, types, held_tokens=held_tokens, recipient=SENTINEL_ADDRESS)
        return base, seeded_calldata(fn, principal, directions=directions, executor=sentinel_exec)
    taint_idx = _taint_index(fn, types, directions)
    sentinel = (
        seeded_calldata(fn, principal, sentinel_index=taint_idx, directions=directions) if taint_idx is not None else {}
    )
    return base, sentinel
