"""Value-out / supply / timelock plan synthesis."""

from __future__ import annotations

import logging
from collections.abc import Sequence
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


_SUPPLY_DIRECTIONS = frozenset({"mint", "burn"})
# The supply plan reads lattice facts through ``in``/``out``: artifacts never emit mint/burn as flow directions, so
# filtering by them left no amount, taint or recipient. Applicability still uses :data:`_SUPPLY_DIRECTIONS` from
# ``effect_labels``.
_SUPPLY_LATTICE_DIRECTIONS = frozenset({"in", "out"})


@dataclass(frozen=True)
class _ProbeInputs:
    calldata: str
    taint_param_reaches_sink: bool
    sentinel_calldata: str | None
    token_param_indexes: tuple[int, ...]
    inputs_vacuous: bool
    sentinel_param: str | None = None


def _sentinel_param_name(fn: "FunctionFacts", types: Sequence[str], index: int) -> str | None:
    """The declared name of slot ``index``, or ``None``.

    The sentinel proof is about one parameter, and consumers (``distill._fork_caller_arbitrary_param``) need to know
    which. An unnamed slot publishes nothing rather than a positional ``arg3`` nothing else speaks.
    """
    names = _declared_param_names(fn, len(types))
    if not (0 <= index < len(names)):
        return None
    return names[index] or None


def _value_probe_inputs(
    fn: FunctionFacts, principal: str, directions: frozenset[str], held_tokens: Sequence[str] = ()
) -> _ProbeInputs | None:
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
        # An executor's sentinel goes inside the payload (the redirected destination), superseding the taint slot.
        sentinel_exec = executor_call(fn, types, held_tokens=held_tokens, recipient=SENTINEL_ADDRESS)
        if sentinel_exec is not None and sentinel_exec.values:
            sentinel_subs = _arg_values(
                types, identity=principal, amount=ARG_AMOUNT, integer_roles=roles, executor=sentinel_exec
            ).substitutions
            sentinel_calldata = encode_calldata(fn.selector, fn.canonical_signature, substitutions=sentinel_subs)
            # The payload slot: the outer target keeps the base probe's value.
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
        # Only set beside calldata that actually carries the sentinel.
        sentinel_param=sentinel_param if sentinel_calldata else None,
    )


def synthesize_value_out(candidate: Candidate, fn: FunctionFacts) -> ValueOutPlanInputs | None:
    """Applicable when static says F moves value out.

    Gated functions need a resolved principal; public ones are probed from :data:`NEUTRAL_CALLER`.
    """
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
        # Measured holdings only, never a hardcoded asset.
        contract_holdings=tuple(candidate.input_token_addresses),
        sentinel_param=built.sentinel_param,
    )


def synthesize_supply(candidate: Candidate, fn: FunctionFacts) -> SupplyPlanInputs | None:
    labels = {str(lbl) for lbl in (fn.effect_info.get("effect_labels") or [])}
    if not (_flow_directions(fn) & _SUPPLY_DIRECTIONS or labels & _SUPPLY_DIRECTIONS):
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
        # A non-ERC-20 target fails the pre-read and lands ``unknown``.
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


# A delayed executor's own minimum delay, read not assumed (per deployment; OZ rejects below it).
_MIN_DELAY_SIGNATURE = "getMinDelay()"
_ERC20_BALANCE_OF_SIGNATURE = "balanceOf(address)"


def _schedule_sibling(facts: ContractFacts, fn: FunctionFacts, types: Sequence[str]) -> tuple[str, str] | None:
    """``(selector, signature)`` of the function scheduling what ``fn`` executes, or ``None``.

    Found by ABI shape (the executed tuple plus a trailing ``uint256`` delay); two matches yield nothing.
    """
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
    """The address that can drive both halves (OZ ``PROPOSER_ROLE`` and ``EXECUTOR_ROLE``).

    Seeding the role would be the forbidden move. With no intersection, probe as the executor and let the schedule's
    revert be recorded.
    """
    principals = [p.lower() for p in candidate.principal_addresses if isinstance(p, str) and p]
    scheduler = _principals_by_selector(session, candidate.contract_id).get(schedule_selector.lower())
    if scheduler and scheduler.lower() in principals:
        return scheduler.lower()
    return principals[0] if principals else None


def _probe_salt(candidate: Candidate) -> bytes:
    """Deterministic per-(function, contract) salt, as the differential probe derives identities, so the op doesn't
    collide with one already pending.
    """
    return keccak(text=f"timelock-probe:{candidate.selector or ''}:{candidate.contract_address}")


def synthesize_timelock(
    session: Session, candidate: Candidate, facts: ContractFacts, fn: FunctionFacts
) -> TimelockPlanInputs | None:
    """Applicable when F is a proven arbitrary-call executor whose contract also exposes the scheduling half and a
    minimum delay.

    Schedules an ERC-20 transfer to the sentinel of an asset the timelock provably holds. Timelocks usually hold
    nothing, so then it's a bare call to the sentinel: it still proves the delayed path runs, and the recipe reports "no
    asset to witness".
    """
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
        # A principal behind neither role only proves the gate rejected it.
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
            # The rest take zero: native value the timelock lacks, and a predecessor meaning "depends on nothing".
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
        # Gas only, so the schedule can't revert for a harness reason.
        fixtures=(ForkFixture(kind="set_balance", address=principal, value=hex(FIXTURE_BALANCE_WEI)),),
    )


def _token_arg_candidates(candidate: Candidate, token_params: Sequence[int]) -> tuple[str, ...]:
    """Assets the deployment provably holds, offered only to functions with a token parameter.

    From ``contract_balances``, priced only (:func:`selection.select_candidates`), since an unpriced spam token would
    make a mint look backed. A rejected candidate only reverts; backing comes from emitted Transfers.
    """
    return tuple(candidate.input_token_addresses) if token_params else ()


def _seeded_probe_calldata(
    fn: FunctionFacts, principal: str, directions: frozenset[str], held_tokens: Sequence[str] = ()
) -> tuple[dict[int, str], dict[int, str]]:
    """``(base, sentinel)`` whole-unit retry calldata by decimals; empty when the signature won't encode."""
    types = _parse_arg_types(fn.canonical_signature)
    if types is None:
        return {}, {}
    executor = executor_call(fn, types, held_tokens=held_tokens, recipient=principal)
    base = seeded_calldata(fn, principal, directions=directions, executor=executor)
    if executor is not None and executor.values:
        # Keep the synthesized inner call on the retry, or it resends the empty payload.
        sentinel_exec = executor_call(fn, types, held_tokens=held_tokens, recipient=SENTINEL_ADDRESS)
        return base, seeded_calldata(fn, principal, directions=directions, executor=sentinel_exec)
    taint_idx = _taint_index(fn, types, directions)
    sentinel = (
        seeded_calldata(fn, principal, sentinel_index=taint_idx, directions=directions) if taint_idx is not None else {}
    )
    return base, sentinel
