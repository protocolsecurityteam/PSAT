"""Tier-1 effect recipes: value-out, code-upgrade, authority-change, supply.

Each recipe is a pure decision over injected seams (``Simulate`` / ``CallBatch`` and the transcript store) returning a
transcripted :class:`~services.effects.harness.ObservedEffect`. Positive verdicts are observed transitions; everything
else is ``unknown``. Recipes record discrepancies but don't persist or route them. The Tier-2 pause recipe is in
``services.effects.anvil`` (needs the fork).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from services.clients.rpc import EthCallResult
from services.effects.calldata import NEUTRAL_CALLER, SENTINEL_ADDRESS, substitute_address_arg
from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    OBSERVATION_EXECUTED,
    OBSERVATION_NOT_RUN,
    OBSERVATION_REVERTED,
    SCOPE_KERNEL,
    SHAPE_CALLER_ARBITRARY,
    SHAPE_IMMUTABLE_FIXED,
    SHAPE_STORAGE_DETERMINED,
    SHAPE_UNKNOWN,
    TIER_CALL,
    TIER_HISTORICAL,
)
from services.effects.harness import (
    Discrepancy,
    ObservedEffect,
    SimContext,
    TranscriptStore,
    authorization_opened,
    emit,
    new_transcript,
    proven,
    record_calls,
    unknown,
)
from services.effects.seeding import (
    SEED_ETH_VALUE,
    Seeder,
    Seeding,
    SeedRequest,
    budget_of,
    contract_balance_override,
    eth_value_override,
)
from services.effects.selection import (
    HOLDINGS_COMPLETENESS_AT_PAGE_CAP,
    AssetHolding,
)
from services.effects.selection import (
    HOLDINGS_COMPLETENESS_NOT_DETERMINED as HOLDINGS_NOT_DETERMINED,
)
from services.effects.simulate import (
    SimCall,
    SimCallResult,
    Simulate,
    StateOverride,
    transfers_in,
    transfers_out,
    transfers_out_with_asset,
)
from utils.evm import EIP1967_IMPL_SLOT
from utils.execution_record import PROVING_EXECUTION_KEY, residue_payload

logger = logging.getLogger(__name__)

TOTAL_SUPPLY_SELECTOR = "0x18160ddd"

# Re-exported from :mod:`services.effects.config`, since anvil's pause rows use it too.


def _sim_to_ethcall(r: SimCallResult) -> EthCallResult:
    """Adapt a simulate result to ``EthCallResult`` for the raw-revert discipline."""
    return EthCallResult(r.success, r.return_data, r.revert_data, None)


# ``contract_balance`` is the most synthetic and always runs last.
_ATTEMPT_SEEDED = "seeded_probe"
_ATTEMPT_PAYABLE = "seeded_probe_payable"
_ATTEMPT_CONTRACT_BALANCE = "seeded_probe_contract_balance"
_ATTEMPT_CONTRACT_TOKEN = "seeded_probe_contract_token"
# Contract-token seeding runs on at most this many measured holdings; the seeder's layout budget caps it further.
_MAX_CONTRACT_HOLDINGS = 2

# Why a seeded attempt produced no observation, recorded on the transcript and counted on the seed budget so
# ``executed=0`` names the failing precondition.
_OUTCOME_EXECUTED = "executed"
_OUTCOME_TARGET_REVERTED = "target_reverted"
_OUTCOME_READBACK_FAILED = "readback_failed"
_OUTCOME_MALFORMED = "malformed_response"
_SKIP_NO_SEEDER = "skipped_no_seeder"
_SKIP_NO_CALLDATA = "skipped_no_seeded_calldata"
_SKIP_BUDGET = "skipped_budget_exhausted"
_SKIP_NO_TOKEN = "skipped_no_token_resolved"
_SKIP_NO_ATTEMPT_PATH = "skipped_no_viable_attempt"
# Nothing honest to put in a token parameter; the call reverts on it (a recorded non-observation, never a guessed
# address).
_SKIP_NO_TOKEN_ARG = "skipped_no_token_for_param"


@dataclass(frozen=True)
class _SeedAttempt:
    label: str
    overrides: StateOverride | None
    value: int
    calldata: str
    sentinel_calldata: str | None
    seeding: Seeding | None
    contract_balance_seeded: bool = False
    # ``param index -> token address`` placed in the calldata; only read-back-proved tokens, which gate the backing
    # witness (see :func:`_backing_admissible`).
    token_args: Mapping[str, str] = field(default_factory=dict)

    @property
    def readback(self) -> tuple[SimCall, ...]:
        return self.seeding.readback_calls if self.seeding else ()

    @property
    def expected(self) -> tuple[str, ...]:
        return self.seeding.readback_expected if self.seeding else ()


def _record_seed_outcome(
    transcript: dict[str, Any],
    seeder: Seeder | None,
    label: str,
    outcome: str,
    *,
    detail: str | None = None,
) -> None:
    """Record which precondition an attempt died on (transcript plus budget metric)."""
    entry: dict[str, Any] = {"label": label, "outcome": outcome}
    if detail:
        entry["detail"] = detail
    transcript.setdefault("seed_attempts", []).append(entry)
    budget = budget_of(seeder)
    if budget is not None:
        budget.record_outcome(outcome)
    if outcome != _OUTCOME_EXECUTED:
        logger.debug(
            "effects recipes: seeded attempt %s discarded (%s%s)", label, outcome, f": {detail}" if detail else ""
        )


def _seed_attempts(
    *,
    seeder: Seeder | None,
    transcript: dict[str, Any],
    contract_address: str,
    principal: str | None,
    token_hints: Sequence[str],
    seeded_calldata: Mapping[int, str],
    seeded_sentinel_calldata: Mapping[int, str],
    block_tag: str,
    target_payable: bool | None = None,
    native_payout: bool = False,
    token_param_indexes: Sequence[int] = (),
    contract_holdings: Sequence[str] = (),
) -> list[_SeedAttempt]:
    """The ordered retries for a probe whose unseeded call already reverted.

    The order is the soundness argument:

    * ERC-20 seeding first at ``value == 0``, so any asset consumed is genuinely pulled;
    * ``msg.value`` only second, after a zero-value call failed, so a payable admin mint can't bank our own ETH as an
    "inflow";
    * the target contract's own balance last, only for functions static says pay native ETH out; its verdicts mean
    "would move value if funded".

    Non-payable functions never get ``msg.value`` (rejected before the body; it wasted 9 of 13 seeded calls on one run).
    The path is charged to the job's :class:`~services.effects.seeding.SeedBudget` first; an exhausted budget returns no
    attempts.
    """
    if seeder is None or not principal:
        _record_seed_outcome(transcript, seeder, "seed_path", _SKIP_NO_SEEDER)
        return []
    if not seeded_calldata:
        _record_seed_outcome(transcript, seeder, "seed_path", _SKIP_NO_CALLDATA)
        return []
    budget = budget_of(seeder)
    if budget is not None and not budget.take_retry(contract_address.lower()):
        _record_seed_outcome(transcript, seeder, "seed_path", _SKIP_BUDGET)
        return []
    seeding: Seeding | None = None
    if token_hints:
        try:
            seeding = seeder(
                SeedRequest(
                    spender=contract_address,
                    principal=principal,
                    token_hints=tuple(token_hints),
                    block_tag=block_tag,
                )
            )
        except Exception:  # noqa: BLE001 - a failed seeder only means "do not seed"
            logger.debug("effects recipes: seeder failed for %s", contract_address, exc_info=True)
            seeding = None
    if seeding is None:
        _record_seed_outcome(transcript, seeder, "seed_path", _SKIP_NO_TOKEN)
    decimals = seeding.decimals if seeding else 18
    calldata = seeded_calldata.get(decimals) or seeded_calldata.get(18)
    if calldata is None:
        _record_seed_outcome(transcript, seeder, "seed_path", _SKIP_NO_CALLDATA)
        return []
    sentinel = seeded_sentinel_calldata.get(decimals) or seeded_sentinel_calldata.get(18)
    if seeding is not None:
        transcript["seeding"] = dict(seeding.detail)
    placed: dict[str, str] = {}
    if token_param_indexes:
        calldata, sentinel, placed = _place_token_args(
            calldata, sentinel, token_param_indexes, seeding, contract_address
        )
        if not placed:
            _record_seed_outcome(transcript, seeder, "seed_path", _SKIP_NO_TOKEN_ARG)
        elif seeding is not None:
            transcript.setdefault("seeding", {})["token_args"] = placed
    attempts: list[_SeedAttempt] = []
    if seeding is not None:
        attempts.append(
            _SeedAttempt(_ATTEMPT_SEEDED, seeding.overrides, 0, calldata, sentinel, seeding, token_args=placed)
        )
    if target_payable is not False:
        attempts.append(
            _SeedAttempt(
                _ATTEMPT_PAYABLE,
                eth_value_override(principal, seeding.overrides if seeding else None),
                SEED_ETH_VALUE,
                calldata,
                sentinel,
                seeding,
                token_args=placed,
            )
        )
    else:
        _record_seed_outcome(transcript, seeder, _ATTEMPT_PAYABLE, _SKIP_NO_ATTEMPT_PATH, detail="non_payable_target")
    if native_payout:
        attempts.append(
            _SeedAttempt(
                _ATTEMPT_CONTRACT_BALANCE,
                contract_balance_override(contract_address, seeding.overrides if seeding else None),
                0,
                calldata,
                sentinel,
                seeding,
                contract_balance_seeded=True,
                token_args=placed,
            )
        )
    # Seed the contract's own token balance (``principal == spender == contract``), read back via
    # ``balanceOf(contract)``. Runs last and carries ``contract_balance_seeded``: a code capability, not a live outflow.
    # Tokens are what the deployment provably holds.
    for token in list(contract_holdings)[:_MAX_CONTRACT_HOLDINGS]:
        if not isinstance(token, str) or token.lower() == contract_address.lower():
            continue
        try:
            held = seeder(
                SeedRequest(
                    spender=contract_address,
                    principal=contract_address,
                    token_hints=(token,),
                    block_tag=block_tag,
                )
            )
        except Exception:  # noqa: BLE001 - a failed seeder only means "do not seed"
            logger.debug("effects recipes: contract-holding seed failed for %s", token, exc_info=True)
            held = None
        if held is None or not held.overrides:
            _record_seed_outcome(transcript, seeder, _ATTEMPT_CONTRACT_TOKEN, _SKIP_NO_TOKEN, detail=token)
            continue
        attempts.append(
            _SeedAttempt(
                _ATTEMPT_CONTRACT_TOKEN,
                held.overrides,
                0,
                calldata,
                sentinel,
                held,
                contract_balance_seeded=True,
                token_args=placed,
            )
        )
    if not attempts:
        _record_seed_outcome(transcript, seeder, "seed_path", _SKIP_NO_ATTEMPT_PATH)
    return attempts


def _place_token_args(
    calldata: str,
    sentinel: str | None,
    indexes: Sequence[int],
    seeding: Seeding | None,
    contract_address: str,
) -> tuple[str, str | None, dict[str, str]]:
    """Write a seeded token into each proved token parameter.

    Only tokens the seeder actually seeded, so the pull can succeed and emit the Transfer the backing witness needs. The
    probe target itself is excluded: a vault given its own share token as the asset produces an ``inflow_observed:
    false`` about our argument, not the function.

    Returns the calldata pair and a map of what was placed (empty means defaults kept).
    """
    tokens = [t for t in (seeding.tokens if seeding else ()) if t != contract_address.lower()]
    if not tokens:
        return calldata, sentinel, {}
    placed: dict[str, str] = {}
    for n, index in enumerate(indexes):
        token = tokens[min(n, len(tokens) - 1)]
        rewritten = substitute_address_arg(calldata, index, token)
        if rewritten is None:
            continue
        calldata = rewritten
        if sentinel is not None:
            sentinel = substitute_address_arg(sentinel, index, token) or sentinel
        placed[str(index)] = token
    return calldata, sentinel, placed


def _token_slots_unresolved(token_param_indexes: Sequence[int], used: _SeedAttempt | None) -> bool:
    """Did a slot static proved is a token keep the encoder's filler? Only half the mint-backing gate:
    ``token_param_indexes`` comes from parameter names and sink heads, so unconventionally named asset params
    leave it empty (hence :func:`_prober_address_inert`).
    """
    if not token_param_indexes:
        return False
    return used is None or not set(used.token_args) >= {str(i) for i in token_param_indexes}


def _stamp_seed_qualifiers(details: dict[str, Any], used: _SeedAttempt | None) -> None:
    """Copy ``value_out``'s top-level seeding qualifiers onto a supply verdict's ``details``.

    ``claims_bridge._observed_summary`` only propagates top-level keys, and ``contract_balance_seeded`` must travel with
    the verdict. No-op when nothing was seeded.
    """
    if used is None:
        return
    details["input_seeded"] = True
    if used.contract_balance_seeded:
        details["contract_balance_seeded"] = True


# ``PUSH1 0 PUSH1 0 REVERT``: reverts on any fork (no ``PUSH0``) and is non-empty, so ``isContract`` checks behave as
# with a real token.
_REVERT_STUB_CODE = "0x60006000fd"


def _prober_supplied_address_args(calldata: str, principal: str | None) -> list[str]:
    """Addresses this prober invented and wrote into ``calldata``'s head words.

    The encoder writes the acting identity into every address param, and seeded token slots are overwritten, so a head
    word still equal to the principal is a prober-chosen address. Read from the executed bytes, not a type list.
    """
    if not principal or not isinstance(calldata, str):
        return []
    raw = principal[2:] if principal.startswith("0x") else principal
    word = raw.lower().rjust(64, "0")
    body = calldata[2:] if calldata.startswith("0x") else calldata
    args = body[8:]
    for start in range(0, len(args) // 64 * 64, 64):
        if args[start : start + 64].lower() == word:
            return [principal.lower()]
    return []


def _prober_address_inert(
    simulate: Simulate,
    transcript: dict[str, Any],
    *,
    token_address: str,
    principal: str | None,
    calldata: str,
    attempt: _SeedAttempt | None,
    delta: int,
    suspects: Sequence[str],
) -> bool:
    """Is the observed mint provably independent of addresses the prober supplied?

    The mint-backing negative depends on this. A call to a codeless address is a silent success in ``SafeTransferLib``,
    so a deposit given a codeless asset still mints while pulling nothing. Names can't rule that out, and codesize can't
    either (principals are often EOAs).

    So re-run read, mint, read under the same seed with reverting code at each prober-supplied address. The same delta
    means those addresses weren't on the path; a revert, divergence or failure withholds the witness.

    Known limit: a pull via an unchecked low-level call would survive the stub.
    """
    overrides: StateOverride = {}
    if attempt is not None and attempt.overrides:
        overrides = {addr: dict(fields) for addr, fields in attempt.overrides.items()}
    for addr in suspects:
        overrides.setdefault(addr.lower(), {})["code"] = _REVERT_STUB_CODE
    readback = attempt.readback if attempt is not None else ()
    read = SimCall(to=token_address, data=TOTAL_SUPPLY_SELECTOR)
    mint = SimCall(
        to=token_address, data=calldata, from_addr=principal, value=attempt.value if attempt is not None else 0
    )
    calls = [*readback, read, mint, read]
    try:
        res = _run(simulate, transcript, calls, overrides=overrides or None, label="backing_inertness_probe")
    except Exception:  # noqa: BLE001 - a transport failure withholds, never publishes
        logger.debug("effects recipes: backing inertness probe failed for %s", token_address, exc_info=True)
        return False
    if res is None or len(res.calls) != len(calls):
        return False
    if attempt is not None and not _readback_ok(attempt, res.calls):
        return False
    head = len(readback)
    before_c, mint_c, after_c = res.calls[head], res.calls[head + 1], res.calls[head + 2]
    if not (before_c.success and mint_c.success and after_c.success):
        return False
    before_ts, after_ts = _to_int(before_c.return_data), _to_int(after_c.return_data)
    if before_ts is None or after_ts is None:
        return False
    return after_ts - before_ts == delta


def _readback_ok(attempt: _SeedAttempt, results: Sequence[SimCallResult]) -> bool:
    """Did every seeded slot echo its written word in this probe's block? Any revert or mismatch discards the
    attempt; an honest unseeded ``unknown`` beats a wrongly-seeded positive.
    """
    expected = attempt.expected
    if len(results) < len(expected):
        return False
    for want, got in zip(expected, results, strict=False):
        if not got.success:
            return False
        value = _to_int(got.return_data)
        if value is None or value != _to_int(want):
            return False
    return True


def value_out(
    *,
    simulate: Simulate,
    store: TranscriptStore,
    ctx: SimContext,
    contract_address: str,
    principal: str | None,
    calldata: str,
    simulate_supported: bool,
    taint_param_reaches_sink: bool = False,
    sentinel_address: str | None = None,
    sentinel_calldata: str | None = None,
    static_shape: str | None = None,
    static_destination: str | None = None,
    value_holders: Sequence[AssetHolding] = (),
    acting_balance_usd: float | None = None,
    protocol_tvl_usd: float | None = None,
    gate_ref: str = "",
    seeder: Seeder | None = None,
    input_token_hints: Sequence[str] = (),
    token_param_indexes: Sequence[int] = (),
    seeded_calldata: Mapping[int, str] | None = None,
    seeded_sentinel_calldata: Mapping[int, str] | None = None,
    target_payable: bool | None = None,
    native_payout: bool = False,
    inputs_vacuous: bool = False,
    contract_holdings: Sequence[str] = (),
    sentinel_param: str | None = None,
) -> ObservedEffect:
    """Does calling F move value out, and to what kind of destination?

    Tier 1 needs ``eth_simulateV1``; without it the class declares its Tier-2 fallback. Value moved comes from the sim;
    fixed shapes are static universals; only ``caller_arbitrary`` is proven by a landing sentinel. A sentinel that moves
    nothing when taint says it reaches the sink is a recorded discrepancy.

    Two ``details`` flags weaken the verdict and travel with it:

    * ``input_seeded``: the caller was given the asset F pulls.
    * ``contract_balance_seeded``: the target's own ETH balance was overridden, so this means "would move value if
    funded".

    ``sentinel_param`` names the one parameter the sentinel went into (:func:`calldata._value_probe_inputs`);
    ``caller_arbitrary`` proves nothing about other parameters. Present only when a sentinel probe ran; consumers
    (``distill._fork_caller_arbitrary_param``) must refuse when absent.
    """
    tr = new_transcript(ctx, feature="value_out", tier=TIER_CALL, effect_class=EFFECT_CLASS_VALUE_OUT)
    if not simulate_supported:
        tr["fallback"] = "tier2"
        return emit(
            store,
            unknown(
                EFFECT_CLASS_VALUE_OUT,
                gate_ref=gate_ref,
                reason="simulate_unsupported_tier2_fallback",
                details={"fallback": "tier2", "observation": OBSERVATION_NOT_RUN},
                transcript=tr,
            ),
        )

    base_call = SimCall(to=contract_address, data=calldata, from_addr=principal)
    base_res = _run(simulate, tr, [base_call], label="value_probe")
    if base_res is None:
        return emit(store, _sim_precondition_unknown(EFFECT_CLASS_VALUE_OUT, gate_ref, tr))
    observed = base_res.calls[0]
    used: _SeedAttempt | None = None
    if not observed.success:
        # A precondition revert, not absence of value movement.
        used, seeded_result = _seeded_call(
            simulate,
            tr,
            attempts=_seed_attempts(
                seeder=seeder,
                transcript=tr,
                contract_address=contract_address,
                principal=principal,
                token_hints=input_token_hints,
                token_param_indexes=token_param_indexes,
                seeded_calldata=seeded_calldata or {},
                seeded_sentinel_calldata=seeded_sentinel_calldata or {},
                block_tag=hex(tr["block_number"]),
                target_payable=target_payable,
                native_payout=native_payout,
                contract_holdings=contract_holdings,
            ),
            to=contract_address,
            principal=principal,
            seeder=seeder,
        )
        if seeded_result is not None:
            observed = seeded_result
    moved = transfers_out(observed, contract_address)
    value_moved = bool(moved)
    budget = budget_of(seeder)
    if used is not None:
        tr["input_seeded"] = True
        tr["contract_balance_seeded"] = used.contract_balance_seeded
        if budget is not None:
            budget.record_executed()

    sentinel_transfers = _run_sentinel(
        simulate,
        tr,
        contract_address,
        principal,
        used.sentinel_calldata if used is not None else sentinel_calldata,
        sentinel_address,
        attempt=used,
    )
    shape, proved_by, concrete_dest, disc = _resolve_destination_shape(
        effect_class=EFFECT_CLASS_VALUE_OUT,
        base_transfers=moved,
        sentinel_address=sentinel_address,
        sentinel_transfers=sentinel_transfers,
        taint_param_reaches_sink=taint_param_reaches_sink,
        static_shape=static_shape,
        static_destination=static_destination,
    )
    # A reverted call has no logs, so without this "moved nothing" and "never got past its precondition" look identical.
    executed = observed.success
    details: dict[str, Any] = {
        "value_moved": value_moved,
        "observation": OBSERVATION_EXECUTED if executed else OBSERVATION_REVERTED,
        "destination_shape": shape,
        "shape_proved_by": proved_by,
    }
    # Keyed on whether a sentinel probe ran, not whether it landed.
    if sentinel_param and sentinel_transfers is not None:
        details["sentinel_param"] = sentinel_param
    if used is not None:
        # Which token and how much stays in the transcript (state plane).
        details["input_seeded"] = True
        if used.contract_balance_seeded:
            # The payout needed the contract's own balance overridden: a capability, not a live outflow. Must travel
            # with the verdict, cache included.
            details["contract_balance_seeded"] = True
    concrete: dict[str, Any] = {
        # F6: record the call actually issued (the seeded retry if one landed). In ``concrete``, since caller and height
        # are per-deployment and mustn't reach bytecode twins via the cache (``db/effect_cache.py``). Absent on older
        # verdicts means not_determined.
        PROVING_EXECUTION_KEY: residue_payload(
            caller=principal,
            target=contract_address,
            calldata=used.calldata if used is not None else calldata,
            probe_label=used.label if used is not None else "value_probe",
            succeeded=observed.success,
            block_number=tr.get("block_number"),
            block_source=tr.get("block_source"),
            chain_id=ctx.chain_id,
            tier=TIER_CALL,
            # Earned negatives: no attempt landed, so the unseeded probe itself succeeded.
            input_seeded=used is not None,
            contract_balance_seeded=used is not None and used.contract_balance_seeded,
        )
    }
    if concrete_dest is not None:
        concrete["destination"] = concrete_dest
    if not value_moved and shape != SHAPE_CALLER_ARBITRARY:
        # Separate reasons: a call that ran and moved nothing is code-plane and cacheable; a reverted call is
        # input-dependent and must re-probe (``value_probe_reverted`` is excluded from
        # ``effects_worker._CACHEABLE_UNKNOWN_REASONS``). A call that ran with an effect-relevant argument left at the
        # default also observed nothing about F and stays uncached.
        if executed and inputs_vacuous:
            reason = "no_value_observed_vacuous_input"
            details["vacuous_input"] = True
        elif executed:
            reason = "no_value_observed"
        else:
            reason = "value_probe_reverted"
        return emit(
            store,
            unknown(
                EFFECT_CLASS_VALUE_OUT,
                gate_ref=gate_ref,
                reason=reason,
                details=details,
                transcript=tr,
                discrepancy=disc,
            ),
        )
    # Reach rides the proven flow.out verdict and is state-plane (hence ``concrete``). Measured on ``observed``, the
    # execution the verdict came from; the reverted unseeded call has no logs.
    _add_reach(concrete, observed, value_holders, acting_balance_usd, protocol_tvl_usd)
    if budget is not None and used is not None:
        budget.record_proven()
    eff = proven(
        EFFECT_CLASS_VALUE_OUT,
        gate_ref=gate_ref,
        reason="value_moved" if value_moved else "caller_arbitrary_via_sentinel",
        details=details,
        concrete=concrete,
        transcript=tr,
    )
    eff.discrepancy = disc
    return emit(store, eff)


def code_upgrade(
    *,
    simulate: Simulate,
    store: TranscriptStore,
    ctx: SimContext,
    proxy_address: str,
    principal: str | None,
    upgrade_calldata: str,
    sentinel_address: str,
    sentinel_override: dict[str, Any] | None,
    impl_before: str | None,
    impl_slot: str = EIP1967_IMPL_SLOT,
    indexed_upgrade: bool = False,
    current_impl_nonzero: bool | None = None,
    gate_ref: str = "",
) -> ObservedEffect:
    """Can calling F change the executing code?

    Tier 0 first: an indexed upgrade plus a non-zero current impl is proven now; if the current check fails,
    ``unknown``. Else Tier 1: read the impl slot, call F as the principal with a sentinel that survives proxy validation
    (plain code for transparent, an ERC-1822 stub for UUPS), re-read. A bare-address sentinel reverts and proves
    nothing.
    """
    if indexed_upgrade and current_impl_nonzero is not None:
        tr0 = new_transcript(ctx, feature="code_upgrade", tier=TIER_HISTORICAL, effect_class=EFFECT_CLASS_CODE_UPGRADE)
        tr0["indexed_upgrade"] = True
        tr0["current_impl_nonzero"] = current_impl_nonzero
        if current_impl_nonzero:
            return emit(
                store,
                proven(
                    EFFECT_CLASS_CODE_UPGRADE,
                    tier=TIER_HISTORICAL,
                    gate_ref=gate_ref,
                    reason="indexed_upgrade_plus_current_state",
                    details={"historical": True, "current_capability": True, "observation": OBSERVATION_NOT_RUN},
                    concrete={"current_check_passed": True},
                    transcript=tr0,
                ),
            )
        return emit(
            store,
            unknown(
                EFFECT_CLASS_CODE_UPGRADE,
                tier=TIER_HISTORICAL,
                gate_ref=gate_ref,
                reason="historical_only_current_check_failed",
                details={"historical": True, "current_capability": None, "observation": OBSERVATION_NOT_RUN},
                concrete={"current_check_passed": False},
                transcript=tr0,
            ),
        )

    tr = new_transcript(ctx, feature="code_upgrade", tier=TIER_CALL, effect_class=EFFECT_CLASS_CODE_UPGRADE)
    tr["impl_slot"] = impl_slot
    tr["impl_before"] = impl_before
    if not sentinel_override:
        # No code at the target, so proxy validation reverts; proves nothing.
        return emit(
            store,
            unknown(
                EFFECT_CLASS_CODE_UPGRADE,
                gate_ref=gate_ref,
                reason="bare_sentinel_proves_nothing",
                details={"sentinel_override": False, "observation": OBSERVATION_NOT_RUN},
                transcript=tr,
            ),
        )
    call = SimCall(to=proxy_address, data=upgrade_calldata, from_addr=principal)
    res = _run(simulate, tr, [call], overrides={sentinel_address.lower(): sentinel_override}, label="upgrade_probe")
    if res is None:
        return emit(store, _sim_precondition_unknown(EFFECT_CLASS_CODE_UPGRADE, gate_ref, tr))
    probe = res.calls[0]
    impl_after = res.storage.get(proxy_address.lower(), {}).get(impl_slot.lower()) or res.storage.get(
        proxy_address.lower(), {}
    ).get(impl_slot)
    tr["impl_after"] = impl_after
    if not probe.success:
        # A reverted upgrade says nothing about upgradeability (principal or argument rejected), so it isn't cached as
        # ``impl_slot_unchanged``. Checked before the positive branch.
        return emit(
            store,
            unknown(
                EFFECT_CLASS_CODE_UPGRADE,
                gate_ref=gate_ref,
                reason="upgrade_probe_reverted",
                details={"upgradeable": None, "observation": OBSERVATION_REVERTED},
                transcript=tr,
            ),
        )
    if impl_after is not None and _addr_eq(impl_after, sentinel_address):
        return emit(
            store,
            proven(
                EFFECT_CLASS_CODE_UPGRADE,
                gate_ref=gate_ref,
                reason="impl_slot_changed_to_sentinel",
                details={"upgradeable": True, "observation": OBSERVATION_EXECUTED},
                concrete={"impl_before": impl_before, "impl_after": impl_after},
                transcript=tr,
            ),
        )
    return emit(
        store,
        unknown(
            EFFECT_CLASS_CODE_UPGRADE,
            gate_ref=gate_ref,
            reason="impl_slot_unchanged",
            details={"upgradeable": None, "observation": OBSERVATION_EXECUTED},
            transcript=tr,
        ),
    )


def authority_change(
    *,
    simulate: Simulate,
    store: TranscriptStore,
    ctx: SimContext,
    contract_address: str,
    principal: str | None,
    mutate_calldata: str,
    probe_calldata: str,
    randoms: Sequence[str],
    gate_ref: str = "",
) -> ObservedEffect:
    """Does calling F change who can call some gate G? (kernel only)

    In one simulated block: probe G as two or more random identities, call F as the principal, re-probe with the same
    randoms. Opened iff all were rejected before and all succeed after (raw reverts compared); anything else fails
    closed. The whole-contract delta is a separate projection.
    """
    tr = new_transcript(ctx, feature="authority_change", tier=TIER_CALL, effect_class=EFFECT_CLASS_AUTHORITY_CHANGE)
    n = max(2, len(randoms))
    rlist = list(randoms)[:n] if len(randoms) >= 2 else list(randoms)
    if len(rlist) < 2:
        return emit(
            store,
            unknown(
                EFFECT_CLASS_AUTHORITY_CHANGE,
                gate_ref=gate_ref,
                reason="insufficient_identities",
                details={"identities": len(rlist), "observation": OBSERVATION_NOT_RUN},
                transcript=tr,
            ),
        )
    before_calls = [SimCall(to=contract_address, data=probe_calldata, from_addr=r) for r in rlist]
    mutate_call = SimCall(to=contract_address, data=mutate_calldata, from_addr=principal)
    after_calls = [SimCall(to=contract_address, data=probe_calldata, from_addr=r) for r in rlist]
    res = _run(simulate, tr, [*before_calls, mutate_call, *after_calls], label="authority_delta")
    if res is None or len(res.calls) != len(rlist) * 2 + 1:
        return emit(store, _sim_precondition_unknown(EFFECT_CLASS_AUTHORITY_CHANGE, gate_ref, tr))
    before = [_sim_to_ethcall(c) for c in res.calls[: len(rlist)]]
    mutate = res.calls[len(rlist)]
    after = [_sim_to_ethcall(c) for c in res.calls[len(rlist) + 1 :]]
    if not mutate.success:
        # The principal couldn't execute F: a precondition revert, not absence of effect. No seeding for this class, but
        # keep the decoded revert for the census.
        revert_reason = _revert_detail(mutate)
        tr["mutate_revert"] = revert_reason
        return emit(
            store,
            unknown(
                EFFECT_CLASS_AUTHORITY_CHANGE,
                gate_ref=gate_ref,
                reason="mutation_call_reverted",
                details={"observation": OBSERVATION_REVERTED, "revert_reason": revert_reason},
                transcript=tr,
            ),
        )
    if authorization_opened(before, after):
        return emit(
            store,
            proven(
                EFFECT_CLASS_AUTHORITY_CHANGE,
                scope=SCOPE_KERNEL,
                gate_ref=gate_ref,
                reason="gate_opened_to_randoms",
                details={"gate_mutation": True, "observation": OBSERVATION_EXECUTED},
                transcript=tr,
            ),
        )
    return emit(
        store,
        unknown(
            EFFECT_CLASS_AUTHORITY_CHANGE,
            gate_ref=gate_ref,
            reason="no_authorization_delta_observed",
            details={"observation": OBSERVATION_EXECUTED},
            transcript=tr,
        ),
    )


def supply(
    *,
    simulate: Simulate,
    store: TranscriptStore,
    ctx: SimContext,
    token_address: str,
    principal: str | None,
    mint_calldata: str,
    simulate_supported: bool,
    taint_param_reaches_sink: bool = False,
    sentinel_address: str | None = None,
    sentinel_calldata: str | None = None,
    static_shape: str | None = None,
    static_destination: str | None = None,
    gate_ref: str = "",
    seeder: Seeder | None = None,
    input_token_hints: Sequence[str] = (),
    token_param_indexes: Sequence[int] = (),
    seeded_calldata: Mapping[int, str] | None = None,
    seeded_sentinel_calldata: Mapping[int, str] | None = None,
    target_payable: bool | None = None,
    native_payout: bool = False,
    inputs_vacuous: bool = False,
    contract_holdings: Sequence[str] = (),
) -> ObservedEffect:
    """Does calling F change ``totalSupply``?

    Tier 1 via ``eth_simulateV1`` (read, call, read). A signed delta labels mint or burn; zero is ``unknown``.
    Destination shape follows value-out.
    """
    tr = new_transcript(ctx, feature="supply", tier=TIER_CALL, effect_class=EFFECT_CLASS_SUPPLY)
    if not simulate_supported:
        tr["fallback"] = "tier2"
        return emit(
            store,
            unknown(
                EFFECT_CLASS_SUPPLY,
                gate_ref=gate_ref,
                reason="simulate_unsupported_tier2_fallback",
                details={"fallback": "tier2", "observation": OBSERVATION_NOT_RUN},
                transcript=tr,
            ),
        )
    read = SimCall(to=token_address, data=TOTAL_SUPPLY_SELECTOR)
    mint = SimCall(to=token_address, data=mint_calldata, from_addr=principal)
    res = _run(simulate, tr, [read, mint, read], label="supply_delta")
    if res is None or len(res.calls) != 3:
        return emit(store, _sim_precondition_unknown(EFFECT_CLASS_SUPPLY, gate_ref, tr))
    before_c, mint_c, after_c = res.calls
    used: _SeedAttempt | None = None
    if not mint_c.success:
        # Deposit-backed conversions revert on the asset they pull before minting; retry with the input seeded so they
        # (and their backing witness) aren't lost.
        used, seeded = _seeded_supply_call(
            simulate,
            tr,
            attempts=_seed_attempts(
                seeder=seeder,
                transcript=tr,
                contract_address=token_address,
                principal=principal,
                token_hints=input_token_hints,
                token_param_indexes=token_param_indexes,
                seeded_calldata=seeded_calldata or {},
                seeded_sentinel_calldata=seeded_sentinel_calldata or {},
                block_tag=hex(tr["block_number"]),
                target_payable=target_payable,
                native_payout=native_payout,
                contract_holdings=contract_holdings,
            ),
            token_address=token_address,
            principal=principal,
            seeder=seeder,
        )
        if seeded is not None:
            before_c, mint_c, after_c = seeded
            tr["input_seeded"] = True
            tr["contract_balance_seeded"] = used.contract_balance_seeded if used is not None else False
            budget = budget_of(seeder)
            if budget is not None:
                budget.record_executed()
    observation = OBSERVATION_EXECUTED if mint_c.success else OBSERVATION_REVERTED
    if not (before_c.success and after_c.success):
        read_failed_details: dict[str, Any] = {"observation": observation}
        _stamp_seed_qualifiers(read_failed_details, used)
        return emit(
            store,
            unknown(
                EFFECT_CLASS_SUPPLY,
                gate_ref=gate_ref,
                reason="total_supply_read_failed",
                details=read_failed_details,
                transcript=tr,
            ),
        )
    if not mint_c.success:
        mint_reverted_details: dict[str, Any] = {"observation": OBSERVATION_REVERTED}
        _stamp_seed_qualifiers(mint_reverted_details, used)
        return emit(
            store,
            unknown(
                EFFECT_CLASS_SUPPLY,
                gate_ref=gate_ref,
                reason="mint_call_reverted",
                details=mint_reverted_details,
                transcript=tr,
            ),
        )
    before_ts = _to_int(before_c.return_data)
    after_ts = _to_int(after_c.return_data)
    if before_ts is None or after_ts is None:
        undecodable_details: dict[str, Any] = {"observation": OBSERVATION_EXECUTED}
        _stamp_seed_qualifiers(undecodable_details, used)
        return emit(
            store,
            unknown(
                EFFECT_CLASS_SUPPLY,
                gate_ref=gate_ref,
                reason="total_supply_undecodable",
                details=undecodable_details,
                transcript=tr,
            ),
        )
    delta = _signed_delta(after_ts, before_ts)
    # Mints are Transfers from 0x0 emitted by the token whose supply moved; other tokens don't count.
    minted = transfers_out(mint_c, "0x" + "00" * 20, only_asset=token_address)
    burned = transfers_in(mint_c, "0x" + "00" * 20, only_asset=token_address)
    if delta == 0:
        # ``totalSupply`` isn't the unit count for share-accounted or rebasing tokens (EETH, stETH read pooled ether),
        # so a zero delta doesn't mean nothing was minted. One-directional zero-address Transfers are the witness;
        # ambiguous evidence stays a non-observation.
        if bool(minted) != bool(burned):
            sign = "mint" if minted else "burn"
        else:
            no_delta_details: dict[str, Any] = {"observation": OBSERVATION_EXECUTED}
            _stamp_seed_qualifiers(no_delta_details, used)
            if inputs_vacuous:
                # An effect-relevant argument was left at the default, so keep this out of the behaviour cache.
                no_delta_details["vacuous_input"] = True
                reason = "no_supply_delta_vacuous_input"
            else:
                reason = "no_supply_delta"
            return emit(
                store,
                unknown(
                    EFFECT_CLASS_SUPPLY,
                    gate_ref=gate_ref,
                    reason=reason,
                    details=no_delta_details,
                    transcript=tr,
                ),
            )
    else:
        sign = "mint" if delta > 0 else "burn"
    if _sign_contradicted_by_events(sign, minted, burned):
        # The two witnesses disagree, so hold neither; a burn was once published as proven dilution this way.
        contradicted_details: dict[str, Any] = {"observation": OBSERVATION_EXECUTED}
        _stamp_seed_qualifiers(contradicted_details, used)
        return emit(
            store,
            unknown(
                EFFECT_CLASS_SUPPLY,
                gate_ref=gate_ref,
                reason="supply_sign_contradicted_by_transfers",
                details=contradicted_details,
                transcript=tr,
            ),
        )
    _, _, _, disc = _resolve_destination_shape(
        effect_class=EFFECT_CLASS_SUPPLY,
        base_transfers=minted,
        sentinel_address=sentinel_address,
        sentinel_transfers=_run_sentinel(
            simulate,
            tr,
            token_address,
            principal,
            used.sentinel_calldata if used is not None else sentinel_calldata,
            sentinel_address,
            mint_from_zero=True,
            only_asset=token_address,
            attempt=used,
        ),
        taint_param_reaches_sink=taint_param_reaches_sink,
        static_shape=static_shape,
        static_destination=static_destination,
    )
    details: dict[str, Any] = {"supply_delta_sign": sign, "observation": OBSERVATION_EXECUTED}
    # At the top level, the only place ``claims_bridge._observed_summary`` reads, for mints and burns alike.
    _stamp_seed_qualifiers(details, used)
    concrete: dict[str, Any] = {}
    withheld: str | None = None
    if sign == "mint":
        # Mint backing: an inflow of a different asset into the vault in the same call separates a deposit-backed
        # conversion (WeETH.wrap, BoringVault.enter) from an unbacked admin mint. The logs are complete for the call, so
        # ``inflow_observed is False`` is a witnessed negative. Proportionality is left to the scorer. The minted token
        # itself is excluded: a fee mint to the vault is the dilution, not backing.
        inflow = transfers_in(mint_c, token_address, exclude_asset=token_address)
        # Asymmetric burden: ``inflow_observed: true`` needs only the log, but the negative is published as dilution and
        # must be earned. It's withheld if a named token slot didn't get a proven token
        # (:func:`_token_slots_unresolved`), or if an unnamed asset param still held our identity and the stub
        # differential fails (:func:`_prober_address_inert`).
        withheld = "token_param_unresolved" if _token_slots_unresolved(token_param_indexes, used) else None
        if withheld is None and not inflow:
            suspects = _prober_supplied_address_args(used.calldata if used is not None else mint_calldata, principal)
            if suspects and not _prober_address_inert(
                simulate,
                tr,
                token_address=token_address,
                principal=principal,
                calldata=used.calldata if used is not None else mint_calldata,
                attempt=used,
                delta=delta,
                suspects=suspects,
            ):
                withheld = "prober_address_not_proven_inert"
            elif not suspects and not principal:
                # No identity means address(0) fills address args: the codeless case, with no way to tell which slots.
                withheld = "prober_address_unidentifiable"
        if withheld is not None:
            # Withholding isn't a negative: ``backing`` is absent (read as unmeasured) and the reason is on the
            # transcript.
            tr["backing_withheld"] = withheld
        else:
            # Counts vary by deployment, so they go to per-deployment residue; the code-plane witness is the boolean
            # pair.
            concrete["backing_inflow_transfers"] = len(inflow)
            concrete["backing_mint_transfers"] = len(minted)
            details["backing"] = {
                "inflow_observed": bool(inflow),
                "minted": bool(minted),
                # How the call was reached, not what it did: seeding emits no Transfers, so ``inflow_observed`` is
                # unaffected.
                "input_seeded": used is not None,
                # See ``value_out``: a capability claim, not a live one.
                "contract_balance_seeded": used is not None and used.contract_balance_seeded,
            }
    if used is not None:
        seed_budget = budget_of(seeder)
        if seed_budget is not None:
            seed_budget.record_proven()
    eff = proven(
        EFFECT_CLASS_SUPPLY,
        gate_ref=gate_ref,
        reason=f"supply_{sign}",
        details=details,
        concrete=concrete,
        transcript=tr,
    )
    eff.discrepancy = disc
    return emit(store, eff)


def _run(
    simulate: Simulate,
    transcript: dict[str, Any],
    calls: list[SimCall],
    *,
    overrides: dict[str, Any] | None = None,
    label: str,
):
    """Issue and record one simulated block; ``None`` on a malformed response (fewer results than calls)."""
    call_dicts = [{"to": c.to, "data": c.data, "from": c.from_addr, "value": c.value} for c in calls]
    result = simulate(calls, hex(transcript["block_number"]), overrides)
    if result is None or len(result.calls) < len(calls):
        record_calls(transcript, call_dicts, [], label=label)
        return None
    record_calls(transcript, call_dicts, list(result.calls), label=label)
    return result


def _seeded_call(
    simulate: Simulate,
    transcript: dict[str, Any],
    *,
    attempts: Sequence[_SeedAttempt],
    to: str,
    principal: str | None,
    seeder: Seeder | None = None,
) -> tuple[_SeedAttempt | None, SimCallResult | None]:
    """Run seeded retries until one executes with its read-back intact; else ``(None, None)`` and the unseeded
    verdict stands. Every discarded attempt records why.
    """
    for attempt in attempts:
        calls = [
            *attempt.readback,
            SimCall(to=to, data=attempt.calldata, from_addr=principal, value=attempt.value),
        ]
        res = _run(simulate, transcript, calls, overrides=attempt.overrides, label=attempt.label)
        if res is None:
            _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_MALFORMED)
            continue
        if not _readback_ok(attempt, res.calls):
            _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_READBACK_FAILED)
            continue
        target = res.calls[len(attempt.readback)]
        if target.success:
            _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_EXECUTED)
            return attempt, target
        _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_TARGET_REVERTED, detail=_revert_detail(target))
    return None, None


def _revert_detail(result: SimCallResult) -> str:
    """A replayable reason for a revert: decoded error, else raw selector, else ``empty_revert``."""
    from services.resolution.differential_probe import decode_error

    raw = result.revert_data
    if not raw or raw == "0x":
        return "empty_revert"
    decoded = decode_error(raw)
    return str(decoded) if decoded else raw[:10]


def _seeded_supply_call(
    simulate: Simulate,
    transcript: dict[str, Any],
    *,
    attempts: Sequence[_SeedAttempt],
    token_address: str,
    principal: str | None,
    seeder: Seeder | None = None,
) -> tuple[_SeedAttempt | None, tuple[SimCallResult, SimCallResult, SimCallResult] | None]:
    """Seeded read, mint, read. Both reads must bracket the seeded call in one block, so the triple is re-run."""
    read = SimCall(to=token_address, data=TOTAL_SUPPLY_SELECTOR)
    for attempt in attempts:
        mint = SimCall(to=token_address, data=attempt.calldata, from_addr=principal, value=attempt.value)
        calls = [*attempt.readback, read, mint, read]
        res = _run(simulate, transcript, calls, overrides=attempt.overrides, label=attempt.label)
        if res is None or len(res.calls) != len(calls):
            _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_MALFORMED)
            continue
        if not _readback_ok(attempt, res.calls):
            _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_READBACK_FAILED)
            continue
        head = len(attempt.readback)
        before_c, mint_c, after_c = res.calls[head], res.calls[head + 1], res.calls[head + 2]
        if mint_c.success:
            _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_EXECUTED)
            return attempt, (before_c, mint_c, after_c)
        _record_seed_outcome(transcript, seeder, attempt.label, _OUTCOME_TARGET_REVERTED, detail=_revert_detail(mint_c))
    return None, None


def _run_sentinel(
    simulate: Simulate,
    transcript: dict[str, Any],
    source_address: str,
    principal: str | None,
    sentinel_calldata: str | None,
    sentinel_address: str | None,
    *,
    mint_from_zero: bool = False,
    only_asset: str | None = None,
    attempt: _SeedAttempt | None = None,
) -> list[tuple[str, str, str]] | None:
    """Run the sentinel probe if supplied; ``None`` when none ran, ``[]`` when it moved nothing (rule-8.1
    ``unknown``).

    When the base probe needed a seed, the sentinel uses the same seed; an unseeded sentinel would revert on the
    precondition and falsely read as "the caller can't redirect this".
    """
    if not sentinel_calldata or not sentinel_address:
        return None
    overrides = attempt.overrides if attempt is not None else None
    value = attempt.value if attempt is not None else 0
    readback = attempt.readback if attempt is not None else ()
    call = SimCall(to=source_address, data=sentinel_calldata, from_addr=principal, value=value)
    res = _run(simulate, transcript, [*readback, call], overrides=overrides, label="sentinel_probe")
    if res is None:
        return None
    if attempt is not None and not _readback_ok(attempt, res.calls):
        return None
    src = "0x" + "00" * 20 if mint_from_zero else source_address
    return transfers_out(res.calls[len(readback)], src, only_asset=only_asset)


def _resolve_destination_shape(
    *,
    effect_class: str,
    base_transfers: list[tuple[str, str, str]],
    sentinel_address: str | None,
    sentinel_transfers: list[tuple[str, str, str]] | None,
    taint_param_reaches_sink: bool,
    static_shape: str | None,
    static_destination: str | None,
) -> tuple[str, str, str | None, Discrepancy | None]:
    """Three-valued destination shape: ``(shape, proved_by, concrete_destination, discrepancy)``.

    A landing sentinel proves ``caller_arbitrary``; else static's fixed-shape proof; a discrepancy when taint said the
    param reaches the sink but the sentinel moved nothing; otherwise ``unknown``.

    ``concrete_destination`` is an address observed receiving the outflow (or static's proven fixed address), computed
    from the base probe, never the sentinel. Invented identities (the sentinel and :data:`calldata.NEUTRAL_CALLER`,
    which fills every address argument and comes back in the Transfer log) are excluded, and ``caller_arbitrary``
    publishes no address: it would just be our own input, misleadingly reassuring.

    The exclusion applies after the convergence test, not before; see the capture comment.
    """
    # Capture the destination only when every outflow converged on one address (several logs to one address is fine).
    # Order matters: test convergence over every destination first, then refuse invented identities. Filtering first
    # turned "90% to the caller, 10% fee to treasury" into "the money goes to treasury".
    out_destinations = {to for _f, to, _v in base_transfers}
    observed_dest = next(iter(out_destinations)) if len(out_destinations) == 1 else None
    if _is_invented_identity(observed_dest):
        observed_dest = None
    if sentinel_transfers is not None and sentinel_address is not None:
        landed = any(_addr_eq(to, sentinel_address) for _f, to, _v in sentinel_transfers)
        if landed:
            # Proven caller-arbitrary: the recipient is our own calldata, so publish no address.
            return SHAPE_CALLER_ARBITRARY, "simulation", None, None
    # Checked before the static branch returns: taint vs a silent sentinel is a soundness problem, most interesting when
    # static claims a fixed shape.
    disc = (
        Discrepancy(
            kind="taint_param_sentinel_negative",
            effect_class=effect_class,
            detail={"sentinel_address": sentinel_address},
        )
        if taint_param_reaches_sink and sentinel_transfers is not None
        else None
    )
    if static_shape in (SHAPE_IMMUTABLE_FIXED, SHAPE_STORAGE_DETERMINED):
        # The shape is static's universal; the address is the observation's and may be absent. Requiring a static
        # address made this branch dead (static never resolves the value behind an immutable), leaving
        # ``destination_shape`` ~95% unknown.
        return static_shape, "static", static_destination or observed_dest, disc
    # Taint says the param reaches the sink but the sentinel moved nothing: a discrepancy, not "fixed".
    return SHAPE_UNKNOWN, "none", observed_dest, disc


def _add_reach(
    concrete: dict[str, Any],
    base_call: SimCallResult,
    value_holders: Sequence[AssetHolding],
    acting_balance_usd: float | None,
    protocol_tvl_usd: float | None = None,
) -> None:
    """Downstream value reach from the same fork execution of F.

    A holder whose balance provably left (a Transfer out in this call's logs) is an observed reach, attributed at its
    full USD (an upper bound). Never imputed from control-graph edges. Skipped when no holder set is supplied.

    * ``reach_determined: True`` with ``observed_reach_value_usd``, ``observed_reach_holders``,
    ``observed_reach_assets``: every moved asset had a priced holding.
    * ``reach_determined: False``, ``reach_indeterminate: True``, ``observed_reach_floor_usd``: nothing left a holder,
    which isn't "no reach" (routers and zaps move value they don't hold). The acting deployment's balance is published
    as a floor, never as measured reach.
    * The same without ``observed_reach_floor_usd``: no balance row for the acting deployment either. A ``0.0`` floor
    would mean a row was read and summed to zero.
    * ``reach_determined: False`` without ``reach_indeterminate``: value left but some (holder, asset) pair has no
    priced holding. ``observed_reach_priced_usd`` is the priced part (a floor) with ``observed_reach_priced_holders``;
    withheld if it exceeds TVL.
    * Everything absent: no holder set supplied.

    The unvalued disclosure is per (holder, asset), matching the arithmetic: ``observed_reach_unvalued_pairs`` (one
    entry per unvalued pair), ``observed_reach_unvalued_assets`` (assets no holder priced; ``[]`` is an earned
    negative), ``observed_reach_priced_holders``. Keying it per asset once published an asset as both the only mover and
    unvaluable beside a figure made from another holder's balance.

    Written to ``concrete``, not ``details``: holders and USD are per-deployment and mustn't reach bytecode twins via
    the cache.

    Matching is per (holder, asset), where asset is the Transfer emitter (``NATIVE_ASSET_LOG_EMITTER`` for native).
    Asset-blind matching published $3.489B of reach for ``WeETH.recoverETH`` from one synthetic native Transfer.

    One add per (holder, asset), never per log, since the figure is the whole balance.
    """
    if not value_holders:
        return
    priced_usd = 0.0
    priced_any = False
    # Accumulated per (holder, asset), the arithmetic's key.
    unvalued_pairs: list[dict[str, str]] = []
    priced_holders: set[str] = set()
    priced_assets: set[str] = set()
    reach_holders: set[str] = set()
    reach_assets: set[str] = set()
    # (holder, asset) -> priced holding, or None if unpriced. A missing pair means no balance row at all.
    known: dict[tuple[str, str], float | None] = {
        (h.holder.lower(), h.asset.lower()): h.usd_value for h in value_holders
    }
    # What's known about assets absent from ``known`` per holder. Never "the list is whole": nothing can prove that
    # (``selection._completeness_from_fetch`` has no ``complete`` member).
    completeness: dict[str, str] = {h.holder.lower(): h.completeness for h in value_holders}
    # Pairs value provably left, deduped before any USD is added; several logs of one asset from one holder must count
    # once.
    moved: set[tuple[str, str]] = set()
    for holder in sorted({h.holder.lower() for h in value_holders}):
        for _frm, _to, _value, asset in transfers_out_with_asset(base_call, holder):
            moved.add((holder, asset))
    for holder, asset in sorted(moved):
        reach_holders.add(holder)
        reach_assets.add(asset)
        if (holder, asset) not in known:
            # No balance row: "holds nothing", "not fetched" and "fetch failed" look the same, so it's not a zero.
            # ``holdings_at_page_cap`` when stored rows hit the fetch cap, else ``asset_not_in_recorded_holdings``.
            reason = _UNVALUED_REASON_BY_COMPLETENESS[completeness.get(holder, HOLDINGS_NOT_DETERMINED)]
            unvalued_pairs.append({"holder": holder, "asset": asset, "reason": reason})
            continue
        usd = known[(holder, asset)]
        if usd is None:
            # Held but unpriced, per pair.
            unvalued_pairs.append({"holder": holder, "asset": asset, "reason": "unpriced_holding"})
        else:
            priced_usd += usd
            priced_any = True
            priced_holders.add(holder)
            priced_assets.add(asset)
    if not reach_holders:
        concrete["reach_determined"] = False
        concrete["reach_indeterminate"] = True
        if acting_balance_usd is not None:
            concrete["observed_reach_floor_usd"] = acting_balance_usd
        return
    concrete["observed_reach_holders"] = sorted(reach_holders)
    concrete["observed_reach_assets"] = sorted(reach_assets)
    if unvalued_pairs:
        # Witnessed but not valued; the priced part is a floor.
        concrete["reach_determined"] = False
        # Already sorted: the loop walks ``sorted(moved)``.
        concrete["observed_reach_unvalued_pairs"] = unvalued_pairs
        # Assets no holder priced; ``[]`` is an earned negative.
        concrete["observed_reach_unvalued_assets"] = sorted({p["asset"] for p in unvalued_pairs} - priced_assets)
        concrete["observed_reach_unvalued_reasons"] = sorted({p["reason"] for p in unvalued_pairs})
        if priced_any:
            # Whose holdings the figure is, published on both arms so a refused figure's subjects are named.
            concrete["observed_reach_priced_holders"] = sorted(priced_holders)
            # The TVL ceiling applies to the partial floor too; a floor above TVL is even more contradictory than a
            # loose upper bound. Refused, never clamped.
            tvl_state, tvl_note = _reach_tvl_state(priced_usd, protocol_tvl_usd)
            concrete["reach_tvl_check"] = tvl_state
            if tvl_state == REACH_TVL_EXCEEDED:
                logger.warning(
                    "reach floor %.2f exceeds protocol TVL %.2f — refusing the figure; "
                    "priced_holders=%s unvalued_pairs=%s",
                    priced_usd,
                    protocol_tvl_usd or 0.0,
                    sorted(priced_holders),
                    [(p["holder"], p["asset"]) for p in unvalued_pairs],
                )
                concrete["observed_reach_rejected_usd"] = priced_usd
                concrete["protocol_tvl_usd"] = protocol_tvl_usd
            else:
                if tvl_note is not None:
                    logger.warning("reach TVL ceiling not applied: %s", tvl_note)
                concrete["observed_reach_priced_usd"] = priced_usd
        # No figure, so no ``reach_tvl_check``; ``within_protocol_tvl`` over nothing would read as a pass.
        return
    # One function can't reach more than the protocol holds ($3.489B was once published against $3.297B TVL). Refused
    # with both figures, never clamped.
    tvl_state, tvl_note = _reach_tvl_state(priced_usd, protocol_tvl_usd)
    concrete["reach_tvl_check"] = tvl_state
    if tvl_state == REACH_TVL_EXCEEDED:
        logger.warning(
            "reach %.2f exceeds protocol TVL %.2f — refusing the figure; holders=%s assets=%s",
            priced_usd,
            protocol_tvl_usd or 0.0,
            sorted(reach_holders),
            sorted(reach_assets),
        )
        concrete["reach_determined"] = False
        concrete["observed_reach_rejected_usd"] = priced_usd
        concrete["protocol_tvl_usd"] = protocol_tvl_usd
        return
    if tvl_note is not None:
        logger.warning("reach TVL ceiling not applied: %s", tvl_note)
    concrete["reach_determined"] = True
    concrete["observed_reach_value_usd"] = priced_usd


# The ceiling's answers include ``skipped_no_tvl`` so an unchecked ceiling isn't mistaken for a pass. Unvalued reasons
# are keyed on what's known about the holder's list; neither asserts the holder lacks the asset (the old
# ``unrecorded_asset`` name read as proven absence).
_UNVALUED_REASON_BY_COMPLETENESS = {
    HOLDINGS_COMPLETENESS_AT_PAGE_CAP: "holdings_at_page_cap",
    HOLDINGS_NOT_DETERMINED: "asset_not_in_recorded_holdings",
}

REACH_TVL_WITHIN = "within_protocol_tvl"
REACH_TVL_EXCEEDED = "exceeds_protocol_tvl"
REACH_TVL_SKIPPED = "skipped_no_tvl"


def _reach_tvl_state(reached_usd: float, protocol_tvl_usd: float | None) -> tuple[str, str | None]:
    """``(state, log_note)`` for the reach-vs-TVL ceiling.

    Reads only a caller-supplied ``defillama_tvl`` (see ``selection._protocol_tvl_usd``); the tvl_snapshots columns are
    NULL locally.
    """
    if protocol_tvl_usd is None or protocol_tvl_usd <= 0:
        return REACH_TVL_SKIPPED, "no defillama_tvl snapshot for this protocol"
    if reached_usd > protocol_tvl_usd:
        return REACH_TVL_EXCEEDED, None
    return REACH_TVL_WITHIN, None


def _sim_precondition_unknown(effect_class: str, gate_ref: str, transcript: dict[str, Any]) -> ObservedEffect:
    return unknown(
        effect_class,
        gate_ref=gate_ref,
        reason="malformed_simulation_response",
        details={"observation": OBSERVATION_NOT_RUN},
        transcript=transcript,
    )


_UINT256_MOD = 1 << 256


def _signed_delta(after: int, before: int) -> int:
    """``after - before`` as a uint256 delta.

    ``_burn`` often decrements in ``unchecked``, and a wrap past zero comes back from Python subtraction as ~``2^256``,
    a mint. Reading modulo ``2^256`` and taking the short way round restores the EVM's sign; more than ``2^255`` real
    movement isn't plausible.
    """
    raw = (after - before) % _UINT256_MOD
    return raw - _UINT256_MOD if raw > _UINT256_MOD // 2 else raw


def _sign_contradicted_by_events(
    sign: str, minted: list[tuple[str, str, str]], burned: list[tuple[str, str, str]]
) -> bool:
    """Whether zero-address Transfers say the opposite of the ``totalSupply`` arithmetic.

    Requires positive contradicting events, not silence (a token that mints without events isn't lying).
    """
    if sign == "mint":
        return bool(burned) and not minted
    return bool(minted) and not burned


def _to_int(hexval: str | None) -> int | None:
    if not hexval or not isinstance(hexval, str):
        return None
    try:
        return int(hexval, 16)
    except ValueError:
        return None


# Identities this prober invents (the attacker sentinel and the neutral caller, which also fills every address arg), so
# never publishable as observed destinations.
_INVENTED_IDENTITIES = (SENTINEL_ADDRESS, NEUTRAL_CALLER)


def _is_invented_identity(address: str | None) -> bool:
    return any(_addr_eq(address, invented) for invented in _INVENTED_IDENTITIES)


def _addr_eq(a: str | None, b: str | None) -> bool:
    if a is None or b is None:
        return False
    aa = a[2:] if a.startswith("0x") else a
    bb = b[2:] if b.startswith("0x") else b
    return aa.lstrip("0").lower() == bb.lstrip("0").lower()
