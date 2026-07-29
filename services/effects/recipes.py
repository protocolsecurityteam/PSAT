"""Tier-1 effect recipes — value-out, code-upgrade, authority-change, supply.

Each recipe is a PURE decision over injected seams (``Simulate`` / ``CallBatch``
+ the transcript store) that returns a tiered, transcripted
:class:`~services.effects.harness.ObservedEffect`. Names never enter a
definition; every positive verdict is an OBSERVED transition, every
non-observation is fail-closed ``unknown``. The Tier-2 pause recipe lives in
``services.effects.anvil`` because it needs the fork transport.

Boundary: recipes RETURN verdicts and RECORD discrepancies on them; they do
not persist to the DB and do not route discrepancies anywhere.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

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
from utils.rpc import EthCallResult

logger = logging.getLogger(__name__)

# EIP-1967 implementation slot. keccak("eip1967.proxy.implementation") - 1.
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# ERC-20 totalSupply().
TOTAL_SUPPLY_SELECTOR = "0x18160ddd"

# Re-exported: the discriminator is the whole stage's contract, not this module's
# (``services.effects.anvil`` emits pause rows under it too), so it lives in the
# shared vocabulary. See :mod:`services.effects.config` for what each value means.


def _sim_to_ethcall(r: SimCallResult) -> EthCallResult:
    """Adapt a simulate call result to the ``EthCallResult`` the raw-revert
    authorization discipline consumes."""
    return EthCallResult(r.success, r.return_data, r.revert_data, None)


def transparent_sentinel_override(sentinel_address: str) -> dict[str, dict[str, Any]]:
    """State override placing plain nonzero code at the sentinel so a transparent
    proxy's ``_setImplementation`` code check passes. A single ``STOP``
    (extcodesize=1) is enough — a bare address with no code would revert the
    upgrade and prove nothing."""
    return {sentinel_address.lower(): {"code": "0x00"}}


def uups_sentinel_override(sentinel_address: str, impl_slot: str = EIP1967_IMPL_SLOT) -> dict[str, dict[str, Any]]:
    """State override placing an ERC-1822 stub at the sentinel whose
    ``proxiableUUID()`` returns the canonical impl slot, so a UUPS
    ``upgradeToAndCall`` (which delegatecalls the new impl to validate it) accepts
    it. The stub returns ``impl_slot`` for ANY call — a minimal
    ``PUSH32 slot; PUSH0; MSTORE; PUSH1 32; PUSH0; RETURN``."""
    slot = impl_slot[2:] if impl_slot.startswith("0x") else impl_slot
    slot = slot.rjust(64, "0")
    code = "0x7f" + slot + "5f52" + "6020" + "5f" + "f3"
    return {sentinel_address.lower(): {"code": code}}


# ---------------------------------------------------------------------------
# Input-asset seeding (shared by value-out and supply)
# ---------------------------------------------------------------------------


# Attempt labels. ``contract_balance`` is the most synthetic and always runs last.
_ATTEMPT_SEEDED = "seeded_probe"
_ATTEMPT_PAYABLE = "seeded_probe_payable"
_ATTEMPT_CONTRACT_BALANCE = "seeded_probe_contract_balance"
_ATTEMPT_CONTRACT_TOKEN = "seeded_probe_contract_token"
# ERC-20 analogue of the native contract-balance seed runs on at most this many of
# the deployment's measured holdings; the seeder's own layout budget caps distinct
# tokens further.
_MAX_CONTRACT_HOLDINGS = 2

# Why a seeded attempt (or the whole retry path) produced no observation. Recorded
# per attempt on the transcript AND counted on the seed budget's metrics, so a live
# run reporting ``executed=0`` names the failing precondition instead of going
# silent.
_OUTCOME_EXECUTED = "executed"
_OUTCOME_TARGET_REVERTED = "target_reverted"
_OUTCOME_READBACK_FAILED = "readback_failed"
_OUTCOME_MALFORMED = "malformed_response"
_SKIP_NO_SEEDER = "skipped_no_seeder"
_SKIP_NO_CALLDATA = "skipped_no_seeded_calldata"
_SKIP_BUDGET = "skipped_budget_exhausted"
_SKIP_NO_TOKEN = "skipped_no_token_resolved"
_SKIP_NO_ATTEMPT_PATH = "skipped_no_viable_attempt"
# A token PARAMETER was left at the encoder's default because nothing honest
# could be named for it. The call reverts on its own argument — a non-observation
# with a recorded reason, never a guessed address.
_SKIP_NO_TOKEN_ARG = "skipped_no_token_for_param"


@dataclass(frozen=True)
class _SeedAttempt:
    """One seeded retry of a probe call."""

    label: str
    overrides: StateOverride | None
    value: int
    calldata: str
    sentinel_calldata: str | None
    seeding: Seeding | None
    contract_balance_seeded: bool = False
    # ``param index -> token address`` written into this attempt's calldata. Only
    # a read-back-proved token appears here, so it is what the backing witness is
    # gated on (see :func:`_backing_admissible`).
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
    """Append one attempt/skip outcome to the transcript and count it on the
    budget. The transcript already carries the raw calls; this says which
    PRECONDITION each attempt died on, which the call list alone cannot."""
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
    """The ordered retries for a probe whose UNSEEDED call already reverted.

    Ordering is the soundness argument, not an optimization:

    * the ERC-20 attempt runs first, at ``value == 0``, so an asset the call then
      consumes is one it genuinely pulls;
    * ``msg.value`` is attached only on the SECOND attempt — i.e. only after a
      zero-value call provably failed. Attaching ETH up front would let a payable
      admin mint bank our own ``msg.value`` as an "inflow" when a real caller
      could mint with nothing attached. This ordering makes an ETH deposit's
      inflow a witnessed REQUIREMENT;
    * the TARGET CONTRACT's own balance is seeded LAST and only for a function
      static says pays native ETH out. It is the most synthetic override the
      stage makes — a verdict it produces means "would move value if the contract
      were funded", not "moves value in current state" — so it may only ever run
      after every attempt that carries the stronger meaning has failed.

    Attempts a target cannot execute are not issued at all: a NON-payable function
    rejects an attached ``msg.value`` with an empty revert before its body runs,
    which witnesses nothing and cost 9 of the 13 seeded calls on the 2026-07-22
    run. With no token seeding, no payable path and no native payout there is
    nothing left to try, and the probe keeps exactly today's unseeded verdict.

    The whole path is charged to the job's :class:`~services.effects.seeding.SeedBudget`
    FIRST — an exhausted budget returns no attempt at all, which is the exact
    pre-seeding probe, never a less careful one."""
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
    # ERC-20 analogue of the native contract-balance seed: a payout the
    # contract's LIVE balance cannot cover reaches its send once the contract's own
    # token balance is overridden. Seeding with ``principal == spender == contract``
    # makes the seeder write the CONTRACT's balance slot (``slot(principal, spender)``)
    # and read it back via ``balanceOf(contract)`` — the same discipline as every
    # other seed. Runs LAST (most synthetic) and carries ``contract_balance_seeded``:
    # a verdict it produces is "would move value IF THE CONTRACT WERE FUNDED", a
    # capability of the code, not a live outflow. The token is whatever the
    # deployment provably holds, never a hardcoded asset.
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
    """Write a SEEDED token address into each proved token parameter.

    Only a token the seeder actually seeded may be written: the principal now
    holds it, so the pull the function performs can succeed and emit the Transfer
    the backing witness is read from. The probe target itself is excluded even
    when it was the only token seeded — feeding a vault its own share token as
    the deposit asset produces a mint whose inflow is the minted asset, which the
    backing rule discards, and the resulting ``inflow_observed: false`` would
    describe the prober's argument rather than the function.

    Returns the (possibly unchanged) calldata pair and a map of what was placed;
    an empty map means the slots kept the encoder's default."""
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
    """Did a slot the static plane PROVED carries a token keep the encoder's
    filler instead of a read-back-verified one?

    The cheap half of the mint-backing admissibility gate: a call made with a non-token in
    a known token slot cannot witness anything about backing. It is only half
    because ``token_param_indexes`` is derived from parameter NAMES plus body-sink
    heads (``calldata.address_param_roles``), so an asset argument named outside
    that vocabulary leaves it EMPTY — the reason the negative additionally needs
    :func:`_prober_address_inert`."""
    if not token_param_indexes:
        return False
    return used is None or not set(used.token_args) >= {str(i) for i in token_param_indexes}


def _stamp_seed_qualifiers(details: dict[str, Any], used: _SeedAttempt | None) -> None:
    """Mirror ``value_out``'s top-level qualifiers (:func:`value_out`, the
    ``input_seeded`` / ``contract_balance_seeded`` block) onto a supply verdict's
    ``details``.

    ``claims_bridge._observed_summary`` propagates these by TOP-LEVEL key, so a
    qualifier written only into the nested ``backing`` map (or only onto the
    transcript) never reaches the witness and the claim then reads stronger than
    the seeded observation it came from. ``contract_balance_seeded`` is the
    capability-not-current-state weakener and MUST travel wherever the verdict
    does; a plain ``input_seeded`` records that the caller was funded first. A
    no-op when nothing was seeded, so absence still means "no override was
    needed", never "seeded but undisclosed"."""
    if used is None:
        return
    details["input_seeded"] = True
    if used.contract_balance_seeded:
        details["contract_balance_seeded"] = True


# Runtime that reverts on ANY call, on every fork: ``PUSH1 0 PUSH1 0 REVERT``.
# Deliberately not ``PUSH0``-based (that would pin the probe to post-Shanghai) and
# deliberately non-empty, so ``extcodesize`` is nonzero and an ``isContract``
# guard takes the same branch a real token would.
_REVERT_STUB_CODE = "0x60006000fd"


def _prober_supplied_address_args(calldata: str, principal: str | None) -> list[str]:
    """Addresses THIS prober invented and wrote into ``calldata``'s head words.

    The encoder's address policy (``calldata._arg_values``) writes the acting
    identity into EVERY address parameter, and the seeded retry overwrites the
    proved token slots with a read-back-verified token
    (``calldata.substitute_address_arg``). So a head word still equal to the
    principal is an address argument the prober chose, and a slot holding a seeded
    token is excluded by construction — it no longer holds the principal.

    Read off the BYTES that were executed rather than off a parameter-type list,
    so it stays true whatever the encoder did with the signature. A ``uint`` head
    word can only collide with this by carrying the principal's exact 160-bit
    value, which the encoder never writes into an integer slot."""
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
    """Is the mint we just observed PROVABLY independent of the addresses the
    prober itself supplied as arguments?

    This is the proof the mint-backing NEGATIVE rests on, and it exists because absence of
    evidence is not evidence of absence here. A call to a CODELESS address is a
    silent no-op success inside ``SafeTransferLib`` and its imitators, so a
    deposit-backed conversion handed a codeless address for its asset still mints
    while pulling nothing — and ``inflow_observed: false`` would then describe the
    prober's argument, not the function. Parameter names cannot rule that out
    (that is exactly what let it through), and a codesize read cannot either: the
    acting principal is routinely an EOA, and withholding on that alone would
    delete the unbacked-admin-mint witness this stage exists to produce.

    The differential decides it by OBSERVATION instead. Re-run the same read →
    mint → read block, under the same seed, with plain reverting code placed at
    each prober-supplied address. If the mint still executes and moves supply by
    the SAME delta, then no call to those addresses was on the executed path: no
    pull was silently skipped, and ``inflow_observed: false`` is a statement about
    F. If it now reverts, diverges, or cannot be run at all, the execution DID
    depend on an address this prober invented and the witness is withheld.

    Known limit, stated rather than papered over: a pull made through an
    UNCHECKED low-level call would survive the stub and still be counted inert.
    Every safe-transfer wrapper in circulation checks, so this is the residual
    the differential does not close."""
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
    """Did every seeded slot echo its written word inside THIS probe's block?

    The strict gate on every seeded verdict. The discovery block proved the
    getter reads the slot; this proves the seed landed in the block the witness
    comes from. Any revert or any mismatch ⇒ the whole attempt is discarded and
    the probe falls back to its unseeded verdict — an unseeded ``unknown`` is
    honest, a wrongly-seeded positive is not."""
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


# ---------------------------------------------------------------------------
# value-out (+ three-valued destination shape)
# ---------------------------------------------------------------------------


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
    acting_balance_usd: float = 0.0,
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
) -> ObservedEffect:
    """Does calling F move value out, and to what kind of destination?

    Tier 1 needs ``eth_simulateV1`` (balance + ``Transfer``-event diffs); where
    unsupported the class declares its Tier-2 fallback explicitly, never a
    silent degrade. The value-MOVED fact is the sim's; the fixed shapes
    are static UNIVERSALS; only ``caller_arbitrary`` is proven by simulation via
    a sentinel that lands — a sentinel that moves nothing proves nothing and,
    when taint said the param reaches the sink, is a discrepancy (recorded, not
    routed).

    VERDICT SEMANTICS under seeding. A proven verdict normally reads "calling F
    moves value out, in the state at this block". Two flags on ``details`` weaken
    that, and both travel with the verdict through the cache and the claims
    bridge because a consumer that misses them over-reads the witness:

    * ``input_seeded`` — the caller was given the asset F pulls. The effect is
      still fully observed; what is not claimed is that this principal holds the
      asset today.
    * ``contract_balance_seeded`` — the TARGET CONTRACT's own ETH balance was
      overridden before the payout executed. The verdict then means "would move
      value IF THE CONTRACT WERE FUNDED" — a capability of the code — not "moves
      value in current state". Its absence means no override was needed, never
      that the treasury is funded."""
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
        # A precondition revert, not an absence of value movement: a payable or
        # asset-pulling withdrawal never reaches its send with an empty caller.
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
    # Did the execution the transfers were read off actually RUN? ``observed.logs``
    # is empty for a reverted call, so ``transfers_out`` returns ``[]`` for "F moved
    # nothing" and for "F never got past its own precondition" alike. Without this
    # flag both land the identical ``value_moved: false`` payload on the row.
    executed = observed.success
    details: dict[str, Any] = {
        "value_moved": value_moved,
        "observation": OBSERVATION_EXECUTED if executed else OBSERVATION_REVERTED,
        "destination_shape": shape,
        "shape_proved_by": proved_by,
    }
    if used is not None:
        # Code-plane: the function could only be exercised once the caller held
        # the input asset it pulls. Which token / how much is state-plane residue
        # and stays in the transcript.
        details["input_seeded"] = True
        if used.contract_balance_seeded:
            # WEAKER CLAIM, and it has to travel with the verdict everywhere the
            # verdict does (cache included): the payout was only reachable after
            # the TARGET CONTRACT's own ETH balance was overridden, so this proves
            # "would move value if the contract were funded" — a capability of the
            # code — not "moves value in current state". A consumer that ignores
            # this key reads a treasury-empty contract as a live outflow.
            details["contract_balance_seeded"] = True
    concrete: dict[str, Any] = {}
    if concrete_dest is not None:
        concrete["destination"] = concrete_dest
    if not value_moved and shape != SHAPE_CALLER_ARBITRARY:
        # Two different facts, and they must not share a reason string: a call that
        # RAN and moved nothing is a code-plane structural non-observation a
        # bytecode twin inherits, while a call that reverted — on a precondition,
        # or on an argument this prober guessed — is state-/input-dependent and
        # must re-probe. ``value_probe_reverted`` is deliberately absent from
        # ``effects_worker._CACHEABLE_UNKNOWN_REASONS`` for exactly that reason;
        # ``no_supply_delta``/``mint_call_reverted`` already split this way.
        #
        # A THIRD split: a call that RAN but did so with an effect-relevant
        # argument left at the encoder default (an empty dynamic array, an integer
        # role that never resolved) observed nothing about F — it observed a fact
        # about the vacuous argument. That is input-dependent by the same criterion
        # a revert is, so its reason must ALSO stay out of the behaviour cache; a
        # twin must not inherit "moves no value" from an empty-array probe.
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
    # Downstream value-reach rides the proven flow.out verdict only, and is
    # STATE-plane (holder addresses + this protocol's USD) — hence ``concrete``.
    # Measured on ``observed``, the execution the VERDICT came from: on a seeded
    # retry the unseeded call reverted and carries no logs at all, so reading
    # reach off it made every seeded verdict indeterminate by construction.
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


# ---------------------------------------------------------------------------
# code-upgrade
# ---------------------------------------------------------------------------


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

    Tier 0 FIRST — an indexed upgrade proves PAST capability only *in
    conjunction* with a current-state check: indexed + current-impl
    non-zero ⇒ proven now; indexed + current fails ⇒ ``unknown`` (historically
    upgradeable, current capability unknown), fail-closed. Else Tier 1: read the
    impl slot, call F as principal with a sentinel whose override survives the
    proxy's validation (plain nonzero code for transparent, an ERC-1822 stub for
    UUPS), re-read the slot. A bare-address sentinel (no code override) reverts
    and proves nothing."""
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
        # Bare-address sentinel: no code at the target, so the proxy's validation
        # (UUPS proxiableUUID / a code check) reverts the upgrade — proves nothing.
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
        # Same split as ``value_out``: an upgrade call that REVERTED leaves the
        # impl slot untouched for a reason that has nothing to do with the code's
        # upgradeability — the principal was rejected, or an argument this prober
        # chose was. Reading it as ``impl_slot_unchanged`` put a state-dependent
        # non-observation into the code-plane cache, where it transferred to every
        # bytecode twin. Checked BEFORE the positive branch: a reverted call cannot
        # have moved the slot, so a match here would be a node artifact.
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


# ---------------------------------------------------------------------------
# authority-change kernel (function-local gate mutation)
# ---------------------------------------------------------------------------


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
    """Does calling F change WHO can call some gate G? (kernel only)

    One simulated block carries state across calls: probe G as ≥2 random
    identities → call F as principal (e.g. grantRole) → re-probe G as the same
    randoms. Opened iff the randoms were consistently rejected before and ALL
    succeed after (raw reverts compared undecoded); a single-identity flip or
    an ambiguous outcome never opens (fail-closed). The whole-contract
    authorization DELTA is a projection on whole-contract identity — this
    returns the function-local gate-mutation kernel only."""
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
        # The principal could not even execute F — a precondition revert, not a
        # proven absence of effect. This class takes NO seeder: its
        # reverts are on the gate, not a missing asset, so there is nothing to
        # seed away. But the decoded revert IS worth keeping — without it the next
        # census cannot name why the mutation reverted. Record it the way
        # ``value_out`` records a seeded attempt's revert, via ``_revert_detail``.
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


# ---------------------------------------------------------------------------
# supply (mint / burn)
# ---------------------------------------------------------------------------


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

    Tier 1 via ``eth_simulateV1`` (read → call → read in one context): a signed
    delta is the label (up = mint, down = burn); a zero delta is a
    non-observation (``unknown``). Destination shape follows value-out — sentinel
    proves ``caller_arbitrary``; sentinel-negative is ``unknown``, never fixed."""
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
        # A deposit-backed conversion (wrap / enter / deposit) reverts here on the
        # asset it pulls, never reaching the mint — so it drops out of the mint
        # population and takes its backing witness with it. Retry with the input
        # asset seeded.
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
    # mint = Transfer from the zero address, EMITTED BY the token whose
    # ``totalSupply`` moved. Any other token minting inside the same call is a
    # different asset's supply event and must not stand in for this one's.
    minted = transfers_out(mint_c, "0x" + "00" * 20, only_asset=token_address)
    # The mirror: units destroyed are a Transfer TO the zero address.
    burned = transfers_in(mint_c, "0x" + "00" * 20, only_asset=token_address)
    if delta == 0:
        # ``totalSupply`` is NOT the unit count for a share-accounted or
        # rebasing token — EETH's reads ``liquidityPool.getTotalPooledEther()``,
        # stETH's reads pooled ether — so a zero delta there does not mean no units
        # were minted or burned. An UNAMBIGUOUS zero-address ``Transfer`` (exactly
        # one direction present) IS that witness; take the sign from it. Only when
        # the transfer evidence is ambiguous (both directions, or neither) is this
        # the honest non-observation. Erring toward under-claiming: missing this
        # capped the entire share-accounted population, not two functions.
        if bool(minted) != bool(burned):
            sign = "mint" if minted else "burn"
        else:
            no_delta_details: dict[str, Any] = {"observation": OBSERVATION_EXECUTED}
            _stamp_seed_qualifiers(no_delta_details, used)
            if inputs_vacuous:
                # The mint call ran but an effect-relevant argument was
                # left at the encoder default, so "no supply delta" is a fact about
                # the vacuous input, not about F — its reason must stay OUT of the
                # behaviour cache (a twin must not inherit it).
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
        # Two independent witnesses of the same event disagree, so we hold none of
        # it. Publishing the arithmetic anyway is how a burn was once published as
        # proven dilution — the strongest claim this stage can make, on a call that
        # destroyed units. An unknown here is not a gap in coverage; it is the only
        # honest reading of contradictory evidence.
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
    # The synthesis qualifiers must live at ``details`` TOP LEVEL — the only
    # place ``claims_bridge._observed_summary`` carries them from — for EVERY
    # supply verdict, mint or burn. The nested ``backing`` copy below (mint-only,
    # withheld-gated) never reaches a burn witness, so a seeded burn read stronger
    # than its observation until this stamp.
    _stamp_seed_qualifiers(details, used)
    concrete: dict[str, Any] = {}
    withheld: str | None = None
    if sign == "mint":
        # Mint backing: an asset Transfer INTO the vault during the SAME simulated
        # mint call is the co-occurring inflow that separates a deposit-backed
        # conversion (WeETH.wrap / BoringVault.enter) from an unbacked, dilutive
        # admin mint. The mint ran as the resolved principal for an attacker-chosen
        # amount, and ``mint_c.logs`` is the COMPLETE set of Transfers it emitted —
        # so ``inflow_observed is False`` is a WITNESSED negative (supply rose with
        # zero matching asset inflow in the same observed call = dilution), not an
        # absence-of-evidence guess. Fork-observed, Tier 1. Proportionality (the
        # backed-vs-partial distinction) is left to the scorer from these counts —
        # the assets differ in token/decimals, so the recipe does NOT collapse them
        # to a ratio here. NEVER inferred from static flow.in + supply.mint
        # co-occurrence (that proves neither causation nor proportionality).
        #
        # The inflow must be an asset OTHER than the one just minted: a mint that
        # credits the vault itself (``_mint(address(this), fee)``) emits a
        # ``Transfer(0x0 -> vault)`` from the minted token, which is the dilution
        # being measured, not backing for it. Counting it produced a
        # ``backing.inflow_observed: true`` byte-identical to a real deposit-backed
        # conversion on the purest case of unbacked issuance.
        inflow = transfers_in(mint_c, token_address, exclude_asset=token_address)
        # ASYMMETRIC BURDEN, and the asymmetry is the whole point. ``inflow_observed:
        # true`` is a positive observation — a Transfer log exists — and needs no
        # further proof. The NEGATIVE has to be EARNED: it is published as witnessed
        # dilution, so it may not rest on a pull that failed to happen because of an
        # argument this prober invented. Two independent ways that can happen, each
        # with its own gate:
        #
        #   * a slot static NAMED as a token never received a proven one
        #     (:func:`_token_slots_unresolved`);
        #   * a slot static never named at all — an asset parameter called ``want``
        #     or ``market`` yields an EMPTY ``token_param_indexes``, so the first
        #     gate passes vacuously — still holds the acting identity, and a call to
        #     a codeless address is a silent no-op inside ``SafeTransferLib``. That
        #     one is settled by OBSERVATION (:func:`_prober_address_inert`), never by
        #     vocabulary.
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
                # No identity to fill address arguments with means the encoder's
                # ``address(0)`` occupies them — the codeless case in its purest
                # form — and nothing here can tell which slots those were.
                withheld = "prober_address_unidentifiable"
        if withheld is not None:
            # WITHHOLDING IS NOT A NEGATIVE. The ``backing`` key is simply absent,
            # which ``claims_bridge._observed_summary`` and the scorer read as
            # unmeasured; the reason lives on the transcript so a live run can name
            # what it could not prove instead of going quiet.
            tr["backing_withheld"] = withheld
        else:
            # HOW MANY transfers this execution emitted is an observation of THIS
            # deployment at this block, not a property of the bytecode: the same code
            # on a vault with two fee recipients emits a different count. The
            # code-plane witness is the BOOLEAN pair (an inflow co-occurred / units
            # were minted), which is what a twin deployment may inherit; the counts go
            # to the per-deployment residue.
            concrete["backing_inflow_transfers"] = len(inflow)
            concrete["backing_mint_transfers"] = len(minted)
            details["backing"] = {
                "inflow_observed": bool(inflow),
                "minted": bool(minted),
                # Whether the acting principal had to be given the input asset before
                # the mint would execute at all. It records HOW the call was reached,
                # never what the call did: ``inflow_observed`` above still comes
                # solely from Transfers this execution emitted, and storage seeding
                # emits none. A seeded mint that pulls nothing is still an honest
                # ``inflow_observed: false`` (witnessed dilution); an unseeded mint is
                # unaffected by any of this.
                "input_seeded": used is not None,
                # See ``value_out``: a mint only reachable once the CONTRACT's own ETH
                # balance was overridden is a capability claim, not a live one.
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


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _run(
    simulate: Simulate,
    transcript: dict[str, Any],
    calls: list[SimCall],
    *,
    overrides: dict[str, Any] | None = None,
    label: str,
):
    """Issue one simulated block and record it. Returns ``None`` on a malformed
    response (fewer results than calls) so the caller fails closed."""
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
    """Run the seeded retries of a single-call probe until one EXECUTES.

    Returns the attempt and its result only when the read-back held AND the call
    succeeded; otherwise ``(None, None)`` and the caller keeps its unseeded
    verdict verbatim. Every discarded attempt records WHY."""
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
    """A short, replayable reason for one reverted attempt: the decoded error when
    the revert data decodes, else the raw selector, else ``empty_revert``."""
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
    """Seeded-retry form of the read → mint → read block. The two ``totalSupply``
    reads must bracket the seeded call in the SAME block, so the whole triple is
    re-run rather than splicing a seeded mint into the unseeded reads."""
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
    """Run the attacker-sentinel probe if one was supplied, returning its
    transfers of interest (or ``None`` when no sentinel probe ran). A sentinel
    that moves nothing returns ``[]`` — a non-observation the shape resolver
    treats as rule-8.1 ``unknown``, never "fixed".

    When the base probe only executed under a seed, the sentinel runs under the
    SAME seed: an unseeded sentinel would revert on the same precondition and its
    empty result would read as "the caller cannot redirect this", which is a
    conclusion the probe never actually tested."""
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
    """Three-valued destination shape. Returns
    ``(shape, proved_by, concrete_destination, discrepancy)``.

    Priority: a sentinel that LANDS proves ``caller_arbitrary`` (existential,
    simulation) → static's positive proof of a fixed shape (universal) → a
    discrepancy when taint said the param reaches the sink but the
    sentinel moved nothing → otherwise ``unknown`` (an observation of one
    destination can't prove "fixed").

    ``concrete_destination`` means one thing everywhere it is returned: an address
    value that was OBSERVED to receive the outflow (or, on the static branch, the
    fixed address static positively proved). It is deliberately computed from the
    BASE probe's transfers and never from the sentinel: the sentinel is an address
    this prober invented, so publishing it in the column that otherwise means
    "where the money went" would present a fabricated address as an observation.
    The caller_arbitrary PROOF loses nothing by that — it lives in
    ``destination_shape``/``shape_proved_by``, which is where a consumer reads
    "the caller chooses this destination"; the sentinel's own address adds no
    information (it is recomputable, and it is in the transcript).

    TWO INVENTED ADDRESSES, NOT ONE. The sentinel is not the only
    identity this prober invents: :data:`calldata.NEUTRAL_CALLER` is the caller a
    public/unresolved-principal probe runs as, it is substituted into every address
    ARGUMENT of the synthesized call, and it comes straight back out in the
    ``Transfer`` log. Measured: on 35 of 35 ``caller_arbitrary`` rows in the local DB
    the stored ``concrete_destination`` is a ``function_principals`` address of the
    same function echoed back; a stored ``NEUTRAL_CALLER`` has zero realised rows
    here (lower bound — it arises whenever a probe runs with no resolved principal,
    which the exclusion below is test-pinned against). Both invented identities are
    excluded here, and a ``caller_arbitrary`` shape publishes NO address at all: the shape
    IS the adverse finding, the address is by construction whatever WE passed, and
    a stored one can only mislead in the reassuring direction ("the money goes to
    the timelock, so this is fine").

    The exclusion is applied to the CONVERGENCE ANSWER, never to the destination set
    it is computed from: removing an invented recipient before counting destinations
    manufactures agreement out of a genuinely ambiguous outflow. See the comment on
    the capture itself.
    """
    # State-plane residue: the address value actually left to THIS run. Capture it
    # whenever every observed outflow converged on a single destination — a
    # withdrawal that emits several Transfer logs (burn + send, or send + fee to
    # the same address) still has one concrete destination. Divergent destinations
    # are genuinely ambiguous → withheld. This never proves the SHAPE (a single
    # observation can't prove "always this address").
    #
    # ORDER IS LOAD-BEARING: the convergence test runs over EVERY destination, and
    # only then is an invented identity refused. Filtering first turned an ambiguous
    # two-destination outflow into a "convergent" one and published the survivor:
    # `from=holder, to=NEUTRAL_CALLER` is the ordinary "paid msg.sender" leg of a
    # withdrawal, so dropping it and asserting the residual fee/treasury address as
    # "the address value actually left to" is exactly the reassuring-direction
    # mislead this filter exists to remove ("the money goes to the timelock, so this
    # is fine") — measured: 90% to the impersonated caller and a 10% fee to the
    # treasury published the treasury as THE destination. An invented recipient among
    # several destinations means the destination is NOT determined.
    out_destinations = {to for _f, to, _v in base_transfers}
    observed_dest = next(iter(out_destinations)) if len(out_destinations) == 1 else None
    if _is_invented_identity(observed_dest):
        observed_dest = None
    if sentinel_transfers is not None and sentinel_address is not None:
        landed = any(_addr_eq(to, sentinel_address) for _f, to, _v in sentinel_transfers)
        if landed:
            # PROVEN caller-arbitrary: the destination is whatever the caller says,
            # so this run's recipient is our own calldata read back, never an
            # observation about the contract. Withheld (the column has no
            # "probe_supplied" state, and NULL is the honest one of the two it has).
            return SHAPE_CALLER_ARBITRARY, "simulation", None, None
    # Evaluated BEFORE the static branch returns. Taint saying the param
    # reaches the sink while the sentinel moved nothing is a matcher/probe
    # soundness problem whatever static believes — and it is most interesting
    # precisely when static claims a fixed shape, because then the two planes
    # contradict each other. Returning early on the static branch filed no
    # discrepancy in exactly that case.
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
        # The SHAPE is static's to prove and it is a universal — "this destination
        # cannot be redirected" holds whether or not this particular probe moved
        # anything. The ADDRESS is the observation's to supply, and it is fine for
        # it to be absent: a probe that reverted still leaves the shape true and
        # ``concrete_destination`` simply unfilled.
        #
        # Requiring a static ADDRESS here is what made this branch dead code for
        # the stage's whole life: the static plane classifies destinations by KIND
        # and never resolves the value behind an immutable, so no caller could
        # ever satisfy the condition and ``destination_shape`` stayed ~95%
        # ``unknown`` — the single most security-relevant bit, unproven.
        return static_shape, "static", static_destination or observed_dest, disc
    # Taint says the param reaches the sink, yet the sentinel moved nothing: a
    # discrepancy (matcher/probe-soundness), NOT a "fixed" verdict.
    return SHAPE_UNKNOWN, "none", observed_dest, disc


def _add_reach(
    concrete: dict[str, Any],
    base_call: SimCallResult,
    value_holders: Sequence[AssetHolding],
    acting_balance_usd: float,
    protocol_tvl_usd: float | None = None,
) -> None:
    """Downstream value-reach. From the SAME fork execution of F, a value-holder
    from which value provably LEFT (a ``Transfer`` out in this call's logs) is a
    fork-OBSERVED reach; its full on-chain USD is attributed as reached (a
    conservative upper bound). Downstream value is NEVER imputed via the
    control-graph reference heuristic (``control_graph_edges`` carries no fund-flow
    edge). Skipped entirely when no value-holder set was supplied (nothing to
    measure), leaving the verdict shape unchanged.

    THREE STATES, and ``reach_determined`` is the one key that tells them apart:

    * ``reach_determined: True`` + ``observed_reach_value_usd`` +
      ``observed_reach_holders`` + ``observed_reach_assets`` — measured, and every
      asset that moved had a priced holding. The USD is an upper bound.
    * ``reach_determined: False`` + ``reach_indeterminate: True`` +
      ``observed_reach_floor_usd`` — NOTHING was witnessed leaving a holder, which is
      not the same as "reach is nothing": this branch fires for any zap / router /
      adapter that moves value it does not itself hold (18 armed ``flow.out``
      functions on 6 zero-balance contracts locally). It used to publish the acting
      deployment's own balance as ``observed_reach_value_usd``, so a consumer reading
      the number and ignoring the flag got **"$0 reach" for a function that may move
      millions** — a proven-absence sentence minted out of a non-observation. The
      floor is still recorded, under a name that says what it is, and the key that
      means "measured reach" is ABSENT.
    * ``reach_determined: False`` WITHOUT ``reach_indeterminate`` +
      ``observed_reach_holders`` / ``observed_reach_assets`` /
      ``observed_reach_unvalued_pairs`` — value WAS witnessed leaving a holder and
      its USD is not determined, because at least one (holder, asset) pair that moved
      has no priced holding on record. ``observed_reach_priced_usd`` carries the part
      that IS priced (a partial floor), with ``observed_reach_priced_holders`` naming
      whose holdings it came from; both are omitted when that part is nothing, and the
      figure is withheld when the TVL ceiling refuses it
      (``reach_tvl_check: exceeds_protocol_tvl`` + ``observed_reach_rejected_usd`` +
      ``protocol_tvl_usd`` then record the contradiction, exactly as on the measured
      branch). This is the unpriced-asset case: 1001 of 1376 local
      ``contract_balances`` rows are unpriced, and the recoverETH row moved native ETH
      out of a deployment with no native balance row at all — "holds nothing", "not
      fetched" and "fetch failed" are one shape there, so the only honest USD is
      *unknown*.
    * every key absent — no holder set was supplied, so nothing was even attempted.

    THE UNVALUED DISCLOSURE IS KEYED THE WAY THE ARITHMETIC IS — per (holder, asset).
    It used to be a set of ASSETS while the pricing loop ran per pair, so an asset
    priced for holder A and unrecorded for holder B was published as unvaluable
    *tout court* beside a concrete USD figure computed from A. On three PR-161 rows
    that produced a payload asserting both halves of a contradiction: verdict 198
    (``PriorityWithdrawalQueue.requestWithdrawWithWeETH``) named weETH as the ONLY
    asset that moved, named weETH as the ONLY asset that could not be valued, and
    published ``observed_reach_priced_usd: 8471736.29`` — every dollar of it the
    BoringVault holder's weETH row, a holder the disclosure never connected to the
    figure. Three keys keep the two facts apart now:

    * ``observed_reach_unvalued_pairs`` — the disclosure proper: one
      ``{holder, asset, reason}`` per pair whose USD is not known.
    * ``observed_reach_unvalued_assets`` — the assets NO holder priced (an asset that
      moved and contributed nothing to the figure). Published on this branch even when
      EMPTY, because on this branch it is computed: ``[]`` is the earned negative
      "every asset that moved was priced for at least one holder", and absence of the
      key means the branch never ran.
    * ``observed_reach_priced_holders`` — whose holdings the figure is made of,
      published beside every figure this branch publishes. It is deliberately absent
      on the measured branch, where ``reach_determined: True`` already says every
      holder in ``observed_reach_holders`` was priced.

    Writes to ``concrete``, NOT ``details``. Every value here is
    per-deployment — the holders are addresses and the USD is this protocol's
    balance sheet at this block — while ``details`` is the code-plane witness the
    behavioral cache stores and re-publishes to every OTHER deployment sharing the
    bytecode. Reach in ``details`` meant a second deployment's verdict named the
    first one's holders and USD as its own.

    ASSET-SCOPED MATCHING. ``transfers_out`` is asked per (holder, asset), where
    the asset is the ``Transfer`` log's EMITTER — the token contract, or
    ``NATIVE_ASSET_LOG_EMITTER`` for a native move (measured against the live node,
    see that constant). Asset-blind matching is what published $3.489B of reach for
    ``WeETH.recoverETH``: the contract-balance seed gave the proxy synthetic native
    ETH, ``traceTransfers`` emitted one synthetic ``Transfer`` out of it, and the
    holder's ENTIRE balance — 99.99% of it eETH — was attributed as reached. Two rows
    of that shape carried 64.96% of all published reach USD in the DB and both are
    truly $0.

    Note what is NOT done: this does not pass ``only_asset`` to a single whole-holder
    match — a synthetic native log has no token emitter, so that would have matched
    nothing and under-claimed 100%. The
    INPUT changed: holdings arrive per asset, native included, keyed on the emitter
    the node actually uses.

    ONE ADD PER (HOLDER, ASSET), never per LOG. The attributed figure is a whole
    recorded balance, so a second Transfer log of the same asset out of the same
    holder must contribute nothing: summing per log published a MULTIPLE of the
    balance in the field that documents itself as an upper bound."""
    if not value_holders:
        return
    priced_usd = 0.0
    priced_any = False
    # Both sides of the disclosure are accumulated per (holder, asset) — the key the
    # arithmetic uses. Publishing the unvalued side per ASSET is what let one asset be
    # named as the only thing that moved AND the only thing that could not be valued,
    # next to a figure made of a different holder's balance.
    unvalued_pairs: list[dict[str, str]] = []
    priced_holders: set[str] = set()
    priced_assets: set[str] = set()
    reach_holders: set[str] = set()
    reach_assets: set[str] = set()
    # (holder, asset) -> the priced holding, or None when we hold it unpriced. A
    # (holder, asset) pair MISSING from this map is the third case: value left that
    # holder in an asset we have no balance row for at all.
    known: dict[tuple[str, str], float | None] = {
        (h.holder.lower(), h.asset.lower()): h.usd_value for h in value_holders
    }
    # Uniform per holder (see ``AssetHolding.completeness``): what is KNOWN about an
    # asset absent from ``known`` for that holder. Two states, and neither is "the
    # list is whole" — the stored rows cannot prove that (``_holdings_completeness``),
    # so the reason an absent asset gets is "not in the holdings we recorded, which
    # are not provably all of them", never "this holder does not hold it".
    completeness: dict[str, str] = {h.holder.lower(): h.completeness for h in value_holders}
    # The (holder, asset) PAIRS value provably left, deduped BEFORE any USD is added.
    # Deduping is not tidiness: the figure attributed for a pair is the holder's WHOLE
    # recorded balance for that asset (the documented conservative upper bound), and a
    # single call legitimately emits several Transfer logs of the same asset out of the
    # same holder — the shape ``_resolve_destination_shape`` names one screen up, "a
    # withdrawal that emits several Transfer logs (burn + send, or send + fee to the
    # same address)". Adding once per LOG published a MULTIPLE of the entire balance
    # and called it an upper bound; two logs made a $100 holding read as $200 reach.
    moved: set[tuple[str, str]] = set()
    for holder in sorted({h.holder.lower() for h in value_holders}):
        for _frm, _to, _value, asset in transfers_out_with_asset(base_call, holder):
            moved.add((holder, asset))
    for holder, asset in sorted(moved):
        reach_holders.add(holder)
        reach_assets.add(asset)
        if (holder, asset) not in known:
            # No balance row at all for this (holder, asset): value left in an asset
            # we never recorded. Absence there conflates "holds nothing", "not
            # fetched" and "fetch failed", so it is not a zero. The reason names which
            # of the two things we know, and neither is "the holder does not hold it":
            # ``holdings_at_page_cap`` when the holder's stored rows reach the
            # fetcher's one-page cap (assets are probably missing), otherwise
            # ``asset_not_in_recorded_holdings`` — recorded, not proven-complete.
            reason = _UNVALUED_REASON_BY_COMPLETENESS[completeness.get(holder, HOLDINGS_NOT_DETERMINED)]
            unvalued_pairs.append({"holder": holder, "asset": asset, "reason": reason})
            continue
        usd = known[(holder, asset)]
        if usd is None:
            # Held, but unpriced. Per PAIR: this says nothing about another holder's
            # holding of the same asset, and it never did — the old asset-keyed set
            # said it anyway.
            unvalued_pairs.append({"holder": holder, "asset": asset, "reason": "unpriced_holding"})
        else:
            priced_usd += usd
            priced_any = True
            priced_holders.add(holder)
            priced_assets.add(asset)
    if not reach_holders:
        concrete["reach_determined"] = False
        concrete["reach_indeterminate"] = True
        concrete["observed_reach_floor_usd"] = acting_balance_usd
        return
    concrete["observed_reach_holders"] = sorted(reach_holders)
    concrete["observed_reach_assets"] = sorted(reach_assets)
    if unvalued_pairs:
        # Witnessed, and NOT valued. The priced part is a floor, never the answer.
        concrete["reach_determined"] = False
        # Sorted by (holder, asset) already: the loop above walks ``sorted(moved)``.
        concrete["observed_reach_unvalued_pairs"] = unvalued_pairs
        # The assets NO holder priced. An asset that IS priced for some holder is not
        # one of them, however many other holders moved it unvalued — that is the whole
        # correction, and ``[]`` here is the earned negative, not a missing answer.
        concrete["observed_reach_unvalued_assets"] = sorted({p["asset"] for p in unvalued_pairs} - priced_assets)
        concrete["observed_reach_unvalued_reasons"] = sorted({p["reason"] for p in unvalued_pairs})
        if priced_any:
            # WHOSE holdings the figure is. Published beside the figure on both arms
            # below — a refused figure is still a figure, and the contradiction the
            # ceiling records is only inspectable if its subjects are named.
            concrete["observed_reach_priced_holders"] = sorted(priced_holders)
            # The CEILING applies to the partial floor too. It used to guard only
            # the branch below, so a floor ABOVE the protocol's own measured TVL was
            # publishable with no ``reach_tvl_check`` at all — the same contradiction on
            # the sibling key, and worse on this branch than on a measured total: the
            # floor is a LOWER bound over a subset of the assets that moved, so a floor
            # above the ceiling cannot be explained by the upper bound being loose.
            # Refused the same way (recorded, never clamped) and the unvalued-asset
            # disclosure stands either way — the two facts are independent.
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
        # ``priced_any`` False publishes NO ``reach_tvl_check``: there is no figure for a
        # ceiling to bear on, and ``within_protocol_tvl`` over an absent number would
        # read as a check that passed. Absence of the key here means "no figure", which
        # is exactly what the absent ``observed_reach_priced_usd`` beside it says.
        return
    # CORROBORATING CEILING: no exercise of one function can reach more value than the
    # protocol holds. The worst published row asserted $3.489B against a protocol TVL
    # of $3.297B, and nothing checked. A sum above the ceiling is not clamped (a clamp
    # would invent a number nothing measured) — it is refused, with both figures
    # recorded so the contradiction is inspectable.
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


# The three answers of the reach-vs-TVL ceiling. ``skipped_no_tvl`` is published, not
# implied: an absent ceiling must be visible as "not checked" rather than looking like
# a check that passed — a gate that silently never fires is not a mitigation.
# Why an asset that moved could not be valued, keyed on what is KNOWN about the
# holder's holdings list. Neither reason asserts the holder does not hold the asset:
# ``asset_not_in_recorded_holdings`` says only that our recorded set does not contain
# it and that set is not provably complete (the stored rows already dropped every
# zero-balance entry, so a below-cap count proves nothing — ``selection
# ._holdings_completeness``). The previous name, ``unrecorded_asset``, read as a
# proven absence and was derived from exactly that lossy count.
_UNVALUED_REASON_BY_COMPLETENESS = {
    HOLDINGS_COMPLETENESS_AT_PAGE_CAP: "holdings_at_page_cap",
    HOLDINGS_NOT_DETERMINED: "asset_not_in_recorded_holdings",
}

REACH_TVL_WITHIN = "within_protocol_tvl"
REACH_TVL_EXCEEDED = "exceeds_protocol_tvl"
REACH_TVL_SKIPPED = "skipped_no_tvl"


def _reach_tvl_state(reached_usd: float, protocol_tvl_usd: float | None) -> tuple[str, str | None]:
    """``(state, log_note)`` for the reach-vs-TVL ceiling.

    Reads ONLY a caller-supplied ``defillama_tvl`` figure (see
    ``selection._protocol_tvl_usd``): ``tvl_snapshots.total_usd`` and
    ``contract_breakdown`` are NULL on every local row, so a ceiling written against
    them could never fire.
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
    """``after - before`` read as the uint256 word it actually is.

    ``totalSupply`` is a uint256 and the ubiquitous ``_burn`` idiom decrements it
    inside ``unchecked``. Python subtracts arbitrary-precision integers, so a burn
    that wrapped past zero on-chain comes back here as a delta of nearly ``2^256``
    — a positive number, i.e. a MINT, on a call that destroyed units. Reading the
    difference modulo ``2^256`` and taking the short way round restores the sign
    the EVM computed.

    The halfway split is sound because both readings cannot be plausible at once:
    a supply that genuinely moved by more than ``2^255`` units has overflowed any
    real token's economics, and the burn reading is the only one that corresponds
    to code that can execute."""
    raw = (after - before) % _UINT256_MOD
    return raw - _UINT256_MOD if raw > _UINT256_MOD // 2 else raw


def _sign_contradicted_by_events(
    sign: str, minted: list[tuple[str, str, str]], burned: list[tuple[str, str, str]]
) -> bool:
    """True when the zero-address ``Transfer`` logs say the OPPOSITE of what the
    ``totalSupply`` arithmetic said.

    A mint is ``Transfer(0x0 -> holder)`` and a burn is ``Transfer(holder -> 0x0)``,
    both emitted by the token whose supply moved. When the events present are
    exclusively the other direction's, one of the two witnesses is wrong and this
    stage must publish neither — least of all the "witnessed dilution" output,
    which asserts that units were printed against no inflow.

    Deliberately requires POSITIVE contradicting evidence rather than mere absence:
    a token that mints without emitting anything is unhelpful but not lying, and
    treating its silence as a contradiction would withhold every honest verdict on
    it. Absence of evidence is not evidence of absence — here as everywhere."""
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


# The identities this prober INVENTS and substitutes into the calls it synthesizes.
# Neither is ever a fact about the contract, so neither may be published as an
# observed destination: ``SENTINEL_ADDRESS`` is the attacker stand-in planted at a
# taint-identified address parameter, and ``NEUTRAL_CALLER`` is both the caller a
# public / unresolved-principal probe runs as AND the filler for every address
# argument of the synthesized call — so it arrives back in the ``Transfer`` log as
# the "destination" of our own making.
_INVENTED_IDENTITIES = (SENTINEL_ADDRESS, NEUTRAL_CALLER)


def _is_invented_identity(address: str | None) -> bool:
    return any(_addr_eq(address, invented) for invented in _INVENTED_IDENTITIES)


def _addr_eq(a: str | None, b: str | None) -> bool:
    """Compare a 32-byte-padded slot value or a raw address against an address."""
    if a is None or b is None:
        return False
    aa = a[2:] if a.startswith("0x") else a
    bb = b[2:] if b.startswith("0x") else b
    return aa.lstrip("0").lower() == bb.lstrip("0").lower()
