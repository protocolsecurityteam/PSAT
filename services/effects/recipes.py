"""Tier-1 effect recipes (EFFECTS_RESOLUTION_SPEC §4.2–§4.5).

Each recipe is a PURE decision over injected seams (``Simulate`` / ``CallBatch``
+ the transcript store) that returns a tiered, transcripted
:class:`~services.effects.harness.ObservedEffect`. Names never enter a definition
(inv. 1); every positive verdict is an OBSERVED transition, every non-observation
is fail-closed ``unknown`` (§8). The Tier-2 pause recipe (§4.1) lives in
``services.effects.anvil`` because it needs the fork transport.

Boundary: recipes RETURN verdicts and RECORD §9 discrepancies on them; they do
not persist to the DB and do not route discrepancies anywhere (Phase 3).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from services.effects.config import (
    EFFECT_CLASS_AUTHORITY_CHANGE,
    EFFECT_CLASS_CODE_UPGRADE,
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
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
from services.effects.simulate import SimCall, SimCallResult, Simulate, transfers_in, transfers_out
from utils.rpc import EthCallResult

# EIP-1967 implementation slot. keccak("eip1967.proxy.implementation") - 1.
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
# ERC-20 totalSupply().
TOTAL_SUPPLY_SELECTOR = "0x18160ddd"

# Destination-shape vocabulary (§4.2). Only ``immutable_fixed`` is benign; only
# static can positively PROVE the two fixed shapes (universals); simulation can
# only PROVE ``caller_arbitrary`` (an existential, via a sentinel that lands).
SHAPE_CALLER_ARBITRARY = "caller_arbitrary"
SHAPE_STORAGE_DETERMINED = "storage_determined"
SHAPE_IMMUTABLE_FIXED = "immutable_fixed"
SHAPE_UNKNOWN = "unknown"


def _sim_to_ethcall(r: SimCallResult) -> EthCallResult:
    """Adapt a simulate call result to the ``EthCallResult`` the raw-revert
    authorization discipline (§8.2/§8.3) consumes."""
    return EthCallResult(r.success, r.return_data, r.revert_data, None)


def transparent_sentinel_override(sentinel_address: str) -> dict[str, dict[str, Any]]:
    """State override placing plain nonzero code at the sentinel so a transparent
    proxy's ``_setImplementation`` code check passes (§4.3). A single ``STOP``
    (extcodesize=1) is enough — a bare address with no code would revert the
    upgrade and prove nothing."""
    return {sentinel_address.lower(): {"code": "0x00"}}


def uups_sentinel_override(sentinel_address: str, impl_slot: str = EIP1967_IMPL_SLOT) -> dict[str, dict[str, Any]]:
    """State override placing an ERC-1822 stub at the sentinel whose
    ``proxiableUUID()`` returns the canonical impl slot, so a UUPS
    ``upgradeToAndCall`` (which delegatecalls the new impl to validate it) accepts
    it (§4.3). The stub returns ``impl_slot`` for ANY call — a minimal
    ``PUSH32 slot; PUSH0; MSTORE; PUSH1 32; PUSH0; RETURN``."""
    slot = impl_slot[2:] if impl_slot.startswith("0x") else impl_slot
    slot = slot.rjust(64, "0")
    code = "0x7f" + slot + "5f52" + "6020" + "5f" + "f3"
    return {sentinel_address.lower(): {"code": code}}


# ---------------------------------------------------------------------------
# §4.2 — value-out (+ three-valued destination shape)
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
    gate_ref: str = "",
) -> ObservedEffect:
    """Does calling F move value out, and to what kind of destination? (§4.2)

    Tier 1 needs ``eth_simulateV1`` (balance + ``Transfer``-event diffs); where
    unsupported the class declares its Tier-2 fallback explicitly (inv. 14),
    never a silent degrade. The value-MOVED fact is the sim's; the fixed shapes
    are static UNIVERSALS; only ``caller_arbitrary`` is proven by simulation via
    a sentinel that lands — a sentinel that moves nothing proves nothing
    (rule 8.1) and, when taint said the param reaches the sink, is a §9
    discrepancy (recorded, not routed)."""
    tr = new_transcript(ctx, feature="value_out", tier=TIER_CALL, effect_class=EFFECT_CLASS_VALUE_OUT)
    if not simulate_supported:
        tr["fallback"] = "tier2"
        return emit(
            store,
            unknown(
                EFFECT_CLASS_VALUE_OUT,
                gate_ref=gate_ref,
                reason="simulate_unsupported_tier2_fallback",
                details={"fallback": "tier2"},
                transcript=tr,
            ),
        )

    base_call = SimCall(to=contract_address, data=calldata, from_addr=principal)
    base_res = _run(simulate, tr, [base_call], label="value_probe")
    if base_res is None:
        return emit(store, _sim_precondition_unknown(EFFECT_CLASS_VALUE_OUT, gate_ref, tr))
    moved = transfers_out(base_res.calls[0], contract_address)
    value_moved = bool(moved)

    sentinel_transfers = _run_sentinel(simulate, tr, contract_address, principal, sentinel_calldata, sentinel_address)
    shape, proved_by, concrete_dest, disc = _resolve_destination_shape(
        effect_class=EFFECT_CLASS_VALUE_OUT,
        base_transfers=moved,
        sentinel_address=sentinel_address,
        sentinel_transfers=sentinel_transfers,
        taint_param_reaches_sink=taint_param_reaches_sink,
        static_shape=static_shape,
        static_destination=static_destination,
    )
    details: dict[str, Any] = {
        "value_moved": value_moved,
        "destination_shape": shape,
        "shape_proved_by": proved_by,
    }
    concrete: dict[str, Any] = {}
    if concrete_dest is not None:
        concrete["destination"] = concrete_dest
    if not value_moved and shape != SHAPE_CALLER_ARBITRARY:
        return emit(
            store,
            unknown(
                EFFECT_CLASS_VALUE_OUT,
                gate_ref=gate_ref,
                reason="no_value_observed",
                details=details,
                transcript=tr,
                discrepancy=disc,
            ),
        )
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
# §4.3 — code-upgrade
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
    """Can calling F change the executing code? (§4.3)

    Tier 0 FIRST — an indexed upgrade proves PAST capability only *in
    conjunction* with a current-state check (inv. 13): indexed + current-impl
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
                    details={"historical": True, "current_capability": True},
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
                details={"historical": True, "current_capability": None},
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
                details={"sentinel_override": False},
                transcript=tr,
            ),
        )
    call = SimCall(to=proxy_address, data=upgrade_calldata, from_addr=principal)
    res = _run(simulate, tr, [call], overrides={sentinel_address.lower(): sentinel_override}, label="upgrade_probe")
    if res is None:
        return emit(store, _sim_precondition_unknown(EFFECT_CLASS_CODE_UPGRADE, gate_ref, tr))
    impl_after = res.storage.get(proxy_address.lower(), {}).get(impl_slot.lower()) or res.storage.get(
        proxy_address.lower(), {}
    ).get(impl_slot)
    tr["impl_after"] = impl_after
    if impl_after is not None and _addr_eq(impl_after, sentinel_address):
        return emit(
            store,
            proven(
                EFFECT_CLASS_CODE_UPGRADE,
                gate_ref=gate_ref,
                reason="impl_slot_changed_to_sentinel",
                details={"upgradeable": True},
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
            details={"upgradeable": None},
            transcript=tr,
        ),
    )


# ---------------------------------------------------------------------------
# §4.4 — authority-change kernel (function-local gate mutation)
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
    """Does calling F change WHO can call some gate G? (§4.4, kernel only)

    One simulated block carries state across calls: probe G as ≥2 random
    identities → call F as principal (e.g. grantRole) → re-probe G as the same
    randoms. Opened iff the randoms were consistently rejected before and ALL
    succeed after (§8.2, raw-revert compared per §8.3); a single-identity flip or
    an ambiguous outcome never opens (fail-closed). The whole-contract
    authorization DELTA is a projection (Phase 3, whole-contract identity) — this
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
                details={"identities": len(rlist)},
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
        # proven absence of effect (§8.4).
        return emit(
            store,
            unknown(
                EFFECT_CLASS_AUTHORITY_CHANGE,
                gate_ref=gate_ref,
                reason="mutation_call_reverted",
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
                details={"gate_mutation": True},
                transcript=tr,
            ),
        )
    return emit(
        store,
        unknown(
            EFFECT_CLASS_AUTHORITY_CHANGE,
            gate_ref=gate_ref,
            reason="no_authorization_delta_observed",
            transcript=tr,
        ),
    )


# ---------------------------------------------------------------------------
# §4.5 — supply (mint / burn)
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
) -> ObservedEffect:
    """Does calling F change ``totalSupply``? (§4.5)

    Tier 1 via ``eth_simulateV1`` (read → call → read in one context): a signed
    delta is the label (up = mint, down = burn); a zero delta is a
    non-observation (``unknown``). Destination shape follows §4.2 — sentinel
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
                details={"fallback": "tier2"},
                transcript=tr,
            ),
        )
    read = SimCall(to=token_address, data=TOTAL_SUPPLY_SELECTOR)
    mint = SimCall(to=token_address, data=mint_calldata, from_addr=principal)
    res = _run(simulate, tr, [read, mint, read], label="supply_delta")
    if res is None or len(res.calls) != 3:
        return emit(store, _sim_precondition_unknown(EFFECT_CLASS_SUPPLY, gate_ref, tr))
    before_c, mint_c, after_c = res.calls
    if not (before_c.success and after_c.success):
        return emit(
            store,
            unknown(EFFECT_CLASS_SUPPLY, gate_ref=gate_ref, reason="total_supply_read_failed", transcript=tr),
        )
    if not mint_c.success:
        return emit(
            store,
            unknown(EFFECT_CLASS_SUPPLY, gate_ref=gate_ref, reason="mint_call_reverted", transcript=tr),
        )
    before_ts = _to_int(before_c.return_data)
    after_ts = _to_int(after_c.return_data)
    if before_ts is None or after_ts is None:
        return emit(
            store,
            unknown(EFFECT_CLASS_SUPPLY, gate_ref=gate_ref, reason="total_supply_undecodable", transcript=tr),
        )
    delta = after_ts - before_ts
    if delta == 0:
        return emit(
            store,
            unknown(EFFECT_CLASS_SUPPLY, gate_ref=gate_ref, reason="no_supply_delta", transcript=tr),
        )
    sign = "mint" if delta > 0 else "burn"
    minted = transfers_out(mint_c, "0x" + "00" * 20)  # mint = Transfer from the zero address
    _, _, _, disc = _resolve_destination_shape(
        effect_class=EFFECT_CLASS_SUPPLY,
        base_transfers=minted,
        sentinel_address=sentinel_address,
        sentinel_transfers=_run_sentinel(
            simulate, tr, token_address, principal, sentinel_calldata, sentinel_address, mint_from_zero=True
        ),
        taint_param_reaches_sink=taint_param_reaches_sink,
        static_shape=static_shape,
        static_destination=static_destination,
    )
    details: dict[str, Any] = {"supply_delta_sign": sign}
    if sign == "mint":
        # §5a backing: an asset Transfer INTO the vault during the SAME simulated
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
        inflow = transfers_in(mint_c, token_address)
        details["backing"] = {
            "inflow_observed": bool(inflow),
            "minted": bool(minted),
            "inflow_transfers": len(inflow),
            "mint_transfers": len(minted),
        }
    eff = proven(
        EFFECT_CLASS_SUPPLY,
        gate_ref=gate_ref,
        reason=f"supply_{sign}",
        details=details,
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


def _run_sentinel(
    simulate: Simulate,
    transcript: dict[str, Any],
    source_address: str,
    principal: str | None,
    sentinel_calldata: str | None,
    sentinel_address: str | None,
    *,
    mint_from_zero: bool = False,
) -> list[tuple[str, str, str]] | None:
    """Run the attacker-sentinel probe if one was supplied, returning its
    transfers of interest (or ``None`` when no sentinel probe ran). A sentinel
    that moves nothing returns ``[]`` — a non-observation the shape resolver
    treats as rule-8.1 ``unknown``, never "fixed"."""
    if not sentinel_calldata or not sentinel_address:
        return None
    call = SimCall(to=source_address, data=sentinel_calldata, from_addr=principal)
    res = _run(simulate, transcript, [call], label="sentinel_probe")
    if res is None:
        return None
    src = "0x" + "00" * 20 if mint_from_zero else source_address
    return transfers_out(res.calls[0], src)


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
    """Three-valued destination shape (§4.2). Returns
    ``(shape, proved_by, concrete_destination, discrepancy)``.

    Priority: a sentinel that LANDS proves ``caller_arbitrary`` (existential,
    simulation) → static's positive proof of a fixed shape (universal) → the
    rule-8.1 discrepancy when taint said the param reaches the sink but the
    sentinel moved nothing → otherwise ``unknown`` (an observation of one
    destination can't prove "fixed" — §8 rule 1)."""
    if sentinel_transfers is not None and sentinel_address is not None:
        landed = any(_addr_eq(to, sentinel_address) for _f, to, _v in sentinel_transfers)
        if landed:
            return SHAPE_CALLER_ARBITRARY, "simulation", None, None
    if static_shape in (SHAPE_IMMUTABLE_FIXED, SHAPE_STORAGE_DETERMINED) and static_destination:
        return static_shape, "static", static_destination, None
    if taint_param_reaches_sink and sentinel_transfers is not None:
        # Taint says the param reaches the sink, yet the sentinel moved nothing:
        # a §9 discrepancy (matcher/probe-soundness), NOT a "fixed" verdict.
        disc = Discrepancy(
            kind="taint_param_sentinel_negative",
            effect_class=effect_class,
            detail={"sentinel_address": sentinel_address},
        )
        return SHAPE_UNKNOWN, "none", None, disc
    observed_dest = base_transfers[0][1] if len(base_transfers) == 1 else None
    return SHAPE_UNKNOWN, "none", observed_dest, None


def _sim_precondition_unknown(effect_class: str, gate_ref: str, transcript: dict[str, Any]) -> ObservedEffect:
    return unknown(
        effect_class,
        gate_ref=gate_ref,
        reason="malformed_simulation_response",
        transcript=transcript,
    )


def _to_int(hexval: str | None) -> int | None:
    if not hexval or not isinstance(hexval, str):
        return None
    try:
        return int(hexval, 16)
    except ValueError:
        return None


def _addr_eq(a: str | None, b: str | None) -> bool:
    """Compare a 32-byte-padded slot value or a raw address against an address."""
    if a is None or b is None:
        return False
    aa = a[2:] if a.startswith("0x") else a
    bb = b[2:] if b.startswith("0x") else b
    return aa.lstrip("0").lower() == bb.lstrip("0").lower()
