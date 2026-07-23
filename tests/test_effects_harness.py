"""Tier-1 effect harness tests (EFFECTS_RESOLUTION_SPEC §4.2–§4.5, §8).

Every recipe is exercised against a stubbed ``Simulate`` wire with recorded
transcripts — no live RPC (inv. 8 / §8.6). The §8 soundness rules each carry an
explicit NEGATIVE fail-closed test; the mapping is in ``test_section8_*`` below.
"""

from __future__ import annotations

from collections.abc import Sequence

from services.effects import recipes
from services.effects.config import (
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    TIER_CALL,
    TIER_HISTORICAL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.harness import (
    SimContext,
    authorization_opened,
    same_gate,
    select_identities,
)
from services.effects.preflight import (
    InMemoryCapabilityStore,
    probe_simulate_support,
    require_simulate_or_fallback,
)
from services.effects.simulate import (
    TRANSFER_TOPIC,
    SimCall,
    SimCallResult,
    SimLog,
    SimResult,
    SimulateUnsupportedError,
    transfers_out,
)
from utils.rpc import EthCallResult

CONTRACT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20
SENTINEL = "0x" + "ee" * 20
TOKEN = "0x" + "33" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")

_REVERT_A = "0x08c379a0" + "00" * 4
_REVERT_B = "0x" + "deadbeef"


# --- stubs ------------------------------------------------------------------


class ScriptedSimulate:
    """Returns pre-programmed ``SimResult``s in order; records every block."""

    def __init__(self, *results: SimResult) -> None:
        self._results = list(results)
        self.blocks: list[tuple[Sequence[SimCall], str, dict | None]] = []
        self._i = 0

    def __call__(self, calls, block_tag, overrides):
        self.blocks.append((list(calls), block_tag, overrides))
        res = self._results[self._i]
        self._i += 1
        return res


class RecordingStore:
    """Injected transcript store: records each dict, hands back a fake key."""

    def __init__(self) -> None:
        self.stored: list[dict] = []

    def __call__(self, transcript: dict) -> str:
        self.stored.append(transcript)
        return f"artifact://transcript/{len(self.stored)}"


def transfer_log(token: str, frm: str, to: str, value: int) -> SimLog:
    return SimLog(
        address=token.lower(),
        topics=(TRANSFER_TOPIC, _addr_topic(frm), _addr_topic(to)),
        data="0x" + value.to_bytes(32, "big").hex(),
    )


def _addr_topic(addr: str) -> str:
    return "0x" + addr[2:].rjust(64, "0").lower()


def ok(ret: str = "0x", logs=()) -> SimCallResult:
    return SimCallResult(True, ret, None, tuple(logs))


def rv(data: str = _REVERT_A) -> SimCallResult:
    return SimCallResult(False, "0x", data, ())


def uint_ret(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


# ---------------------------------------------------------------------------
# transfers_out — raw-log extraction, no name inference
# ---------------------------------------------------------------------------


def test_transfers_out_extracts_only_source_sends():
    call = ok(logs=[transfer_log(TOKEN, CONTRACT, SENTINEL, 5), transfer_log(TOKEN, PRINCIPAL, CONTRACT, 9)])
    out = transfers_out(call, CONTRACT)
    assert len(out) == 1
    assert out[0][0] == CONTRACT.lower()
    assert out[0][1] == SENTINEL.lower()


# ---------------------------------------------------------------------------
# preflight (inv. 14)
# ---------------------------------------------------------------------------


def test_preflight_probes_and_persists_support():
    store = InMemoryCapabilityStore()
    sim = ScriptedSimulate(SimResult(calls=(ok(),)))
    assert probe_simulate_support(sim, 1, store) is True
    assert store.get_simulate_support(1) is True
    # Cached — no second probe.
    assert probe_simulate_support(sim, 1, store) is True
    assert len(sim.blocks) == 1


def test_preflight_records_unsupported_and_routes_to_fallback():
    class Unsupported:
        def __call__(self, *_a):
            raise SimulateUnsupportedError("method not found")

    store = InMemoryCapabilityStore()
    assert probe_simulate_support(Unsupported(), 8453, store) is False
    assert require_simulate_or_fallback(store, 8453) is False
    # Unprobed chain is fail-closed (never assumed supported).
    assert require_simulate_or_fallback(store, 999) is False


# ---------------------------------------------------------------------------
# §4.2 value-out — recorded-transcript recipe test
# ---------------------------------------------------------------------------


def test_value_out_caller_arbitrary_proven_via_sentinel():
    base = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, "0x" + "ab" * 20, 3)]),))
    sentinel = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, SENTINEL, 3)]),))
    sim = ScriptedSimulate(base, sentinel)
    store = RecordingStore()
    eff = recipes.value_out(
        simulate=sim,
        store=store,
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xdeadbeef",
        simulate_supported=True,
        taint_param_reaches_sink=True,
        sentinel_address=SENTINEL,
        sentinel_calldata="0xdeadbeef" + "ee" * 32,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["destination_shape"] == recipes.SHAPE_CALLER_ARBITRARY
    assert eff.details["shape_proved_by"] == "simulation"
    assert eff.discrepancy is None
    assert eff.transcript_ptr is not None


def test_value_out_static_fixed_shape_from_static_plane():
    base = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, "0x" + "cd" * 20, 7)]),))
    sim = ScriptedSimulate(base)
    eff = recipes.value_out(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xabcd0001",
        simulate_supported=True,
        static_shape=recipes.SHAPE_IMMUTABLE_FIXED,
        static_destination="0x" + "cd" * 20,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["destination_shape"] == recipes.SHAPE_IMMUTABLE_FIXED
    assert eff.details["shape_proved_by"] == "static"
    assert eff.concrete["destination"] == "0x" + "cd" * 20


# ---------------------------------------------------------------------------
# §4.3 code-upgrade — recorded-transcript recipe test
# ---------------------------------------------------------------------------


def test_code_upgrade_tier1_sentinel_slot_changed_proven():
    slot = recipes.EIP1967_IMPL_SLOT
    post = SimResult(calls=(ok(),), storage={CONTRACT.lower(): {slot: _addr_topic(SENTINEL)}})
    sim = ScriptedSimulate(post)
    eff = recipes.code_upgrade(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x3659cfe6" + "ee" * 32,
        sentinel_address=SENTINEL,
        sentinel_override=recipes.uups_sentinel_override(SENTINEL),
        impl_before=_addr_topic("0x" + "01" * 20),
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.tier == TIER_CALL
    assert eff.details["upgradeable"] is True


def test_code_upgrade_tier0_indexed_plus_current_state_proven():
    eff = recipes.code_upgrade(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x",
        sentinel_address=SENTINEL,
        sentinel_override=None,
        impl_before=None,
        indexed_upgrade=True,
        current_impl_nonzero=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.tier == TIER_HISTORICAL
    assert eff.concrete["current_check_passed"] is True


# ---------------------------------------------------------------------------
# §4.4 authority-change kernel — recorded-transcript recipe test
# ---------------------------------------------------------------------------


def test_authority_change_kernel_gate_opened_proven():
    randoms, _ = select_identities("0x2f2ff15d", CONTRACT, principal=PRINCIPAL)
    # before: both randoms rejected at the SAME gate; mutate succeeds; after: both open.
    res = SimResult(calls=(rv(), rv(), ok(), ok(uint_ret(1)), ok(uint_ret(1))))
    sim = ScriptedSimulate(res)
    eff = recipes.authority_change(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        mutate_calldata="0x2f2ff15d" + "00" * 64,
        probe_calldata="0xaabbccdd",
        randoms=randoms,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.scope == SCOPE_KERNEL
    assert eff.details["gate_mutation"] is True


# ---------------------------------------------------------------------------
# §4.5 supply — recorded-transcript recipe test
# ---------------------------------------------------------------------------


def test_supply_mint_delta_sign_proven():
    zero = "0x" + "00" * 20
    res = SimResult(
        calls=(
            ok(uint_ret(1000)),
            ok(logs=[transfer_log(TOKEN, zero, PRINCIPAL, 500)]),
            ok(uint_ret(1500)),
        )
    )
    # supply() also runs a sentinel probe (returns nothing → no sentinel given here).
    sim = ScriptedSimulate(res)
    eff = recipes.supply(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"


# ===========================================================================
# §8 soundness rules — one NEGATIVE fail-closed test per rule
# ===========================================================================


def test_section8_rule1_existential_only_nonobservation_is_unknown():
    # No transfer observed + no sentinel → unknown, never proven-absent.
    sim = ScriptedSimulate(SimResult(calls=(ok(),)))
    eff = recipes.value_out(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "no_value_observed"


def test_section8_rule1b_supply_zero_delta_is_unknown():
    res = SimResult(calls=(ok(uint_ret(42)), ok(), ok(uint_ret(42))))
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "no_supply_delta"


def test_section8_rule2_single_identity_never_opens():
    # authorization_opened requires ≥2 identities on BOTH sides.
    opened = authorization_opened(
        [EthCallResult(False, "0x", _REVERT_A, None)], [EthCallResult(True, "0x", None, None)]
    )
    assert opened is False
    # And the recipe rejects a <2 random set outright.
    eff = recipes.authority_change(
        simulate=ScriptedSimulate(SimResult(calls=(ok(),))),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        mutate_calldata="0x2f2ff15d",
        probe_calldata="0xaabbccdd",
        randoms=[SENTINEL],
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "insufficient_identities"


def test_section8_rule2b_indeterminate_after_split_never_opens():
    before = [EthCallResult(False, "0x", _REVERT_A, None), EthCallResult(False, "0x", _REVERT_A, None)]
    after_split = [EthCallResult(True, "0x", None, None), EthCallResult(False, "0x", _REVERT_A, None)]
    assert authorization_opened(before, after_split) is False


def test_section8_rule3_raw_revert_compare_same_gate():
    a = EthCallResult(False, "0x", _REVERT_A, None)
    b = EthCallResult(False, "0x", _REVERT_A, None)
    c = EthCallResult(False, "0x", _REVERT_B, None)
    assert same_gate(a, b) is True
    assert same_gate(a, c) is False
    # A node error (no revert data) is never "same".
    assert same_gate(a, EthCallResult(False, "0x", None, "oog")) is False


def test_section8_rule4_precondition_revert_is_unknown():
    # authority-change: principal cannot even execute F → precondition, not absence.
    randoms, _ = select_identities("0x2f2ff15d", CONTRACT, principal=PRINCIPAL)
    res = SimResult(calls=(rv(), rv(), rv(), rv(), rv()))  # mutate (index 2) reverts
    eff = recipes.authority_change(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        mutate_calldata="0x2f2ff15d",
        probe_calldata="0xaabbccdd",
        randoms=randoms,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "mutation_call_reverted"


def test_section8_rule4b_supply_mint_revert_is_unknown():
    res = SimResult(calls=(ok(uint_ret(10)), rv(), ok(uint_ret(10))))
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "mint_call_reverted"


def test_section8_rule5_every_verdict_is_tiered_and_replayable():
    store = RecordingStore()
    res = SimResult(
        calls=(ok(uint_ret(1)), ok(logs=[transfer_log(TOKEN, "0x" + "00" * 20, PRINCIPAL, 1)]), ok(uint_ret(2)))
    )
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=store,
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19",
        simulate_supported=True,
    )
    assert eff.tier == TIER_CALL
    assert eff.transcript_ptr is not None
    tr = store.stored[-1]
    for key in ("tier", "block_number", "hardfork", "calls", "results"):
        assert key in tr


def test_section8_rule6_pure_given_injected_simulate():
    # No wire is touched: a stub with zero real I/O produces a full verdict.
    sim = ScriptedSimulate(SimResult(calls=(ok(),)))
    eff = recipes.value_out(
        simulate=sim,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x00000000",
        simulate_supported=True,
    )
    assert eff.effect_class == EFFECT_CLASS_VALUE_OUT


def test_section8_rule14_simulate_unsupported_declares_tier2_fallback():
    # An unsupported chain never silently degrades — the verdict states the fallback.
    value = recipes.value_out(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x00000000",
        simulate_supported=False,
    )
    supply = recipes.supply(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19",
        simulate_supported=False,
    )
    for eff, klass in ((value, EFFECT_CLASS_VALUE_OUT), (supply, EFFECT_CLASS_SUPPLY)):
        assert eff.verdict == VERDICT_UNKNOWN
        assert eff.details["fallback"] == "tier2"
        assert eff.effect_class == klass


# --- sentinel-specific fail-closed cases -----------------------------------


def test_registry_param_sentinel_negative_is_unknown_not_fixed():
    # taint says the addr param reaches the sink, but the sentinel (an index into
    # registry[param], not the raw address) moves nothing → unknown + §9 discrepancy.
    base = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, "0x" + "77" * 20, 4)]),))
    sentinel = SimResult(calls=(ok(),))  # sentinel probe moves nothing
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base, sentinel),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xabcdef01",
        simulate_supported=True,
        taint_param_reaches_sink=True,
        sentinel_address=SENTINEL,
        sentinel_calldata="0xabcdef01" + "ee" * 32,
    )
    assert eff.details["destination_shape"] == recipes.SHAPE_UNKNOWN
    assert eff.details["shape_proved_by"] == "none"
    assert eff.discrepancy is not None
    assert eff.discrepancy.kind == "taint_param_sentinel_negative"


def test_bare_sentinel_reverts_proves_nothing():
    # No code override at the sentinel → the upgrade reverts, proving nothing.
    eff = recipes.code_upgrade(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x3659cfe6",
        sentinel_address=SENTINEL,
        sentinel_override=None,
        impl_before=_addr_topic("0x" + "01" * 20),
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "bare_sentinel_proves_nothing"


def test_code_upgrade_slot_unchanged_is_unknown():
    slot = recipes.EIP1967_IMPL_SLOT
    # Slot still points at the old impl → not proven.
    post = SimResult(calls=(ok(),), storage={CONTRACT.lower(): {slot: _addr_topic("0x" + "01" * 20)}})
    eff = recipes.code_upgrade(
        simulate=ScriptedSimulate(post),
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x3659cfe6" + "ee" * 32,
        sentinel_address=SENTINEL,
        sentinel_override=recipes.transparent_sentinel_override(SENTINEL),
        impl_before=_addr_topic("0x" + "01" * 20),
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "impl_slot_unchanged"


def test_code_upgrade_tier0_historical_only_current_fails_is_unknown():
    eff = recipes.code_upgrade(
        simulate=ScriptedSimulate(),
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x",
        sentinel_address=SENTINEL,
        sentinel_override=None,
        impl_before=None,
        indexed_upgrade=True,
        current_impl_nonzero=False,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.concrete["current_check_passed"] is False
