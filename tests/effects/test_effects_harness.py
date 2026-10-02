"""Every recipe runs against a stubbed ``Simulate`` wire with recorded transcripts; each soundness rule has a
negative fail-closed test.
"""

from __future__ import annotations

from services.clients.rpc import EthCallResult
from services.effects import recipes
from services.effects.config import (
    EFFECT_CLASS_SUPPLY,
    EFFECT_CLASS_VALUE_OUT,
    SCOPE_KERNEL,
    TIER_CALL,
    VERDICT_PROVEN,
    VERDICT_UNKNOWN,
)
from services.effects.harness import (
    authorization_opened,
    select_identities,
)
from services.effects.preflight import (
    InMemoryCapabilityStore,
    probe_simulate_support,
)
from services.effects.simulate import (
    SimResult,
    SimulateUnsupportedError,
)
from tests.support.effects_stubs import (
    _REVERT_A,
    CONTRACT,
    CTX,
    PRINCIPAL,
    SENTINEL,
    TOKEN,
    RecordingStore,
    ScriptedSimulate,
    _addr_topic,
    ok,
    rv,
    transfer_log,
    uint_ret,
)


def test_preflight_probes_and_persists_support():
    store = InMemoryCapabilityStore()
    sim = ScriptedSimulate(SimResult(calls=(ok(),)))
    assert probe_simulate_support(sim, 1, store) is True
    assert store.get_simulate_support(1) is True
    assert probe_simulate_support(sim, 1, store) is True
    assert len(sim.blocks) == 1


def test_preflight_records_unsupported_and_routes_to_fallback():
    class Unsupported:
        def __call__(self, *_a):
            raise SimulateUnsupportedError("method not found")

    store = InMemoryCapabilityStore()
    assert probe_simulate_support(Unsupported(), 8453, store) is False
    assert store.get_simulate_support(8453) is False
    assert store.get_simulate_support(999) is None


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
        sentinel_override={"code": "0x00"},
        impl_before=_addr_topic("0x" + "01" * 20),
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.tier == TIER_CALL
    assert eff.details["upgradeable"] is True


def test_authority_change_kernel_gate_opened_proven():
    randoms, _ = select_identities("0x2f2ff15d", CONTRACT, principal=PRINCIPAL)
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


def test_self_mint_into_the_vault_is_not_backing():
    # ``_mint(address(this), fee)`` emits a Transfer from the minted token itself; backing needs an inflow of some other
    # asset.
    zero = "0x" + "00" * 20
    res = SimResult(
        calls=(
            ok(uint_ret(1000)),
            ok(logs=[transfer_log(TOKEN, zero, TOKEN, 500)]),  # mint TO the vault, of the vault's own token
            ok(uint_ret(1500)),
        )
    )
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    backing = eff.details["backing"]
    assert backing["inflow_observed"] is False
    assert eff.concrete["backing_inflow_transfers"] == 0
    assert backing["minted"] is True
    assert eff.concrete["backing_mint_transfers"] == 1


def test_supply_mint_backed_emits_backing_inflow_true():
    zero = "0x" + "00" * 20
    asset = "0x" + "44" * 20
    res = SimResult(
        calls=(
            ok(uint_ret(1000)),
            ok(
                logs=[
                    transfer_log(asset, PRINCIPAL, TOKEN, 500),  # backing asset INTO the vault
                    transfer_log(TOKEN, zero, PRINCIPAL, 500),  # shares minted to depositor
                ]
            ),
            ok(uint_ret(1500)),
        )
    )
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    backing = eff.details["backing"]
    assert backing["inflow_observed"] is True
    assert eff.concrete["backing_inflow_transfers"] == 1
    assert backing["minted"] is True


def test_section8_rule2_single_identity_never_opens():
    opened = authorization_opened(
        [EthCallResult(False, "0x", _REVERT_A, None)], [EthCallResult(True, "0x", None, None)]
    )
    assert opened is False
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


def test_section8_rule4_precondition_revert_is_unknown():
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


def test_section8_rule14_simulate_unsupported_declares_tier2_fallback():
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


def test_registry_param_sentinel_negative_is_unknown_not_fixed():
    # The sentinel indexes registry[param], not the raw address.
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
    post = SimResult(calls=(ok(),), storage={CONTRACT.lower(): {slot: _addr_topic("0x" + "01" * 20)}})
    eff = recipes.code_upgrade(
        simulate=ScriptedSimulate(post),
        store=RecordingStore(),
        ctx=CTX,
        proxy_address=CONTRACT,
        principal=PRINCIPAL,
        upgrade_calldata="0x3659cfe6" + "ee" * 32,
        sentinel_address=SENTINEL,
        sentinel_override={"code": "0x00"},
        impl_before=_addr_topic("0x" + "01" * 20),
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "impl_slot_unchanged"


# The withholding branches never ran in the corpus. Each asserts ``backing`` is absent, not false, since unmeasured
# backing must not read as dilution.
