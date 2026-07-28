"""Tier-1 effect harness tests (EFFECTS_RESOLUTION_SPEC §4.2–§4.5, §8).

Every recipe is exercised against a stubbed ``Simulate`` wire with recorded
transcripts — no live RPC (inv. 8 / §8.6). The §8 soundness rules each carry an
explicit NEGATIVE fail-closed test; the mapping is in ``test_section8_*`` below.
"""

from __future__ import annotations

from collections.abc import Sequence

from services.effects import calldata as calldata_mod
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
from services.effects.selection import AssetHolding
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


def test_transfers_in_extracts_only_dest_receives():
    # Mirror of transfers_out: value ARRIVING at dest_address (the §5a backing check).
    call = ok(logs=[transfer_log(TOKEN, CONTRACT, SENTINEL, 5), transfer_log(TOKEN, PRINCIPAL, CONTRACT, 9)])
    from services.effects.simulate import transfers_in

    ins = transfers_in(call, CONTRACT)
    assert len(ins) == 1
    assert ins[0][0] == PRINCIPAL.lower()
    assert ins[0][1] == CONTRACT.lower()


def test_transfers_in_can_exclude_the_emitting_asset():
    # A ``Transfer`` topic says nothing about WHICH contract emitted it, so a
    # caller asking "did some other asset arrive" must pin ``SimLog.address``.
    from services.effects.simulate import transfers_in

    other = "0x" + "77" * 20
    call = ok(logs=[transfer_log(CONTRACT, PRINCIPAL, CONTRACT, 5), transfer_log(other, PRINCIPAL, CONTRACT, 9)])
    assert len(transfers_in(call, CONTRACT)) == 2
    kept = transfers_in(call, CONTRACT, exclude_asset=CONTRACT)
    assert len(kept) == 1
    assert kept[0][2] == "0x" + (9).to_bytes(32, "big").hex()


def test_transfers_out_can_pin_the_emitting_asset():
    other = "0x" + "77" * 20
    call = ok(logs=[transfer_log(TOKEN, CONTRACT, SENTINEL, 5), transfer_log(other, CONTRACT, SENTINEL, 9)])
    assert len(transfers_out(call, CONTRACT)) == 2
    kept = transfers_out(call, CONTRACT, only_asset=other)
    assert len(kept) == 1
    assert kept[0][2] == "0x" + (9).to_bytes(32, "big").hex()


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
    # INVERTED (G6-3). This used to assert the BASE probe's recipient
    # ("0xabab…ab") as the concrete destination. That address is the recipient
    # argument the prober itself supplied — measured on 35 of 35 caller_arbitrary
    # rows in the local DB — so publishing it in the column that means "where the
    # money went" presents our own calldata as an observation, and it can only
    # mislead in the reassuring direction. A caller-arbitrary destination IS the
    # adverse finding; the shape carries it, the address adds nothing.
    assert "destination" not in eff.concrete
    assert SENTINEL.lower() not in str(eff.concrete)
    assert eff.discrepancy is None
    assert eff.transcript_ptr is not None


def test_a_probe_supplied_recipient_is_never_published_as_an_observed_destination():
    """G6-3, the second invented identity. ``SENTINEL_ADDRESS`` was already excluded
    by construction (the destination is read off the BASE probe); ``NEUTRAL_CALLER``
    was not, and it is BOTH the caller a public/unresolved-principal probe runs as
    AND the filler substituted into every address argument of the synthesized call
    — so it comes straight back in the ``Transfer`` log. The one local
    caller_arbitrary row with no resolved principals stored ``0x1111…1111``
    verbatim.

    Here the shape stays ``unknown`` (no sentinel), so this exercises the ordinary
    destination-capture path rather than the caller_arbitrary early return."""
    base = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, calldata_mod.NEUTRAL_CALLER, 7)]),))
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xdeadbeef",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["value_moved"] is True
    assert "destination" not in eff.concrete
    # POSITIVE CONTROL: a real counterparty in the same position is still recorded,
    # so this is an exclusion of two known-invented addresses and not a blanket
    # withholding.
    real = "0x" + "cd" * 20
    eff2 = recipes.value_out(
        simulate=ScriptedSimulate(SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, real, 7)]),))),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xdeadbeef",
        simulate_supported=True,
    )
    assert eff2.concrete["destination"] == real


def test_an_invented_recipient_among_several_destinations_leaves_it_undetermined():
    """The invented-identity exclusion applies to the convergence ANSWER, not to the
    set convergence is computed from.

    Applied to the set first, it manufactured agreement: this call provably sends 90%
    to ``NEUTRAL_CALLER`` — the caller a public/unresolved-principal probe
    impersonates, i.e. the ordinary "paid msg.sender" leg of a withdrawal — and a 10%
    fee to the treasury. Dropping the caller left ONE destination, and the fee sink
    was published as "the address value actually left to": the reassuring-direction
    mislead the exclusion exists to remove, newly created BY the exclusion. Two
    destinations, one of them invented, means the destination is not determined."""
    treasury = "0x" + "17" * 20
    base = SimResult(
        calls=(
            ok(
                logs=[
                    transfer_log(TOKEN, CONTRACT, calldata_mod.NEUTRAL_CALLER, 90),
                    transfer_log(TOKEN, CONTRACT, treasury, 10),
                ]
            ),
        )
    )
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xdeadbeef",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert "destination" not in eff.concrete
    # POSITIVE CONTROL: two REAL destinations were already withheld as ambiguous and
    # still are, so the answer above is not an artifact of the invented address.
    other = "0x" + "ce" * 20
    diverged = SimResult(
        calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, treasury, 90), transfer_log(TOKEN, CONTRACT, other, 10)]),)
    )
    eff2 = recipes.value_out(
        simulate=ScriptedSimulate(diverged),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xdeadbeef",
        simulate_supported=True,
    )
    assert "destination" not in eff2.concrete
    # NEGATIVE CONTROL: several logs CONVERGING on one real destination (burn + send,
    # or send + fee to the same address) is still one concrete destination.
    converged = SimResult(
        calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, treasury, 90), transfer_log(TOKEN, CONTRACT, treasury, 10)]),)
    )
    eff3 = recipes.value_out(
        simulate=ScriptedSimulate(converged),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xdeadbeef",
        simulate_supported=True,
    )
    assert eff3.concrete["destination"] == treasury


def test_sentinel_only_caller_arbitrary_publishes_no_destination():
    # The sentinel lands but the base probe moved nothing: caller_arbitrary is
    # still proven, and the concrete destination is EMPTY rather than the
    # fabricated probe address (nothing was observed leaving).
    base = SimResult(calls=(ok(),))
    sentinel = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, SENTINEL, 3)]),))
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base, sentinel),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xdeadbeef",
        simulate_supported=True,
        sentinel_address=SENTINEL,
        sentinel_calldata="0xdeadbeef" + "ee" * 32,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["destination_shape"] == recipes.SHAPE_CALLER_ARBITRARY
    assert eff.details["value_moved"] is False
    assert "destination" not in eff.concrete


def test_value_out_value_moved_records_single_observed_destination():
    # value moved, no sentinel, no static shape → shape stays unknown (a single
    # observation can't prove a fixed shape) BUT the concrete destination the
    # value reached this run is recorded for the state plane.
    recipient = "0x" + "ab" * 20
    base = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, recipient, 9)]),))
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xabcd0002",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["value_moved"] is True
    assert eff.details["destination_shape"] == recipes.SHAPE_UNKNOWN
    assert eff.details["shape_proved_by"] == "none"
    assert eff.concrete["destination"] == recipient.lower()


def test_value_out_multi_log_single_destination_records_it():
    # A withdrawal emitting several outbound Transfer logs that all converge on
    # ONE destination still has one concrete destination (len(logs) != 1).
    recipient = "0x" + "ab" * 20
    base = SimResult(
        calls=(
            ok(
                logs=[
                    transfer_log(TOKEN, CONTRACT, recipient, 5),
                    transfer_log(TOKEN, CONTRACT, recipient, 3),
                ]
            ),
        )
    )
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xabcd0003",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.concrete["destination"] == recipient.lower()


def test_value_out_divergent_destinations_withheld():
    # Outflow to TWO distinct destinations is genuinely ambiguous → no concrete
    # destination recorded (never guess which is "the" destination).
    base = SimResult(
        calls=(
            ok(
                logs=[
                    transfer_log(TOKEN, CONTRACT, "0x" + "ab" * 20, 5),
                    transfer_log(TOKEN, CONTRACT, "0x" + "cd" * 20, 3),
                ]
            ),
        )
    )
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0xabcd0004",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert "destination" not in eff.concrete


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


def test_supply_mint_unbacked_emits_backing_inflow_false():
    # §5a: supply rises but the mint call's COMPLETE Transfer set carries no asset
    # into the vault → witnessed dilution (inflow_observed False), never "backed".
    zero = "0x" + "00" * 20
    res = SimResult(
        calls=(
            ok(uint_ret(1000)),
            ok(logs=[transfer_log(TOKEN, zero, PRINCIPAL, 500)]),  # mint-from-zero only
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
    assert backing["minted"] is True
    assert eff.concrete["backing_inflow_transfers"] == 0
    assert eff.concrete["backing_mint_transfers"] == 1


def test_self_mint_into_the_vault_is_not_backing():
    # THE over-claim: ``_mint(address(this), fee)`` emits Transfer(0x0 -> vault)
    # FROM the minted token itself. Matching only on the recipient counted that as
    # an asset inflow, so the purest case of unbacked issuance produced a
    # ``backing`` object byte-identical to a real deposit-backed conversion.
    # Backing means an inflow of some OTHER asset; freshly-printed units of the
    # token whose supply just rose back nothing.
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
    # ...and the mint itself is still witnessed.
    assert backing["minted"] is True
    assert eff.concrete["backing_mint_transfers"] == 1


def test_foreign_asset_mint_into_the_vault_still_counts_as_backing():
    # The mirror of the test above: the same shape with a DIFFERENT token emitting
    # the inbound Transfer is a genuine inflow and must keep reporting True.
    zero = "0x" + "00" * 20
    asset = "0x" + "77" * 20
    res = SimResult(
        calls=(
            ok(uint_ret(1000)),
            ok(logs=[transfer_log(asset, zero, TOKEN, 500), transfer_log(TOKEN, zero, PRINCIPAL, 500)]),
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
    assert eff.details["backing"]["inflow_observed"] is True
    assert eff.concrete["backing_inflow_transfers"] == 1


def test_supply_mint_counts_only_the_measured_token_as_minted():
    # The mirror-image of the backing defect on ``transfers_out``: ``totalSupply``
    # was measured on ONE token, so an unrelated token minting inside the same
    # call must not stand in for its mint witness.
    zero = "0x" + "00" * 20
    other = "0x" + "88" * 20
    res = SimResult(
        calls=(
            ok(uint_ret(1000)),
            ok(logs=[transfer_log(other, zero, PRINCIPAL, 500)]),  # a DIFFERENT token's mint
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
    assert eff.details["backing"]["minted"] is False
    assert eff.concrete["backing_mint_transfers"] == 0


def test_supply_mint_backed_emits_backing_inflow_true():
    # §5a: a proportional asset Transfer INTO the vault co-occurs with the mint
    # (deposit-backed conversion) → inflow_observed True.
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


def test_supply_burn_emits_no_backing():
    # Backing is a mint-only concept; a burn verdict must not carry it.
    zero = "0x" + "00" * 20
    res = SimResult(
        calls=(
            ok(uint_ret(1500)),
            ok(logs=[transfer_log(TOKEN, PRINCIPAL, zero, 500)]),
            ok(uint_ret(1000)),
        )
    )
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x42966c68" + "00" * 32,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "burn"
    assert "backing" not in eff.details


def test_supply_mint_reverted_fails_closed_no_backing():
    # §5a fallback: a reverted mint is unknown, never "backed" — no backing field.
    res = SimResult(calls=(ok(uint_ret(10)), rv(), ok(uint_ret(10))))
    eff = recipes.supply(
        simulate=ScriptedSimulate(res),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert "backing" not in eff.details


def test_supply_unsupported_downgrades_no_backing():
    # §5a fallback: simulate_unsupported → Tier-2 downgrade unknown, never backed.
    eff = recipes.supply(
        simulate=ScriptedSimulate(SimResult(calls=(ok(),))),
        store=RecordingStore(),
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=False,
    )
    assert eff.verdict == VERDICT_UNKNOWN
    assert "backing" not in eff.details


# ---------------------------------------------------------------------------
# §5b downstream value-reach — fork-observed, over the value_out recipe
# ---------------------------------------------------------------------------


def test_value_out_reach_measures_downstream_holder_loss():
    # A genuine value-out (the acting contract sends value → proven flow.out) that
    # ALSO drains a downstream value-holder in the same call. Reach sums each holder
    # whose value provably left (full on-chain USD, conservative upper bound),
    # fork-observed via Transfer-out logs; a holder that didn't move is excluded.
    lp = "0x" + "55" * 20
    other = "0x" + "66" * 20
    base = SimResult(
        calls=(
            ok(logs=[transfer_log(TOKEN, CONTRACT, "0x" + "ab" * 20, 3), transfer_log(TOKEN, lp, "0x" + "ab" * 20, 9)]),
        )
    )
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
        value_holders=(
            AssetHolding(CONTRACT, TOKEN, 221_000_000.0),
            AssetHolding(lp, TOKEN, 55_200_000.0),
            AssetHolding(other, TOKEN, 1_000.0),
        ),
        acting_balance_usd=221_000_000.0,
    )
    assert eff.verdict == VERDICT_PROVEN
    # Reach is STATE-plane (holder addresses + this protocol's USD), so it rides
    # ``concrete`` — ``details`` is what the cross-deployment behavioral cache
    # stores and re-publishes to every twin of this bytecode (inv. 3).
    assert eff.concrete["observed_reach_value_usd"] == 221_000_000.0 + 55_200_000.0
    assert eff.concrete["observed_reach_holders"] == sorted([CONTRACT.lower(), lp.lower()])
    assert eff.concrete["reach_determined"] is True
    assert "reach_indeterminate" not in eff.concrete
    assert "observed_reach_floor_usd" not in eff.concrete
    assert not any(k.startswith(("observed_reach", "reach_")) for k in eff.details)
    assert lp.lower() not in str(eff.details)


def test_value_out_reach_floors_and_flags_when_no_holder_moved():
    # Acting contract moves value (value_moved) but NO downstream holder loses value
    # → floor to the acting deployment's own balance, flag reach_indeterminate.
    # Downstream value is never imputed via the control graph.
    lp = "0x" + "55" * 20
    base = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, "0x" + "ab" * 20, 3)]),))
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
        value_holders=(AssetHolding(lp, TOKEN, 55_200_000.0),),
        acting_balance_usd=221_000_000.0,
    )
    assert eff.verdict == VERDICT_PROVEN
    # D3: the floor is published as a FLOOR. The key that means "measured reach" is
    # absent, because nothing was measured — publishing the acting balance as
    # ``observed_reach_value_usd`` is what let a zero-balance router read "$0 reach".
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    assert eff.concrete["observed_reach_floor_usd"] == 221_000_000.0
    assert "observed_reach_value_usd" not in eff.concrete
    assert "observed_reach_holders" not in eff.concrete
    assert not any(k.startswith(("observed_reach", "reach_")) for k in eff.details)


def test_value_out_reach_absent_without_holder_set():
    # No value-holder set supplied → verdict shape unchanged (no reach fields), so
    # existing callers and the value_out contract stay byte-identical.
    base = SimResult(calls=(ok(logs=[transfer_log(TOKEN, CONTRACT, "0x" + "ab" * 20, 3)]),))
    eff = recipes.value_out(
        simulate=ScriptedSimulate(base),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x11111111",
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert "observed_reach_value_usd" not in eff.concrete
    assert "reach_indeterminate" not in eff.concrete
    # ...and no discriminator either: absence of EVERY key is the third state, "no
    # reach measurement was attempted", distinct from a measured or a floored one.
    assert "reach_determined" not in eff.concrete
    assert "observed_reach_floor_usd" not in eff.concrete
    assert "observed_reach_value_usd" not in eff.details
    assert "reach_indeterminate" not in eff.details


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


# ---------------------------------------------------------------------------
# §5a backing — the WITHHOLDING branches (W0-7 fixture 7)
#
# ``inflow_observed`` was ``true`` on 11/11 rows and ``backing_withheld`` on
# zero, anywhere. Every one of the four branches below the ASYMMETRIC BURDEN
# comment had therefore never executed, and they are the adverse half: the
# negative is what renders as "(unbacked)" and as the inspector's "supply rose
# alone (dilution)" sentence. Etherfi's mints are deposit-backed conversions, so
# 11/11 is a property of that corpus, not of the code.
#
# Withholding is NOT the negative. Each test below asserts that ``backing`` is
# ABSENT rather than present-and-false: a mint whose backing could not be
# measured must not be published as dilution.
# ---------------------------------------------------------------------------


def _mint_block(supply_before: int = 1000, supply_after: int = 1500, logs=()):
    """read -> mint -> read, with the mint emitting ``logs``."""
    return SimResult(calls=(ok(uint_ret(supply_before)), ok(logs=logs), ok(uint_ret(supply_after))))


def test_backing_withheld_when_a_proven_token_slot_kept_the_encoder_filler():
    """Reason 1 — ``token_param_unresolved``. The static plane PROVED parameter 1
    carries a token and no seeded retry ever supplied one, so the call was made
    with a non-token in a known token slot. Nothing about backing is witnessable
    from it, and the absent inflow is an artifact of the argument."""
    zero = "0x" + "00" * 20
    store = RecordingStore()
    eff = recipes.supply(
        simulate=ScriptedSimulate(_mint_block(logs=[transfer_log(TOKEN, zero, PRINCIPAL, 500)])),
        store=store,
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=True,
        token_param_indexes=(1,),
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"
    assert "backing" not in eff.details
    # The reason is named on the transcript, so a run can say what it could not
    # prove instead of going quiet.
    assert store.stored[-1]["backing_withheld"] == "token_param_unresolved"


def test_backing_withheld_when_no_identity_could_fill_the_address_arguments():
    """Reason 3 — ``prober_address_unidentifiable``. With no principal the
    encoder wrote ``address(0)`` into every address argument, and a call to a
    codeless address is a silent no-op inside every safe-transfer wrapper. The
    mint executed and nothing came in — but the reason nothing came in may be the
    prober's own zero address, and nothing here can tell which slots those were."""
    zero = "0x" + "00" * 20
    store = RecordingStore()
    eff = recipes.supply(
        simulate=ScriptedSimulate(_mint_block(logs=[transfer_log(TOKEN, zero, CONTRACT, 500)])),
        store=store,
        ctx=CTX,
        token_address=TOKEN,
        principal=None,
        mint_calldata="0x40c10f19" + "00" * 64,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"
    assert "backing" not in eff.details
    assert store.stored[-1]["backing_withheld"] == "prober_address_unidentifiable"


def test_backing_withheld_when_the_prober_supplied_address_is_not_proven_inert():
    """Reason 2 — ``prober_address_not_proven_inert``. The prober wrote its own
    identity into an address argument, no inflow was seen, and the differential
    (same block, reverting code at that address) did NOT reproduce the same
    delta. The execution depended on an address this prober invented, so the
    empty inflow describes the argument and not the function."""
    zero = "0x" + "00" * 20
    principal_word = PRINCIPAL[2:].rjust(64, "0")
    store = RecordingStore()
    eff = recipes.supply(
        simulate=ScriptedSimulate(
            _mint_block(logs=[transfer_log(TOKEN, zero, PRINCIPAL, 500)]),
            # The inertness differential: the mint now reverts with the suspect
            # stubbed out, so the pull it made was on the executed path.
            SimResult(calls=(ok(uint_ret(1000)), rv(), ok(uint_ret(1000)))),
        ),
        store=store,
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + principal_word + "00" * 32,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["supply_delta_sign"] == "mint"
    assert "backing" not in eff.details
    assert store.stored[-1]["backing_withheld"] == "prober_address_not_proven_inert"


def test_the_same_call_publishes_dilution_once_the_prober_address_is_proven_inert():
    """THE DISCRIMINATING SIBLING for the three above, and the reason they are not
    just "withhold everything". Identical calldata, identical logs; the only
    change is that the differential REPRODUCES the delta with reverting code at
    the prober's address, so no pull was silently skipped and the empty inflow is
    a statement about F. ``inflow_observed: false`` is then earned."""
    zero = "0x" + "00" * 20
    principal_word = PRINCIPAL[2:].rjust(64, "0")
    store = RecordingStore()
    eff = recipes.supply(
        simulate=ScriptedSimulate(
            _mint_block(logs=[transfer_log(TOKEN, zero, PRINCIPAL, 500)]),
            # Same +500 delta with the suspect stubbed: provably independent.
            SimResult(calls=(ok(uint_ret(1000)), ok(), ok(uint_ret(1500)))),
        ),
        store=store,
        ctx=CTX,
        token_address=TOKEN,
        principal=PRINCIPAL,
        mint_calldata="0x40c10f19" + principal_word + "00" * 32,
        simulate_supported=True,
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["backing"]["inflow_observed"] is False
    assert eff.details["backing"]["minted"] is True
    assert "backing_withheld" not in store.stored[-1]
