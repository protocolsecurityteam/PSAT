"""Input-asset seeding for Tier-1 value/supply probes (EFFECTS_RESOLUTION_SPEC §4.2/§4.5).

A deposit-backed conversion reverts at its ERC-20 precondition, so it never
reaches the mint and drops out of the backing population. These tests drive the
REAL recipes against a slot-faithful fake ERC-20 + vault: the storage overrides
the probe sends are applied to the fake's storage, so a wrong slot produces a
wrong read-back exactly as it would on chain.

The witness bar is what most of this file is about:
  * a seeded verdict exists only when the read-back echoed inside the probe block;
  * ``inflow_observed`` still comes only from Transfers the call emitted;
  * ETH is attached only after a zero-value attempt provably failed;
  * every unseedable shape degrades to the pre-seeding probe, verbatim.
"""

from __future__ import annotations

from collections.abc import Sequence
from types import SimpleNamespace
from typing import cast

from eth_utils.crypto import keccak

from services.effects import claims_bridge, recipes
from services.effects.calldata import (
    FunctionFacts,
    _seeded_probe_calldata,
    input_token_hints,
    seeded_calldata,
)
from services.effects.config import EFFECT_CLASS_SUPPLY, TIER_CALL, VERDICT_PROVEN, VERDICT_UNKNOWN
from services.effects.harness import SimContext
from services.effects.seeding import (
    SEED_AMOUNT,
    SEED_ETH_VALUE,
    AnchorSlot,
    SeedBudget,
    SimulateSeeder,
    balance_seed_amount,
    discover_token_layout,
)
from services.effects.simulate import SimCallResult, SimResult
from tests.test_effects_harness import RecordingStore, ok, transfer_log, uint_ret

VAULT = "0x" + "11" * 20
PRINCIPAL = "0x" + "22" * 20
ASSET = "0x" + "44" * 20
CTX = SimContext(chain_id=1, block=1000, hardfork="prague")

BAL_BASE = 3
ALLOW_BASE = 4
ASSET_GETTER = "underlying()"


def sel(sig: str) -> str:
    return "0x" + keccak(text=sig).hex()[:8]


def _arg(data: str, index: int) -> str:
    """The address at word ``index`` of a calldata payload."""
    start = 10 + index * 64
    return "0x" + data[start + 24 : start + 64].lower()


def _slot(base: int, arity: int, holder: str, spender: str) -> str:
    return AnchorSlot(signature="x", arity=arity, ordering="solidity", base=base).slot(holder, spender)


class FakeChain:
    """A slot-faithful ERC-20 plus a vault that wraps it.

    ``balance_scale`` > 1 models a rebasing token whose ``balanceOf`` is COMPUTED
    from the stored word — the shape whose read-back must never match.
    """

    def __init__(
        self,
        *,
        balance_base: int | None = BAL_BASE,
        allowance_base: int | None = ALLOW_BASE,
        decimals: int = 18,
        balance_scale: int = 1,
        vault_pulls: bool = True,
        vault_needs_eth: bool = False,
        vault_needs_asset: bool = True,
        total_supply: int = 10**24,
        readback_liar: bool = False,
        asset_total_supply: int | None = None,
    ) -> None:
        # ``None`` = the asset does not answer ``totalSupply()`` at all, which is
        # the shape every pre-existing test here assumes.
        self.asset_total_supply = asset_total_supply
        self.balance_base = balance_base
        self.allowance_base = allowance_base
        self.decimals = decimals
        self.balance_scale = balance_scale
        self.vault_pulls = vault_pulls
        self.vault_needs_eth = vault_needs_eth
        self.vault_needs_asset = vault_needs_asset
        self.total_supply = total_supply
        self.readback_liar = readback_liar
        self.blocks: list[tuple[list, str, dict | None]] = []

    # -- helpers ------------------------------------------------------------
    def _diff(self, overrides, address):
        entry = (overrides or {}).get(address.lower()) or {}
        return entry.get("stateDiff") or {}

    def _stored(self, overrides, holder, spender, *, arity):
        base = self.balance_base if arity == 1 else self.allowance_base
        if base is None:
            return None
        diff = self._diff(overrides, ASSET)
        raw = diff.get(_slot(base, arity, holder, spender))
        return int(raw, 16) if raw else 0

    # -- the wire seam ------------------------------------------------------
    def __call__(self, calls, block_tag, overrides):
        self.blocks.append((list(calls), block_tag, overrides))
        results = []
        minted = self.total_supply
        for call in calls:
            results.append(self._one(call, overrides))
            if call.to.lower() == VAULT.lower() and call.data.startswith(sel("wrap(uint256)")):
                if results[-1].success:
                    minted = self.total_supply = self.total_supply + int(call.data[10:74], 16)
        del minted
        return SimResult(calls=tuple(results))

    def _one(self, call, overrides) -> SimCallResult:
        to = call.to.lower()
        data = call.data
        if to == ASSET.lower():
            return self._asset_call(data, overrides)
        if to == VAULT.lower():
            return self._vault_call(call, data, overrides)
        return ok()

    def _asset_call(self, data, overrides) -> SimCallResult:
        if data.startswith(sel("decimals()")):
            return ok(uint_ret(self.decimals))
        if data.startswith(sel("totalSupply()")):
            if self.asset_total_supply is None:
                return SimCallResult(False, "0x", "0x", ())
            return ok(uint_ret(self.asset_total_supply))
        if data.startswith(sel("balanceOf(address)")):
            stored = self._stored(overrides, _arg(data, 0), VAULT, arity=1)
            if stored is None:
                return SimCallResult(False, "0x", "0x", ())
            if self.readback_liar:
                return ok(uint_ret(stored + 1))
            return ok(uint_ret((stored * self.balance_scale) % 2**256))
        if data.startswith(sel("allowance(address,address)")):
            stored = self._stored(overrides, _arg(data, 0), _arg(data, 1), arity=2)
            if stored is None:
                return SimCallResult(False, "0x", "0x", ())
            return ok(uint_ret(stored))
        # shares()/sharesOf() are absent on this token.
        return SimCallResult(False, "0x", "0x", ())

    def _vault_call(self, call, data, overrides) -> SimCallResult:
        if data.startswith(sel("totalSupply()")):
            return ok(uint_ret(self.total_supply))
        if data.startswith(sel(ASSET_GETTER)):
            return ok("0x" + ASSET[2:].rjust(64, "0"))
        if data.startswith(sel("wrap(uint256)")):
            amount = int(data[10:74], 16)
            held = self._stored(overrides, PRINCIPAL, VAULT, arity=1) or 0
            allowed = self._stored(overrides, PRINCIPAL, VAULT, arity=2) or 0
            if self.vault_needs_asset and (held < amount or allowed < amount):
                return SimCallResult(False, "0x", "0x08c379a0", ())
            if self.vault_needs_eth and call.value < SEED_ETH_VALUE:
                return SimCallResult(False, "0x", "0x08c379a0", ())
            logs = []
            if self.vault_pulls and self.vault_needs_asset:
                logs.append(transfer_log(ASSET, PRINCIPAL, VAULT, amount))
            logs.append(transfer_log(VAULT, "0x" + "00" * 20, PRINCIPAL, amount))
            return ok(logs=logs)
        if data.startswith(sel("unwrap(uint256)")):
            # Same precondition shape as ``wrap``; the observable difference is
            # that value LEAVES the vault (the §4.2 witness).
            amount = int(data[10:74], 16)
            held = self._stored(overrides, PRINCIPAL, VAULT, arity=1) or 0
            if held < amount:
                return SimCallResult(False, "0x", "0x08c379a0", ())
            return ok(logs=[transfer_log(ASSET, VAULT, PRINCIPAL, amount)])
        return SimCallResult(False, "0x", "0x", ())


def _facts(
    sig: str,
    *,
    pull_sink: str | None = None,
    flows: Sequence[dict] = (),
    param_names: Sequence[str] = ("amount",),
) -> FunctionFacts:
    sinks = []
    if pull_sink:
        sinks.append({"kind": "external_call", "origin": "body", "selector": "0x23b872dd", "target": pull_sink})
    return FunctionFacts(
        full_name=sig,
        selector=sel(sig),
        canonical_signature=sig,
        effect_info={
            "sinks": sinks,
            "value_flows": [],
            "effect_labels": [],
            # wrap/unwrap take one quantity; the seeded retry may only scale a
            # parameter the static plane names as one.
            "parameter_names": list(param_names),
        },
        tree=None,
        legacy_value_flows=tuple(flows),
    )


def _wrap_inputs(chain: FakeChain):
    fn = _facts("wrap(uint256)", pull_sink=f"{ASSET_GETTER[:-2]}.transferFrom")
    hints = input_token_hints(fn)
    seeded, seeded_sentinel = _seeded_probe_calldata(fn, PRINCIPAL, frozenset({"mint", "burn"}))
    return {
        "input_token_hints": hints,
        "seeded_calldata": seeded,
        "seeded_sentinel_calldata": seeded_sentinel,
        "seeder": SimulateSeeder(chain, chain_id=1),
    }


def _unwrap_inputs(chain: FakeChain):
    fn = _facts("unwrap(uint256)", flows=[{"direction": "burn", "token_var": ASSET_GETTER[:-2], "is_parameter": False}])
    seeded, seeded_sentinel = _seeded_probe_calldata(fn, PRINCIPAL, frozenset({"out", "eth_out"}))
    return {
        "input_token_hints": input_token_hints(fn),
        "seeded_calldata": seeded,
        "seeded_sentinel_calldata": seeded_sentinel,
        "seeder": SimulateSeeder(chain, chain_id=1),
    }


def _supply(chain, store, **kwargs):
    return recipes.supply(
        simulate=chain,
        store=store,
        ctx=CTX,
        token_address=VAULT,
        principal=PRINCIPAL,
        mint_calldata=sel("wrap(uint256)") + (1).to_bytes(32, "big").hex(),
        simulate_supported=True,
        gate_ref="gate:none",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Slot discovery — identification IS the read-back
# ---------------------------------------------------------------------------


def test_discovery_identifies_balance_and_allowance_bases():
    chain = FakeChain()
    layout = discover_token_layout(chain, token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1")
    found = {(a.signature, a.base, a.ordering) for a in layout.anchors}
    assert found == {
        ("balanceOf(address)", BAL_BASE, "solidity"),
        ("allowance(address,address)", ALLOW_BASE, "solidity"),
    }
    assert layout.decimals == 18
    # One block, one RPC: every candidate carries a distinct magic word.
    assert len(chain.blocks) == 1


def test_a_seeded_holder_balance_never_exceeds_the_supply_backing_it():
    """``totalSupply >= balanceOf(holder)`` is an invariant every real token keeps
    and a direct storage write does not. Handing a caller more shares than exist
    makes a burn arithmetically impossible — ``unchecked { totalSupply -= amount }``
    wraps past zero — so the seed is capped at the live supply. The ALLOWANCE slot
    is not capped: approvals above the supply are ordinary and bound nothing."""
    supply = 10**20  # well under SEED_AMOUNT (2**128)
    chain = FakeChain(asset_total_supply=supply)
    layout = discover_token_layout(chain, token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1")

    assert layout.total_supply == supply
    by_sig = {a.signature: a for a in layout.anchors}
    assert balance_seed_amount(by_sig["balanceOf(address)"], layout) == supply
    assert balance_seed_amount(by_sig["allowance(address,address)"], layout) == SEED_AMOUNT


def test_an_unanswered_total_supply_leaves_the_seed_at_full_value():
    """No supply to respect, and seeding nothing would simply lose the probe."""
    chain = FakeChain(asset_total_supply=None)
    layout = discover_token_layout(chain, token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1")

    assert layout.total_supply is None
    for anchor in layout.anchors:
        assert balance_seed_amount(anchor, layout) == SEED_AMOUNT


def test_a_supply_above_the_seed_leaves_the_seed_at_full_value():
    """The cap is a minimum, not a replacement: a token whose supply dwarfs the
    seed keeps the seed, which is already far above any probe amount."""
    chain = FakeChain(asset_total_supply=2**200)
    layout = discover_token_layout(chain, token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1")

    for anchor in layout.anchors:
        assert balance_seed_amount(anchor, layout) == SEED_AMOUNT


def test_discovery_reads_back_token_decimals():
    layout = discover_token_layout(FakeChain(decimals=6), token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1")
    assert layout.decimals == 6


def test_discovery_rejects_a_computed_balance_getter():
    """A rebasing ``balanceOf = shares * rate`` never echoes the seeded word, so
    it is never seeded — the exotic-layout degrade."""
    layout = discover_token_layout(
        FakeChain(balance_scale=3), token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1"
    )
    assert [a.signature for a in layout.anchors] == ["allowance(address,address)"]


def test_discovery_yields_nothing_for_an_unreadable_token():
    layout = discover_token_layout(
        FakeChain(balance_base=None, allowance_base=None),
        token=ASSET,
        holder=PRINCIPAL,
        spender=VAULT,
        block_tag="0x1",
    )
    assert layout.anchors == ()


def test_discovery_retries_narrow_when_the_wide_write_breaks_the_getter():
    """Writing ~550 candidate slots can clobber a slot the getter itself reads.
    That reverts every anchor, so a much smaller perturbation is tried once."""

    class FragileToken(FakeChain):
        """Reverts every anchor while any base above 3 is written."""

        def _asset_call(self, data, overrides):
            diff = self._diff(overrides, ASSET)
            wide = len(diff) > 40
            if wide and not data.startswith(sel("decimals()")):
                return SimCallResult(False, "0x", "0x", ())
            return super()._asset_call(data, overrides)

    chain = FragileToken(balance_base=1, allowance_base=2)
    layout = discover_token_layout(chain, token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1")
    assert len(chain.blocks) == 2
    assert {(a.signature, a.base) for a in layout.anchors} == {
        ("balanceOf(address)", 1),
        ("allowance(address,address)", 2),
    }


def test_discovery_survives_a_wire_error():
    def boom(_calls, _tag, _ov):
        raise RuntimeError("upstream said no")

    layout = discover_token_layout(boom, token=ASSET, holder=PRINCIPAL, spender=VAULT, block_tag="0x1")
    assert layout.anchors == ()


def test_seeder_survives_a_wire_error_on_token_identity():
    calls = {"n": 0}

    def flaky(sim_calls, tag, ov):
        calls["n"] += 1
        raise RuntimeError("upstream said no")

    seeding = SimulateSeeder(flaky, chain_id=1)(
        recipes.SeedRequest(spender=VAULT, principal=PRINCIPAL, token_hints=(ASSET_GETTER,), block_tag="0x1")
    )
    assert seeding is None


def test_seeder_builds_the_expected_overrides_for_a_standard_erc20():
    chain = FakeChain()
    seeding = SimulateSeeder(chain, chain_id=1)(
        recipes.SeedRequest(spender=VAULT, principal=PRINCIPAL, token_hints=(ASSET_GETTER, "__self__"), block_tag="0x1")
    )
    assert seeding is not None
    word = "0x" + format(SEED_AMOUNT, "064x")
    diff = seeding.overrides[ASSET.lower()]["stateDiff"]
    assert diff[_slot(BAL_BASE, 1, PRINCIPAL, VAULT)] == word
    assert diff[_slot(ALLOW_BASE, 2, PRINCIPAL, VAULT)] == word
    # Nothing beyond the principal's own holding of the input asset is touched.
    assert set(diff) == {_slot(BAL_BASE, 1, PRINCIPAL, VAULT), _slot(ALLOW_BASE, 2, PRINCIPAL, VAULT)}
    assert seeding.readback_expected == (word, word)


def test_seeder_memoizes_identity_and_layout_across_candidates():
    chain = FakeChain()
    seeder = SimulateSeeder(chain, chain_id=1)
    request = recipes.SeedRequest(spender=VAULT, principal=PRINCIPAL, token_hints=(ASSET_GETTER,), block_tag="0x1")
    seeder(request)
    first = len(chain.blocks)
    seeder(request)
    assert len(chain.blocks) == first  # second candidate pays nothing


# ---------------------------------------------------------------------------
# §4.5 supply — the backing witness
# ---------------------------------------------------------------------------


def test_unseeded_probe_runs_first_and_no_seeding_happens_when_it_succeeds():
    """An admin mint that needs no input asset must never trigger discovery — and
    its ``inflow_observed: false`` (witnessed dilution) is unchanged."""
    chain = FakeChain(vault_needs_asset=False, vault_pulls=False)
    store = RecordingStore()
    eff = _supply(chain, store, **_wrap_inputs(chain))
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["backing"] == {
        "inflow_observed": False,
        "minted": True,
        "input_seeded": False,
        "contract_balance_seeded": False,
    }
    # The per-execution counts are state-plane residue, not cacheable details.
    assert eff.concrete["backing_inflow_transfers"] == 0
    assert eff.concrete["backing_mint_transfers"] == 1
    assert len(chain.blocks) == 1
    assert "seeding" not in store.stored[-1]


def test_seeded_conversion_proves_the_mint_and_witnesses_the_inflow():
    chain = FakeChain()
    store = RecordingStore()
    unseeded = _supply(chain, RecordingStore())
    assert unseeded.verdict == VERDICT_UNKNOWN and unseeded.reason == "mint_call_reverted"

    chain = FakeChain()
    eff = _supply(chain, store, **_wrap_inputs(chain))
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["backing"]["inflow_observed"] is True
    assert eff.concrete["backing_inflow_transfers"] == 1
    assert eff.details["backing"]["input_seeded"] is True
    assert store.stored[-1]["seeding"]["tokens"] == [ASSET.lower()]


def test_a_seeded_supply_verdict_carries_its_qualifiers_through_to_the_claim():
    """G8, seam ``claims_bridge.verdict_to_claim``. The synthesis qualifiers must
    sit at the TOP LEVEL of a supply witness — the only plane ``_observed_summary``
    carries — or the minted/burned claim reads STRONGER than the seeded observation
    it came from. The recipe wrote ``input_seeded`` only into the nested
    ``backing`` map (mint-only, withheld-gated), which the bridge never reads, so
    every seeded supply row (incl. all 4 burns) disclosed nothing. Feeds the REAL
    recipe witness through the bridge, so reverting the recipe's top-level stamp
    fails this."""
    chain = FakeChain()
    eff = _supply(chain, RecordingStore(), **_wrap_inputs(chain))
    assert eff.verdict == VERDICT_PROVEN
    # The fix: the qualifier is at witness TOP LEVEL, not only under ``backing``.
    assert eff.details["input_seeded"] is True

    claim = claims_bridge.verdict_to_claim(
        cast(
            claims_bridge.VerdictLike,
            SimpleNamespace(
                id=1,
                effect_class=EFFECT_CLASS_SUPPLY,
                verdict=VERDICT_PROVEN,
                tier=TIER_CALL,
                behavior_hash="bh",
                current_check_passed=None,
                witness=eff.witness_payload,
                observed_residue=None,
            ),
        )
    )
    assert claim is not None
    assert claim["witness"]["observed"]["input_seeded"] is True


def test_a_seeded_supply_burn_witness_reaches_the_claim_observed_summary():
    """The burn half of G8 explicitly: a ``supply.burn`` witness carrying the
    top-level qualifiers projects them into ``observed`` exactly as a mint does.
    (There was no burn equivalent of the value_out top-level assertion, which is
    why the gap shipped green.)"""
    claim = claims_bridge.verdict_to_claim(
        cast(
            claims_bridge.VerdictLike,
            SimpleNamespace(
                id=1,
                effect_class=EFFECT_CLASS_SUPPLY,
                verdict=VERDICT_PROVEN,
                tier=TIER_CALL,
                behavior_hash="bh",
                current_check_passed=None,
                witness={"supply_delta_sign": "burn", "input_seeded": True, "contract_balance_seeded": True},
                observed_residue=None,
            ),
        )
    )
    assert claim is not None
    observed = claim["witness"]["observed"]
    assert observed["input_seeded"] is True
    assert observed["contract_balance_seeded"] is True


def test_seeded_mint_that_pulls_nothing_still_reports_inflow_false():
    """Seeding cannot invent a Transfer: storage writes emit no logs. A mint the
    seed merely unblocked, which then pulls nothing, is still dilution."""
    chain = FakeChain(vault_pulls=False)
    eff = _supply(chain, RecordingStore(), **_wrap_inputs(chain))
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["backing"]["inflow_observed"] is False
    assert eff.details["backing"]["input_seeded"] is True


def test_readback_mismatch_discards_the_seeded_attempt():
    """The token echoes a DIFFERENT word inside the probe block: the seed did not
    land where discovery said, so nothing about the seeded call may be trusted."""
    chain = FakeChain(readback_liar=True)
    eff = _supply(chain, RecordingStore(), **_wrap_inputs(chain))
    assert eff.verdict == VERDICT_UNKNOWN
    assert eff.reason == "mint_call_reverted"
    assert "backing" not in eff.details


def test_unseedable_token_leaves_the_verdict_exactly_as_today():
    chain = FakeChain(balance_base=None, allowance_base=None)
    seeded = _supply(chain, RecordingStore(), **_wrap_inputs(chain))
    plain = _supply(FakeChain(balance_base=None, allowance_base=None), RecordingStore())
    assert seeded.verdict == plain.verdict == VERDICT_UNKNOWN
    assert seeded.reason == plain.reason == "mint_call_reverted"


def test_no_seeder_issues_exactly_one_block():
    chain = FakeChain()
    _supply(chain, RecordingStore())
    assert len(chain.blocks) == 1


# ---------------------------------------------------------------------------
# msg.value staging — ETH only after a zero-value call provably failed
# ---------------------------------------------------------------------------


def test_eth_is_attached_only_after_the_zero_value_attempt_failed():
    chain = FakeChain(vault_needs_asset=False, vault_needs_eth=True, vault_pulls=False)
    eff = _supply(chain, RecordingStore(), **_wrap_inputs(chain))
    assert eff.verdict == VERDICT_PROVEN
    mints = [
        c.value
        for block, _tag, _ov in chain.blocks
        for c in block
        if c.to.lower() == VAULT.lower() and c.data.startswith(sel("wrap(uint256)"))
    ]
    # Every attempt before the last carried value 0, so a payable mint's own
    # msg.value can never be read as an inflow a caller would not have to supply.
    assert mints[-1] == SEED_ETH_VALUE
    assert all(v == 0 for v in mints[:-1])
    assert len(mints) >= 2


def test_payable_attempt_seeds_only_the_principals_eth_balance():
    chain = FakeChain(vault_needs_asset=False, vault_needs_eth=True, vault_pulls=False)
    _supply(chain, RecordingStore(), **_wrap_inputs(chain))
    _calls, _tag, overrides = chain.blocks[-1]
    assert overrides is not None
    assert set(overrides[PRINCIPAL.lower()]) == {"balance"}


# ---------------------------------------------------------------------------
# §4.2 value_out
# ---------------------------------------------------------------------------


def test_value_out_seeded_retry_proves_a_precondition_blocked_withdrawal():
    chain = FakeChain()
    calldata = sel("unwrap(uint256)") + (1).to_bytes(32, "big").hex()
    plain = recipes.value_out(
        simulate=FakeChain(),
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata=calldata,
        simulate_supported=True,
        gate_ref="gate:none",
    )
    # The UNSEEDED probe reverted on the precondition, and that is a different
    # non-observation from "the call ran and moved nothing" — same empty log set,
    # different fact. The reason must say so, or the code-plane cache transfers a
    # precondition revert to every bytecode twin.
    assert plain.verdict == VERDICT_UNKNOWN and plain.reason == "value_probe_reverted"
    assert plain.details["observation"] == "reverted"

    eff = recipes.value_out(
        simulate=chain,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=VAULT,
        principal=PRINCIPAL,
        calldata=calldata,
        simulate_supported=True,
        gate_ref="gate:none",
        **_unwrap_inputs(chain),
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.details["value_moved"] is True
    assert eff.details["input_seeded"] is True


# ---------------------------------------------------------------------------
# Static-side hint + calldata synthesis
# ---------------------------------------------------------------------------


def test_input_token_hints_come_from_a_pull_sink_and_a_flow_token_var():
    fn = _facts(
        "wrap(uint256)",
        pull_sink="eETH.transferFrom",
        flows=[{"direction": "in", "token_var": "depositToken", "is_parameter": False}],
    )
    hints = input_token_hints(fn)
    assert hints[:2] == ("eETH()", "depositToken()")
    assert hints[-1] == "__self__"
    assert "asset()" in hints


def test_input_token_hints_exclude_a_caller_supplied_token_param():
    """The encoder substitutes the principal for every address arg, so a token
    that arrives as a parameter is not present to be seeded."""
    fn = _facts("enter(address,uint256)", flows=[{"direction": "in", "token_var": "asset_", "is_parameter": True}])
    assert "asset_()" not in input_token_hints(fn)


def test_input_token_hints_ignore_an_outflow_token():
    fn = _facts("send(uint256)", flows=[{"direction": "out", "token_var": "rewardToken", "is_parameter": False}])
    assert "rewardToken()" not in input_token_hints(fn)


def test_seeded_calldata_encodes_one_whole_unit_per_token_scale():
    fn = _facts("wrap(uint256)")
    variants = seeded_calldata(fn, PRINCIPAL)
    assert set(variants) == {18, 8, 6}
    assert variants[18].endswith((10**18).to_bytes(32, "big").hex())
    assert variants[6].endswith((10**6).to_bytes(32, "big").hex())


def test_seeded_calldata_places_the_sentinel_at_the_taint_index():
    fn = _facts("withdraw(address,uint256)")
    variants = seeded_calldata(fn, PRINCIPAL, sentinel_index=0)
    assert "ee" * 20 in variants[18]


def test_seeded_calldata_is_empty_for_an_unencodable_signature():
    fn = _facts("weird")
    assert seeded_calldata(fn, PRINCIPAL) == {}


# ---------------------------------------------------------------------------
# Kill valve
# ---------------------------------------------------------------------------


def test_kill_valve_disables_the_default_seeder(monkeypatch):
    from services.effects.orchestrator import ProbeContext

    ctx = ProbeContext(
        chain_id=1,
        block=1,
        hardfork="prague",
        simulate=FakeChain(),
        simulate_supported=True,
        transcript_store=RecordingStore(),
    )
    monkeypatch.setenv("PSAT_EFFECTS_INPUT_SEEDING", "0")
    assert ctx.effective_seeder() is None
    monkeypatch.setenv("PSAT_EFFECTS_INPUT_SEEDING", "1")
    assert ctx.effective_seeder() is not None


def test_no_seeder_without_simulate_support():
    from services.effects.orchestrator import ProbeContext

    ctx = ProbeContext(
        chain_id=1,
        block=1,
        hardfork="prague",
        simulate=FakeChain(),
        simulate_supported=False,
        transcript_store=RecordingStore(),
    )
    assert ctx.effective_seeder() is None


# ---------------------------------------------------------------------------
# Per-job cost ceiling (SeedBudget)
#
# The retry path fires on the COMMON case — an unseeded probe that reverted —
# not the rare one, so its cost scales with the protocol's distinct vaults and
# tokens with nothing holding it down. These tests pin the ceiling, the degrade
# (exactly the pre-seeding probe, never a guess), the log, and the counters that
# let the next live run judge the spend on evidence rather than a projection.
# ---------------------------------------------------------------------------


def test_layout_budget_stops_discovery_and_degrades_to_the_unseeded_probe(caplog):
    budget = SeedBudget(max_identity_probes=8, max_layout_discoveries=0, max_probe_retries=8)
    chain = FakeChain()
    inputs = _wrap_inputs(chain)
    inputs["seeder"] = SimulateSeeder(chain, chain_id=1, budget=budget)

    with caplog.at_level("WARNING", logger="services.effects.seeding"):
        eff = _supply(chain, RecordingStore(), **inputs)

    # Exactly the pre-seeding verdict.
    assert eff.verdict == VERDICT_UNKNOWN and eff.reason == "mint_call_reverted"
    assert budget.layout_discoveries == 0
    assert budget.skipped_layout_discoveries >= 1
    assert budget.metrics()["seed_budget_skips"] >= 1
    # Not silent: the message names what was skipped.
    assert any(ASSET.lower() in r.getMessage().lower() for r in caplog.records)
    assert budget.exhausted_any is True
    assert ASSET.lower() in " ".join(budget.skipped_names).lower()


def test_retry_budget_stops_the_seeded_attempt_entirely(caplog):
    budget = SeedBudget(max_identity_probes=8, max_layout_discoveries=8, max_probe_retries=0)
    chain = FakeChain()
    inputs = _wrap_inputs(chain)
    inputs["seeder"] = SimulateSeeder(chain, chain_id=1, budget=budget)

    with caplog.at_level("WARNING", logger="services.effects.seeding"):
        eff = _supply(chain, RecordingStore(), **inputs)

    assert eff.verdict == VERDICT_UNKNOWN and eff.reason == "mint_call_reverted"
    # One block only — the unseeded read/mint/read. No identity, no discovery,
    # no seeded attempt, no seeded sentinel.
    assert len(chain.blocks) == 1
    assert budget.identity_probes == 0 and budget.layout_discoveries == 0
    assert budget.skipped_probe_retries == 1
    assert any("retry" in r.getMessage() for r in caplog.records)


def test_budget_counters_report_the_spend_and_the_yield():
    budget = SeedBudget()
    chain = FakeChain()
    inputs = _wrap_inputs(chain)
    inputs["seeder"] = SimulateSeeder(chain, chain_id=1, budget=budget)

    eff = _supply(chain, RecordingStore(), **inputs)

    assert eff.verdict == VERDICT_PROVEN
    metrics = budget.metrics()
    assert metrics["seed_probe_retries"] == 1
    assert metrics["seed_identity_probes"] == 1
    assert metrics["seed_layout_discoveries"] == 1
    assert metrics["seed_probes_executed"] == 1
    assert metrics["seed_verdicts_proven"] == 1
    assert metrics["seed_budget_skips"] == 0
    assert budget.exhausted_any is False


def test_a_probe_that_succeeds_unseeded_spends_nothing():
    """No retry, so no identity probe, no discovery and no budget consumed — the
    common admin-mint case must stay free."""
    budget = SeedBudget()
    chain = FakeChain(vault_needs_asset=False, vault_pulls=False)
    inputs = _wrap_inputs(chain)
    inputs["seeder"] = SimulateSeeder(chain, chain_id=1, budget=budget)

    eff = _supply(chain, RecordingStore(), **inputs)

    assert eff.verdict == VERDICT_PROVEN
    assert len(chain.blocks) == 1
    assert budget.metrics() == {
        "seed_identity_probes": 0,
        "seed_layout_discoveries": 0,
        "seed_probe_retries": 0,
        "seed_probes_executed": 0,
        "seed_verdicts_proven": 0,
        "seed_budget_skips": 0,
    }


def test_self_token_discovery_is_skipped_once_a_named_asset_anchors():
    """``__self__`` is the always-appended fallback and resolves with no wire
    call, so every reverting probe used to pay a full 548-override discovery
    block for the probe target itself. A specific hint that already anchored is
    the asset static actually saw flow in."""
    budget = SeedBudget()
    chain = FakeChain()
    inputs = _wrap_inputs(chain)
    seeder = SimulateSeeder(chain, chain_id=1, budget=budget)
    inputs["seeder"] = seeder

    eff = _supply(chain, RecordingStore(), **inputs)

    assert eff.verdict == VERDICT_PROVEN
    assert "__self__" in inputs["input_token_hints"]
    assert budget.layout_discoveries == 1  # the asset only, not the vault
    assert VAULT.lower() not in seeder._layouts


def test_self_token_is_still_discovered_when_nothing_else_anchors():
    """The withdrawal-burns-your-own-shares shape keeps its discovery: the skip
    is conditional on another candidate having anchored, not unconditional."""
    budget = SeedBudget()
    chain = FakeChain()
    seeder = SimulateSeeder(chain, chain_id=1, budget=budget)
    seeder(recipes.SeedRequest(spender=VAULT, principal=PRINCIPAL, token_hints=("__self__",), block_tag="0x1"))
    assert budget.layout_discoveries == 1
    assert VAULT.lower() in seeder._layouts
