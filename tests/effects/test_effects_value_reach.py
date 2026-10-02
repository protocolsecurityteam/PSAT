"""Downstream value-reach: which address the money is keyed on, and which execution it is read from.

All six proven ``value_out`` rows on the 2026-07-25 run had zero reach on deployments holding billions:
balances fetched for the proxy are stored on the implementation row, and reach was read off the unseeded call.
"""

from __future__ import annotations

from services.effects import recipes
from services.effects.config import NATIVE_ASSET_LOG_EMITTER, VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.selection import (
    AssetHolding,
    select_candidates,
)
from services.effects.simulate import SimCallResult, SimResult
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _balance, _contract, _fn, _principal, _protocol
from tests.support.effects_stubs import RecordingStore, transfer_log

CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


@requires_postgres
def test_candidate_floor_and_holder_set_use_the_holding_address(db_session):
    p = _protocol(db_session, "reach-candidate")
    impl = _contract(db_session, p.id, ADDR(0x2201))
    deployment = ADDR(0x2202)
    fn = _fn(
        db_session,
        impl.id,
        name="withdraw",
        selector="0xbbbb0201",
        effect_targets=["S"],
        deployment_address=deployment,
    )
    _principal(db_session, fn.id, ADDR(0x2203))
    _balance(db_session, impl.id, 7_500.0)
    db_session.flush()

    cand = next(c for c in select_candidates(db_session, p.id) if c.selector == "0xbbbb0201")
    assert cand.acting_balance_usd == 7_500.0
    assert AssetHolding(deployment.lower(), NATIVE_ASSET_LOG_EMITTER, 7_500.0) in cand.value_holders


CONTRACT = "0x" + "c0" * 20
PRINCIPAL = "0x" + "22" * 20
PAYEE = "0x" + "33" * 20
HOLDER = "0x" + "44" * 20
# Reach matching is per asset.
TOKEN = "0x" + "7a" * 20


def _value_out(
    blocks, *, seeding=None, holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor: float | None = 100.0, tvl=None
):
    remaining = list(blocks)

    def simulate(calls, block_tag=None, overrides=None):
        return remaining.pop(0)

    return recipes.value_out(
        simulate=simulate,
        store=RecordingStore(),
        ctx=CTX,
        contract_address=CONTRACT,
        principal=PRINCIPAL,
        calldata="0x" + "de" * 4,
        simulate_supported=True,
        value_holders=holders,
        acting_balance_usd=floor,
        protocol_tvl_usd=tvl,
        seeder=(lambda _req: seeding),
        seeded_calldata={18: "0x" + "de" * 4},
        target_payable=True,
    )


def test_an_unwitnessed_acting_balance_publishes_no_floor_key():
    """Nothing was read, so ``0.0`` would be a bound minted from a failed fetch."""
    moved_nothing = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved_nothing], holders=(AssetHolding(HOLDER, TOKEN, 42.0),), floor=None)

    assert eff.verdict == VERDICT_PROVEN
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    # A ``null`` would pass a bare ``is not None`` check.
    assert "observed_reach_floor_usd" not in eff.concrete
    assert "observed_reach_value_usd" not in eff.concrete
    assert "observed_reach_holders" not in eff.concrete


EETH = "0x" + "e1" * 20
# WeETH's proxy holds $3.49B of eETH and no native row, and the contract-balance seed made it move native ETH.


def test_an_unvalued_branch_with_nothing_priced_publishes_no_ceiling_outcome():
    """With no priced figure there is nothing for a ceiling to bear on."""
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    eff = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, None),), floor=0.0, tvl=1_000.0)

    assert eff.concrete["reach_determined"] is False
    assert "reach_tvl_check" not in eff.concrete
    assert "observed_reach_priced_usd" not in eff.concrete
    assert "observed_reach_rejected_usd" not in eff.concrete
    assert eff.concrete["observed_reach_unvalued_assets"] == sorted([TOKEN, EETH])
    assert eff.concrete["observed_reach_unvalued_reasons"] == sorted(
        ["unpriced_holding", "asset_not_in_recorded_holdings"]
    )


def test_the_partial_floor_and_the_tvl_ceiling_both_read_the_deduped_sum():
    """The per-log sum also inflated the partial floor and could trip the TVL ceiling wrongly."""
    logs = (
        transfer_log(TOKEN, CONTRACT, PAYEE, 5),
        transfer_log(TOKEN, CONTRACT, HOLDER, 1),
        transfer_log(EETH, CONTRACT, PAYEE, 5),
    )
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    partial = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0)
    assert partial.concrete["reach_determined"] is False
    assert partial.concrete["observed_reach_priced_usd"] == 100.0

    priced = SimResult(
        calls=(
            SimCallResult(
                True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, CONTRACT, HOLDER, 1))
            ),
        )
    )
    within = _value_out([priced], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0, tvl=150.0)
    assert within.concrete["reach_tvl_check"] == "within_protocol_tvl"
    assert within.concrete["reach_determined"] is True
    assert within.concrete["observed_reach_value_usd"] == 100.0
    over = _value_out([priced], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0, tvl=50.0)
    assert over.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert over.concrete["reach_determined"] is False


# PR-161 verdict 198 in miniature: weETH was named both moved-and-priced and unvaluable, beside the vault's priced
# figure.
_VAULT_WEETH_USD = 8_471_736.29


def _two_holders_move_one_asset(vault_usd: float | None, tvl: float | None = 3_322_211_996.00):
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, HOLDER, PAYEE, 7))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    holdings = (AssetHolding(CONTRACT, EETH, 0.0), AssetHolding(HOLDER, TOKEN, vault_usd))
    return _value_out([moved], holders=holdings, floor=0.0, tvl=tvl)


def test_an_asset_one_holder_prices_is_not_published_as_unvaluable_for_every_holder():
    eff = _two_holders_move_one_asset(_VAULT_WEETH_USD)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["observed_reach_assets"] == [TOKEN]
    assert eff.concrete["observed_reach_holders"] == sorted([CONTRACT, HOLDER])
    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": CONTRACT, "asset": TOKEN, "reason": "asset_not_in_recorded_holdings"}
    ]
    assert eff.concrete["observed_reach_unvalued_reasons"] == ["asset_not_in_recorded_holdings"]
    # Earned empty, published rather than omitted.
    assert eff.concrete["observed_reach_unvalued_assets"] == []
    assert eff.concrete["observed_reach_priced_usd"] == _VAULT_WEETH_USD
    assert eff.concrete["observed_reach_priced_holders"] == [HOLDER]
    assert eff.concrete["reach_tvl_check"] == "within_protocol_tvl"
    assert not set(eff.concrete["observed_reach_assets"]) & set(eff.concrete["observed_reach_unvalued_assets"])


def test_an_asset_no_holder_could_value_is_still_named_as_unvaluable():
    eff = _two_holders_move_one_asset(None)

    assert eff.concrete["observed_reach_unvalued_assets"] == [TOKEN]
    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": HOLDER, "asset": TOKEN, "reason": "unpriced_holding"},
        {"holder": CONTRACT, "asset": TOKEN, "reason": "asset_not_in_recorded_holdings"},
    ]
    assert eff.concrete["observed_reach_unvalued_reasons"] == sorted(
        ["unpriced_holding", "asset_not_in_recorded_holdings"]
    )
    assert "observed_reach_priced_usd" not in eff.concrete
    assert "observed_reach_priced_holders" not in eff.concrete
    assert "reach_tvl_check" not in eff.concrete
