"""Downstream value-reach: which address the money is keyed on, and which execution it is read from.

All six proven ``value_out`` rows on the 2026-07-25 run had zero reach on deployments holding billions:
balances fetched for the proxy are stored on the implementation row, and reach was read off the unseeded call.
"""

from __future__ import annotations

import pytest

from services.effects import recipes
from services.effects.config import NATIVE_ASSET_LOG_EMITTER, VERDICT_PROVEN
from services.effects.harness import SimContext
from services.effects.selection import (
    HOLDINGS_COMPLETENESS_AT_PAGE_CAP,
    AssetHolding,
    build_authority_graph,
    select_candidates,
)
from services.effects.simulate import SimCallResult, SimResult
from tests.conftest import ADDR, requires_postgres
from tests.support.effects_builders import _balance, _contract, _fn, _principal, _protocol
from tests.support.effects_stubs import RecordingStore, transfer_log
from utils.execution_record import PROVING_EXECUTION_KEY

CTX = SimContext(chain_id=1, block=1000, hardfork="prague")


@requires_postgres
def test_balances_are_keyed_on_the_address_that_holds_them(db_session):
    """Only the proxy can appear in a ``Transfer`` log."""
    p = _protocol(db_session, "reach-keying")
    impl = _contract(db_session, p.id, ADDR(0x2001))
    deployment = ADDR(0x2002)
    _fn(
        db_session, impl.id, name="withdraw", selector="0xbbbb0001", effect_targets=["S"], deployment_address=deployment
    )
    _balance(db_session, impl.id, 1_000.0)
    db_session.flush()

    graph = build_authority_graph(db_session, p.id)
    assert graph.deployment_balance[deployment.lower()] == 1_000.0
    assert graph.balance[impl.address.lower()] == 1_000.0


@requires_postgres
def test_two_implementations_behind_one_proxy_do_not_double_count(db_session):
    p = _protocol(db_session, "reach-dedup")
    deployment = ADDR(0x2102)
    for n, addr in enumerate((ADDR(0x2100), ADDR(0x2101))):
        c = _contract(db_session, p.id, addr)
        _fn(
            db_session,
            c.id,
            name=f"f{n}",
            selector=f"0xbbbb010{n}",
            effect_targets=["S"],
            deployment_address=deployment,
        )
        _balance(db_session, c.id, 500.0)
    db_session.flush()

    assert build_authority_graph(db_session, p.id).deployment_balance[deployment.lower()] == 500.0


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


@requires_postgres
def test_a_contract_with_no_balance_row_carries_no_floor_not_a_zero(db_session):
    """The inner join gives no key for "holds nothing", "not fetched" and "fetch failed" alike, so the candidate
    carries ``None``, not a 0.0 floor.
    """
    p = _protocol(db_session, "reach-no-balance")
    impl = _contract(db_session, p.id, ADDR(0x2301))
    deployment = ADDR(0x2302)
    _fn(
        db_session,
        impl.id,
        name="route",
        selector="0xbbbb0301",
        effect_targets=["S"],
        deployment_address=deployment,
    )
    db_session.flush()

    graph = build_authority_graph(db_session, p.id)
    assert deployment.lower() not in graph.deployment_balance

    cand = next(c for c in select_candidates(db_session, p.id) if c.selector == "0xbbbb0301")
    assert cand.acting_balance_usd is None


@requires_postgres
def test_a_priced_zero_balance_row_carries_a_floor_of_zero(db_session):
    """A priced $0 row is a read witness, so ``0.0`` not ``None``."""
    p = _protocol(db_session, "reach-priced-zero")
    impl = _contract(db_session, p.id, ADDR(0x2401))
    deployment = ADDR(0x2402)
    _fn(
        db_session,
        impl.id,
        name="route",
        selector="0xbbbb0401",
        effect_targets=["S"],
        deployment_address=deployment,
    )
    _balance(db_session, impl.id, 0.0)
    db_session.flush()

    graph = build_authority_graph(db_session, p.id)
    assert graph.deployment_balance[deployment.lower()] == 0

    cand = next(c for c in select_candidates(db_session, p.id) if c.selector == "0xbbbb0401")
    assert cand.acting_balance_usd == 0.0
    assert cand.acting_balance_usd is not None


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


def test_reach_is_read_from_the_execution_the_verdict_came_from():
    from services.effects.seeding import Seeding

    reverted = SimResult(calls=(SimCallResult(False, "0x", "0x", ()),))
    seeded = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out(
        [reverted, seeded],
        seeding=Seeding(overrides={}, readback_calls=(), readback_expected=(), tokens=(), decimals=18),
    )
    assert eff.verdict == VERDICT_PROVEN
    assert eff.concrete["observed_reach_holders"] == [CONTRACT]
    assert eff.concrete["observed_reach_value_usd"] == 100.0
    assert "reach_indeterminate" not in eff.concrete


def test_a_holder_that_moved_nothing_still_floors_and_stays_indeterminate():
    """The floor is the acting deployment's own balance, never a claim that reach is zero."""
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=(AssetHolding(HOLDER, TOKEN, 42.0),), floor=250.0)
    assert eff.concrete["observed_reach_floor_usd"] == 250.0
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    assert "observed_reach_value_usd" not in eff.concrete


def test_a_zero_balance_deployment_publishes_no_reach_number_at_all():
    """Zaps and routers hold nothing, and publishing that zero as reach read as "$0 reach" for functions that may
    move millions.
    """
    moved_nothing = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved_nothing], holders=(AssetHolding(HOLDER, TOKEN, 42.0),), floor=0.0)

    assert eff.verdict == VERDICT_PROVEN
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_indeterminate"] is True
    assert eff.concrete["observed_reach_floor_usd"] == 0.0
    assert "observed_reach_holders" not in eff.concrete


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


def test_zero_reach_without_the_flag_is_a_measured_zero_not_a_floor():
    """A measured zero and an unmeasured one must be different payloads."""
    moved = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, HOLDER, PAYEE, 7)),
            ),
        )
    )
    eff = _value_out([moved], holders=(AssetHolding(HOLDER, TOKEN, 0.0),), floor=250.0)

    assert eff.concrete["observed_reach_value_usd"] == 0.0
    assert eff.concrete["observed_reach_holders"] == [HOLDER.lower()]
    assert eff.concrete["reach_determined"] is True
    assert "reach_indeterminate" not in eff.concrete
    assert "observed_reach_floor_usd" not in eff.concrete


EETH = "0x" + "e1" * 20
NATIVE = NATIVE_ASSET_LOG_EMITTER
# WeETH's proxy holds $3.49B of eETH and no native row, and the contract-balance seed made it move native ETH.
WEETH_SHEET = (
    AssetHolding(CONTRACT, EETH, 3_488_954_369.29),
    AssetHolding(CONTRACT, TOKEN, 759.15),
)


def _native_transfer_out(holder: str = CONTRACT) -> SimResult:
    """The emitter was measured live."""
    return SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(NATIVE, holder, PAYEE, 10**18),)),))


def test_a_native_move_does_not_reach_a_holders_token_balance_sheet():
    """Asset-blind matching published $3.489B of reach for a native move; with no native row the only honest USD is
    unknown.
    """
    eff = _value_out([_native_transfer_out()], holders=WEETH_SHEET, floor=3_488_955_156.06)

    assert eff.verdict == VERDICT_PROVEN
    assert eff.concrete["reach_determined"] is False
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["observed_reach_holders"] == [CONTRACT]
    assert eff.concrete["observed_reach_assets"] == [NATIVE]
    assert eff.concrete["observed_reach_unvalued_assets"] == [NATIVE]
    assert "observed_reach_priced_usd" not in eff.concrete
    assert "3488954369" not in str(eff.concrete)


def test_the_asset_that_moved_contributes_its_own_holding_and_only_it():
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=WEETH_SHEET, floor=3_488_955_156.06)

    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 759.15
    assert eff.concrete["observed_reach_assets"] == [TOKEN.lower()]
    assert eff.concrete["observed_reach_holders"] == [CONTRACT]


def test_a_priced_native_holding_is_matched_by_the_emitter_the_node_uses():
    """A native holding is matchable when keyed on the ``traceTransfers`` pseudo-address."""
    holdings = (AssetHolding(CONTRACT, NATIVE, 4_200.0), AssetHolding(CONTRACT, EETH, 3_488_954_369.29))
    eff = _value_out([_native_transfer_out()], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 4_200.0
    assert eff.concrete["observed_reach_assets"] == [NATIVE]


def test_an_unpriced_holding_that_moves_makes_the_total_not_determined():
    """Most local rows have no price; reading that as $0 is a confident low where the answer is unknown."""
    unpriced = "0x" + "9d" * 20
    holdings = (AssetHolding(CONTRACT, TOKEN, 759.15), AssetHolding(CONTRACT, unpriced, None))
    moved = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(unpriced, CONTRACT, PAYEE, 9)),
            ),
        )
    )
    eff = _value_out([moved], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is False
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["observed_reach_unvalued_assets"] == [unpriced]
    assert eff.concrete["observed_reach_priced_usd"] == 759.15
    assert eff.concrete["observed_reach_assets"] == sorted([TOKEN.lower(), unpriced])


def test_two_holders_moving_two_assets_sum_only_those_two_holdings():
    other = "0x" + "b1" * 20
    holdings = (
        AssetHolding(CONTRACT, TOKEN, 100.0),
        AssetHolding(CONTRACT, EETH, 999_999.0),
        AssetHolding(other, EETH, 25.0),
    )
    moved = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, other, PAYEE, 7)),
            ),
        )
    )
    eff = _value_out([moved], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 125.0
    assert eff.concrete["observed_reach_holders"] == sorted([CONTRACT, other])


def test_a_reach_above_protocol_tvl_is_refused_not_published():
    """A sum above TVL is refused, not clamped; clamping invents a number."""
    holdings = (AssetHolding(CONTRACT, TOKEN, 3_488_955_156.06),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0, tvl=3_297_344_734.00)

    assert eff.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert eff.concrete["reach_determined"] is False
    assert "observed_reach_value_usd" not in eff.concrete
    assert eff.concrete["observed_reach_rejected_usd"] == 3_488_955_156.06
    assert eff.concrete["protocol_tvl_usd"] == 3_297_344_734.00


@pytest.mark.parametrize(
    ("tvl", "expected_check"),
    [
        pytest.param(1_000.0, "within_protocol_tvl", id="within_tvl_says_it_was_checked"),
        # An absent ceiling must not look like one that passed.
        pytest.param(None, "skipped_no_tvl", id="no_tvl_snapshot_skips_out_loud"),
    ],
)
def test_a_measured_reach_publishes_the_outcome_of_the_tvl_check(tvl, expected_check):
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0, tvl=tvl)

    assert eff.concrete["reach_tvl_check"] == expected_check
    assert eff.concrete["reach_determined"] is True
    assert eff.concrete["observed_reach_value_usd"] == 100.0


def _partial_floor(*, floor_usd: float, tvl: float | None):
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    return _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, floor_usd),), floor=0.0, tvl=tvl)


def test_a_priced_floor_above_protocol_tvl_is_refused_like_a_measured_figure():
    """The floor branch used to return before the ceiling check; a lower bound over a subset exceeding TVL is a real
    contradiction. The unvalued-asset disclosure survives the refusal.
    """
    eff = _partial_floor(floor_usd=3_488_955_156.06, tvl=3_297_344_734.00)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert "observed_reach_priced_usd" not in eff.concrete
    assert eff.concrete["observed_reach_rejected_usd"] == 3_488_955_156.06
    assert eff.concrete["protocol_tvl_usd"] == 3_297_344_734.00
    assert eff.concrete["observed_reach_unvalued_assets"] == [EETH]
    assert eff.concrete["observed_reach_unvalued_reasons"] == ["asset_not_in_recorded_holdings"]
    assert "observed_reach_value_usd" not in eff.concrete
    assert "reach_indeterminate" not in eff.concrete


@pytest.mark.parametrize(
    ("tvl", "expected_check"),
    [
        pytest.param(1_000.0, "within_protocol_tvl", id="within_tvl_says_it_was_checked"),
        pytest.param(None, "skipped_no_tvl", id="no_tvl_snapshot_skips_out_loud"),
    ],
)
def test_a_priced_floor_publishes_the_outcome_of_the_tvl_check(tvl, expected_check):
    eff = _partial_floor(floor_usd=100.0, tvl=tvl)

    assert eff.concrete["reach_tvl_check"] == expected_check
    assert eff.concrete["observed_reach_priced_usd"] == 100.0
    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["observed_reach_unvalued_assets"] == [EETH]


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


def test_a_truncated_holdings_list_names_truncation_as_the_reason():
    """A capped list must lower confidence, never produce a confident low; the below-cap reason says only the asset
    isn't recorded.
    """
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0, completeness=HOLDINGS_COMPLETENESS_AT_PAGE_CAP),)
    moved = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(EETH, CONTRACT, PAYEE, 5),)),))
    eff = _value_out([moved], holders=holdings, floor=1.0)

    assert eff.concrete["reach_determined"] is False
    assert eff.concrete["observed_reach_unvalued_reasons"] == ["holdings_at_page_cap"]
    eff2 = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=1.0)
    assert eff2.concrete["observed_reach_unvalued_reasons"] == ["asset_not_in_recorded_holdings"]
    held = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    assert _value_out([held], holders=holdings, floor=1.0).concrete["observed_reach_value_usd"] == 100.0


def test_two_logs_of_one_asset_out_of_one_holder_attribute_that_holding_once():
    """The figure is a holder's whole balance for the asset, so a second log of it must add nothing (two logs read a
    $100 holding as $200).
    """
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0),)
    one_log = SimResult(calls=(SimCallResult(True, "0x", None, (transfer_log(TOKEN, CONTRACT, PAYEE, 5),)),))
    send_and_fee = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, CONTRACT, HOLDER, 1)),
            ),
        )
    )
    single = _value_out([one_log], holders=holdings, floor=0.0)
    doubled = _value_out([send_and_fee], holders=holdings, floor=0.0)

    assert single.concrete["observed_reach_value_usd"] == 100.0
    assert doubled.concrete["observed_reach_value_usd"] == 100.0, (
        "a second log of the same asset added the balance again"
    )
    assert doubled.concrete["observed_reach_holders"] == [CONTRACT]
    assert doubled.concrete["observed_reach_assets"] == [TOKEN]
    two_assets = SimResult(
        calls=(
            SimCallResult(
                True,
                "0x",
                None,
                (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5)),
            ),
        )
    )
    summed = _value_out(
        [two_assets],
        holders=(AssetHolding(CONTRACT, TOKEN, 100.0), AssetHolding(CONTRACT, EETH, 25.0)),
        floor=0.0,
    )
    assert summed.concrete["observed_reach_value_usd"] == 125.0
    assert summed.concrete["observed_reach_assets"] == sorted([TOKEN, EETH])


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


def test_a_fully_priced_two_holder_move_is_untouched_by_the_pair_keying():
    """Whole-dict equality so a new key can't slip in; the proving execution is not a reach key."""
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(TOKEN, HOLDER, PAYEE, 7))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    holdings = (AssetHolding(CONTRACT, TOKEN, 100.0), AssetHolding(HOLDER, TOKEN, _VAULT_WEETH_USD))
    eff = _value_out([moved], holders=holdings, floor=0.0, tvl=3_322_211_996.00)

    reach = dict(eff.concrete)
    assert reach.pop(PROVING_EXECUTION_KEY)["target"] == CONTRACT.lower()
    assert reach == {
        "destination": PAYEE,
        "observed_reach_holders": sorted([CONTRACT, HOLDER]),
        "observed_reach_assets": [TOKEN],
        "reach_determined": True,
        "reach_tvl_check": "within_protocol_tvl",
        "observed_reach_value_usd": 100.0 + _VAULT_WEETH_USD,
    }


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


def test_a_refused_partial_floor_still_names_the_holders_the_figure_came_from():
    """The contradiction's subjects must be named to be inspectable."""
    eff = _two_holders_move_one_asset(_VAULT_WEETH_USD, tvl=1_000.0)

    assert eff.concrete["reach_tvl_check"] == "exceeds_protocol_tvl"
    assert eff.concrete["observed_reach_rejected_usd"] == _VAULT_WEETH_USD
    assert "observed_reach_priced_usd" not in eff.concrete
    assert eff.concrete["observed_reach_priced_holders"] == [HOLDER]
    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": CONTRACT, "asset": TOKEN, "reason": "asset_not_in_recorded_holdings"}
    ]


def test_the_single_holder_partial_floor_publishes_the_pair_it_could_not_value():
    logs = (transfer_log(TOKEN, CONTRACT, PAYEE, 5), transfer_log(EETH, CONTRACT, PAYEE, 5))
    moved = SimResult(calls=(SimCallResult(True, "0x", None, logs),))
    eff = _value_out([moved], holders=(AssetHolding(CONTRACT, TOKEN, 100.0),), floor=0.0, tvl=1_000.0)

    assert eff.concrete["observed_reach_unvalued_pairs"] == [
        {"holder": CONTRACT, "asset": EETH, "reason": "asset_not_in_recorded_holdings"}
    ]
    assert eff.concrete["observed_reach_unvalued_assets"] == [EETH]
    assert eff.concrete["observed_reach_priced_usd"] == 100.0
    assert eff.concrete["observed_reach_priced_holders"] == [CONTRACT]


def test_every_reach_key_the_producer_publishes_reaches_the_row_and_the_claim():
    """``_RESIDUE_JSON_KEYS`` and ``claims_bridge._REACH_KEYS`` are the only paths to a published surface; an unnamed
    key silently drops.
    """
    from services.effects.claims_bridge import _REACH_KEYS
    from workers.effects_worker import _RESIDUE_JSON_KEYS

    branches = (
        _two_holders_move_one_asset(_VAULT_WEETH_USD),  # partial floor, figure published
        _two_holders_move_one_asset(_VAULT_WEETH_USD, tvl=1_000.0),  # partial floor, refused
        _two_holders_move_one_asset(None),  # partial floor, nothing priced
        _value_out([_native_transfer_out()], holders=(AssetHolding(CONTRACT, NATIVE, 42.0),), floor=1.0),  # measured
        _value_out([SimResult(calls=(SimCallResult(True, "0x", None, ()),))], floor=7.0),  # indeterminate
    )
    published = {
        key for eff in branches for key in eff.concrete if key.startswith(("observed_reach", "reach_", "protocol_tvl"))
    }
    assert {"observed_reach_unvalued_pairs", "observed_reach_priced_holders"} <= published
    assert published - set(_RESIDUE_JSON_KEYS) == set()
    assert published - set(_REACH_KEYS) == set()
