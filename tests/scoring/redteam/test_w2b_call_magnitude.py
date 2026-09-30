
from __future__ import annotations

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import FunctionSignal, PrincipalRef, Tri
from tests.support.scoring_builders import (
    EOA,
    KEY_C,
    KEY_V,
    OWNERS,
    SAFE,
    TIMELOCK,
    bounded_by_sheet,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)
from utils.scoring_status import VALUE_BOUND_EXACT, VALUE_BOUND_FLOOR


def _exact_flow(magnitude: float, *keys: str) -> FunctionSignal:
    return flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", magnitude).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(*keys, bound=VALUE_BOUND_EXACT),
    )


def test_r4_one_exact_witness_is_a_per_call_bound_not_a_per_key_one(fold):
    """``min(held, magnitude)`` per key then summed exceeds what one call's witness proved."""
    document = fold(
        [_exact_flow(100.0, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert sum(finding["value_by_entity"].values()) <= 100.0
    # An exhausted budget is not a measurement of zero.
    assert 0.0 not in finding["value_by_entity"].values()
    assert any(row["entity"] == KEY_V for row in finding["undetermined_instances"])
    cap = finding["witnessed_magnitude_caps"][0]
    assert (cap["witnessed_usd"], cap["uncapped_sum_usd"], cap["published_sum_usd"]) == (100.0, 200.0, 100.0)
    assert cap["entities_left_not_determined"] == [KEY_V]
    assert finding["exposure_usd"] <= 100.0


def test_r4_a_capped_split_between_keys_is_published_as_order_determined(fold):
    document = fold(
        [_exact_flow(100.0, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 60.0}, KEY_V: {"usdc": 60.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert finding["value_by_entity"] == {KEY_C: 60.0, KEY_V: 40.0}
    cap = finding["witnessed_magnitude_caps"][0]
    assert cap["uncapped_sum_usd"] == 120.0
    assert "not by evidence" in cap["reading"]


def test_r4_a_sub_cent_residual_is_not_a_published_zero(fold):
    """Every published dollar is rounded to the cent, so a $0.004 residual would publish as $0.00."""
    document = fold(
        [_exact_flow(100.004, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 100.0}, KEY_V: {"usdc": 100.0}}),
    )
    finding = document.findings[0]
    assert finding["value_by_entity"] == {KEY_C: 100.0}
    assert finding["value_at_stake_usd"] == 100.0
    cap = finding["witnessed_magnitude_caps"][0]
    assert cap["entities_left_not_determined"] == [KEY_V]
    assert any(
        row["entity"] == KEY_V and "consumed_by_earlier_keys" in row["why"] for row in finding["undetermined_instances"]
    )


def test_r4_reach_membership_survives_a_magnitude_the_fold_refuses(fold):
    """Reading ``reach_entities`` off the value map deleted memberships whose magnitude was undetermined."""
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, KEY_V, bound=VALUE_BOUND_FLOOR),
    )
    document = fold(
        [signal],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])


def test_r4_a_floor_magnitude_over_two_keys_has_no_apportionment_witness(fold):
    """Multiplying or splitting the floor would invent a share nobody witnessed."""
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, KEY_V, bound=VALUE_BOUND_FLOOR),
    )
    document = fold(
        [signal],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_state"] == "not_determined"
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    assert {row["entity"] for row in finding["undetermined_instances"]} == {KEY_C, KEY_V}
    cap = finding["witnessed_magnitude_caps"][0]
    assert (cap["witness_state"], cap["published_sum_usd"]) == ("proven_floor", None)


def test_r4_one_key_keeps_its_floor_witness_exactly(fold):
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 100.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_FLOOR),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000_000.0}}))
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert finding["value_by_entity"] == {KEY_C: 100.0}
    assert finding["witnessed_magnitude_caps"] == []


def test_r4_a_floor_magnitude_is_bounded_by_the_entity_it_is_charged_against(fold):
    """The floor branch skipped ``min(sheet, witness)``, so a $28M floor published against a $1k sheet."""
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 28_000_000.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_FLOOR),
    )
    document = fold([signal], value=value_plane({KEY_C: {"usdc": 1_000.0}}))
    finding = document.findings[0]
    assert finding["value_by_entity"] == {KEY_C: 1_000.0}
    assert finding["value_at_stake_usd"] == 1_000.0
    assert finding["unbounded_floor_magnitudes"] == []


def test_r4_a_floor_against_an_undetermined_sheet_is_disclosed_not_absorbed(fold):
    signal = flow_sig(
        function_name="withdraw",
        authority_openness="open",
        principal_state="none_required",
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 28_000_000.0).to_json()},
        **proven(0.9, ("caller_arbitrary_proven",)),
        **reaches(KEY_C, bound=VALUE_BOUND_FLOOR),
    )
    document = fold([signal], value=value_plane(contracts=(KEY_C,)))
    finding = document.findings[0]
    assert finding["value_by_entity"] == {KEY_C: 28_000_000.0}
    disclosed = finding["unbounded_floor_magnitudes"]
    assert [row["entity"] for row in disclosed] == [KEY_C]
    assert disclosed[0]["witnessed_floor_usd"] == 28_000_000.0


def test_r7_an_exhausted_exposure_budget_is_not_a_measured_zero(fold):
    """``priced_entities`` counted before the budget test, publishing a measured 0.0 from accounting that never ran."""
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000002{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, SAFE, TIMELOCK))
    ]
    document = fold(
        signals,
        principals={
            1: facts(1, EOA, "eoa"),
            2: facts(2, SAFE, "eoa"),
            3: facts(3, TIMELOCK, "eoa"),
        },
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    starved = [f for f in document.findings if f["exposure_usd"] is None]
    assert starved, "the third row must find no budget left"
    finding = starved[0]
    assert finding["exposure_entities_charged"] == [KEY_C]
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if g["principal_unit"] == finding["principal_unit"] and g["capability"] == finding["capability"]
    )
    exhausted = gap["budget_exhausted_entities"]
    assert [row["entity"] for row in exhausted] == [KEY_C]
    claimants = {row["principal_unit"] for row in exhausted[0]["claimed_by"]}
    assert claimants and finding["principal_unit"] not in claimants
    assert round(sum(row["fraction_taken"] for row in exhausted[0]["claimed_by"]), 6) == 1.0
    assert gap["budget_partially_exhausted_entities"] == []


def test_r7_a_partly_charged_row_says_its_figure_is_marginal(fold):
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000004{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, SAFE))
    ]
    document = fold(
        signals,
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    later = document.findings[1]
    assert later["exposure_usd"] is not None and later["exposure_usd"] > 0
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if g["principal_unit"] == later["principal_unit"] and g["capability"] == later["capability"]
    )
    trimmed = gap["budget_partially_exhausted_entities"]
    assert [row["entity"] for row in trimmed] == [KEY_C]
    assert trimmed[0]["fraction_taken"] < trimmed[0]["fraction_wanted"]
    assert trimmed[0]["claimed_by"][0]["principal_unit"] == document.findings[0]["principal_unit"]
    assert "MARGINAL" in gap["reading"]
    assert "where the exposure is null" not in gap["reading"]


def test_r8_rows_that_tie_publish_that_the_order_decided_the_split(fold):
    """The ``principal_unit`` tie-break decides the budget split, so the split is disclosed."""
    signals = [
        sig(
            claim_id="upgrade.implementation",
            function_name=f"upgradeTo{index}",
            contract_id=index + 1,
            selector=f"0x0000003{index}",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(index + 1, "ethereum", address),),
            gates=bounded_by_sheet(10_000_000.0),
            **proven(1.0),
            **reaches(KEY_C),
        )
        for index, address in enumerate((EOA, TIMELOCK))
    ]
    document = fold(
        signals,
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, TIMELOCK, "eoa")},
        value=value_plane({KEY_C: {"usdc": 10_000_000.0}}),
    )
    first, second = document.findings[0], document.findings[1]
    assert first["raw_points"] == second["raw_points"]
    assert first["exposure_order_tie"]["tied_with"] == [second["principal_unit"]]
    assert second["exposure_order_tie"]["tied_with"] == [first["principal_unit"]]
    assert first["exposure_order_tie"]["shared_entities"] == [KEY_C]
    assert first["exposure_order_tie"]["position_in_tie"] == 0
    assert "not by evidence" in first["exposure_order_tie"]["reading"]
    assert first["exposure_usd"] > second["exposure_usd"]


def test_s5_an_entity_holding_unpriced_assets_makes_the_value_a_floor(fold):
    """The flag only read whole-instance undetermination."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(5_000_000.0),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane({KEY_C: {"usdc": 5_000_000.0}})
    plane.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert finding["undetermined_instances"] == []
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_band"].startswith(">= ")
    assert finding["entities_priced_from_a_composed_ceiling"] == []


def test_s5_one_priced_asset_beside_unanswered_ones_is_not_a_priced_entity(fold):
    """Sheet state ranks ``priced`` first; NULL ``usd_value`` beside priced rows (the dominant shape) must still make
    the total a floor.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        # Set above both sheets so the floor flag is what the assertions read.
        gates=bounded_by_sheet(7_000_000.0),
        **proven(1.0),
        **reaches(KEY_C, KEY_V),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}, KEY_V: {"usdc": 2_000_000.0}},
        per_asset_state={
            KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED},
            KEY_V: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_BELOW_RESOLUTION},
        },
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert plane.sheet_state(KEY_C) == P.SHEET_PRICED
    assert finding["undetermined_instances"] == []
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_FLOOR
    assert finding["value_at_stake_is_floor"] is True
    assert finding["entities_holding_unpriced_assets"] == sorted([KEY_C, KEY_V])
    assert finding["value_band"].startswith(">= ")
    assert finding["entities_priced_from_a_composed_ceiling"] == []


def test_s5_a_fully_priced_entity_earns_its_hard_band(fold):
    """Gate control shows ``is_floor`` stays off over an absent figure; code control's ceiling is a different case."""
    signal = sig(
        claim_id="authority.replace",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_PROVEN_ZERO}},
    )
    document = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane)
    finding = document.findings[0]
    assert finding["value_at_stake_is_floor"] is False
    assert finding["entities_holding_unpriced_assets"] == []
    assert not finding["value_band"].startswith(">= ")
    assert finding["value_at_stake_usd"] is None
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED


def test_b7_two_absent_coverage_signals_do_not_add_up_to_an_exact_total(fold):
    """The absence of two unrelated coverage signals says nothing about direction, so the band carries no qualifier."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates={"reach_magnitude_usd": Tri.proven("proven_floor", 1_000_000.0).to_json()},
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    finding = fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane).findings[0]
    assert finding["value_at_stake_usd"] == 1_000_000.0
    assert finding["undetermined_instances"] == []
    assert finding["entities_holding_unpriced_assets"] == []
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert finding["value_at_stake_is_floor"] is False
    assert finding["value_band"] == "$1M-$10M"
    assert "NEITHER" not in finding["value_at_stake_basis"]
    assert not hasattr(FOLD, "BOUND_DIRECTION_EXACT")


def test_r21_a_reach_key_outside_the_perimeter_is_disclosed(fold):
    """Its weight would be in no denominator."""
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C, KEY_V),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}}, contracts=(KEY_C,)),
    )
    detail = document.document()["model_parameters"]["confidence_detail"]
    assert detail["signal_entities_outside_perimeter"] == [KEY_V]
