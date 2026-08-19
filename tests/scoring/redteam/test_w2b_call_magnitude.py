"""W2b: per-call magnitude, budget honesty, order disclosure, floor flag.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

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
    """One openly-callable ``flow.out`` call with one exact magnitude witness."""
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
    """A magnitude proven for one call, charged once per reached key, is N x real.

    ``min(held, magnitude)`` per key bounds each key by the witness and then sums
    them, so two keys published twice the one number the witness proved. The
    published sum may never exceed the witness the call carries.
    """
    document = fold(
        [_exact_flow(100.0, KEY_C, KEY_V)],
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 1_000_000.0}}),
    )
    finding = document.findings[0]
    assert finding["value_at_stake_usd"] == 100.0
    assert sum(finding["value_by_entity"].values()) <= 100.0
    # The key left with no room is not_determined: an exhausted budget is not a
    # measurement that the entity holds nothing.
    assert 0.0 not in finding["value_by_entity"].values()
    assert any(row["entity"] == KEY_V for row in finding["undetermined_instances"])
    cap = finding["witnessed_magnitude_caps"][0]
    assert (cap["witnessed_usd"], cap["uncapped_sum_usd"], cap["published_sum_usd"]) == (100.0, 200.0, 100.0)
    assert cap["entities_left_not_determined"] == [KEY_V]
    # The exposure the grade charges is bounded by the same one witness.
    assert finding["exposure_usd"] <= 100.0


def test_r4_a_capped_split_between_keys_is_published_as_order_determined(fold):
    """The cap has to fall somewhere, and where it falls is not evidence."""
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
    """A share that rounds to $0.00 IS a published zero, whatever it was.

    Testing the residual against exact zero let a $0.004 remainder through, and
    every published dollar is rounded to the cent — so the entity reached a
    consumer at $0.00 with a proven-looking figure behind it.
    """
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
    """Reach is membership; the dollars are a separate question with its own answer.

    Reading ``reach_entities`` off the value map deleted a proven membership
    whenever its magnitude was undetermined — so refusing to publish an unproven
    number would have silently emptied the reach sets it is meant to preserve.
    """
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
    # No magnitude survived the refusal...
    assert finding["value_at_stake_usd"] is None
    assert finding["value_by_entity"] == {}
    # ...and the membership did.
    assert finding["reach_entities"] == sorted([KEY_C, KEY_V])


def test_r4_a_floor_magnitude_over_two_keys_has_no_apportionment_witness(fold):
    """A floor proves how much moves, never how it divides between holders.

    Charging the floor once per key multiplies it; splitting it between them
    invents a share nobody witnessed. Both are refused, so the call's magnitude
    is not_determined until an apportionment witness exists.
    """
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
    """The N=1 case carries no ambiguity and must not be touched by the rule."""
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
    """A floor witness is not licence to publish more than the entity holds.

    The exact branch has always taken ``min(sheet, witness)``; the floor branch
    returned the witness untouched, so a $28M floor charged against a $1k sheet
    published $28M — the balance-sheet substitution inverted, with the word
    "floor" hiding which direction the error runs in.
    """
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
    # Nothing was left unbounded: the sheet did the bounding.
    assert finding["unbounded_floor_magnitudes"] == []


def test_r4_a_floor_against_an_undetermined_sheet_is_disclosed_not_absorbed(fold):
    """No sheet means nothing to bound the floor with, and that is a fact.

    The floor still stands — it is a witness — but it stands ALONE, and a reader
    must be able to tell a figure two witnesses agreed on from one the entity's
    own books never answered.
    """
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
    """Rows that spent an entity's budget leave the next one nothing to measure.

    ``priced_entities`` counted the entity before the budget test, so a row whose
    every entity was already claimed landed in the priced branch with ``mine ==
    0.0`` and published ``exposure_usd: 0.0`` beside a list of charged entities —
    a measured zero out of an accounting that never ran.
    """
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
    # The rows that took the budget are NAMED, so the null is attributable.
    claimants = {row["principal_unit"] for row in exhausted[0]["claimed_by"]}
    assert claimants and finding["principal_unit"] not in claimants
    assert round(sum(row["fraction_taken"] for row in exhausted[0]["claimed_by"]), 6) == 1.0
    assert gap["budget_partially_exhausted_entities"] == []


def test_r7_a_partly_charged_row_says_its_figure_is_marginal(fold):
    """A row charged at less than its own fraction publishes an understatement.

    The second row wants its full fraction of the vault and gets whatever the
    first left. The figure is still published — it is real — but reading it as
    this row's exposure to that entity is reading a marginal share as a total,
    and the gap entry is where the difference is named.
    """
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
    # The reading may not describe a published figure as an unmeasured one.
    assert "MARGINAL" in gap["reading"]
    assert "where the exposure is null" not in gap["reading"]


def test_r8_rows_that_tie_publish_that_the_order_decided_the_split(fold):
    """Equal points and capability leave the address string holding the money.

    The tie is broken by ``principal_unit``, and that order is spent on the
    exposure budget: the first row takes the shared entity's fraction and the
    second gets the remainder. The order stays deterministic; what it decided is
    published rather than read as an attribution.
    """
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
    # The disclosure is about the arbitrariness, not a reason to reorder.
    assert first["exposure_usd"] > second["exposure_usd"]


def test_s5_an_entity_holding_unpriced_assets_makes_the_value_a_floor(fold):
    """A partly-priced entity is a floor even when every instance answered.

    The flag read whole-instance undetermination only, so a row reaching an
    entity whose priced sheet covers part of what it holds published its total as
    the entity's value rather than as the floor it is.
    """
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
    # No contribution came through composition, so the floor is the row's own.
    assert finding["entities_priced_from_a_composed_ceiling"] == []


def test_s5_one_priced_asset_beside_unanswered_ones_is_not_a_priced_entity(fold):
    """The sheet state ranks ``priced`` first; the per-asset map holds the truth.

    An entity with one answered price and a hundred unanswered rows reads as
    ``priced`` at sheet level, so consulting that state published its one
    answered asset as the entity's value. The dominant real shape — balance rows
    whose ``usd_value`` is NULL beside rows that priced — has to make the total a
    floor, and an asset priced at the storage floor is the same shortfall.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        # One call over two keys, so the EXACT witness is a budget across them:
        # set above their sum, it leaves both sheets standing and the subject of
        # this test — the floor flag — is what the assertions read.
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
    # A reading at the storage floor is a holding the total does not carry, so
    # it is the same shortfall as one nobody priced.
    assert finding["entities_holding_unpriced_assets"] == sorted([KEY_C, KEY_V])
    assert finding["value_band"].startswith(">= ")
    assert finding["entities_priced_from_a_composed_ceiling"] == []


def test_s5_a_fully_priced_entity_earns_its_hard_band(fold):
    """The flag is an earned negative in the other direction and must stay off.

    Asked of GATE control: the coverage axis is the subject, and the row must
    reach the no-total case to show that ``is_floor`` stays off over an absent
    figure rather than over a small one. Code control over the same sheet now
    publishes a ceiling, which is a different case and is pinned as one.
    """
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
    # No magnitude witness, so there is no total — and a row with no total
    # claims no direction for it either.
    assert finding["value_at_stake_usd"] is None
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED


def test_b7_two_absent_coverage_signals_do_not_add_up_to_an_exact_total(fold):
    """The fall-through, and why it is not a fourth claim.

    Neither coverage signal fires here: no instance is undetermined and the
    entity's sheet covers everything it holds. That says nothing about the
    DIRECTION of the figures summed — this call's own witness is a proven FLOOR,
    trimmed to the sheet — so publishing "exact" would mint a two-sided claim
    out of the absence of two unrelated signals, which is the B7 defect on a new
    arm. The band carries no qualifier, exactly as it did before this field
    existed, and the direction says what was established: nothing.
    """
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
    # The fall-through leaves the row's own basis alone: it is not a bound
    # claim, so it is not rewritten into one.
    assert "NEITHER" not in finding["value_at_stake_basis"]
    assert not hasattr(FOLD, "BOUND_DIRECTION_EXACT")


def test_r21_a_reach_key_outside_the_perimeter_is_disclosed(fold):
    """The perimeter disclosure checked deployment keys and never reach keys.

    A reach key absent from the perimeter is value charged into a finding by an
    entity whose unanswered weight is in no denominator — the exact thing the
    disclosure exists to name.
    """
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
