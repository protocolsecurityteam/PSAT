"""Code-control sheet ceiling (CC1-CC7): replacing a node's code removes it from between the principal and what it
holds, so the node's own priced sheet bounds the move from above.
"""

from __future__ import annotations

import pytest

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.constants import FREEZE_CAPABILITY_PROVEN
from services.scoring.schema import PrincipalRef, entity_key
from tests.support.scoring_builders import (
    EOA,
    IMPL,
    KEY_C,
    KEY_IMPL,
    KEY_PROXY,
    KEY_V,
    OWNERS,
    SAFE,
    SCANNED,
    VAULT,
    C,
    _cc_row,
    bounded_by_sheet,
    facts,
    flow_sig,
    fold,  # noqa: F401  (fold fixture, registered by import)
    pause_sig,
    proven,
    reaches,
    sig,
    value_plane,
)
from utils import execution_record as EX
from utils.scoring_status import VALUE_STATE_PROVEN_REACH


def test_cc1_code_control_over_a_priced_node_is_priced_at_that_nodes_own_sheet(fold):
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    finding = _cc_row(document)
    assert finding["value_at_stake_usd"] == 5_000_000.0
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert finding["value_by_entity"] == {KEY_C: 5_000_000.0}
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    # Split, never widened.
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["reach_composed_magnitudes"] == []
    # The b7 conjunction is satisfied from the sheet source.
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert finding["value_at_stake_is_floor"] is False
    assert finding["value_band"] == "<= $1M-$10M"
    assert finding["value_at_stake_basis"].startswith("<= ")
    assert "SHEET CEILING" in finding["value_at_stake_basis"]

    entry = finding["reach_sheet_ceiling_magnitudes"][0]
    assert entry["entity"] == KEY_C
    assert entry["published_usd"] == entry["sheet_usd"] == 5_000_000.0
    assert entry["sheet_state"] == P.SHEET_PRICED
    assert entry["ceiling_reason"] == P.CEILING_ADMITTED
    # The reference corpus has no full-coverage carrier.
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["assets_observed"] == entry["assets_priced"] == 1
    assert entry["assets_not_priced"] == []
    assert entry["unpriced_positions"] == 0
    assert entry["per_asset"] == [{"asset": "usdc", "usd": 5_000_000.0, "state": P.ASSET_PRICED}]
    assert "every asset observed at this entity carries a determined reading" in entry["bound_direction_basis"]
    assert finding["reach_sheet_ceiling_magnitudes_withheld"] == []
    # #170: a balance observation has no execution to name, and the reason must not be a fault.
    execution = entry[EX.PROVING_EXECUTION_KEY]
    assert execution["state"] == EX.EXECUTION_NOT_DETERMINED
    assert execution["reason"] == EX.REASON_NOT_PROVEN_BY_A_CALL
    assert EX.REASON_NOT_PROVEN_BY_A_CALL in EX.NOT_DETERMINED_REASONS
    assert EX.REASON_NOT_PROVEN_BY_A_CALL not in EX.FAULT_REASONS
    # The structural census walks proving_execution keys, so the registration is load-bearing.
    assert FOLD._execution_fault_census(document.findings, document.provenance["subsumed_rows"]) is None
    census = finding["magnitude_witness_census"]
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["magnitude_not_witnessed"] == 0
    assert census["magnitude_composed"] == 0


def test_cc2_gate_control_over_the_same_node_earns_no_ceiling(fold):
    """Seizing who may call leaves the node's code standing, so the sheet would be an upper bound on an upper bound."""
    plane = value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    principals = {1: facts(1, EOA, "eoa")}
    for capability in sorted(FOLD.K.GATE_CONTROL_CAPABILITIES):
        signal = sig(
            claim_id=capability,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(KEY_C),
        )
        finding = _cc_row(fold([signal], principals=principals, value=plane), capability)
        assert finding["value_at_stake_usd"] is None, capability
        assert finding["value_state"] == "not_determined", capability
        assert finding["entities_priced_from_a_sheet_ceiling"] == [], capability
        assert finding["reach_sheet_ceiling_magnitudes"] == [], capability
        assert finding["value_band"] == "not_determined", capability


def test_cc3_a_downstream_entity_of_a_code_controlled_node_earns_no_ceiling(fold):
    """A downstream governed node cannot borrow the controlled node's ceiling.

    Code control expands over the closure, but for a downstream B that A merely governs you are
    back to gate control one level down (B's own code still stands). So the ceiling is the
    CONTROLLED node's alone, though the row provably reaches both and both are priced.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    document = fold(
        [signal],
        principals={1: facts(1, EOA, "eoa")},
        closure={KEY_C: {KEY_V}},
        value=value_plane({KEY_C: {"usdc": 1_000_000.0}, KEY_V: {"usdc": 900_000_000.0}}),
    )
    finding = _cc_row(document)
    assert KEY_V in finding["reach_entities"]
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    assert finding["value_by_entity"] == {KEY_C: 1_000_000.0}
    assert finding["value_at_stake_usd"] == 1_000_000.0
    # Disclosed as unmeasured, never dropped or summed.
    assert KEY_V in {row["entity"] for row in finding["undetermined_instances"]}


@pytest.mark.parametrize(
    ("per_asset", "state", "reason"),
    [
        ({}, P.SHEET_NO_ROWS, P.CEILING_NO_ROWS),
        ({"usdc": 0.0}, P.SHEET_BELOW_RESOLUTION, P.CEILING_BELOW_RESOLUTION),
        ({}, P.SHEET_UNPRICED, P.CEILING_UNPRICED),
    ],
)
def test_cc4_an_undetermined_sheet_refuses_under_its_own_reason(fold, per_asset, state, reason):
    """Dust, unpriced and unobserved are different facts; collapsing them reports a price-feed gap as a coverage gap."""
    states = {
        P.SHEET_BELOW_RESOLUTION: {KEY_C: {"usdc": P.ASSET_BELOW_RESOLUTION}},
        P.SHEET_UNPRICED: {KEY_C: {"usdc": P.ASSET_UNPRICED}},
        P.SHEET_NO_ROWS: {},
    }[state]
    plane = value_plane({KEY_C: per_asset} if per_asset else {}, contracts=(KEY_C,), per_asset_state=states)
    assert plane.sheet_state(KEY_C) == state
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] is None
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert finding["reach_sheet_ceiling_magnitudes"] == []
    assert [row["why"] for row in finding["undetermined_instances"]] == [
        f"code_control_sheet_ceiling_refused({reason})"
    ]


def test_cc4_a_proven_empty_sheet_is_a_zero_ceiling_not_a_missing_one(fold):
    """``ValuePlane.total`` returns ``0.0`` here, so ``is not None`` admits it and ``== priced`` refuses it.

    The reference corpus can't exercise this arm.
    """
    plane = value_plane(
        {KEY_C: {"usdc": 0.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    assert plane.sheet_state(KEY_C) == P.SHEET_PROVEN_EMPTY
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] == 0.0
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    entry = finding["reach_sheet_ceiling_magnitudes"][0]
    assert entry["ceiling_reason"] == P.CEILING_PROVEN_EMPTY
    assert entry["sheet_state"] == P.SHEET_PROVEN_EMPTY
    assert entry["published_usd"] == 0.0
    assert "PROVEN ZERO" in entry["reading"]
    assert entry["reading"] != FOLD._CEILING_SOURCE_READINGS[(P.CEILING_ADMITTED, True)] + FOLD._CEILING_CLOSING
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["assets_not_priced"] == [] and entry["unpriced_positions"] == 0

    # A restaking position has no USD column, so a $0 would bound a magnitude at zero over unpriced holdings.
    positions = value_plane(
        {KEY_C: {"usdc": 0.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    positions.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    assert positions.proven_empty_refusal(KEY_C) == P.EMPTY_REFUSED_UNPRICED_POSITIONS
    assert positions.sheet_state(KEY_C) == P.SHEET_UNPRICED
    assert positions.total(KEY_C) is None
    assert P.ceiling_for(positions, KEY_C) == (None, P.CEILING_UNPRICED)
    partial = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=positions))
    assert partial["reach_sheet_ceiling_magnitudes"] == []
    assert partial["entities_priced_from_a_sheet_ceiling"] == []
    assert f"code_control_sheet_ceiling_refused({P.CEILING_UNPRICED})" in [
        instance["why"] for instance in partial["undetermined_instances"]
    ]


def test_cc4_a_shared_implementation_earns_no_ceiling(fold):
    """``_entity_contribution`` refuses a shared-implementation key before every branch, so ``alias_ambiguous`` has
    no published carrier.
    """
    plane = value_plane({KEY_IMPL: {"usdc": 9_000_000.0}}, contracts=(KEY_PROXY,))
    plane.alias_ambiguous = {KEY_IMPL}
    signal = sig(
        deployment_address=IMPL,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_IMPL),
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] is None
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert [row["why"] for row in finding["undetermined_instances"]] == [
        "shared_implementation_folds_onto_no_proxy(not_determined)"
    ]
    assert P.ceiling_for(plane, KEY_IMPL) == (None, P.CEILING_ALIAS_AMBIGUOUS)


def test_cc5_pause_over_a_priced_node_stays_not_determined(fold):
    """Nothing witnesses what share of a sheet a pause immobilises."""
    signal = pause_sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(FREEZE_CAPABILITY_PROVEN, ("freeze_capability_proven",)),
        **reaches(KEY_C),
    )
    finding = _cc_row(
        fold([signal], principals={1: facts(1, EOA, "eoa")}, value=value_plane({KEY_C: {"usdc": 5_000_000.0}})),
        "pause.set",
    )
    assert finding["value_at_stake_usd"] is None
    assert finding["entities_priced_from_a_sheet_ceiling"] == []
    assert finding["reach_sheet_ceiling_magnitudes"] == []


def test_cc6_two_holders_over_one_ceiling_do_not_flatten(fold):
    """Value and difficulty are separate axes: raw_points ratio equals the rung ratio."""
    signals = [
        sig(
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(KEY_C),
        ),
        sig(
            function_name="g",
            selector="0xfeedface",
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
            **proven(1.0),
            **reaches(KEY_C),
        ),
    ]
    document = fold(
        signals,
        principals={
            1: facts(1, EOA, "eoa"),
            2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3),
        },
        value=value_plane({KEY_C: {"usdc": 5_000_000_000.0}}),
    )
    rows = {f["principal_unit"]: f for f in document.findings}
    eoa_row = rows[entity_key("ethereum", EOA)]
    safe_row = rows[entity_key("ethereum", SAFE)]
    assert eoa_row["value_at_stake_usd"] == safe_row["value_at_stake_usd"] == 5_000_000_000.0
    assert eoa_row["value_band"] == safe_row["value_band"] == "<= >$1B"
    assert eoa_row["raw_points"] / safe_row["raw_points"] == pytest.approx(eoa_row["weakness"] / safe_row["weakness"])
    assert eoa_row["weakness"] > safe_row["weakness"]


def test_cc7_a_sheet_ceiling_charges_the_exposure_budget_nothing(fold):
    """Ceilings are risk-weighted upper bounds, never expected loss.

    A ceiling in the numerator (1) inflates ``exposure_usd`` off bounds, so the coverage
    disclosure would claim near-total coverage on their strength, and (2) SPENDS the entity's
    budget, trimming a later row that measured a real extraction there.

    Here the flow.out row measures a real $2M at the shared entity; the ceiling row reaches it
    too and must leave the budget untouched.
    """
    ceiling_row = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    measured = flow_sig(
        function_name="withdraw",
        selector="0x11112222",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        gates=bounded_by_sheet(2_000_000.0),
        **proven(0.9),
        **reaches(KEY_C),
    )
    document = fold(
        [ceiling_row, measured],
        principals={1: facts(1, EOA, "eoa"), 2: facts(2, SAFE, "safe", owners=OWNERS, threshold=3)},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}),
    )
    upgrade = _cc_row(document)
    flow = _cc_row(document, "flow.out")
    assert upgrade["value_at_stake_usd"] == 5_000_000.0
    assert upgrade["exposure_usd"] is None
    assert upgrade["exposure_entities_charged"] == []
    assert flow["exposure_usd"] == pytest.approx(2_000_000.0 * flow["severity_proven"] * flow["weakness"])
    gaps = {(g["principal_unit"], g["capability"]): g for g in document.provenance["exposure_gaps"]}
    ceiling_gap = gaps[(upgrade["principal_unit"], "upgrade.implementation")]
    assert ceiling_gap["ceiling_entities_excluded_from_exposure"] == [KEY_C]
    assert ceiling_gap["budget_exhausted_entities"] == []
    assert ceiling_gap["budget_partially_exhausted_entities"] == []
    assert "ceiling_entities_excluded_from_exposure" in ceiling_gap["reading"]
    coverage = document.provenance["exposure_coverage"]
    assert coverage["findings_with_exposure_not_determined"] >= 1
    assert coverage["perimeter_usd_charged"] == pytest.approx(5_000_000.0)


def test_cc7_the_ceiling_is_capped_per_key_and_never_per_row(fold):
    """S6: the cap holds per key, not per row (the corpus publishes $4.217B over eight hosts)."""
    signals = [
        sig(
            deployment_address=address,
            function_name=name,
            selector=selector,
            authority_openness="restricted",
            principal_state="enumerated",
            principal_refs=(PrincipalRef(1, "ethereum", EOA),),
            **proven(1.0),
            **reaches(key),
        )
        for address, name, selector, key in (
            (C, "f", "0xdeadbeef", KEY_C),
            (VAULT, "g", "0xfeedface", KEY_V),
        )
    ]
    plane = value_plane({KEY_C: {"usdc": 3_000_000.0}, KEY_V: {"usdc": 4_000_000.0}})
    finding = _cc_row(fold(signals, principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] == 7_000_000.0
    for entry in finding["reach_sheet_ceiling_magnitudes"]:
        assert entry["published_usd"] == plane.total(entry["entity"])
        assert entry["published_usd"] < finding["value_at_stake_usd"]


def test_cc1_a_partly_priced_sheet_bounds_the_priced_portion_and_not_the_move(fold):
    """SHEET_PRICED is a floor, so an entity with an unpriced asset holds more than its total and "at most" would be
    false.
    """
    signal = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    plane = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "wsteth": P.ASSET_UNPRICED}},
    )
    finding = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["value_at_stake_usd"] == 5_000_000.0
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]

    entry = finding["reach_sheet_ceiling_magnitudes"][0]
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    assert entry["assets_observed"] == 2 and entry["assets_priced"] == 1
    assert entry["assets_not_priced"] == ["wsteth"]
    assert {a["asset"]: a["usd"] for a in entry["per_asset"]} == {"usdc": 5_000_000.0, "wsteth": None}
    assert "DO NOT bound the move" in entry["reading"]
    assert "AT-MOST" not in entry["reading"].split(". Whatever it bounds")[0]
    assert finding["entities_holding_unpriced_assets"] == [KEY_C]
    assert finding["value_at_stake_bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    dust = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_BELOW_RESOLUTION}},
    )
    dusty = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=dust))
    assert dusty["reach_sheet_ceiling_magnitudes"][0]["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # The restaking plane has no USD column.
    positions = value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    positions.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    with_positions = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=positions))
    held = with_positions["reach_sheet_ceiling_magnitudes"][0]
    assert held["unpriced_positions"] == 1
    assert held["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED


def test_cc7_a_subsumed_rows_sheet_ceiling_leaks_into_the_budget_in_neither_direction(fold):
    """Subsumption leaks both ways with a sheet ceiling, on one principal unit.
      IN: a subsumed row's ceiling at an entity the top row doesn't price would be charged, because the exposure
      skip reads the top row's ceiling list.
      OUT: the top row's ceiling marks the key occupied, discarding a subsumed row's witnessed value there.
    """
    top = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    witnessed_at_c = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        selector="0x11112222",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        gates=bounded_by_sheet(400_000.0),
        **proven(0.5),
        **reaches(KEY_C),
    )
    ceiling_at_v = sig(
        claim_id="exec.arbitrary",
        function_name="execute",
        selector="0x33334444",
        deployment_address=VAULT,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.4),
        **reaches(KEY_V),
    )
    document = fold(
        [top, witnessed_at_c, ceiling_at_v],
        principals={1: facts(1, EOA, "eoa")},
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}, KEY_V: {"usdc": 900_000.0}}),
    )
    finding = _cc_row(document)
    assert finding["capability"] == "upgrade.implementation"
    assert [r["capability"] for r in finding["subsumed_capabilities"]] == ["authority.replace", "exec.arbitrary"]

    exclusive = finding["subsumed_exclusive_value_by_entity"]
    assert KEY_C in exclusive and exclusive[KEY_C]["usd"] == 400_000.0
    assert KEY_V in exclusive
    assert finding["subsumed_exclusive_sheet_ceiling_entities"] == [KEY_V]

    assert finding["exposure_usd"] == pytest.approx(400_000.0 * exclusive[KEY_C]["fraction"])
    assert finding["exposure_entities_charged"] == [KEY_C]
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if (g["principal_unit"], g["capability"]) == (finding["principal_unit"], "upgrade.implementation")
    )
    assert gap["ceiling_entities_excluded_from_exposure"] == [KEY_V]
    assert gap["budget_exhausted_entities"] == [] and gap["budget_partially_exhausted_entities"] == []
