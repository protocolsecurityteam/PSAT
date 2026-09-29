"""Code-control sheet ceiling (CC1-CC7).

The defect: code control had no magnitude path, so every code-control row fell through to
not_determined and the largest capabilities in a protocol ranked below a ninety-dollar
withdrawal. The fix is one branch, over one entity, under one argument: replacing what a node
DOES removes its own code from between the principal and what it holds, so the node's own
priced sheet bounds the move from ABOVE. Each case pins a boundary of that argument.

One of the twenty sections of the former ``test_scoring_redteam.py``.
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
    """The branch, whole: a figure, a band, a ceiling and an execution answer.

    The capability is proven over the node the signal was distilled on, whose sheet is priced.
    The code that would stand in the way is the code being replaced, so the figure is published,
    banded, and typed as an upper bound rather than an amount.
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
        value=value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}}),
    )
    finding = _cc_row(document)
    assert finding["value_at_stake_usd"] == 5_000_000.0
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert finding["value_by_entity"] == {KEY_C: 5_000_000.0}
    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    # SPLIT, never widened: a join to reach_composed_magnitudes[] must not find a sheet entity in it.
    assert finding["entities_priced_from_a_composed_ceiling"] == []
    assert finding["reach_composed_magnitudes"] == []
    # The row's one entity is a ceiling and nothing is missing from the sum, so the b7
    # conjunction is satisfied from the SHEET source (that direction's second producer).
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
    # The full-coverage carrier of the per-entity direction (the reference corpus has none):
    # every asset was priced, so the figure bounds the move from above. The observations it
    # stands on are published beside it (evidence the document doesn't carry is the defect the
    # execution block exists to prevent).
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["assets_observed"] == entry["assets_priced"] == 1
    assert entry["assets_not_priced"] == []
    assert entry["unpriced_positions"] == 0
    assert entry["per_asset"] == [{"asset": "usdc", "usd": 5_000_000.0, "state": P.ASSET_PRICED}]
    assert "every asset observed at this entity carries a determined reading" in entry["bound_direction_basis"]
    assert finding["reach_sheet_ceiling_magnitudes_withheld"] == []
    # The #170 answer. A sheet ceiling is proven by a BALANCE OBSERVATION, so there is no
    # execution to name, and the reason saying so must never be a fault (it would qualify the
    # whole document off an intact proof).
    execution = entry[EX.PROVING_EXECUTION_KEY]
    assert execution["state"] == EX.EXECUTION_NOT_DETERMINED
    assert execution["reason"] == EX.REASON_NOT_PROVEN_BY_A_CALL
    assert EX.REASON_NOT_PROVEN_BY_A_CALL in EX.NOT_DETERMINED_REASONS
    assert EX.REASON_NOT_PROVEN_BY_A_CALL not in EX.FAULT_REASONS
    # The reason rides a proving_execution key, so the structural census walks it; hence its registration is the
    # load-bearing half.
    assert FOLD._execution_fault_census(document.findings, document.provenance["subsumed_rows"]) is None
    # The census counts it as a third answer; left in magnitude_not_witnessed it would sit in the
    # population that publishes not_determined at the unpriced band's floor, which it does not do.
    census = finding["magnitude_witness_census"]
    assert census["magnitude_sheet_ceiling"] == 1
    assert census["magnitude_not_witnessed"] == 0
    assert census["magnitude_composed"] == 0


def test_cc2_gate_control_over_the_same_node_earns_no_ceiling(fold):
    """The anti-regression case, and the reason the split exists.

    Same principal, node and priced sheet; only the capability class differs. Seizing who MAY
    CALL leaves the node's own code, share math and caller conditions standing unexamined, so
    the sheet is an upper bound on an upper bound: not_determined. A figure here would undo the
    reach-model fix over a far larger population than the ceiling prices.
    """
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
    """§3.2, the constraint that keeps this from undoing the reach-model fix.

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
    # The downstream entity is DISCLOSED as unmeasured, never dropped or summed: no witness says what the reach
    # moves there.
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
    """The three refusals stay three, each naming the pipeline that owes it.

    A dust sheet, an unpriced one and one nobody observed are different facts (the first two
    have balances and no usable price, the third no balance observation); collapsing them would
    report a price-feed gap as a coverage gap. The figure is not_determined on all three, but
    the row exists: membership was proven, only the magnitude was not.
    """
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
    # The refusal carries its own typed reason into the why vocabulary; it is NOT a composition arm.
    assert [row["why"] for row in finding["undetermined_instances"]] == [
        f"code_control_sheet_ceiling_refused({reason})"
    ]


def test_cc4_a_proven_empty_sheet_is_a_zero_ceiling_not_a_missing_one(fold):
    """The EARNED NEGATIVE arm, which the reference corpus cannot exercise.

    ``ValuePlane.total`` returns ``0.0`` for a proven-empty sheet, so a naive
    ``total is not None`` admits it and a naive ``== priced`` silently refuses it. Every asset's
    QUANTITY is witnessed zero, proving that replacing this node's code moves nothing;
    not_determined over a proven zero is an under-claim. It bands at the floor either way; the
    STATE is the point.
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
    # Its own sentence: the priced sheet's sentence would call an earned negative an observation of holdings.
    assert "PROVEN ZERO" in entry["reading"]
    assert entry["reading"] != FOLD._CEILING_SOURCE_READINGS[(P.CEILING_ADMITTED, True)] + FOLD._CEILING_CLOSING
    # Every observed asset is a witnessed zero and no position has an absent USD column, so this
    # $0 IS an at-most on the move (coverage conjunct and earned negative agree).
    assert entry["bound_direction"] == FOLD.BOUND_DIRECTION_CEILING
    assert entry["assets_not_priced"] == [] and entry["unpriced_positions"] == 0

    # The CROSS-PLANE gate (formerly a shade of this arm, now a refusal). A restaking position
    # at the node has no USD column, so "every asset is a witnessed zero" is only a fact about the
    # PRICED sheet while the node holds something; a $0 there would contradict a plane already in
    # the document and bound a magnitude at zero over unpriced holdings. The sheet refuses the
    # empty state and publishes unpriced: no ceiling at all, not a $0 one.
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
    """The alias conjunct, refused by the guard that runs before every branch.

    An implementation two proxies share folds onto neither (pinning one charges the loser's
    sheet), and ``_entity_contribution`` refuses such a key ahead of the witnessed, composed and
    ceiling branches. So the resolver's ``alias_ambiguous`` token is unreachable through the fold,
    hence registered as an arm with no published carrier.
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
    """The freeze fraction is untouched, deliberately.

    Pausing is not code control (nothing is rewritten) and nothing in the pipeline witnesses what
    SHARE of a sheet a pause immobilises: same node as the upgrade row, none of it priced.
    """
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
    """Does every upgradeable protocol pin the meter? No: value and difficulty are separate axes.

    Same node, same $3.62B-shaped ceiling, two principals at different weakness rungs: the ratio
    of their raw_points is exactly the ratio of their rungs, on a scale that knows there are
    billions behind the door rather than one scoring both at the unpriced floor.
    """
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
    """§6.4. Ceilings are risk-weighted upper bounds, never expected loss.

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
    # Lands in the undetermined bucket of the coverage disclosure (keeps tracked_share_measured_pct honest).
    coverage = document.provenance["exposure_coverage"]
    assert coverage["findings_with_exposure_not_determined"] >= 1
    # The ceiling's dollars are absent from the charged perimeter; charging them would flip the
    # disclosure from "almost nothing measurable" to near-total coverage built from upper bounds.
    assert coverage["perimeter_usd_charged"] == pytest.approx(5_000_000.0)


def test_cc7_the_ceiling_is_capped_per_key_and_never_per_row(fold):
    """S6. A row's total sums across its priced hosts and may exceed any sheet.

    "Capped by the node's own sheet" holds per KEY, not per row (the reference corpus publishes
    $4.217B over eight hosts, more than the largest), so the invariant is checked per key.
    """
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
    """SHEET_PRICED is a FLOOR over what was priced, so the ceiling is conditional.

    An entity with one priced and one unpriced asset holds MORE than its total, so "at most $X"
    is false; ``ceiling`` on that entry would claim an at-most over unobserved holdings and
    contradict the row header, which refuses on this conjunct. Both read the same predicate.
    Dollars, band and admission are untouched: this is what the row CLAIMS about its figure.
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
    # A below-resolution reading is the same shortfall as an unpriced one (at most half a cent the total does
    # not carry).
    dust = value_plane(
        {KEY_C: {"usdc": 5_000_000.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED, "weth": P.ASSET_BELOW_RESOLUTION}},
    )
    dusty = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=dust))
    assert dusty["reach_sheet_ceiling_magnitudes"][0]["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED
    # An unpriced POSITION defeats it with every asset priced: the restaking plane has no USD column, so a
    # position there is unpriced by construction.
    positions = value_plane({KEY_C: {"usdc": 5_000_000.0}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    positions.unpriced_positions = {KEY_C: [{"asset": "eigenlayer_beacon_shares_wei", "quantity_wei": 3e19}]}
    with_positions = _cc_row(fold([signal], principals={1: facts(1, EOA, "eoa")}, value=positions))
    held = with_positions["reach_sheet_ceiling_magnitudes"][0]
    assert held["unpriced_positions"] == 1
    assert held["bound_direction"] == FOLD.BOUND_DIRECTION_NOT_DETERMINED


def test_cc7_a_subsumed_rows_sheet_ceiling_leaks_into_the_budget_in_neither_direction(fold):
    """The subsumption path, both leaks, on ONE principal unit.

    Subsumption keeps the top row but value only a subsumed row reaches still charges the top
    row's exposure. With a sheet ceiling two leaks go opposite ways.

    IN: a subsumed row's ceiling at an entity the top row doesn't price is exclusive value, but
    the exposure skip reads the TOP row's ceiling list, so it would charge a budget its own
    row's copy is exempt from.

    OUT: the top row's ceiling makes the occupancy test treat that key as taken, discarding a
    subsumed row's WITNESSED value there while the top row charges nothing: measured dollars
    leave the accounting.
    """
    top = sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )
    # Subsumed, same unit: a witnessed figure at the entity the top row ceilings (OUT leak), and
    # a ceiling at an entity the top row doesn't reach (IN leak).
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
    # OUT: the top row prices C from a ceiling and charges nothing there, so the key is NOT occupied and the
    # subsumed $400k survives.
    assert KEY_C in exclusive and exclusive[KEY_C]["usd"] == 400_000.0
    # IN: the vault arrives as exclusive value AND as a ceiling, so the exposure loop can tell it from the
    # witnessed figure.
    assert KEY_V in exclusive
    assert finding["subsumed_exclusive_sheet_ceiling_entities"] == [KEY_V]

    assert finding["exposure_usd"] == pytest.approx(400_000.0 * exclusive[KEY_C]["fraction"])
    assert finding["exposure_entities_charged"] == [KEY_C]
    gap = next(
        g
        for g in document.provenance["exposure_gaps"]
        if (g["principal_unit"], g["capability"]) == (finding["principal_unit"], "upgrade.implementation")
    )
    # Only the vault: the top row's ceiling at C was skipped and the subsumed witnessed figure charged instead,
    # so nothing is disclosed as excluded there.
    assert gap["ceiling_entities_excluded_from_exposure"] == [KEY_V]
    assert gap["budget_exhausted_entities"] == [] and gap["budget_partially_exhausted_entities"] == []
