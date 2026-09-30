"""V1-D1: rounding to cents made a ~$0.00156 sheet publish ``$0.00``, indistinguishable from the earned "holds
nothing".

Each case checks the figure and the sibling fields it makes ordering and equality claims across.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef, Tri
from tests.support.scoring_builders import (
    COMPOSED_SELECTOR,
    EOA,
    KEY_C,
    KEY_V,
    SAFE,
    SCANNED,
    VAULT,
    _composing_case,
    _composing_principals,
    facts,
    flow_sig,
    fold,  # noqa: F401  — the fold fixture
    proven,
    reaches,
    sig,
    value_plane,
)
from utils import execution_record as EX
from utils.scoring_status import VALUE_STATE_PROVEN_REACH

# Two different figures, since the ordering claim is only checkable where they differ.
SUB_CENT_SHEET = 0.00156
SUB_CENT_WITNESS = 0.00234


def _cc_row(document, capability: str = "upgrade.implementation") -> dict[str, Any]:
    return next(f for f in document.findings if f["capability"] == capability)


def _code_control_signal():
    return sig(
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(1.0),
        **reaches(KEY_C),
    )


def _sub_cent_composing_signals(witness_usd: float):
    gate = sig(
        claim_id="authority.replace",
        function_name="setAuthority",
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(1, "ethereum", EOA),),
        **proven(0.75),
        **reaches(KEY_C),
    )
    destination = flow_sig(
        deployment_address=VAULT,
        contract_id=2,
        function_name="exit",
        selector=COMPOSED_SELECTOR,
        authority_openness="restricted",
        principal_state="enumerated",
        principal_refs=(PrincipalRef(2, "ethereum", SAFE),),
        witness_tier="behavioral_observed",
        gates={"reach_magnitude_usd": Tri.proven("proven_exact", witness_usd).to_json()},
        **proven(0.9),
        **reaches(KEY_V),
    )
    return [gate, destination]


def test_a_sheet_ceiling_below_a_cent_publishes_the_bound_it_proved(fold):
    plane = value_plane(
        {KEY_C: {"usdc": SUB_CENT_SHEET}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
    )
    entry = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))[
        "reach_sheet_ceiling_magnitudes"
    ][0]

    assert entry["published_usd"] == SUB_CENT_SHEET
    assert FOLD._round_published(1234.5678) == 1234.57


def test_the_sub_cent_ceiling_record_agrees_with_its_own_evidence(fold):
    """``sheet_usd`` equals the figure by construction and ``per_asset`` is its evidence."""
    plane = value_plane(
        {KEY_C: {"usdc": SUB_CENT_SHEET}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
    )
    entry = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))[
        "reach_sheet_ceiling_magnitudes"
    ][0]

    assert entry["sheet_usd"] == entry["published_usd"] == SUB_CENT_SHEET
    assert entry["per_asset"] == [{"asset": "usdc", "usd": SUB_CENT_SHEET, "state": P.ASSET_PRICED}]
    assert sum(row["usd"] for row in entry["per_asset"]) == entry["published_usd"]


def test_the_row_header_says_what_its_own_record_says(fold):
    """At cents the header read "$0.00 at stake" beside the record's proven bound."""
    plane = value_plane(
        {KEY_C: {"usdc": SUB_CENT_SHEET}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
    )
    finding = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))

    assert finding["value_by_entity"] == {KEY_C: SUB_CENT_SHEET}
    assert finding["value_at_stake_usd"] == SUB_CENT_SHEET
    assert finding["value_at_stake_usd"] == sum(finding["value_by_entity"].values())
    assert finding["value_at_stake_usd"] == finding["reach_sheet_ceiling_magnitudes"][0]["published_usd"]
    # The band derives from the unrounded total.
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert "$" in finding["value_band"]


def test_a_sub_cent_standing_figure_is_reconciled_at_the_resolution_it_publishes(fold):
    """A hand-written two-decimal comparison would label a figure that is not this node's sheet as its ceiling."""
    plane = value_plane(
        {KEY_C: {"usdc": SUB_CENT_SHEET}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
    )
    finding = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))

    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    assert finding["reach_sheet_ceiling_magnitudes_withheld"] == []
    kinds = {KEY_C: FOLD.CEILING_KIND_SHEET}
    withheld = FOLD._reconcile_sheet_ceilings(kinds, {KEY_C: 0.004}, plane)
    assert kinds == {}
    assert [record["entity"] for record in withheld] == [KEY_C]
    assert withheld[0]["standing_usd"] != withheld[0]["sheet_usd"]
    assert (withheld[0]["standing_usd"], withheld[0]["sheet_usd"]) == (0.004, SUB_CENT_SHEET)


def test_an_earned_zero_is_still_published_as_zero(fold):
    """``proven_empty`` is where 0.00 is the number."""
    plane = value_plane(
        {KEY_C: {"usdc": 0.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    assert plane.sheet_state(KEY_C) == P.SHEET_PROVEN_EMPTY
    entry = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))[
        "reach_sheet_ceiling_magnitudes"
    ][0]

    assert entry["published_usd"] == 0.0
    assert entry["sheet_usd"] == 0.0
    assert entry["ceiling_reason"] == P.CEILING_PROVEN_EMPTY
    assert FOLD._round_published(0.0) == 0.0


def test_a_sub_cent_composed_entry_keeps_the_ordering_it_publishes(fold):
    """At cents all three fields collapse onto 0.00."""
    document = fold(
        _sub_cent_composing_signals(SUB_CENT_WITNESS),
        principals=_composing_principals(),
        **_composing_case(value=value_plane({KEY_V: {"usdc": SUB_CENT_SHEET}}, contracts=(KEY_C,))),
    )
    entry = next(f for f in document.findings if f["capability"] == "authority.replace")["reach_composed_magnitudes"][0]

    assert entry["published_usd"] == SUB_CENT_SHEET
    assert entry["destination_sheet_usd"] == SUB_CENT_SHEET
    assert entry["flow_out_witness"]["usd"] == SUB_CENT_WITNESS
    assert entry["published_usd"] < entry["flow_out_witness"]["usd"]
    assert entry["bounded_by"] == FOLD._BOUNDED_BY_SHEET
    assert entry["published_usd"] == entry["destination_sheet_usd"]


def test_the_witness_below_a_cent_is_published_even_where_no_sheet_bounds_it(fold):
    """With no sheet, rounding erased the entry's only dollars."""
    document = fold(
        _sub_cent_composing_signals(SUB_CENT_WITNESS),
        principals=_composing_principals(),
        **_composing_case(value=value_plane(contracts=(KEY_C,))),
    )
    entry = next(f for f in document.findings if f["capability"] == "authority.replace")["reach_composed_magnitudes"][0]

    assert entry["sheet_not_determined"] is True
    assert entry["destination_sheet_usd"] is None
    assert entry["published_usd"] == entry["flow_out_witness"]["usd"] == SUB_CENT_WITNESS
    assert entry["bounded_by"] == FOLD._BOUNDED_BY_WITNESS


def test_the_tie_block_ties_at_the_same_figure_the_entry_publishes(fold):
    entry = FOLD._ComposedMagnitude(
        entity=KEY_V,
        selector=COMPOSED_SELECTOR,
        function="exit",
        witness_state="proven_floor",
        witnessed_usd=SUB_CENT_WITNESS,
        usd=SUB_CENT_SHEET,
        sheet_usd=SUB_CENT_SHEET,
        chain=(),
        predicates=P.DestinationPredicates(P.PREDICATES_FUNCTION_NOT_LOCATED, None, None, None, None, 0),
        execution=EX.not_determined(EX.REASON_NOT_PERSISTED),
    )
    published = entry.as_json()
    tie = replace(entry, tied_with=(entry,))._tie_json()

    assert tie is not None
    assert tie["tied_at_usd"] == published["published_usd"] == SUB_CENT_SHEET
    assert [candidate["witnessed_usd"] for candidate in tie["candidates"]] == [SUB_CENT_WITNESS, SUB_CENT_WITNESS]
