"""V1-D1: rounding to cents made a ~$0.00156 sheet publish ``$0.00``, indistinguishable from the earned "holds
nothing".

Each case checks the figure and the sibling fields it makes ordering and equality claims across.
"""

from __future__ import annotations

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
