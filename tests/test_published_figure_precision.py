"""V1-D1: a proven bound below a cent is a number, and publishes as one.

The scorer rounds published dollars to cents. On a sheet proven to hold about
$0.00156 that rounding published ``$0.00`` — indistinguishable, to every
consumer of the document, from the earned negative "this node holds nothing" and
from a bound of zero on what a code-control move can take. The measurement said
one thing and the document said another, in the direction that reads as safety.

Each case here pins the SAME record from two sides: the figure, and the sibling
fields the record's own ordering and equality claims are made across. A record
that published one of them unrounded and its neighbours at cents would not be
imprecise — it would contradict itself.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from services.scoring import fold as FOLD
from services.scoring import planes as P
from services.scoring.schema import PrincipalRef, Tri
from tests.support.scoring_builders import (
    CALLING_SELECTOR,
    COMPOSED_SELECTOR,
    EOA,
    KEY_C,
    KEY_V,
    OWNERS,
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

# Two figures the cent rounding erases, and they are NOT the same number: the
# record's ordering claim (published <= witness) is only checkable where the two
# differ, and a fixture that used one figure twice would pass with the ordering
# deleted.
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
    """The composing pair, with the destination's own witness set by the caller."""
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


# --------------------------------------------------------------------------
# The sheet-ceiling record
# --------------------------------------------------------------------------


def test_a_sheet_ceiling_below_a_cent_publishes_the_bound_it_proved(fold):  # noqa: F811
    """The figure survives the rounding that used to delete it.

    ``published_usd`` is the ONLY dollar figure this row puts on the move a code
    replacement can make. Published as 0.00 it says the move is worth nothing,
    which is a claim about the entity nobody measured — the measurement was
    $0.00156, earned from an integer quantity and an unrounded price.
    """
    plane = value_plane(
        {KEY_C: {"usdc": SUB_CENT_SHEET}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
    )
    entry = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))[
        "reach_sheet_ceiling_magnitudes"
    ][0]

    assert entry["published_usd"] == SUB_CENT_SHEET
    # The rounding is still a rounding everywhere it is not the difference
    # between a number and an absence.
    assert FOLD._round_published(1234.5678) == 1234.57


def test_the_sub_cent_ceiling_record_agrees_with_its_own_evidence(fold):  # noqa: F811
    """The sibling fields take the same precision, because the record makes
    equality claims across them.

    ``sheet_usd`` is the plane's answer beside the figure the fold took, and the
    record says the two are equal by construction; ``per_asset`` is the evidence
    the sum is checked against. Round the figure and not its neighbours and the
    record publishes $0.00156 standing over a sheet of $0.00 assembled from an
    asset worth $0.00 — three fields, one fact, two answers.
    """
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


def test_the_row_header_says_what_its_own_record_says(fold):  # noqa: F811
    """The three keys are one derivation and are published in ONE object.

    ``value_at_stake_usd`` is the sum of ``value_by_entity``, whose values are
    the same floats the per-entity record prices from. At cents the header read
    "$0.00 at stake" and the breakdown read 0.0 while the record two keys over
    published the bound that was proven — a finding contradicting itself, and
    contradicting itself in the direction that reads as safety. The total is
    included deliberately: on this row it IS the row's whole claim.
    """
    plane = value_plane(
        {KEY_C: {"usdc": SUB_CENT_SHEET}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
    )
    finding = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))

    assert finding["value_by_entity"] == {KEY_C: SUB_CENT_SHEET}
    assert finding["value_at_stake_usd"] == SUB_CENT_SHEET
    assert finding["value_at_stake_usd"] == sum(finding["value_by_entity"].values())
    assert finding["value_at_stake_usd"] == finding["reach_sheet_ceiling_magnitudes"][0]["published_usd"]
    # Nothing GRADED moves with it: the band is derived upstream from the
    # unrounded total and still reads the floor band for a sub-cent figure.
    assert finding["value_state"] == VALUE_STATE_PROVEN_REACH
    assert "$" in finding["value_band"]


def test_a_sub_cent_standing_figure_is_reconciled_at_the_resolution_it_publishes(fold):  # noqa: F811
    """The reconciliation gate reads the SAME rounding the record prints with.

    It compares the standing figure against the node's own sheet and withholds
    the ceiling LABEL where they differ, "at the published resolution". At a
    hand-written two decimals that resolution stopped matching the published one
    in the sub-cent band, so a standing figure that is not this node's sheet
    would have been labelled its ceiling. Here they ARE the same figure, which
    is the case the gate must keep admitting — the tightening may not start
    withholding labels that were earned.
    """
    plane = value_plane(
        {KEY_C: {"usdc": SUB_CENT_SHEET}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}},
    )
    finding = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))

    assert finding["entities_priced_from_a_sheet_ceiling"] == [KEY_C]
    assert finding["reach_sheet_ceiling_magnitudes_withheld"] == []
    # The gate itself, exercised directly on a pair that agrees at cents and
    # differs below one: the old comparison passed it, this one does not.
    kinds = {KEY_C: FOLD.CEILING_KIND_SHEET}
    withheld = FOLD._reconcile_sheet_ceilings(kinds, {KEY_C: 0.004}, plane)
    assert kinds == {}
    assert [record["entity"] for record in withheld] == [KEY_C]
    # And the record shows the two figures it just called unequal as unequal.
    assert withheld[0]["standing_usd"] != withheld[0]["sheet_usd"]
    assert (withheld[0]["standing_usd"], withheld[0]["sheet_usd"]) == (0.004, SUB_CENT_SHEET)


def test_an_earned_zero_is_still_published_as_zero(fold):  # noqa: F811
    """The negative path, and the one the guard must not eat.

    ``proven_empty`` is the state in which 0.00 IS the number — every asset's
    quantity witnessed zero over a list proven whole. A rule that refused to
    publish 0.00 anywhere would turn that earned negative into a figure nobody
    measured, which is the same defect pointed the other way.
    """
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


# --------------------------------------------------------------------------
# The composed-magnitude record
# --------------------------------------------------------------------------


def test_a_sub_cent_composed_entry_keeps_the_ordering_it_publishes(fold):  # noqa: F811
    """The composed record's three dollar fields are one derivation.

    ``published_usd`` is the MIN of the destination's own flow.out witness and
    the destination's sheet, and ``bounded_by`` names which of the two it equals.
    At cents all three collapse onto 0.00 and the record says the min of two
    zeros is zero — true, and about no entity. Unrounded, the sheet is what
    capped the figure and the record can be checked.
    """
    document = fold(
        _sub_cent_composing_signals(SUB_CENT_WITNESS),
        principals=_composing_principals(),
        **_composing_case(value=value_plane({KEY_V: {"usdc": SUB_CENT_SHEET}}, contracts=(KEY_C,))),
    )
    entry = next(f for f in document.findings if f["capability"] == "authority.replace")["reach_composed_magnitudes"][0]

    assert entry["published_usd"] == SUB_CENT_SHEET
    assert entry["destination_sheet_usd"] == SUB_CENT_SHEET
    assert entry["flow_out_witness"]["usd"] == SUB_CENT_WITNESS
    # The two invariants the record states about its own fields, both of which
    # are vacuous once every figure has been rounded onto zero.
    assert entry["published_usd"] < entry["flow_out_witness"]["usd"]
    assert entry["bounded_by"] == FOLD._BOUNDED_BY_SHEET
    assert entry["published_usd"] == entry["destination_sheet_usd"]


def test_the_witness_below_a_cent_is_published_even_where_no_sheet_bounds_it(fold):  # noqa: F811
    """The other arm of ``bounded_by``: the witness is the whole figure.

    With no sheet at the destination the flow.out witness IS the published
    number, so the rounding that erased it erased the only dollars the entry
    carries — and ``sheet_not_determined`` beside a $0.00 reads as "nothing to
    take", which is two unmeasured claims from one rounding.
    """
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


def test_the_tie_block_ties_at_the_same_figure_the_entry_publishes(fold):  # noqa: F811
    """``tied_at_usd`` is the published figure restated for the candidates, so it
    is the same number or the block describes a tie at a value nothing holds."""
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


def test_the_composing_fixture_names_the_selector_the_case_licenses():
    """A guard on the fixtures above, not on the fold: they build their own
    signals rather than reusing the shipped pair, so a drift between the
    licensed selector and the destination's would make every case here compose
    nothing and assert on an empty list."""
    assert CALLING_SELECTOR != COMPOSED_SELECTOR
    assert OWNERS  # the safe principal the destination signal names is a real one
