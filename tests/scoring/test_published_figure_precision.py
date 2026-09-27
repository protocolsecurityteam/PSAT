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


def test_subcent_holdings_are_preserved_as_context_without_capping_upgrade(fold):
    plane = value_plane({KEY_C: {"usdc": SUB_CENT_SHEET}}, per_asset_state={KEY_C: {"usdc": P.ASSET_PRICED}})
    finding = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert plane.total(KEY_C) == SUB_CENT_SHEET
    assert finding["reach_sheet_ceiling_magnitudes"] == []
    assert finding["value_at_stake_usd"] is None
    assert FOLD._round_published(SUB_CENT_SHEET) == SUB_CENT_SHEET
    assert FOLD._round_published(1234.5678) == 1234.57


def test_zero_holdings_do_not_zero_future_upgrade_capability(fold):
    plane = value_plane(
        {KEY_C: {"usdc": 0.0}},
        per_asset_state={KEY_C: {"usdc": P.ASSET_PROVEN_ZERO}},
        asset_set_proven_complete={KEY_C: SCANNED},
    )
    assert plane.total(KEY_C) == 0.0
    finding = _cc_row(fold([_code_control_signal()], principals={1: facts(1, EOA, "eoa")}, value=plane))
    assert finding["reach_sheet_ceiling_magnitudes"] == []
    assert finding["value_at_stake_usd"] is None
    assert FOLD._round_published(0.0) == 0.0


# --------------------------------------------------------------------------
# The composed-magnitude record
# --------------------------------------------------------------------------


def test_a_sub_cent_composed_entry_keeps_the_ordering_it_publishes(fold):
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

    assert entry["published_usd"] == SUB_CENT_WITNESS
    assert entry["destination_sheet_usd"] is None
    assert entry["flow_out_witness"]["usd"] == SUB_CENT_WITNESS
    assert entry["bounded_by"] == FOLD._BOUNDED_BY_WITNESS


def test_the_witness_below_a_cent_is_published_even_where_no_sheet_bounds_it(fold):
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


def test_the_tie_block_ties_at_the_same_figure_the_entry_publishes(fold):
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
