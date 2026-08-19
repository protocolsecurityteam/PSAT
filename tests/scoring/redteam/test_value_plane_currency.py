"""Value plane: which observation is current, and what a $0.00 reading proves.

One of the twenty sections of the former ``test_scoring_redteam.py``.
"""

from __future__ import annotations

from services.scoring import planes as P
from services.scoring.schema import entity_key
from tests.support.scoring_builders import (
    KEY_C,
    KEY_PROXY,
    PROXY,
    SCANNED,
    VAULT,
    _reduce,
    _Row,
    bounded_by_sheet,
    fold,  # noqa: F401  (fold fixture, registered by import)
    proven,
    reaches,
    sig,
    value_plane,
)


def test_one_account_read_twice_publishes_the_LATER_read_not_the_larger():
    """MAX across two heights of one account is a high-water mark, not a holding.

    The shape that fired on the real corpus: a proxy's live row and its
    implementation's frozen row are the SAME on-chain account read at two
    heights, folded into one bucket by the alias map. Reducing by MAX republishes
    a balance that had already moved when it was written.
    """
    account = "0x" + "1" * 40
    values, states, reduction = _reduce(
        **{account: [_Row(26_404_230.63, block=25_658_048, rid=1), _Row(14_346_384.46, block=25_691_487, rid=2)]}
    )
    assert values["k"]["asset"] == 14_346_384.46
    assert states["k"]["asset"] == P.ASSET_PRICED
    # The drop is disclosed, not silently absorbed.
    assert reduction["stale_high_water_marks_dropped"] == 1
    assert reduction["stale_high_water_usd_dropped"] == round(26_404_230.63 - 14_346_384.46, 2)
    assert reduction["height_witnessed_accounts"] == 1


def test_two_DISTINCT_accounts_are_two_holdings_and_the_entity_holds_their_sum():
    """The account is the discriminator: same account = one holding, two = two.

    Unexercised on the corpus this shipped against (every competing pair observes
    one address), so it is pinned here rather than left to a future reader to
    infer from the code.
    """
    a, b = "0x" + "1" * 40, "0x" + "2" * 40
    values, _, reduction = _reduce(**{a: [_Row(1000.0, block=10, rid=1)], b: [_Row(400.0, block=10, rid=2)]})
    assert values["k"]["asset"] == 1400.0
    assert reduction["multi_account_buckets"] == 1
    assert reduction.get("unwitnessed_account_buckets", 0) == 0


def test_an_unwitnessed_account_identity_is_never_summed():
    """Summing readings that may be one account twice re-mints the double count.

    Where the identity is missing the reduction falls back to MAX and says so,
    rather than inventing a holding out of two readings of an unknown number of
    accounts.
    """
    values, _, reduction = _reduce(**{"": [_Row(1000.0, rid=1)], "0x" + "2" * 40: [_Row(400.0, rid=2)]})
    assert values["k"]["asset"] == 1000.0
    assert reduction["unwitnessed_account_buckets"] == 1


def test_a_read_height_nobody_recorded_falls_back_to_write_order_and_says_so():
    """ERC-20 rows are never height-pinned, so most orderings are write order.

    A fact about this database, not about the chain — counted so the fiat is
    stated rather than passed off as an as-of-block reading.
    """
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    account = "0x" + "1" * 40
    values, _, reduction = _reduce(**{account: [_Row(900.0, fetched=late, rid=1), _Row(100.0, fetched=early, rid=2)]})
    assert values["k"]["asset"] == 900.0
    assert reduction["write_order_accounts"] == 1
    assert reduction.get("height_witnessed_accounts", 0) == 0


def test_a_rounding_floor_reading_is_not_a_proven_zero():
    """``usd_value`` is a scaled decimal column: a holding below its last digit —
    the eighteenth decimal — stores as zero.

    Publishing that as a determined 0.0 mints a proven-empty balance sheet out of
    a price lookup that answered "below the column's resolution".
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="12345")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_BELOW_RESOLUTION
    assert "asset" not in plane.per_asset.get("k", {})
    assert plane.sheet_state("k") == P.SHEET_BELOW_RESOLUTION
    assert plane.total("k") is None


def test_a_sub_resolution_priced_reading_keeps_its_magnitude_through_the_reduction():
    """Pins the ROUNDING guard, and only it.

    A holding worth $2e-9 is a determined NON-ZERO reading — the price answered
    and the quantity is not zero — and the plane's presentation rounding is six
    decimals. A rounding that ran to completion would replace the measured figure
    with 0.0: a bound tighter than anything witnessed, and (with the asset list
    proven whole) the input from which ``sheet_state``'s magnitude arm would read
    an empty sheet. What is asserted here is that the figure SURVIVES; the state
    arm is asserted separately below, because with the magnitude preserved this
    case cannot tell the two guards apart.
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(2e-9, rid=1, raw="1")]})
    plane.asset_set_proven_complete["k"] = SCANNED
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_PRICED
    assert plane.per_asset["k"]["asset"] == 2e-9
    assert plane.sheet_state("k") != P.SHEET_PROVEN_EMPTY
    assert plane.sheet_state("k") == P.SHEET_PRICED
    assert plane.total("k") == 2e-9
    assert plane.proven_empty_refusal("k") is None  # the completeness conjunct is SATISFIED here


def test_a_priced_reading_whose_magnitude_is_zero_is_still_never_a_proven_empty_sheet():
    """Pins the STATE arm, and only it.

    The magnitude is 0.0 here and the asset list is proven whole, so every input
    the magnitude arm can see says "empty" — the exact shape any future rounding,
    truncation or unit change could hand ``sheet_state``. The reading's STATE
    says a price answered on a non-zero quantity, and that is the witness the
    branch is required to read: publishing ``proven_empty`` from this plane would
    assert "every asset's quantity is proven zero" of a sheet whose quantity was
    proven otherwise. The two guards are independent and each closes the hazard
    on its own; this case is what fails if the state arm is dropped.
    """
    plane = value_plane(
        per_asset={"k": {"asset": 0.0}},
        per_asset_state={"k": {"asset": P.ASSET_PRICED}},
        asset_set_proven_complete={"k": SCANNED},
    )
    assert plane.proven_empty_refusal("k") is None  # nothing refuses the empty; only the state stands in its way
    assert plane.sheet_state("k") != P.SHEET_PROVEN_EMPTY
    assert plane.sheet_state("k") == P.SHEET_PRICED


def test_a_proven_zero_QUANTITY_is_the_only_witness_of_an_empty_sheet():
    """The quantity, not the price, is what proves a sheet empty.

    Zero of an asset is worth zero at any price, so this is the one reading under
    which 0.00 is a number. The arm is unexercised on the shipped corpus — no row
    anywhere carries a zero raw balance — so it is pinned here.
    """
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="0")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_PROVEN_ZERO
    # The quantity is half of it. The other half is the SET those quantities
    # cover: without a scan proving the list whole, zeros over an unestablished
    # list are refused and publish unpriced, never a $0.
    assert plane.sheet_state("k") == P.SHEET_UNPRICED
    assert plane.total("k") is None
    plane.asset_set_proven_complete["k"] = SCANNED
    assert plane.sheet_state("k") == P.SHEET_PROVEN_EMPTY
    assert plane.total("k") == 0.0


def test_the_three_ways_of_having_no_total_stay_apart():
    """not_determined is not one state: dust, unpriced and no rows are three."""
    plane = value_plane(
        per_asset={},
        per_asset_state={
            "dust": {"a": P.ASSET_BELOW_RESOLUTION},
            "unpriced": {"a": P.ASSET_UNPRICED},
        },
    )
    assert plane.sheet_state("dust") == P.SHEET_BELOW_RESOLUTION
    assert plane.sheet_state("unpriced") == P.SHEET_UNPRICED
    assert plane.sheet_state("never-seen") == P.SHEET_NO_ROWS
    assert [plane.total(k) for k in ("dust", "unpriced", "never-seen")] == [None, None, None]


def test_a_positive_row_beside_dust_keeps_its_positive_floor():
    """Dust withholds a number only where it is the ONLY answer."""
    plane = value_plane(
        per_asset={"k": {"good": 1000.0}},
        per_asset_state={"k": {"good": P.ASSET_PRICED, "dust": P.ASSET_BELOW_RESOLUTION}},
    )
    assert plane.sheet_state("k") == P.SHEET_PRICED
    assert plane.total("k") == 1000.0


def test_an_all_dust_sheet_charges_no_finding_a_proven_zero_exposure(fold):
    """The published shape R6 forbids: exposure 0.0 beside a proven reach.

    ``value_at_stake 0.0 / proven_reach / exposure 0.0`` reads as "this capability
    is proven to reach nothing" — an earned negative minted by a price lookup that
    answered below its own resolution.
    """
    dust_key = entity_key("base", VAULT)
    plane = value_plane(
        per_asset={KEY_PROXY: {"token": 5_000_000.0}},
        per_asset_state={
            KEY_PROXY: {"token": P.ASSET_PRICED},
            dust_key: {"dust": P.ASSET_BELOW_RESOLUTION},
        },
        contracts=(KEY_C, dust_key, KEY_PROXY),
    )
    dust = sig(
        chain="base",
        deployment_address=VAULT,
        **proven(1.0),
        **reaches(dust_key),
        authority_openness="open",
    )
    priced = sig(
        deployment_address=PROXY,
        function_name="g",
        gates=bounded_by_sheet(5_000_000.0),
        **proven(1.0),
        **reaches(KEY_PROXY),
        authority_openness="open",
    )
    document = fold([dust, priced], value=plane).document()
    row = next(r for r in document["findings"] if r["principal_unit"].startswith("base::"))
    assert row["value_at_stake_usd"] is None
    assert row["exposure_usd"] is None
    assert row["value_band"] == "not_determined"
    # The priced row beside it still scores, so this is the dust entity's own
    # answer and not a withheld grade standing in for one.
    assert document["grade_exposure"] is not None
