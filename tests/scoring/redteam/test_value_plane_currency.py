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
    """A proxy's live row and its impl's frozen row are one account at two heights; MAX republished a balance that
    had moved.
    """
    account = "0x" + "1" * 40
    values, states, reduction = _reduce(
        **{account: [_Row(26_404_230.63, block=25_658_048, rid=1), _Row(14_346_384.46, block=25_691_487, rid=2)]}
    )
    assert values["k"]["asset"] == 14_346_384.46
    assert states["k"]["asset"] == P.ASSET_PRICED
    assert reduction["stale_high_water_marks_dropped"] == 1
    assert reduction["stale_high_water_usd_dropped"] == round(26_404_230.63 - 14_346_384.46, 2)
    assert reduction["height_witnessed_accounts"] == 1


def test_two_DISTINCT_accounts_are_two_holdings_and_the_entity_holds_their_sum():
    """Unexercised on the shipped corpus."""
    a, b = "0x" + "1" * 40, "0x" + "2" * 40
    values, _, reduction = _reduce(**{a: [_Row(1000.0, block=10, rid=1)], b: [_Row(400.0, block=10, rid=2)]})
    assert values["k"]["asset"] == 1400.0
    assert reduction["multi_account_buckets"] == 1
    assert reduction.get("unwitnessed_account_buckets", 0) == 0


def test_an_unwitnessed_account_identity_is_never_summed():
    """Missing identity falls back to MAX and says so."""
    values, _, reduction = _reduce(**{"": [_Row(1000.0, rid=1)], "0x" + "2" * 40: [_Row(400.0, rid=2)]})
    assert values["k"]["asset"] == 1000.0
    assert reduction["unwitnessed_account_buckets"] == 1


def test_a_read_height_nobody_recorded_falls_back_to_write_order_and_says_so():
    """ERC-20 rows are never height-pinned, so the write-order fiat is counted and stated."""
    import datetime as _dt

    early = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    late = _dt.datetime(2026, 2, 1, tzinfo=_dt.timezone.utc)
    account = "0x" + "1" * 40
    values, _, reduction = _reduce(**{account: [_Row(900.0, fetched=late, rid=1), _Row(100.0, fetched=early, rid=2)]})
    assert values["k"]["asset"] == 900.0
    assert reduction["write_order_accounts"] == 1
    assert reduction.get("height_witnessed_accounts", 0) == 0


def test_a_rounding_floor_reading_is_not_a_proven_zero():
    """A holding below ``usd_value``'s eighteenth decimal stores as zero; that is not a proven-empty sheet."""
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="12345")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_BELOW_RESOLUTION
    assert "asset" not in plane.per_asset.get("k", {})
    assert plane.sheet_state("k") == P.SHEET_BELOW_RESOLUTION
    assert plane.total("k") is None


def test_a_sub_resolution_priced_reading_keeps_its_magnitude_through_the_reduction():
    """Pins only the rounding guard; the state arm can't be distinguished here and is asserted below."""
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
    """Pins only the state arm: every magnitude input says empty, but a price answered on a non-zero quantity."""
    plane = value_plane(
        per_asset={"k": {"asset": 0.0}},
        per_asset_state={"k": {"asset": P.ASSET_PRICED}},
        asset_set_proven_complete={"k": SCANNED},
    )
    assert plane.proven_empty_refusal("k") is None  # nothing refuses the empty; only the state stands in its way
    assert plane.sheet_state("k") != P.SHEET_PROVEN_EMPTY
    assert plane.sheet_state("k") == P.SHEET_PRICED


def test_a_proven_zero_QUANTITY_is_the_only_witness_of_an_empty_sheet():
    """Only a zero quantity proves empty. Unexercised on the shipped corpus."""
    plane = P.ValuePlane()
    plane.per_asset, plane.per_asset_state, _ = _reduce(**{"0x" + "1" * 40: [_Row(0.0, rid=1, raw="0")]})
    assert plane.per_asset_state["k"]["asset"] == P.ASSET_PROVEN_ZERO
    # Zeros over a list no scan proved whole publish unpriced, never $0.
    assert plane.sheet_state("k") == P.SHEET_UNPRICED
    assert plane.total("k") is None
    plane.asset_set_proven_complete["k"] = SCANNED
    assert plane.sheet_state("k") == P.SHEET_PROVEN_EMPTY
    assert plane.total("k") == 0.0


def test_the_three_ways_of_having_no_total_stay_apart():
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
    plane = value_plane(
        per_asset={"k": {"good": 1000.0}},
        per_asset_state={"k": {"good": P.ASSET_PRICED, "dust": P.ASSET_BELOW_RESOLUTION}},
    )
    assert plane.sheet_state("k") == P.SHEET_PRICED
    assert plane.total("k") == 1000.0


def test_an_all_dust_sheet_charges_no_finding_a_proven_zero_exposure(fold):
    """R6 forbids exposure 0.0 beside a proven reach from a sub-resolution price."""
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
    assert document["grade_exposure"] is not None
