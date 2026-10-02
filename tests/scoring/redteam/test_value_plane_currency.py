from __future__ import annotations

from services.scoring import planes as P
from tests.support.scoring_builders import (
    SCANNED,
    _reduce,
    _Row,
    fold,  # noqa: F401  (fold fixture, registered by import)
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
