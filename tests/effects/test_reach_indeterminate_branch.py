"""Unobserved reach remains unknown regardless of recorded current holdings."""

from __future__ import annotations

from services.effects.recipes import _add_reach
from services.effects.selection import AssetHolding
from services.effects.simulate import SimCallResult
from tests.conftest import ADDR
from tests.support.effects_stubs import transfer_log

HOLDER = ADDR(0x4001)
OUTSIDER = ADDR(0x4002)
TOKEN = ADDR(0x4003)
RECIPIENT = ADDR(0x4004)


def _router_call() -> SimCallResult:
    """The router shape: value provably moves, out of an address the protocol
    holds nothing at, so nothing is witnessed leaving a HOLDER."""
    return SimCallResult(
        True,
        "0x",
        None,
        (transfer_log(TOKEN, OUTSIDER, RECIPIENT, 10**18),),
    )


# Non-empty holder set, so the early return is not what these exercise — the
# holder simply never appears as a Transfer sender.
VALUE_HOLDERS = (AssetHolding(HOLDER.lower(), TOKEN.lower(), 1_000.0),)


def test_value_leaving_a_non_holder_is_indeterminate_not_zero_reach():
    """Byte-exact payload — three keys and no fourth. In particular
    ``observed_reach_value_usd`` / ``observed_reach_holders`` /
    ``observed_reach_assets`` are absent, because none of them was measured.
    """
    concrete: dict[str, object] = {}
    _add_reach(concrete, _router_call(), VALUE_HOLDERS, 250.0)

    assert concrete == {
        "reach_determined": False,
        "reach_magnitude_state": "not_determined",
        "reach_value_scope": "recorded_holdings_of_assets_observed_moving",
        "reach_is_upper_bound": False,
        "reach_indeterminate": True,
    }


def test_a_witnessed_zero_balance_still_publishes_a_floor_of_zero():
    """A PRESENT zero is a witness. ``acting_balance_usd = 0.0`` means the acting
    deployment's balance rows were read and summed to zero, and that is a
    different fact from having read nothing — so the key stays, carrying ``0.0``.

    Byte-exact, and deliberately the same three keys as the positive case: the
    only thing separating this payload from the absent one below is the presence
    of the floor key itself.
    """
    concrete: dict[str, object] = {}
    _add_reach(concrete, _router_call(), VALUE_HOLDERS, 0.0)

    assert concrete == {
        "reach_determined": False,
        "reach_magnitude_state": "not_determined",
        "reach_value_scope": "recorded_holdings_of_assets_observed_moving",
        "reach_is_upper_bound": False,
        "reach_indeterminate": True,
    }


def test_an_absent_acting_balance_publishes_no_floor_key_at_all():
    """THE HONEST ABSENCE. ``acting_balance_usd is None`` — the INNER join at
    ``selection.py:303-308`` produced no ``deployment_balance`` entry for the
    acting address — so there is no floor to state and the key is simply not
    there.

    Byte-exact: TWO keys. Not three-with-a-null, and not three-with-a-zero. A
    consumer reading ``observed_reach_floor_usd`` off this payload with a
    ``.get()`` default reintroduces exactly the defect ``selection.py:1369`` was:
    a floor nobody witnessed, wearing the shape of one that was.
    """
    concrete: dict[str, object] = {}
    _add_reach(concrete, _router_call(), VALUE_HOLDERS, None)

    assert concrete == {
        "reach_determined": False,
        "reach_magnitude_state": "not_determined",
        "reach_value_scope": "recorded_holdings_of_assets_observed_moving",
        "reach_is_upper_bound": False,
        "reach_indeterminate": True,
    }
    # Stated separately from the equality above: a ``null`` under the key would
    # satisfy neither, but only this says which of the two failures we mean.
    assert "observed_reach_floor_usd" not in concrete


def test_no_holder_set_supplied_emits_no_reach_keys_at_all():
    """The early return (``recipes.py``, ``if not value_holders``): with no holder
    set nothing was even attempted, so the correct output is the ABSENCE of every
    reach key — not a floor and not ``reach_indeterminate``. Absence and an
    indeterminate floor are different states and a consumer must keep them apart:
    absence here is "reach was never measured on this deployment".

    Run for BOTH floor states, because the early return must not start depending
    on the floor: an absent holder set outranks whatever the balance plane knew.
    """
    for floor in (0.0, 250.0, None):
        concrete: dict[str, object] = {}
        _add_reach(concrete, _router_call(), (), floor)
        assert concrete == {}
