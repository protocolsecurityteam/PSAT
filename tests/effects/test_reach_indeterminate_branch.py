"""Reachability pin for the reach-indeterminate branch of ``_add_reach`` (``if not reach_holders``).

The branch produced 0 rows on the PR-161 corpus, but it is live code: it fires when a proven
fork value-out moves an asset out of an address that is not a recorded protocol holder (a zap /
router / adapter). These tests keep the zero classified as an unmet data precondition, not dead code.

``observed_reach_floor_usd`` is three-state (``acting_balance_usd`` is ``float | None``):
positive = witnessed lower bound; ``0.0`` = a balance row was read and summed to zero (a witness,
keeps its key); key ABSENT = the INNER join at ``selection.py:303-308`` produced no
``deployment_balance`` entry, so nothing was witnessed. Never ``null``, never a defaulted ``0.0``
(``selection.py:1369`` used to do that, destroying the honest absence).

A ``0.0`` floor is still not a measured reach nor a proven zero balance: ``coalesce(sum(usd_value), 0)``
collapses an all-unpriced sheet into ``0.0``. So the consumer treats it as ``not_determined``, and
``observed_reach_value_usd`` (MEASURED reach) is deliberately absent on every arm; publishing the
floor under that name scored "$0 reach" for a zero-balance router able to move millions.
Zero realized rows on this corpus, so this is a contract statement (B14: calibrate nothing on it).

No wire, no DB: ``_add_reach`` is called directly on stub inputs.
"""

from __future__ import annotations

import pytest

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
    """The router shape: value moves out of an address the protocol holds nothing at."""
    return SimCallResult(
        True,
        "0x",
        None,
        (transfer_log(TOKEN, OUTSIDER, RECIPIENT, 10**18),),
    )


# Non-empty holder set, so the early return is not what these exercise — the
# holder simply never appears as a Transfer sender.
VALUE_HOLDERS = (AssetHolding(HOLDER.lower(), TOKEN.lower(), 1_000.0),)


_INDETERMINATE = {"reach_determined": False, "reach_indeterminate": True}


@pytest.mark.parametrize(
    "acting_balance_usd, expected",
    [
        pytest.param(250.0, {**_INDETERMINATE, "observed_reach_floor_usd": 250.0}, id="positive-floor"),
        # A PRESENT zero is a witness, so the key stays with 0.0. Only the floor key's presence
        # separates it from the absent case.
        pytest.param(0.0, {**_INDETERMINATE, "observed_reach_floor_usd": 0.0}, id="witnessed-zero-keeps-floor-key"),
        # CRITICAL, the honest absence: no ``deployment_balance`` entry, so no floor key. Byte-exact
        # TWO keys, not three-with-a-null or -a-zero. A ``.get()`` default on the floor would
        # reintroduce the ``selection.py:1369`` defect: an unwitnessed floor shaped like a witnessed one.
        pytest.param(None, dict(_INDETERMINATE), id="absent-acting-balance-publishes-no-floor-key"),
    ],
)
def test_value_leaving_a_non_holder_is_indeterminate_not_zero_reach(acting_balance_usd, expected):
    """Byte-exact: the measured ``observed_reach_*`` keys are absent on every arm."""
    concrete: dict[str, object] = {}
    _add_reach(concrete, _router_call(), VALUE_HOLDERS, acting_balance_usd)

    assert concrete == expected
    # Stated separately from the equality above: a ``null`` under the key would satisfy neither
    # arm, but only this says which of the two failures we mean.
    assert ("observed_reach_floor_usd" in concrete) is (acting_balance_usd is not None)


def test_no_holder_set_supplied_emits_no_reach_keys_at_all():
    """Early return (``if not value_holders``): reach was never attempted, so every reach key is
    absent, not a floor and not ``reach_indeterminate``.

    Run for BOTH floor states: the early return must not start depending on the floor.
    """
    for floor in (0.0, 250.0, None):
        concrete: dict[str, object] = {}
        _add_reach(concrete, _router_call(), (), floor)
        assert concrete == {}
