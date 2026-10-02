"""The reach-indeterminate branch of ``_add_reach`` (a zap or router moving value it doesn't hold).

``observed_reach_floor_usd`` is three-state: positive, ``0.0`` (read and summed to zero), or absent (nothing
witnessed). Even ``0.0`` is not measured reach, since an all-unpriced sheet sums to zero, so
``observed_reach_value_usd`` is absent on every arm. Zero rows realise this on PR-161; it is a contract
statement.
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
    return SimCallResult(
        True,
        "0x",
        None,
        (transfer_log(TOKEN, OUTSIDER, RECIPIENT, 10**18),),
    )


# The holder simply never appears as a Transfer sender.
VALUE_HOLDERS = (AssetHolding(HOLDER.lower(), TOKEN.lower(), 1_000.0),)


_INDETERMINATE = {"reach_determined": False, "reach_indeterminate": True}


@pytest.mark.parametrize(
    "acting_balance_usd, expected",
    [
        pytest.param(250.0, {**_INDETERMINATE, "observed_reach_floor_usd": 250.0}, id="positive-floor"),
        # A present zero is a witness, so the key stays.
        pytest.param(0.0, {**_INDETERMINATE, "observed_reach_floor_usd": 0.0}, id="witnessed-zero-keeps-floor-key"),
        # The honest absence: exactly two keys, no null or zero floor.
        pytest.param(None, dict(_INDETERMINATE), id="absent-acting-balance-publishes-no-floor-key"),
    ],
)
def test_value_leaving_a_non_holder_is_indeterminate_not_zero_reach(acting_balance_usd, expected):
    concrete: dict[str, object] = {}
    _add_reach(concrete, _router_call(), VALUE_HOLDERS, acting_balance_usd)

    assert concrete == expected
    assert ("observed_reach_floor_usd" in concrete) is (acting_balance_usd is not None)


def test_no_holder_set_supplied_emits_no_reach_keys_at_all():
    """Reach was never attempted. Run for both floor states."""
    for floor in (0.0, 250.0, None):
        concrete: dict[str, object] = {}
        _add_reach(concrete, _router_call(), (), floor)
        assert concrete == {}
