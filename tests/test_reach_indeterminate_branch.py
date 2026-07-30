"""REACHABILITY PIN for the reach-indeterminate branch of ``_add_reach``.

The branch at ``services/effects/recipes.py:1704-1708`` (``if not reach_holders``)
produced 0 rows on the
PR-161 corpus, and a zero-population field is normally a defect (the L-16
"unreachable branch" shape). This one is NOT: it is live code with a satisfiable
three-conjunct precondition that simply did not occur here. It fires the moment a
proven fork value-out moves an asset out of an address that is not one of the
protocol's recorded holders — a zap / router / adapter moving value it does not
itself hold. These tests are the artifact that keeps the zero classified as an
unmet data precondition rather than as dead code, and they pin the exact payload.

**HOW THE 0.0 FLOOR MUST BE CONSUMED.** ``observed_reach_floor_usd`` is NOT a
measured zero and must never be read as one. It is whatever ``acting_balance_usd``
carried, which is sourced from the B1/B2 balance plane (``selection.py`` ->
``graph.deployment_balance``, itself derived from ``contract_balances``) — a plane
that is blockless and conflates "holds nothing", "not fetched" and "fetch failed"
into an absent row. So a ``0.0`` floor beside ``reach_indeterminate: True`` means
**"no proven bound"**, never "this function reaches $0". The key that means
MEASURED reach — ``observed_reach_value_usd`` — is deliberately ABSENT on this
branch; publishing the floor under that name is the exact regression that scored
"$0 reach" for a zero-balance router able to move millions. Because the branch has
zero realized rows on this corpus, that is a contract statement, not a measured
claim (B14: no rule may be calibrated on it).

No wire, no DB, no fixtures: ``_add_reach`` is called directly on stub inputs.
"""

from __future__ import annotations

from services.effects.recipes import _add_reach
from services.effects.selection import AssetHolding
from services.effects.simulate import SimCallResult
from tests.conftest import ADDR
from tests.test_effects_harness import transfer_log

HOLDER = ADDR(0x4001)
OUTSIDER = ADDR(0x4002)
TOKEN = ADDR(0x4003)
RECIPIENT = ADDR(0x4004)


def test_value_leaving_a_non_holder_is_indeterminate_not_zero_reach():
    """The router shape: value provably moves, out of an address the protocol
    does not hold anything at, so nothing is witnessed leaving a HOLDER.

    Byte-exact payload — three keys and no fourth. In particular
    ``observed_reach_value_usd`` / ``observed_reach_holders`` /
    ``observed_reach_assets`` are absent, because none of them was measured; a
    consumer that sees ``observed_reach_floor_usd: 0.0`` here has "no proven
    bound", not a proven $0 (see the module docstring).
    """
    base_call = SimCallResult(
        True,
        "0x",
        None,
        (transfer_log(TOKEN, OUTSIDER, RECIPIENT, 10**18),),
    )
    # Non-empty holder set, so the early return is not what we are exercising —
    # the holder simply never appears as a Transfer sender.
    value_holders = (AssetHolding(HOLDER.lower(), TOKEN.lower(), 1_000.0),)

    concrete: dict[str, object] = {}
    _add_reach(concrete, base_call, value_holders, 0.0)

    assert concrete == {
        "reach_determined": False,
        "reach_indeterminate": True,
        "observed_reach_floor_usd": 0.0,
    }


def test_no_holder_set_supplied_emits_no_reach_keys_at_all():
    """The early return (``recipes.py:1642-1643``): with no holder set nothing was even
    attempted, so the correct output is the ABSENCE of every reach key — not a
    floor of 0.0 and not ``reach_indeterminate``. Absence and an indeterminate
    floor are different states and a consumer must keep them apart: absence is
    "reach was never measured here", which resolves to ``not_determined``.
    """
    base_call = SimCallResult(
        True,
        "0x",
        None,
        (transfer_log(TOKEN, OUTSIDER, RECIPIENT, 10**18),),
    )

    concrete: dict[str, object] = {}
    _add_reach(concrete, base_call, (), 0.0)

    assert concrete == {}
