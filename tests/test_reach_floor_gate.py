"""B4 — the reach floor may not be adopted without its gate, and 0.00 is not a bound.

``observed_reach_floor_usd`` is emitted only beside ``reach_indeterminate: true``
(``recipes.py:1706-1707`` writes the pair), so it is the acting deployment's own
balance off the B1/B2 balance plane -- never a measurement of what the call moved.
A consumer that adopts it on a bare ``is not None`` has read a balance sheet as a
reach. And a ``0.0`` there is "no proven bound", never a measured zero: on that
plane an absent ``deployment_balance`` key defaults to 0.0
(``selection.py:1369``) and an all-unpriced sheet collapses to 0.0 in
``coalesce(sum(usd_value), 0)`` -- so nothing distinguishes an unfetched contract
from one proven to hold nothing, and both would publish "$0 reach" for a
zero-balance router that can move millions.

``tests/test_reach_indeterminate_branch.py`` covers the PRODUCER side (the branch
fires and emits the pair). This is the CONSUMER side: the two fail-closed arms,
exercised rather than merely present, per the plan's §0 bar.

The decision is loaded WITHOUT importing ``scorer_v3`` -- it opens a DB at
import-adjacent scope and is a CLI, not a library (the same reason
``test_resolver_basis_tiers.py`` reads it through ``ast``). Here the two pure
functions are compiled out of the parsed module and called for real, so this
exercises the arms rather than asserting their shape.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Callable

import pytest

ROOT = Path(__file__).resolve().parents[1]
_WANTED: set[str] = {"_f", "reach_floor_decision"}


def _load_decision() -> Callable[[dict[str, Any]], dict[str, Any]]:
    tree = ast.parse((ROOT / "scoring_prototype" / "scorer_v3.py").read_text())
    picked: list[ast.stmt] = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in _WANTED]
    missing = _WANTED - {n.name for n in picked if isinstance(n, ast.FunctionDef)}
    assert not missing, f"scorer_v3 no longer defines {sorted(missing)} at module level"
    ns: dict[str, Any] = {}
    exec(compile(ast.Module(body=picked, type_ignores=[]), "scorer_v3<extract>", "exec"), ns)
    return ns["reach_floor_decision"]


reach_floor_decision = _load_decision()


def test_zero_floor_with_the_gate_is_not_a_bound():
    """The registered shape, at the value that means "no proven bound"."""
    out = reach_floor_decision({"observed_reach_floor_usd": 0.0, "reach_indeterminate": True})

    assert out["adopted"] is False
    assert out["value"] is None
    assert out["basis"] == "observed_reach_floor_usd_zero(not_determined)"
    # The warning payload has to carry BOTH halves, or the refusal is unauditable.
    assert out["floor_usd"] == 0.0
    assert out["reach_indeterminate"] is True


def test_floor_without_reach_indeterminate_is_not_the_registered_shape():
    """A floor whose gate is absent is refused, not silently adopted."""
    out = reach_floor_decision({"observed_reach_floor_usd": 221_000_000.0})

    assert out["adopted"] is False
    assert out["value"] is None
    assert out["basis"] == "observed_reach_floor_usd_ungated(not_determined)"
    assert out["floor_usd"] == 221_000_000.0
    assert out["reach_indeterminate"] is None


def test_positive_floor_with_the_gate_is_adopted_as_a_lower_bound():
    """The gate must not swallow the case the field exists for."""
    out = reach_floor_decision({"observed_reach_floor_usd": 221_000_000.0, "reach_indeterminate": True})

    assert out["adopted"] is True
    assert out["value"] == 221_000_000.0
    assert out["basis"] == "observed_reach_floor_usd(>= floor, reach_indeterminate)"


@pytest.mark.parametrize("flag", [False, "false", None, "", 0])
def test_every_non_true_flag_refuses(flag):
    """``reach_indeterminate`` is a gate, so anything that is not a proven true
    refuses. A falsy-but-present flag must not read as the gate being satisfied."""
    out = reach_floor_decision({"observed_reach_floor_usd": 1_000.0, "reach_indeterminate": flag})

    assert out["adopted"] is False
    assert out["value"] is None


@pytest.mark.parametrize("floor", [0.0, -1.0, "0", None, "not-a-number"])
def test_no_non_positive_or_unparseable_floor_is_ever_a_bound(floor):
    """A negative balance is impossible and an unparseable one is not a witness;
    both land on the same refusal as 0.00 rather than on a number."""
    out = reach_floor_decision({"observed_reach_floor_usd": floor, "reach_indeterminate": True})

    assert out["adopted"] is False
    assert out["value"] is None
