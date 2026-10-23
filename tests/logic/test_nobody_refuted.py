"""The pass condition fails a row claiming "provably nobody" that a replayed prod holder gets past: its call returns,
or it reverts later than a stranger's, unless the engine's formula is identically false (a function that always
reverts, whose owner merely gets further)."""

from __future__ import annotations

from scripts.logic_run_passes import failures

KEY = ("lido", "0x" + "c" * 40, "f()", "C")
HOLDER = "0x" + "a" * 40


def _row(**fields):
    return {
        "contract": "C",
        "address": KEY[1],
        "function": "f()",
        "lego": "restricted",
        "lego_complete": True,
        **fields,
    }


def test_a_refuted_nobody_fails_the_run():
    found = failures({}, {KEY: _row(lego_principals=[], nobody_refuted=[HOLDER])}, False, False)
    assert len(found) == 1 and found[0].startswith("(d) nobody claimed but prod holder passes")
    assert HOLDER in found[0]


def test_a_nobody_no_replayed_holder_refutes_passes():
    assert failures({}, {KEY: _row(lego_principals=[], nobody_refuted=[])}, False, False) == []
    assert failures({}, {KEY: _row(lego_principals=[])}, False, False) == []


def test_a_holder_past_the_gate_fails_a_nobody_unless_the_formula_is_false():
    differs = _row(lego_principals=[], nobody_refuted=[], nobody_differs=[HOLDER])
    found = failures({}, {KEY: differs}, False, False)
    assert len(found) == 1 and "gets past the gate" in found[0] and HOLDER in found[0]
    # Not recorded either way: not shown false, so it fails.
    assert failures({}, {KEY: {**differs, "lego_formula_false": False}}, False, False) == found
    # WBTC's renounceOwnership: always reverts, its owner only gets further.
    assert failures({}, {KEY: {**differs, "lego_formula_false": True}}, False, False) == []
