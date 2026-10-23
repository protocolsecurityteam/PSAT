"""The pass condition fails a row claiming "provably nobody" that a replayed prod holder gets past."""

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
