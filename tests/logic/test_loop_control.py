"""``continue`` and ``break`` go where the language sends them, in every loop form (Yul's ``for`` too), nested ones
included: a ``break`` to the end of the innermost loop whose source holds it; a ``continue`` to a ``for`` loop's
increment (a Yul loop's post block), else to the condition (``while``, ``do``/``while``, a ``for`` without an
increment), else to the loop's start (``for (;;)``). Slither's own edges send a ``continue`` in a ``while`` or
``do``/``while`` body to the body's last statement, one in a ``for`` without a condition past the increment, a
``break`` in a ``for (;;)`` nested in a loop with a condition to the outer loop's end, and a Yul ``break`` or
``continue`` to the end of its ``if``; a Yul loop's condition node has its sons ordered [exit, body]. An iteration
followed exactly is a region of the graph (an inner loop entered again in each outer iteration, its counter declared
zero again). Each probe's lowered condition, evaluated, must be what ``eth_call`` says on anvil, and definite over the
iterations followed exactly."""

from __future__ import annotations

import pytest

from services.logic.lower import Lowerer
from services.logic.terms import reset_terms, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

UNK = None

SOURCE = """
pragma solidity 0.8.27;

contract C {
    function nestedPlain(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) { for (uint256 j; j < 3; j++) { s += 10; } s += 1; }
        require(s == want);
    }
    function nestedBreak(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) { for (uint256 j; j < 3; j++) { if (j == 1) break; s += 10; } s += 1; }
        require(s == want);
    }
    function nestedContinue(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) { uint256 j; while (j < 3) { j++; if (j == 2) continue; s += 10; } s += 1; }
        require(s == want);
    }
    function nestedSymbolic(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < 2; i++) { for (uint256 j; j < n; j++) { s += 10; } s += 1; }
        require(s == want);
    }
    function declaredInLoop(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i = 1; i <= n; i++) { uint256 t; t += i; s += t; }
        require(s == want);
    }
    function whileBreakContinue(uint256 n, uint256 want) external pure {
        uint256 i; uint256 s;
        while (true) { i++; if (i > n) break; if (i == 2) continue; s += i; }
        require(s == want);
    }
    function whileContinue(uint256 n, uint256 want) external pure {
        uint256 i; uint256 s;
        while (i < n) { i++; if (i == 2) continue; s += i; }
        require(s == want);
    }
    function doContinue(uint256 n, uint256 want) external pure {
        uint256 i; uint256 s;
        do { i++; if (i == 2) continue; s += i; } while (i < n);
        require(s == want);
    }
    function forWithoutIncrement(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i = 0; i < n; ) { i++; if (i == 2) continue; s += i; }
        require(s == want);
    }
    function forWithoutCondition(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i = 1; ; i++) { if (i > n) break; if (i == 2) continue; s += i; }
        require(s == want);
    }
    function forever(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i = 1; ; ) { if (i > n) break; i++; if (i == 3) continue; s += i; }
        require(s == want);
    }
    function forContinue(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i = 1; i <= n; i++) { if (i == 2) continue; s += i; }
        require(s == want);
    }
    function foreverInFor(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) { for (;;) { s++; if (s % 3 == 0) break; } }
        require(s == want);
    }
    function foreverInWhileInFor(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) {
            uint256 j;
            while (j < 2) { uint256 k; for (;;) { k++; if (k > 1) break; } s += k; j++; }
        }
        require(s == want);
    }
    function foreverInForever(uint256 n, uint256 want) external pure {
        uint256 s;
        for (;;) { if (s >= 4 * n) break; for (;;) { s++; if (s % 2 == 0) break; } }
        require(s == want);
    }
    function doBreakInFor(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) { do { s++; if (s == 4) break; } while (s % 3 != 0); }
        require(s == want);
    }
    function yulFor(uint256 n, uint256 want) external pure {
        uint256 s;
        assembly { for { let k := 0 } lt(k, n) { k := add(k, 1) } { s := add(s, add(k, 1)) } }
        require(s == want);
    }
    function yulContinueBreak(uint256 n, uint256 want) external pure {
        uint256 s;
        assembly {
            for { let k := 0 } lt(k, 100) { k := add(k, 1) } {
                if gt(k, n) { break }
                if eq(k, 2) { continue }
                s := add(s, k)
            }
        }
        require(s == want);
    }
    function yulNested(uint256 n, uint256 want) external pure {
        uint256 s;
        assembly {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                for { let j := 0 } lt(j, 3) { j := add(j, 1) } { if eq(j, 1) { break } s := add(s, 10) }
                s := add(s, 1)
            }
        }
        require(s == want);
    }
    function yulPost(uint256 n, uint256 want) external pure {
        uint256 s;
        assembly {
            let j := 5
            for { let i := 0 } lt(i, n) { i := add(i, 1) j := add(j, 2) } { if eq(i, 1) { continue } s := add(s, j) }
        }
        require(s == want);
    }
    function yulInFor(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) {
            assembly { for { let k := 0 } lt(k, 3) { k := add(k, 1) } { if eq(k, 1) { continue } s := add(s, 1) } }
            s += 100;
        }
        require(s == want);
    }
    function yulLetInLoop(uint256 n, uint256 want) external pure {
        uint256 s;
        assembly { for { let k := 0 } lt(k, n) { k := add(k, 1) } { let j s := add(s, add(j, 1)) j := 7 } }
        require(s == want);
    }
    function yulLetSwitch(uint256 n, uint256 want) external pure {
        uint256 s;
        assembly {
            for { let k := 0 } lt(k, 3) { k := add(k, 1) } {
                let a let b := 0 switch eq(k, n) case 1 { a := 4 } s := add(s, add(a, add(b, 1)))
            }
        }
        require(s == want);
    }
    function yulFunctionLet(uint256 n, uint256 want) external pure {
        uint256 s;
        assembly {
            function f(m) -> r { let t if gt(m, 2) { t := 5 } r := add(r, add(t, 1)) }
            s := add(f(n), f(0))
        }
        require(s == want);
    }
}
"""


def _sum(n: int, skip: int) -> int:
    return sum(i for i in range(1, n + 1) if i != skip)


def _do(n: int) -> int:
    i = s = 0
    while True:
        i += 1
        if i != 2:
            s += i
        if not i < n:
            return s


def _forever(n: int) -> int:
    s, i = 0, 1
    while i <= n:
        i += 1
        if i != 3:
            s += i
    return s


def _do_break(n: int) -> int:
    s = 0
    for _ in range(n):
        while True:
            s += 1
            if s == 4 or s % 3 == 0:
                break
    return s


def _forever_in_forever(n: int) -> int:
    s = 0
    while s < 4 * n:
        s += 1
        if s % 2:
            s += 1
    return s


EXPECTED = {
    "nestedPlain": lambda n: 31 * n,
    "nestedBreak": lambda n: 11 * n,
    "nestedContinue": lambda n: 21 * n,
    "nestedSymbolic": lambda n: 2 * (10 * n + 1),
    "declaredInLoop": lambda n: n * (n + 1) // 2,
    "whileBreakContinue": lambda n: _sum(n, 2),
    "whileContinue": lambda n: _sum(n, 2),
    "doContinue": _do,
    "forWithoutIncrement": lambda n: _sum(n, 2),
    "forWithoutCondition": lambda n: _sum(n, 2),
    "forever": _forever,
    "forContinue": lambda n: _sum(n, 2),
    "foreverInFor": lambda n: 3 * n,
    "foreverInWhileInFor": lambda n: 4 * n,
    "foreverInForever": _forever_in_forever,
    "doBreakInFor": _do_break,
    "yulFor": lambda n: n * (n + 1) // 2,
    "yulContinueBreak": lambda n: _sum(n, 2),
    "yulNested": lambda n: 11 * n,
    "yulPost": lambda n: sum(5 + 2 * i for i in range(n) if i != 1),
    "yulInFor": lambda n: 102 * n,
    # A Yul ``let`` without a value is zero each time it runs, an earlier iteration's value gone.
    "yulLetInLoop": lambda n: n,
    "yulLetSwitch": lambda n: 3 + (4 if n < 3 else 0),
    "yulFunctionLet": lambda n: (6 if n > 2 else 1) + 1,
}
CASES = [(name, (n, want(n) + d)) for name, want in EXPECTED.items() for n in range(5) for d in (0, 2)]
# Bounds read from an argument are followed exactly for a couple of iterations, then forgotten (``loop:N``).
EXACT = {name: range(1, 4) for name in EXPECTED} | {"nestedSymbolic": range(1, 3), "doBreakInFor": range(1, 3)}


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    d.deploy("C")
    return d


@pytest.mark.parametrize(("name", "values"), CASES, ids=[f"{c[0]}{c[1]}" for c in CASES])
def test_a_loop_continues_and_breaks_where_the_language_sends_it(deployed, name, values):
    fn = O.function(deployed, "C", name)
    formula, engine = O.engine_says(deployed, fn, values)
    rejected = sorted({t[1] for t in subterms(formula, "unknown") if str(t[1]).startswith("unsupported:")})
    assert not rejected, (name, rejected)
    if values[0] in EXACT[name]:
        assert engine is not UNK, (name, values)
    O.agrees(formula, engine, O.chain_says(deployed, fn, values), (name, values))


def test_a_break_whose_loop_cant_be_told_from_the_source_is_rejected_by_name(deployed, monkeypatch):
    """A ``break``'s target is read from the source (the innermost loop holding it), never from Slither's edge, which
    sends one in a ``for (;;)`` nested in a loop with a condition to the outer loop's end. Without a source span the
    path is rejected by name."""
    from slither.core.cfg.node import NodeType

    import services.logic.lower as lower

    real = lower._span
    monkeypatch.setattr(lower, "_span", lambda n: None if n.type == NodeType.BREAK else real(n))
    monkeypatch.setattr(lower, "_LOOP_PARTS", {})
    fn = next(f for f in deployed.slither["C"].functions_entry_points if f.name == "foreverInFor")
    reset_terms()
    formula = Lowerer(deployed.slither["C"]).success(fn)
    assert "unsupported:break" in {t[1] for t in subterms(formula, "unknown")}


def test_a_back_edge_is_ordered_by_its_own_source_node(deployed):
    """``_schedule`` orders a back edge into a ``for (;;)``'s start before that loop's end unless the edge comes from a
    loop condition (a ``do``/``while``). It is judged by the edge's own source node: a run started at the inner
    ``for (;;)`` of a loop nested in one with a condition schedules every node it reaches."""
    from slither.core.cfg.node import NodeType

    from services.logic.lower import _loop_nodes_raw, _schedule

    fn = next(f for f in deployed.slither["C"].functions_entry_points if f.name == "foreverInFor")
    starts = sorted((n for n in fn.nodes if n.type == NodeType.STARTLOOP), key=lambda n: n.source_mapping.start)
    inner = starts[-1]
    order, edges = _schedule(inner)
    assert len(order) == len(edges) == len(_loop_nodes_raw(inner, None))
