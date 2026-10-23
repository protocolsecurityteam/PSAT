"""``continue`` and ``break`` go where the language sends them, in every loop form, nested ones included: a
``continue`` to a ``for`` loop's increment, else to the condition (``while``, ``do``/``while``, a ``for`` without an
increment), else to the loop's start (``for (;;)``). Slither's own edge sends a ``continue`` in a ``while`` or
``do``/``while`` body to the body's last statement, and one in a ``for`` without a condition past the increment. An
iteration followed exactly is a region of the graph (an inner loop entered again in each outer iteration, its counter
declared zero again). Each probe's lowered condition, evaluated, must be what ``eth_call`` says on anvil, and definite
over the iterations followed exactly."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from services.logic.decide import UNK, Evaluator, World
from services.logic.lower import Lowerer, parameter
from services.logic.terms import reset_terms, subterms
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

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
}
CASES = [(name, (n, want(n) + d)) for name, want in EXPECTED.items() for n in range(5) for d in (0, 2)]
# Bounds read from an argument are followed exactly for a couple of iterations, then forgotten (``loop:N``).
EXACT = {name: range(1, 4) for name in EXPECTED} | {"nestedSymbolic": range(1, 3)}


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("C")
    return d


def _chain_says(d, fn, values) -> bool:
    data = keccak(text=fn.solidity_signature)[:4] + encode(["uint256", "uint256"], list(values))
    try:
        rpc(d.url, "eth_call", [{"from": ACCOUNT0, "to": "0x%040x" % d.at["C"], "data": "0x" + data.hex()}, "latest"])
        return True
    except RuntimeError:
        return False


def _engine_says(d, fn, values):
    reset_terms()
    formula = Lowerer(d.slither["C"]).success(fn)
    world = World(d.chain(), d.at["C"], int.from_bytes(keccak(text=fn.solidity_signature)[:4], "big"), {})
    assignment = {parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, values))}
    caller = int(ACCOUNT0, 16)
    return formula, Evaluator(world, {"caller": caller, "signer": caller}, assignment).truth(formula)


@pytest.mark.parametrize(("name", "values"), CASES, ids=[f"{c[0]}{c[1]}" for c in CASES])
def test_a_loop_continues_and_breaks_where_the_language_sends_it(deployed, name, values):
    fn = next(f for f in deployed.slither["C"].functions_entry_points if f.name == name)
    formula, engine = _engine_says(deployed, fn, values)
    rejected = sorted({t[1] for t in subterms(formula, "unknown") if str(t[1]).startswith("unsupported:")})
    assert not rejected, (name, rejected)
    if values[0] in EXACT[name]:
        assert engine is not UNK, (name, values)
    if engine is not UNK:
        assert engine == _chain_says(deployed, fn, values), (name, values, formula)
