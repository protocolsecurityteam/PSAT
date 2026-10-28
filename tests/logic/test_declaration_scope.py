"""A local declared without a value is zero where the compiler makes it so. Since Solidity 0.5 locals are
block-scoped: zero (a fresh zeroed object in memory) each time the declaration runs. Before, they are function-scoped:
zeroed once at the function's entry, and the declaration emits no code, so a loop's body keeps what the previous
iteration left and an assignment written above the declaration stands. The version is the compilation unit's. Each
probe's lowered condition, evaluated, must be what ``eth_call`` says on anvil, and definite.

A modifier running ``_`` more than once (twice, in a loop) runs the body again from the frame the last run left, in
every version: parameters and return variables as written, and before 0.5 the function-scoped locals too."""

from __future__ import annotations

import pytest

from services.logic.lower import Lowerer
from services.logic.terms import reset_terms, subterms
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

UNK = None

SOURCE_04 = """
pragma solidity 0.4.19;

contract C {
    struct S { uint256 x; }
    function acc(uint256 n, uint256 want) public pure {
        uint256 s;
        for (uint256 i = 0; i < n; i++) { uint256 j; j += 1; s += j; }
        require(s == want);
    }
    function hoisted(uint256 n, uint256 want) public pure {
        j = n;
        uint256 j;
        require(j == want);
    }
    function memoryAcc(uint256 n, uint256 want) public pure {
        uint256 s;
        for (uint256 i = 0; i < n; i++) { S memory m; m.x += 1; s += m.x; }
        require(s == want);
    }
    function branch(uint256 n, uint256 want) public pure {
        if (n > 1) { uint256 j = 5; }
        require(j + n == want);
    }
    uint256 private t;
    modifier twice(uint256 n, uint256 want) { uint256 b = t; _; _; require(t - b == want); }
    modifier loopy(uint256 n, uint256 want) {
        uint256 b = t; for (uint256 i = 0; i < n; i++) { _; } require(t - b == want);
    }
    function twiceAcc(uint256 n, uint256 want) public twice(n, want) { uint256 j; j += 1; t += j; }
    function loopAcc(uint256 n, uint256 want) public loopy(n, want) { uint256 j; j += 1; t += j; }
    function twiceBranch(uint256 n, uint256 want) public twice(n, want) { uint256 j; if (n > 0) { j = j + n; } t += j; }
}
"""

SOURCE_05 = """
pragma solidity 0.5.14;

contract C {
    struct S { uint256 x; }
    function acc(uint256 n, uint256 want) public pure {
        uint256 s;
        for (uint256 i = 0; i < n; i++) { uint256 j; j += 1; s += j; }
        require(s == want);
    }
    function memoryAcc(uint256 n, uint256 want) public pure {
        uint256 s;
        for (uint256 i = 0; i < n; i++) { S memory m; m.x += 1; s += m.x; }
        require(s == want);
    }
    uint256 private t;
    modifier twice(uint256 n, uint256 want) { uint256 b = t; _; _; require(t - b == want); }
    modifier loopy(uint256 n, uint256 want) {
        uint256 b = t; for (uint256 i = 0; i < n; i++) { _; } require(t - b == want);
    }
    function twiceAcc(uint256 n, uint256 want) public twice(n, want) { uint256 j; j += 1; t += j; }
    function loopAcc(uint256 n, uint256 want) public loopy(n, want) { uint256 j; j += 1; t += j; }
    function twiceBranch(uint256 n, uint256 want) public twice(n, want) { uint256 j; if (n > 0) { j = j + n; } t += j; }
}
"""

SOURCE_08 = """
pragma solidity 0.8.27;

contract C {
    uint256 private t;
    modifier twice(uint256 n, uint256 want) { uint256 b = t; _; _; require(t - b == want); }
    function twiceParameter(uint256 n, uint256 want) external twice(n, want) { n += 1; t += n; }
    function twiceReturned(uint256 n, uint256 want) external twice(n, want) returns (uint256 q) { q += n + 1; t += q; }
    function twiceReturn(uint256 n, uint256 want) external twice(n, want) returns (uint256) {
        uint256 j; j += n + 1; t += j; return t;
    }
}
"""

EXPECTED = {
    ("0.4.19", "acc"): lambda n: n * (n + 1) // 2,
    ("0.4.19", "hoisted"): lambda n: n,
    ("0.4.19", "memoryAcc"): lambda n: n * (n + 1) // 2,
    ("0.4.19", "branch"): lambda n: n + (5 if n > 1 else 0),
    ("0.5.14", "acc"): lambda n: n,
    ("0.5.14", "memoryAcc"): lambda n: n,
    # ``_`` run again: before 0.5 the body's local keeps what the last run left; from 0.5 it is zeroed again.
    ("0.4.19", "twiceAcc"): lambda n: 3,
    ("0.4.19", "loopAcc"): lambda n: n * (n + 1) // 2,
    ("0.4.19", "twiceBranch"): lambda n: 3 * n,
    ("0.5.14", "twiceAcc"): lambda n: 2,
    ("0.5.14", "loopAcc"): lambda n: n,
    ("0.5.14", "twiceBranch"): lambda n: 2 * n,
    # Parameters and return variables keep what the last run wrote.
    ("0.8.27", "twiceParameter"): lambda n: 2 * n + 3,
    ("0.8.27", "twiceReturned"): lambda n: 3 * n + 3,
    ("0.8.27", "twiceReturn"): lambda n: 2 * n + 2,
}
SOURCES = {"0.4.19": SOURCE_04, "0.5.14": SOURCE_05, "0.8.27": SOURCE_08}
CASES = [(v, name, (n, want(n) + d)) for (v, name), want in EXPECTED.items() for n in range(4) for d in (0, 2)]


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    out = {}
    for version, source in SOURCES.items():
        if solc_path(version) is None:
            continue
        out[version] = O.deployment(*anvil, source, version)
        out[version].deploy("C")
    return out


@pytest.mark.parametrize(("version", "name", "values"), CASES, ids=[f"{c[0]}-{c[1]}{c[2]}" for c in CASES])
def test_a_local_declared_without_a_value_is_zero_where_the_compiler_makes_it_so(deployed, version, name, values):
    if version not in deployed:
        pytest.skip(f"solc {version} not installed")
    d = deployed[version]
    fn = O.function(d, "C", name)
    chain = O.chain_says(d, fn, values)
    formula, engine = O.engine_says(d, fn, values, contracts=d.contracts("C"))
    # The full formula may retain a qualified, unreachable loop tail. At these concrete
    # inputs it must still be definite and agree with the EVM.
    assert engine is not UNK, (version, name, values, formula)
    assert engine == chain, (version, name, values, formula)
    assert chain == (values[1] == EXPECTED[(version, name)](values[0]))


def test_a_declaration_whose_version_cant_be_read_keeps_no_guess(deployed, monkeypatch):
    """Where the compilation unit's version can't be read, a local the declaration would either zero or keep is
    unknown by name, never one of the two guessed."""
    if "0.4.19" not in deployed:
        pytest.skip("solc 0.4.19 not installed")
    import services.logic.lower as lower

    monkeypatch.setattr(lower, "_solc_version", lambda function: None)
    d = deployed["0.4.19"]
    fn = next(f for f in d.slither["C"].functions_entry_points if f.name == "hoisted")
    reset_terms()
    formula = Lowerer(d.slither["C"]).success(fn)
    assert "unsupported:declaration_scope" in {t[1] for t in subterms(formula, "unknown")}
