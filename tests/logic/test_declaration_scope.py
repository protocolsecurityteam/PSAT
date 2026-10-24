"""A local declared without a value is zero where the compiler makes it so. Since Solidity 0.5 locals are
block-scoped: zero (a fresh zeroed object in memory) each time the declaration runs. Before, they are function-scoped:
zeroed once at the function's entry, and the declaration emits no code, so a loop's body keeps what the previous
iteration left and an assignment written above the declaration stands. The version is the compilation unit's. Each
probe's lowered condition, evaluated, must be what ``eth_call`` says on anvil, and definite."""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

import tests.logic._anvil as A
from services.logic.decide import UNK, Evaluator, World
from services.logic.lower import Lowerer, parameter
from services.logic.terms import reset_terms, subterms
from tests.fuzz.authority import solc_path
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

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
}
"""

EXPECTED = {
    ("0.4.19", "acc"): lambda n: n * (n + 1) // 2,
    ("0.4.19", "hoisted"): lambda n: n,
    ("0.4.19", "memoryAcc"): lambda n: n * (n + 1) // 2,
    ("0.4.19", "branch"): lambda n: n + (5 if n > 1 else 0),
    ("0.5.14", "acc"): lambda n: n,
    ("0.5.14", "memoryAcc"): lambda n: n,
}
SOURCES = {"0.4.19": SOURCE_04, "0.5.14": SOURCE_05}
CASES = [(v, name, (n, want(n) + d)) for (v, name), want in EXPECTED.items() for n in range(4) for d in (0, 2)]


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    url, root = anvil
    out = {}
    for version, source in SOURCES.items():
        if solc_path(version) is None:
            continue
        old, A.SOLC = A.SOLC, version
        try:
            sub = root / version
            sub.mkdir(exist_ok=True)
            out[version] = A.Deployment(url, sub, source)
        finally:
            A.SOLC = old
        out[version].deploy("C")
    return out


@pytest.mark.parametrize(("version", "name", "values"), CASES, ids=[f"{c[0]}-{c[1]}{c[2]}" for c in CASES])
def test_a_local_declared_without_a_value_is_zero_where_the_compiler_makes_it_so(deployed, version, name, values):
    if version not in deployed:
        pytest.skip(f"solc {version} not installed")
    d = deployed[version]
    fn = next(f for f in d.slither["C"].functions_entry_points if f.name == name)
    data = keccak(text=fn.solidity_signature)[:4] + encode(["uint256", "uint256"], list(values))
    try:
        rpc(d.url, "eth_call", [{"from": ACCOUNT0, "to": "0x%040x" % d.at["C"], "data": "0x" + data.hex()}, "latest"])
        chain = True
    except RuntimeError:
        chain = False
    reset_terms()
    formula = Lowerer(d.slither["C"]).success(fn)
    world = World(d.chain(), d.at["C"], int.from_bytes(keccak(text=fn.solidity_signature)[:4], "big"), {})
    assignment = {parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, values))}
    caller = int(ACCOUNT0, 16)
    engine = Evaluator(world, {"caller": caller, "signer": caller}, assignment).truth(formula)
    rejected = sorted({t[1] for t in subterms(formula, "unknown") if str(t[1]).startswith("unsupported:")})
    assert not rejected, (name, rejected)
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
