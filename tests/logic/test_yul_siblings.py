"""Sibling Yul blocks each declaring ``let x``: Slither makes a variable per declaration, both named alike, and binds
every use of ``x`` to one of them, so a read after the second ``let x`` read the first block's value. Yul forbids
shadowing a name still in scope, so the declarations' lifetimes never overlap: the name is one cell, which each
declaration starts again (zero without a value). Where the uses can't be told apart that way, a read of the name is
``unknown:shadowed:<name>``. Each probe's lowered condition, evaluated, must be what ``eth_call`` says on anvil."""

from __future__ import annotations

from types import SimpleNamespace

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
    function sibUnset(uint256 n, uint256 want) external pure {
        uint256 acc;
        assembly {
            { let x := add(n, 1) acc := x }
            { let x acc := add(acc, x) }
        }
        require(acc == want);
    }
    function sibValue(uint256 n, uint256 want) external pure {
        uint256 acc;
        assembly {
            { let x := add(n, 1) acc := x }
            { let x := 7 acc := add(acc, x) }
        }
        require(acc == want);
    }
    function sibThree(uint256 n, uint256 want) external pure {
        uint256 acc;
        assembly {
            { let x := mul(n, 2) acc := x }
            { let x acc := add(acc, x) x := 5 acc := add(acc, x) }
            { let x acc := add(acc, x) }
        }
        require(acc == want);
    }
    function sibInLoop(uint256 n, uint256 want) external pure {
        uint256 acc;
        assembly {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                { let x acc := add(acc, x) x := 1 acc := add(acc, x) }
                { let x acc := add(acc, x) }
            }
        }
        require(acc == want);
    }
}
"""
NAMES = ["sibUnset", "sibValue", "sibThree", "sibInLoop"]


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("C")
    return d


def _fn(d, name):
    return next(f for f in d.slither["C"].functions_entry_points if f.name == name)


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


@pytest.mark.parametrize("name", NAMES)
def test_a_name_declared_in_sibling_yul_blocks_reads_its_own_block_s_value(deployed, name):
    fn = _fn(deployed, name)
    passing = 0
    for n in range(4):
        for want in range(14):
            chain = _chain_says(deployed, fn, (n, want))
            formula, engine = _engine_says(deployed, fn, (n, want))
            assert engine == chain, (name, n, want, chain, engine)
            passing += chain
    assert passing == 4  # one want passes for each n: both directions are checked
    assert not any(str(u[1]).startswith("shadowed:") for u in subterms(formula, "unknown"))


def test_uses_that_can_t_be_told_apart_are_unknown_by_name(deployed, monkeypatch):
    fn = _fn(deployed, "sibUnset")
    xs = [n.variable_declaration for n in fn.nodes if n.variable_declaration and n.variable_declaration.name != "acc"]
    assert len(xs) == 2 and xs[0].name == xs[1].name
    monkeypatch.setattr(Lowerer, "_same_named", lambda self, function: ({}, frozenset(id(x) for x in xs)))
    formula, engine = _engine_says(deployed, fn, (0, 1))
    assert engine is UNK
    assert any(u[1] == f"shadowed:{xs[0].name}" for u in subterms(formula, "unknown"))


def _var(name):
    return SimpleNamespace(name=name)


def _node(declared=None, uses=(), yul=True):
    irs = [SimpleNamespace(read=list(uses), lvalue=None)] if uses else []
    return SimpleNamespace(variable_declaration=declared, irs=irs, scope=SimpleNamespace(is_yul=yul))


def test_same_named_locals_one_cell_unknown_or_told_apart():
    a, b = _var("x"), _var("x")
    same = Lowerer._same_named
    # Yul, every use bound to one of them: one cell.
    cells, unknown = same(
        SimpleNamespace(_named={}), SimpleNamespace(nodes=[_node(a, [a]), _node(b), _node(None, [a])])
    )
    assert cells == {id(a): a, id(b): a} and not unknown
    # Yul, uses naming both: which one a use reads isn't known.
    cells, unknown = same(SimpleNamespace(_named={}), SimpleNamespace(nodes=[_node(a, [a]), _node(b, [b])]))
    assert not cells and unknown == {id(a), id(b)}
    # Solidity, uses naming each (scoping resolved by declaration): told apart.
    cells, unknown = same(
        SimpleNamespace(_named={}), SimpleNamespace(nodes=[_node(a, [a], yul=False), _node(b, [b], yul=False)])
    )
    assert not cells and not unknown
    # Solidity, one declaration no use names: the uses' variable can't be trusted to be theirs.
    cells, unknown = same(
        SimpleNamespace(_named={}), SimpleNamespace(nodes=[_node(a, [a], yul=False), _node(b, yul=False)])
    )
    assert not cells and unknown == {id(a), id(b)}
