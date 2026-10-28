"""Sibling Yul blocks each declaring ``let x``: Slither makes a variable per declaration, both named alike, and binds
every use of ``x`` to one of them, so a read after the second ``let x`` read the first block's value. Yul forbids
shadowing a name still in scope, so the declarations' lifetimes never overlap: the name is one cell, which each
declaration starts again (zero without a value). Where the uses can't be told apart that way, a read of the name is
``unknown:shadowed:<name>``. Each probe's lowered condition, evaluated, must be what ``eth_call`` says on anvil."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from services.logic.lower import Lowerer
from services.logic.terms import subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

UNK = None

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

# A Solidity local declared again under a name in use: Slither renames the later one ``x_scope_0`` and binds an
# assembly use of ``x`` to the first, whichever is in scope (review 5, ``q4``).
SOLIDITY_LOCALS = """
pragma solidity 0.8.27;

contract S {
    function solSolYul(uint256 n, uint256 want) external pure {
        uint256 acc;
        { uint256 x = n + 9; acc = x; }
        { uint256 x = 3; assembly { acc := add(acc, x) } }
        require(acc == want);
    }
    function solYulSol(uint256 n, uint256 want) external pure {
        uint256 acc;
        { uint256 x = n + 9; assembly { acc := x } }
        { uint256 x = 3; acc = acc + x; }
        require(acc == want);
    }
    function yulWritesSecond(uint256 n, uint256 want) external pure {
        uint256 acc;
        { uint256 x = n + 9; acc = x; }
        { uint256 x = 3; assembly { x := add(x, 1) } acc = acc + x; }
        require(acc == want);
    }
    function solThenYul(uint256 n, uint256 want) external pure {
        uint256 acc;
        { uint256 x = n + 1; acc = x; }
        assembly { let x := 2 acc := add(acc, x) }
        require(acc == want);
    }
    function solSol(uint256 n, uint256 want) external pure {
        uint256 acc;
        { uint256 x = n + 9; acc = x; }
        { uint256 x = 3; acc = acc + x; }
        require(acc == want);
    }
}
"""
SHADOWED = ["solSolYul", "solYulSol", "yulWritesSecond"]


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE + SOLIDITY_LOCALS.split("\n", 2)[2])
    d.deploy("C")
    d.deploy("S")
    return d


def _fn(d, name, contract="C"):
    return O.function(d, contract, name)


def _chain_says(d, fn, values, contract="C") -> bool:
    return O.chain_says(d, fn, values, contract)


def _engine_says(d, fn, values, contract="C"):
    return O.engine_says(d, fn, values, contract)


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
    O.agrees(formula, engine, _chain_says(deployed, fn, (0, 1)))
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


@pytest.mark.parametrize("name", [*SHADOWED, "solThenYul", "solSol"])
def test_assembly_naming_a_solidity_local_declared_twice_reads_it_or_says_it_cannot(deployed, name):
    # Slither's binding of the assembly's ``x`` can't be trusted where two Solidity locals are named ``x``: every
    # read of either is ``unknown:shadowed:x``, never the other one's value. Without assembly naming one (``solSol``),
    # or with a Yul ``let x`` of its own (``solThenYul``), the answer is definite and the chain's.
    fn = _fn(deployed, name, "S")
    passing = 0
    for n in range(4):
        for want in range(20):
            chain = _chain_says(deployed, fn, (n, want), "S")
            formula, engine = _engine_says(deployed, fn, (n, want), "S")
            passing += chain
            if name in SHADOWED:
                O.agrees(formula, engine, chain, (name, n, want))
                assert "shadowed:x" in {u[1] for u in subterms(formula, "unknown")}
            else:
                assert engine == chain, (name, n, want, chain, engine)
    assert passing == 4
