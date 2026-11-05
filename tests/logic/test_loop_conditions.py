"""Loop simplification preserves conditions, writes, and the source function's domain."""

import operator
from typing import cast

import pytest
import z3

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.model import Formula, Reads
from services.logic.solver import Translation
from services.logic.terms import CALLER, FALSE, const, mk, mk_and, mk_cmp, unknown
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


@pytest.mark.parametrize(
    "op,relation",
    [
        ("lt", operator.lt),
        ("le", operator.le),
        ("gt", operator.gt),
        ("ge", operator.ge),
        ("eq", operator.eq),
        ("ne", operator.ne),
    ],
)
def test_comparison_normalization_is_equivalent_for_arbitrary_integers(op, relation):
    x, y = mk("arg", "x", "int256"), mk("arg", "y", "int256")
    tr = Translation(cast(Reads, object()), {}, 1)
    a, b = tr.translate(x), tr.translate(y)
    solver = z3.Solver()
    solver.add(tr.translate(mk_cmp(op, x, y)) != relation(a, b))
    assert solver.check() == z3.unsat


def test_complementary_bounds_prune_only_modeled_values():
    x = mk("arg", "length", "uint256")
    assert mk_and([mk_cmp("le", x, const(3)), mk_cmp("lt", const(3), x)]) == FALSE
    gap = unknown("unmodeled read")
    assert mk_and([mk_cmp("le", gap, const(3)), mk_cmp("lt", const(3), gap)]) != FALSE


SOURCE = """pragma solidity ^0.8.10;
contract C {uint public result;
function bounded(uint n) external {require(n<=3);for(uint i=0;i<n;i++){result+=i;}}
function contradictory(uint n) external {require(n<=3);require(n>3);result=1;}
function unbounded(uint n) external {for(uint i=0;i<n;i++){result+=i;}}
}"""


def test_bounded_input_loop_finishes_without_larger_budgets(anvil, tmp_path):
    from services.logic.lower import parameter

    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C")
    reads = d.chain()
    for name in ("bounded", "contradictory", "unbounded"):
        fn = O.function(d, "C", name)
        formula = generate_function(
            d.slither["C"], fn, d.at["C"], reads, d.contracts("C"), steps=10000, loop_iterations=4
        )
        if name == "unbounded":
            assert isinstance(formula, PendingCompilation) and formula.reason == "loop_iterations"
            continue
        assert isinstance(formula, Formula)
        for n in (0, 1, 2, 3, 4, 2**256 - 1):
            tr = Translation(
                reads,
                d.contracts("C"),
                d.at["C"],
                formula.selector,
                bindings={CALLER: O.OWNER, mk("callvalue"): 0, parameter(fn.parameters[0], 0): n},
            )
            assert tr.truth(formula.success) == O.chain_says(d, fn, (n,), sender=O.OWNER)
