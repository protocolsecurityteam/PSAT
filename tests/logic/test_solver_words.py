"""Word conversion preserves semantics without obscuring finite storage values."""

import pytest
import z3

from services.logic.formula import compile_function
from services.logic.model import Limits
from services.logic.solver import Translation, project, word
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


def test_conditional_word_conversion_is_equivalent_for_unbounded_integer_leaves():
    a, b, c = z3.Ints("a b c")
    p, q = z3.Bools("p q")
    value = z3.If(p, a, z3.If(q, b, c))
    difference = word(value) != z3.Int2BV(value, 256)
    # Exhaust all Boolean branches; integer leaves remain arbitrary in each proof.
    for pv in (False, True):
        for qv in (False, True):
            branch = z3.substitute(difference, (p, z3.BoolVal(pv)), (q, z3.BoolVal(qv)))
            assert z3.is_false(z3.simplify(branch))


@pytest.mark.parametrize("value", [-(2**300), -1, 0, 2**255, 2**256 - 1, 2**256, 2**300 + 7])
def test_word_conversion_preserves_modular_values(value):
    expression = z3.If(z3.Bool("choose"), z3.IntVal(value), z3.IntVal(0))
    actual = z3.simplify(z3.substitute(word(expression), (z3.Bool("choose"), z3.BoolVal(True))))
    assert actual.as_long() == value % 2**256


def test_deep_shared_conditionals_do_not_recurse_or_duplicate_subtrees():
    x = z3.Int("x")
    value = z3.IntVal(-1)
    for i in range(2000):
        value = z3.If(x == i, i, value)
    actual = word(value)
    assert z3.simplify(z3.substitute(actual, (x, z3.IntVal(1000)))).as_long() == 1000
    assert z3.simplify(z3.substitute(actual, (x, z3.IntVal(-1)))).as_long() == 2**256 - 1


SOURCE = """pragma solidity ^0.8.10;
contract C {
 mapping(address=>uint256) roles;
 constructor() { for(uint i=0;i<24;i++) roles[address(uint160(100+i))] = (1 << (i+32)) | (i%2==0 ? 8:4); }
 function act() external view { require(roles[msg.sender] & 8 != 0); }
}"""


def test_role_bitmaps_project_to_the_complete_known_set(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C")
    chain = d.chain()
    keys = set(range(100, 124))

    class Reads:
        block = chain.block

        def __getattr__(self, name):
            return getattr(chain, name)

        def storage_dump(self, address):
            return {O.slot(key, 0): chain.storage(address, O.slot(key, 0)) for key in keys}

        def key_words(self, address):
            return keys

        def preimages(self, address, slots):
            raise AssertionError("constructor write domain is complete")

    reads = Reads()
    fn = O.function(d, "C", "act")
    formula = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
    result = project(
        formula.success, Translation(reads, d.contracts("C"), d.at["C"], formula.selector, Limits(solver_ms=1000))
    )
    expected = tuple(range(100, 124, 2))
    assert result.complete and result.representation == "finite" and result.members == expected
    # Fixture truth comes from the independently compiled constructor and actual EVM execution.
    for caller in [0, 99, *range(100, 125), 2**160 - 1]:
        assert O.chain_says(d, fn, (), sender=caller) is (caller in expected)
