"""Zero is a valid EVM value, but not a real controller in a caller projection."""

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from services.logic.model import Limits, decode_formula, encode
from services.logic.solver import Translation, project
from services.logic.terms import CALLER, TRUE, const, mk, mk_cmp
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
contract C {
 address public owner;
 address public destination;
 function renounced() external {require(msg.sender==owner); destination=msg.sender;}
 function acceptZero(address next) external {require(next==address(0));destination=next;}
 function badSignature() external {
 require(ecrecover(bytes32(0),0,bytes32(0),bytes32(0))==owner);destination=msg.sender;}
}"""


def test_zero_caller_is_excluded_even_when_the_formula_accepts_it():
    result = project(mk_cmp("eq", CALLER, const(0)), Translation(None, {}, 1))
    assert result.complete and result.representation == "finite" and result.members == ()
    opened = project(TRUE, Translation(None, {}, 1))
    assert opened.complete and opened.representation == "cofinite" and opened.excluded == (0,)


def test_zero_argument_identity_remains_a_valid_value():
    arg = mk("arg", "who", "address")
    result = project(mk_cmp("eq", arg, const(0)), Translation(None, {}, 1), identity=arg)
    assert result.complete and result.members == (0,)


def test_unfinished_projection_keeps_the_nonzero_constraint():
    result = project(TRUE, Translation(None, {}, 1, limits=Limits(solver_ms=0)))
    assert not result.complete and not result.members
    import z3

    evaluated = Translation(None, {}, 1, bindings={CALLER: 0}).translate(result.predicate)
    assert z3.is_false(z3.simplify(evaluated))


def test_zero_owner_and_zero_signature_have_different_authorization_meanings(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C")
    reads = d.chain()
    for name, values in [("renounced", ()), ("acceptZero", (0,)), ("badSignature", ())]:
        fn = O.function(d, "C", name)
        formula = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
        before = encode(formula)
        result = expand_formula(formula, reads, d.contracts("C")).callers
        assert encode(formula) == before and decode_formula(before) == formula
        assert result.complete and 0 not in result.members
        if name == "renounced":
            assert result.representation == "finite" and not result.members
        else:
            assert result.representation == "cofinite" and result.excluded == (0,)
        for caller in O.ACCOUNTS:
            assert O.chain_says(d, fn, values, sender=caller) is (name != "renounced")
