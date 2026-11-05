"""Control of distinct outcomes, independently from success or write occurrence."""

import pytest
import z3

from services.logic.model import Effect, Limits
from services.logic.power import write_power
from services.logic.solver import Translation, project
from services.logic.terms import CALLER, FALSE, TRUE, const, mk, mk_and, mk_cmp, mk_ite, mk_or, unknown
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

OWNER = 42
VALUE = mk("arg", "v", "uint8")
TARGET = (const(123, "address"), "value", ())
IS_OWNER = mk_cmp("eq", CALLER, const(OWNER, "address"))


class NoReads:
    block = 1

    def __getattr__(self, name):
        raise AssertionError(f"unexpected state read {name}")


def solve(guard, value, target=TARGET, limits=Limits(solver_ms=3000)):
    effect = Effect("write", target, value, guard)
    return project(write_power(effect), Translation(NoReads(), {}, 123, limits=limits))


@pytest.mark.parametrize(
    "guard,value",
    [
        (TRUE, mk_ite(IS_OWNER, VALUE, const(1))),
        (mk_or([IS_OWNER, mk_cmp("eq", VALUE, const(1))]), VALUE),
        (mk_cmp("le", VALUE, mk_ite(IS_OWNER, const(100), const(1))), VALUE),
        (IS_OWNER, VALUE),
    ],
)
def test_owner_has_outcomes_unavailable_to_everyone(guard, value):
    result = solve(guard, value)
    assert result.complete and result.members == (OWNER,), result


@pytest.mark.parametrize(
    "guard,value",
    [
        (TRUE, VALUE),
        (TRUE, const(1)),
        (FALSE, VALUE),
        # The expression depends on identity, but every caller can still choose any byte.
        (TRUE, mk_ite(IS_OWNER, VALUE, mk("op", "sub", (const(255), VALUE)))),
    ],
)
def test_common_outcomes_do_not_create_privileged_addresses(guard, value):
    result = solve(guard, value)
    assert result.complete and result.representation == "finite" and result.members == (), result


@pytest.mark.parametrize("owner_only", [False, True])
def test_raw_byte_inputs_retain_value_control(owner_only):
    raw = mk("arg", "raw", "bytes")
    value = mk("elem", raw, const(0))
    guard = mk_cmp("eq", mk("len", raw), const(32))
    result = solve(mk_and([guard, IS_OWNER]) if owner_only else guard, value)
    assert result.complete and result.members == ((OWNER,) if owner_only else ()), result


@pytest.mark.parametrize("payload", [b"", b"\x01", bytes(31) + b"\x07", bytes(range(65))])
def test_power_chunk_bindings_match_the_byte_window(payload):
    tr = Translation(NoReads(), {}, 123, bindings={mk("arg", "raw", "bytes"): payload})
    raw = mk("arg", "raw", "bytes")
    for index in (-1, 0, 1, 2, 2**251):
        part = tr.translate(mk("byte_chunk", raw, const(index)))
        expected = payload[32 * index : 32 * (index + 1)] if index >= 0 else b""
        assert z3.simplify(part).as_long() == int.from_bytes(expected.ljust(32, b"\0"), "big")
    assert not tr.issues


def test_all_callers_have_distinct_targets_not_uniform_target_control():
    result = solve(TRUE, const(1), (TARGET[0], "balances", (("k", CALLER),)))
    assert result.complete and result.representation == "cofinite" and result.excluded == (0,), result


def test_constraints_on_both_copies_exclude_unattainable_values():
    guard = mk_and([mk_cmp("lt", VALUE, const(4)), mk_or([IS_OWNER, mk_cmp("lt", VALUE, const(2))])])
    result = solve(guard, VALUE)
    assert result.complete and result.members == (OWNER,), result


@pytest.mark.parametrize("value", [unknown("unsupported:value"), mk("origin"), mk("arg", "data", "bytes")])
def test_unmodeled_or_noncaller_authority_is_never_a_power_proof(value):
    result = solve(TRUE, value)
    assert not result.complete and result.issues, result


def test_exhausted_solver_preserves_the_relational_query():
    result = solve(TRUE, mk_ite(IS_OWNER, VALUE, const(1)), limits=Limits(solver_ms=0))
    assert not result.complete and result.predicate[0] == "and"
    assert result.issues[0].kind == "budget"


@pytest.mark.parametrize("bound", [True, False])
def test_comparison_inputs_are_independent_of_bindings_and_variable_order(bound):
    effect = Effect("write", TARGET, mk_ite(IS_OWNER, VALUE, const(1)), TRUE)
    for value, expected in [(1, z3.unsat), (2, z3.sat)]:
        bindings = {CALLER: OWNER, VALUE: value} if bound else None
        tr = Translation(NoReads(), {}, 123, bindings=bindings)
        tr.translate(VALUE)  # Deliberately invert the inner/outer Z3 variable names.
        predicate = tr.translate(write_power(effect))
        solver = z3.Solver()
        solver.set(timeout=3000)
        solver.add(predicate, *tr.bounds, tr.translate(CALLER) == OWNER, tr.translate(VALUE) == value)
        assert not tr.issues and solver.check() == expected


@pytest.mark.parametrize("type_,valid,invalid", [("uint8", 255, 256), ("int8", -128, -129), ("bytes1", 255, 256)])
def test_output_substitution_keeps_bounds_and_repeated_coordinates(type_, valid, invalid):
    arg = mk("arg", "typed", type_)
    effect = Effect("write", (TARGET[0], "m", (("k", arg), ("k", arg))), arg, IS_OWNER)
    for value, expected in [(valid, z3.sat), (invalid, z3.unsat)]:
        tr = Translation(NoReads(), {}, 123, bindings={CALLER: OWNER, arg: value})
        predicate = tr.translate(write_power(effect))
        solver = z3.Solver()
        solver.set(timeout=3000)
        solver.add(predicate, *tr.bounds)
        assert solver.check() == expected


def test_repeated_coordinates_keep_the_other_callers_value_limit():
    guard = mk_or([IS_OWNER, mk_cmp("lt", VALUE, const(2))])
    result = solve(guard, VALUE, (TARGET[0], "m", (("k", VALUE), ("k", VALUE))))
    assert result.complete and result.members == (OWNER,), result


def test_same_target_does_not_imply_same_value():
    other = mk("arg", "other", "uint16")
    effect = Effect("write", (TARGET[0], "m", (("k", VALUE),)), mk_ite(IS_OWNER, other, VALUE), TRUE)
    for caller, value, expected in [(OWNER, 256, z3.sat), (OWNER, 1, z3.unsat), (7, 256, z3.unsat)]:
        tr = Translation(NoReads(), {}, 123, bindings={CALLER: caller, VALUE: 1, other: value})
        predicate = tr.translate(write_power(effect))
        solver = z3.Solver()
        solver.set(timeout=3000)
        solver.add(predicate, *tr.bounds)
        assert solver.check() == expected


def test_caller_coordinate_keeps_its_comparison_quantifier():
    result = solve(TRUE, VALUE, (TARGET[0], "m", (("k", CALLER), ("k", VALUE))))
    assert result.complete and result.representation == "cofinite" and result.excluded == (0,), result


@pytest.mark.parametrize("extra", [0, 1])
def test_shared_mapping_state_and_public_baseline(anvil, tmp_path, extra):
    from services.logic.expansion import Selection, expand_formula
    from services.logic.formula import compile_function

    limit = f"{extra}+limits[msg.sender]" if extra else "limits[msg.sender]"
    source = f"""pragma solidity ^0.8.10;
    contract C {{
      mapping(address=>uint8) public limits;uint8 public value;
      constructor(address a,address b){{limits[a]=5;limits[b]=2;}}
      function act(uint8 v) external returns(uint8){{require(v<={limit});value=v;return value;}}
    }}"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address", "address"), O.ACCOUNTS[:2])
    chain = d.chain()

    class Reads:
        block = chain.block

        def __getattr__(self, name):
            return getattr(chain, name)

        def storage_dump(self, address):
            # Independent constructor write domain; values still read from the EVM.
            return {O.slot(k, 0): chain.storage(address, O.slot(k, 0)) for k in O.ACCOUNTS[:2]}

        def key_words(self, address):
            return set(O.ACCOUNTS[:2])

        def preimages(self, address, slots):
            raise AssertionError("fixture constructor keys already known")

    reads, fn = Reads(), O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
    result = expand_formula(f, reads, d.contracts("C"), selection=Selection(False, (0,), (0,))).effects[0]
    if extra == 0 or result.complete:
        assert result.complete and set(result.members) == set(O.ACCOUNTS[:2]), result
    else:
        # Quantified modulo/ITE arithmetic is currently solver-limited. A stronger
        # future result is welcome; an optimistic complete answer is not.
        assert result.issues and any(i.kind in {"solver", "budget"} for i in result.issues), result
    assert O.passes(d, "C", fn, (2 + extra,), sender=O.ACCOUNTS[1])
    assert not O.passes(d, "C", fn, (3 + extra,), sender=O.ACCOUNTS[1])
    assert O.passes(d, "C", fn, (extra,), sender=O.ACCOUNTS[2])
    assert not O.passes(d, "C", fn, (extra + 1,), sender=O.ACCOUNTS[2])


def test_physical_target_metadata_preserves_mapping_admin_power(anvil, tmp_path):
    from services.logic.expansion import Selection, expand_formula
    from services.logic.formula import compile_function

    d = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity 0.8.27;
    contract C {address owner=msg.sender;mapping(address=>bool) roles;
    function set(address a,bool v) external {require(msg.sender==owner);roles[a]=v;}}""",
    )
    d.deploy("C")
    chain = d.chain()

    class Reads:
        block = chain.block

        def __getattr__(self, name):
            return getattr(chain, name)

        def storage_dump(self, address):
            return {0: chain.storage(address, 0)}

        def key_words(self, address):
            return {O.OWNER}

        def preimages(self, address, slots):
            raise AssertionError("complete fixture slots already attributed")

    reads = Reads()
    known = d.contracts("C")
    fn = O.function(d, "C", "set")
    assert O.passes(d, "C", fn, (O.ACCOUNTS[1], True), sender=O.OWNER)
    assert not O.passes(d, "C", fn, (O.ACCOUNTS[1], True), sender=O.ACCOUNTS[1])
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, known)
    for scope in ((), (0,)):
        result = expand_formula(f, reads, known, selection=Selection(False, (0,), scope)).effects[0]
        assert result.complete and result.members == (O.OWNER,), result
