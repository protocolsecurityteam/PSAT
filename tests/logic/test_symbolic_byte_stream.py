"""All reads of a symbolic byte input share one stream, including overlapping words."""

import pytest
import z3

from services.logic.solver import Translation, integer
from services.logic.terms import CALLDATA, const, mk
from tests.logic._anvil import anvil  # noqa: F401


def translator():
    return Translation(None, {}, 0)


def solver_for(tr, *conditions):
    solver = z3.Solver()
    # Bit-level oracle proofs get a watchdog independent of the engine projection budget.
    solver.set(timeout=20000)
    solver.add(*tr.bounds, *conditions)
    return solver


@pytest.mark.parametrize("offset", [0, 1, 31, 32, 33, 63, 2**256 - 1])
@pytest.mark.parametrize("size", [0, 1, 31, 32, 33, 64, 67])
def test_symbolic_window_matches_a_fully_bound_stream(offset, size):
    data = bytes((i * 29 + 7) % 256 for i in range(size))
    tr = translator()
    length = integer(tr.translate(mk("len", CALLDATA)))
    window = integer(tr.translate(mk("elem", CALLDATA, const(offset))))
    constraints = [length == size]
    for block in range((size + 31) // 32):
        word = integer(tr.translate(mk("abi_word", CALLDATA, block)))
        constraints.append(word == int.from_bytes(data[32 * block : 32 * (block + 1)].ljust(32, b"\0"), "big"))
    expected = int.from_bytes(data[offset : offset + 32].ljust(32, b"\0"), "big")
    assert not tr.issues, tr.issues
    assert solver_for(tr, *constraints).check() == z3.sat
    assert solver_for(tr, *constraints, window != expected).check() == z3.unsat


def test_overlapping_windows_cannot_choose_conflicting_bytes():
    tr = translator()
    length = integer(tr.translate(mk("len", CALLDATA)))
    first = integer(tr.translate(mk("elem", CALLDATA, const(0))))
    second = integer(tr.translate(mk("elem", CALLDATA, const(1))))
    assert not tr.issues
    assert solver_for(tr, length == 33, first == 0, second >= 256).check() == z3.unsat
    assert solver_for(tr, length == 33, first == 0, second == 7).check() == z3.sat


@pytest.mark.parametrize("index", [0, 1, 3])
def test_abi_word_and_byte_offset_are_the_same_read(index):
    tr = translator()
    a = tr.translate(mk("abi_word", CALLDATA, index))
    b = tr.translate(mk("elem", CALLDATA, const(index * 32)))
    assert not tr.issues
    assert solver_for(tr, a != b).check() == z3.unsat


def test_symbolic_offset_uses_same_stream():
    tr = translator()
    offset = mk("arg", "offset", "uint256")
    a = tr.translate(mk("elem", CALLDATA, offset))
    b = tr.translate(mk("elem", CALLDATA, const(17)))
    selected = tr.translate(offset)
    assert not tr.issues
    assert solver_for(tr, selected == 17, a != b).check() == z3.unsat


def test_end_of_word_domain_does_not_wrap_to_the_start_of_calldata():
    tr = translator()
    length = integer(tr.translate(mk("len", CALLDATA)))
    edge = integer(tr.translate(mk("elem", CALLDATA, const(2**256 - 2))))
    assert not tr.issues
    assert solver_for(tr, length == 2**256 - 1, edge % (2**248) != 0).check() == z3.unsat


def test_distinct_inputs_are_independent():
    tr = translator()
    other = mk("arg", "other", "bytes")
    a = tr.translate(mk("elem", CALLDATA, const(0)))
    b = tr.translate(mk("elem", other, const(0)))
    n = tr.translate(mk("len", CALLDATA))
    m = tr.translate(mk("len", other))
    assert not tr.issues
    assert solver_for(tr, n == 32, m == 32, a == 0, b == 1).check() == z3.sat


@pytest.mark.parametrize("offset", [0, 1, 31, 32, 63, 2**256 - 1])
@pytest.mark.parametrize("size", [3, 67])
def test_symbolic_relation_matches_evm_calldataload(anvil, tmp_path, offset, size):
    from tests.logic import _oracle as O
    from tests.support.anvil import rpc

    source = """pragma solidity 0.8.27;
    contract C {fallback() external {assembly {mstore(0,calldataload(OFFSET)) return(0,32)}}}
    """.replace("OFFSET", str(offset))
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    data = bytes((i * 17 + 11) % 256 for i in range(size))
    actual = int(rpc(d.url, "eth_call", [{"to": O.hex20(d.at["C"]), "data": "0x" + data.hex()}, "latest"]), 16)
    tr = translator()
    window = tr.translate(mk("elem", CALLDATA, const(offset)))
    length = tr.translate(mk("len", CALLDATA))
    constraints = [length == size]
    for i in range((size + 31) // 32):
        word = tr.translate(mk("abi_word", CALLDATA, i))
        constraints.append(word == int.from_bytes(data[32 * i : 32 * (i + 1)].ljust(32, b"\0"), "big"))
    assert not tr.issues
    assert solver_for(tr, *constraints, window != actual).check() == z3.unsat


@pytest.mark.parametrize("offset", [0, 1, 17, 31, 32, 66, 67, 2**256 - 1])
def test_symbolic_index_into_bound_bytes(offset):
    data = bytes(range(67))
    tr = Translation(None, {}, 0, bindings={CALLDATA: data})
    selected = mk("arg", "offset", "uint256")
    word = tr.translate(mk("elem", CALLDATA, selected))
    index = tr.translate(selected)
    expected = int.from_bytes(data[offset : offset + 32].ljust(32, b"\0"), "big")
    assert not tr.issues
    assert solver_for(tr, index == offset, word != expected).check() == z3.unsat


def test_caller_can_supply_its_address_without_array_quantifier_timeout():
    from services.logic.model import Limits
    from services.logic.solver import project
    from services.logic.terms import CALLER, mk_and, mk_cmp

    predicate = mk_and(
        [mk_cmp("eq", mk("len", CALLDATA), const(32)), mk_cmp("eq", mk("elem", CALLDATA, const(0)), CALLER)]
    )
    result = project(predicate, Translation(None, {}, 0, limits=Limits(solver_ms=1000, members=5)))
    assert result.complete and result.representation == "cofinite" and result.excluded == (0,), result


@pytest.mark.parametrize("reverse", [False, True])
def test_data_dependent_read_keeps_index_congruence(reverse):
    tr = translator()
    pointer = mk("abi_word", CALLDATA, 0)
    indirect = mk("elem", CALLDATA, pointer)
    if reverse:
        tr.translate(indirect)
    p = tr.translate(pointer)
    v = tr.translate(indirect)
    n = tr.translate(mk("len", CALLDATA))
    assert not tr.issues
    assert solver_for(tr, n == 32, p == 0, v != p).check() == z3.unsat


@pytest.mark.parametrize("seed", range(8))
def test_finite_reads_are_equivalent_to_a_reference_array(seed):
    import random

    from services.logic.solver import WORD
    from services.logic.terms import mk_op

    tr = translator()
    a, b = mk("arg", "a", "bytes"), mk("arg", "b", "bytes")
    i, j = mk("arg", "i", "uint256"), mk("arg", "j", "uint256")
    terms = []
    for data in (a, b):
        first = mk("byte_chunk", data, const(0))
        pointer = mk("byte_chunk", data, i)
        terms.extend(
            (
                first,
                pointer,
                mk("byte_chunk", data, j),
                mk("byte_chunk", data, mk_op("add", (i, const(1)))),
                mk("byte_chunk", data, first),
                mk("byte_chunk", data, pointer),
                mk("byte_chunk", data, mk_op("add", (i, const(0)))),
            )
        )
    random.Random(seed).shuffle(terms)
    for term in terms:
        tr.translate(term)
    reads = [(t, v, tr.translate(t[2])) for t, v in list(tr.variables.items()) if t[0] == "byte_chunk"]
    assert not tr.issues
    # Every consistent finite assignment extends to a total read-only array.
    for data in (a, b):
        reference = z3.K(z3.IntSort(), z3.IntVal(0))
        selected = [(v, index) for t, v, index in reads if t[1] == data]
        for value, index in selected:
            reference = z3.Store(reference, index, value)
        assert solver_for(tr, z3.Or(*[z3.Select(reference, index) != v for v, index in selected])).check() == z3.unsat
    # Conversely, arbitrary bounded reference-array values satisfy the finite constraints.
    references = {data: z3.Array("reference_" + data[1], z3.IntSort(), z3.IntSort()) for data in (a, b)}
    replacements = []
    for term, value, index in reads:
        index = z3.substitute(index, *replacements) if replacements else index
        replacements.append((value, z3.Select(references[term[1]], index)))
    converted = [z3.substitute(bound, *replacements) for bound in tr.bounds]
    external = [v for t, v in tr.variables.items() if t[0] != "byte_chunk"]
    domain = [z3.And(v >= 0, v < WORD) for v in external] + [z3.And(v >= 0, v < WORD) for _, v in replacements]
    solver = z3.Solver()
    solver.set(timeout=20000)
    solver.add(*domain, z3.Not(z3.And(*converted)))
    assert solver.check() == z3.unsat
