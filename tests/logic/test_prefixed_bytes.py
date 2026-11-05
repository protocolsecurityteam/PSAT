"""A fixed prefix does not canonicalize, pad, or discard its arbitrary trailing bytes."""

import pytest
import z3

from services.logic.memory import buffer_length, buffer_uint
from services.logic.solver import Translation
from services.logic.terms import const, mk

TAIL = mk("arg", "raw_tail", "bytes")


@pytest.mark.parametrize("prefix_size", [0, 4, 32, 45])
@pytest.mark.parametrize("size", [0, 1, 31, 32, 67])
@pytest.mark.parametrize("offset", [0, 3, 4, 31, 32, 44, 67, 2**256 - 1])
def test_prefix_windows_match_concrete_concatenation(prefix_size, size, offset):
    prefix = bytes((i * 11 + 1) % 256 for i in range(prefix_size))
    tail = bytes((i * 37 + 2) % 256 for i in range(size))
    stream = mk("bytes_prefix", prefix, TAIL)
    tr = Translation(None, {}, 0, bindings={TAIL: tail})
    read = tr.translate(mk("elem", stream, const(offset)))
    actual = (prefix + tail)[offset : offset + 32]
    assert z3.simplify(read).as_long() == int.from_bytes(actual.ljust(32, b"\0"), "big")
    assert not tr.issues


def test_symbolic_prefix_word_keeps_tail_constraints_and_selector():
    stream = mk("bytes_prefix", b"\x12\x34\x56\x78", TAIL)
    tr = Translation(None, {}, 0)
    word = tr.translate(buffer_uint(stream, 0, 32, padded=True))
    tail = tr.translate(mk("elem", TAIL, const(0)))
    length = tr.translate(buffer_length(stream))
    solver = z3.Solver()
    solver.set(timeout=20000)
    solver.add(*tr.bounds, length == 36, tail == 7)
    solver.add(word != 0x12345678 * 2**224)
    assert solver.check() == z3.unsat
    assert not tr.issues
    assert buffer_uint(stream, 0, 4, padded=True) == const(0x12345678)


@pytest.mark.parametrize("at", [0, 3, 4, 30, 34, 2**256 - 1])
def test_symbolic_prefix_offset_matches_the_same_stream(at):
    stream = mk("bytes_prefix", b"abcd", TAIL)
    index = mk("arg", "index", "uint256")
    tr = Translation(None, {}, 0, bindings={TAIL: bytes(range(33))})
    selected, fixed = tr.translate(mk("elem", stream, index)), tr.translate(mk("elem", stream, const(at)))
    i = tr.translate(index)
    solver = z3.Solver()
    solver.set(timeout=20000)
    solver.add(*tr.bounds, i == at, selected != fixed)
    assert solver.check() == z3.unsat
    assert not tr.issues


@pytest.mark.parametrize("at", [0, 3, 4, 7, 8, 31, 2**256 - 1])
def test_adjacent_prefixes_are_one_stream(at):
    nested = mk("bytes_prefix", b"0123", mk("bytes_prefix", b"abcd", TAIL))
    flat = mk("bytes_prefix", b"0123abcd", TAIL)
    tr = Translation(None, {}, 0)
    a = tr.translate(mk("elem", nested, const(at)))
    b = tr.translate(mk("elem", flat, const(at)))
    solver = z3.Solver()
    solver.set(timeout=1000)
    solver.add(*tr.bounds, a != b)
    assert solver.check() == z3.unsat
    assert not tr.issues


@pytest.mark.parametrize("tail_length,possible", [(2**256 - 1, False), (2**256 - 5, True)])
def test_prefix_length_cannot_wrap(tail_length, possible):
    tr = Translation(None, {}, 0)
    length = tr.translate(buffer_length(mk("bytes_prefix", b"abcd", TAIL)))
    tail = tr.translate(mk("len", TAIL))
    solver = z3.Solver()
    solver.add(*tr.bounds, tail == tail_length)
    assert solver.check() == (z3.sat if possible else z3.unsat)
    if possible:
        assert solver.model().eval(length).as_long() == 2**256 - 1
