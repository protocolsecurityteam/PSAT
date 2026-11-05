"""Byte slices and overlays compared with independent concrete byte operations."""

import random

import pytest
import z3

from services.logic.memory import CALLDATA_COPY, copied_buffer
from services.logic.solver import Translation
from services.logic.terms import const, mk

DATA = mk("arg", "input", "bytes")
WORD = 2**256


@pytest.mark.parametrize("origin", [0, 1, 31, 65, WORD - 1])
@pytest.mark.parametrize("length", [0, 1, 31, 65])
@pytest.mark.parametrize("offset", [0, 1, 31, 64, WORD - 1])
def test_slice_read_matches_concrete_bytes(origin, length, offset):
    source = bytes(range(67))
    expected = source[origin : origin + length].ljust(length, b"\0")
    view = mk("bytes_slice", DATA, const(origin), const(length))
    tr = Translation(None, {}, 0, bindings={DATA: source})
    read = tr.translate(mk("elem", view, const(offset)))
    assert z3.simplify(read).as_long() == int.from_bytes(expected[offset : offset + 32].ljust(32, b"\0"), "big")
    assert tr.translate(view) == expected
    assert not tr.issues


@pytest.mark.parametrize("seed", range(20))
def test_patch_words_match_bytearray_writes(seed):
    randomizer = random.Random(seed)
    source = randomizer.randbytes(randomizer.randrange(0, 100))
    expected = bytearray(source)
    patches = []
    for _ in range(8):
        at = randomizer.randrange(0, 120)
        skip = randomizer.randrange(0, 32)
        width = randomizer.randrange(1, 33 - skip)
        word = randomizer.randbytes(32)
        patches.append((at, const(int.from_bytes(word, "big")), skip, width))
        for i in range(width):
            if at + i < len(expected):
                expected[at + i] = word[skip + i]
    view = mk("bytes_patch", DATA, tuple(patches))
    tr = Translation(None, {}, 0, bindings={DATA: source})
    assert tr.translate(view) == bytes(expected)
    for at in (0, 1, 31, 32, 63, 99, WORD - 1):
        value = tr.translate(mk("elem", view, const(at)))
        assert z3.simplify(value).as_long() == int.from_bytes(expected[at : at + 32].ljust(32, b"\0"), "big")
    assert not tr.issues


@pytest.mark.parametrize("at", [0, 3, 31, 32, 63, WORD - 1])
def test_symbolic_slice_patch_offset_has_one_read_relation(at):
    sliced = mk("bytes_slice", DATA, const(17), const(51))
    view = mk("bytes_patch", sliced, ((2, const(0x123456), 29, 3),))
    index = mk("arg", "offset", "uint256")
    tr = Translation(None, {}, 0, bindings={DATA: bytes(range(65))})
    dynamic = tr.translate(mk("elem", view, index))
    fixed = tr.translate(mk("elem", view, const(at)))
    value = tr.translate(index)
    solver = z3.Solver()
    solver.set(timeout=5000)
    solver.add(*tr.bounds, value == at, dynamic != fixed)
    assert solver.check() == z3.unsat
    assert not tr.issues


def test_copied_extent_clips_crossing_writes_and_rejects_unplaced_copy():
    word = const(int.from_bytes(bytes(range(32)), "big"))
    view = copied_buffer(((4, CALLDATA_COPY), (0, word)), 4, DATA)
    tr = Translation(None, {}, 0, bindings={DATA: b"z" * 40})
    assert tr.translate(view) == bytes(range(4, 32)) + b"z" * 12
    assert copied_buffer(((0, CALLDATA_COPY), (1, CALLDATA_COPY)), 0, DATA) is None


def test_static_encoded_values_can_back_views_without_materialization():
    item = mk("arg", "word", "uint256")
    encoded = mk("enc", "abi.encode", (item,))
    view = mk("bytes_slice", encoded, const(1), const(31))
    tr = Translation(None, {}, 0)
    read = tr.translate(mk("elem", view, const(0)))
    value = tr.translate(item)
    solver = z3.Solver()
    solver.add(*tr.bounds, value == 0x1234, read != 0x123400)
    assert solver.check() == z3.unsat
    assert not tr.issues
