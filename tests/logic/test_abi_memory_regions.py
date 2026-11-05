"""Byte-layout differential against an independent ABI encoder, using fixed random seeds."""

import random

import pytest
from eth_abi import encode as abi_encode
from eth_abi.packed import encode_packed

from services.logic.memory import buffer_memory, memory_uint, memory_word
from services.logic.solver import Translation, number
from services.logic.terms import const, mk


@pytest.fixture(autouse=True)
def value_budget(monkeypatch):
    import services.logic.lower as lower

    monkeypatch.setattr(lower, "_STEPS", [100000])


def build(rng, depth=0):
    if depth < 2 and rng.randrange(3) == 0:
        items = [build(rng, depth + 1) for _ in range(rng.randrange(1, 4))]
        names = tuple("f" + str(i) for i in range(len(items)))
        return (
            ("abi_type", "tuple", tuple(("abi_field", n, x[0]) for n, x in zip(names, items))),
            mk("struct", names, tuple(x[1] for x in items)),
            "(" + ",".join(x[2] for x in items) + ")",
            tuple(x[3] for x in items),
        )
    kinds = ["bool", "address", "uint8", "uint128", "uint256", "int8", "int128", "bytes1", "bytes3", "bytes32"]
    kind = rng.choice(kinds)
    if kind == "bool":
        v = bool(rng.randrange(2))
        logical = int(v)
        abi = v
    elif kind == "address":
        logical = rng.randrange(2**160)
        abi = f"0x{logical:040x}"
    elif kind.startswith("bytes"):
        n = int(kind[5:])
        logical = rng.randrange(2 ** (8 * n))
        abi = logical.to_bytes(n, "big")
    elif kind.startswith("int"):
        bits = int(kind[3:])
        logical = rng.randrange(-(2 ** (bits - 1)), 2 ** (bits - 1))
        abi = logical
    else:
        bits = int(kind[4:])
        logical = rng.randrange(2**bits)
        abi = logical
    if depth < 2 and rng.randrange(3) == 0:
        size = rng.randrange(1, 4)
        return (
            ("abi_type", "array", ("abi_type", kind), size),
            mk("array", const(size), tuple(const(logical, kind) for _ in range(size))),
            kind + "[" + str(size) + "]",
            tuple(abi for _ in range(size)),
        )
    return ("abi_type", kind), const(logical, kind), kind, abi


@pytest.mark.parametrize("seed", range(120))
def test_region_matches_independent_abi(seed):
    rng = random.Random(seed)
    items = [build(rng) for _ in range(rng.randrange(1, 4))]
    term = mk("enc", "abi.encode", tuple(i[1] for i in items), tuple(i[0] for i in items))
    expected = abi_encode([i[2] for i in items], [i[3] for i in items])
    layout = buffer_memory(term)
    assert layout is not None
    size, mem = layout
    assert size == len(expected)
    tr = Translation(None, {}, 0)
    for offset in range(0, size, 32):
        assert number(tr.translate(memory_word(mem, offset))) == int.from_bytes(
            expected[offset : offset + 32], "big"
        ), (seed, items, tr.issues)
    for _ in range(5):
        at = rng.randrange(size)
        length = rng.randrange(1, min(32, size - at) + 1)
        assert number(tr.translate(memory_uint(mem, at, length))) == int.from_bytes(
            expected[at : at + length], "big"
        ), (seed, at, length, tr.issues)
    assert not tr.issues
    assert tr.translate(term) == expected, tr.issues


@pytest.mark.parametrize("seed", range(50))
def test_packed_regions(seed):
    rng = random.Random(seed)
    items = [build(rng, 3) for _ in range(rng.randrange(1, 8))]
    term = mk("enc", "abi.encodePacked", tuple(i[1] for i in items))
    expected = encode_packed([i[2] for i in items], [i[3] for i in items])
    size, mem = buffer_memory(term)
    assert size == len(expected)
    tr = Translation(None, {}, 0)
    for at in range(size):
        assert number(tr.translate(memory_uint(mem, at, 1))) == expected[at], (seed, at, tr.issues)
    assert tr.translate(term) == expected, tr.issues


@pytest.mark.parametrize(
    "kind,value",
    [
        ("bytes1", 1),
        ("bytes4", 1),
        ("bytes16", 1),
        ("bytes31", 1),
        ("bytes32", 1),
        ("address", 2**160 + 7),
        ("uint8", 257),
        ("int8", 255),
        ("bool", 2),
    ],
)
@pytest.mark.parametrize("strict", [True, False])
def test_decoder_shortcuts_match_encoded_numeric_word(kind, value, strict):
    from eth_abi import decode
    from eth_abi.exceptions import DecodingError

    from services.logic.abi_values import decode_static, from_name

    word = mk("conv", "uint256", mk("conv", kind, const(value)))
    tr = Translation(None, {}, 0)
    raw = number(tr.translate(word))
    assert raw is not None
    result, valid = decode_static((word,), from_name(kind), strict)
    engine_valid = tr.truth(valid)
    if strict:
        try:
            decode([kind], raw.to_bytes(32, "big"))
            expected = True
        except DecodingError:
            expected = False
        assert engine_valid is expected, (kind, raw, result, valid)
    else:
        if kind.startswith("bytes"):
            expected = raw >> (256 - 8 * int(kind[5:]))
            assert number(tr.translate(result)) == expected, (kind, raw, result)
