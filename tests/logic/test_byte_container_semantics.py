"""String/bytes indexing uses UTF-8 byte offsets and EVM words, never Python characters."""

import pytest

from services.logic.solver import Translation, number
from services.logic.terms import const, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
contract C {uint value;
function text(uint i,uint b) external {bytes memory s="MOCK_STABLE_DEBT"; require(uint8(s[i])==b);value=1;}
function digit(uint i,uint b) external {bytes memory s="7"; require(uint8(s[i])==b);value=1;}
function unicodeText(uint i,uint b) external {bytes memory s=unicode"é"; require(s.length==2);
require(uint8(s[i])==b);value=1;}
}"""


@pytest.mark.parametrize(
    "name,values",
    [
        ("text", (0, 77)),
        ("text", (0, 0)),
        ("text", (14, 84)),
        ("text", (15, 0)),
        ("digit", (0, 55)),
        ("digit", (0, 7)),
        ("unicodeText", (0, 195)),
        ("unicodeText", (1, 169)),
        ("unicodeText", (1, 0)),
        ("unicodeText", (2, 0)),
    ],
)
def test_byte_reads_match_execution(anvil, tmp_path, name, values):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C")
    fn = O.function(d, "C", name)
    actual = O.chain_says(d, fn, values, sender=O.OWNER)
    _, predicted = O.engine_says(d, fn, values, sender=O.OWNER, contracts=d.contracts(*d.at))
    assert predicted is actual


def test_byte_container_word_is_zero_padded():
    translation = Translation(None, {}, 1)
    value = const(b"abc", "bytes")
    assert number(translation.translate(mk("elem", value, const(1)))) == int.from_bytes(b"bc" + b"\0" * 30, "big")
    assert number(translation.translate(mk("elem", value, const(33)))) == 0


LITERALS = r"""pragma solidity ^0.8.10;
contract C {uint value; bytes constant RAW=hex"80ff00";
function hexText(uint i,uint b) external {bytes memory s=hex"80ff00c3a9";require(uint8(s[i])==b);value=1;}
function escaped(uint i,uint b) external {bytes memory s="\x80\xff\x00";require(uint8(s[i])==b);value=1;}
function realText(uint i,uint b) external {bytes memory s="0x80ff00";require(uint8(s[i])==b);value=1;}
function constantBytes(uint i,uint b) external {require(uint8(RAW[i])==b);value=1;}
function ambiguous(uint a,uint b) external {
(bytes memory x,bytes memory y)=(hex"80ff","0x80ff");
require(uint8(x[0])==a && uint8(y[0])==b);value=1;
}
}"""


@pytest.mark.parametrize(
    "name,args",
    [
        ("hexText", (0, 128)),
        ("hexText", (0, 48)),
        ("hexText", (4, 169)),
        ("hexText", (5, 48)),
        ("escaped", (0, 128)),
        ("escaped", (1, 255)),
        ("escaped", (2, 0)),
        ("realText", (0, 48)),
        ("realText", (0, 128)),
        ("constantBytes", (0, 128)),
        ("constantBytes", (2, 0)),
    ],
)
def test_literal_bytes_come_from_compiler_provenance(anvil, tmp_path, name, args):
    d = O.deployment(anvil[0], tmp_path, LITERALS)
    d.deploy("C")
    fn = O.function(d, "C", name)
    actual = O.chain_says(d, fn, args, sender=O.OWNER)
    _, predicted = O.engine_says(d, fn, args, sender=O.OWNER, contracts=d.contracts(*d.at))
    assert predicted is actual


def test_ambiguous_ir_constants_are_not_guessed(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, LITERALS)
    d.deploy("C")
    fn = O.function(d, "C", "ambiguous")
    for args in ((128, 48), (48, 48), (128, 128)):
        actual = O.chain_says(d, fn, args, sender=O.OWNER)
        _, predicted = O.engine_says(d, fn, args, sender=O.OWNER, contracts=d.contracts(*d.at))
        assert predicted is None or predicted is actual
