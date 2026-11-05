"""Dynamic ABI byte inputs checked against Solidity's decoder and mined effects."""

import pytest
from eth_abi import encode

from services.logic.continuation import generate_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc


def word(n):
    return n.to_bytes(32, "big")


PAYLOADS = [
    b"",
    bytes(31),
    word(0),
    word(32),
    word(32) + word(0),
    word(32) + word(1),
    word(32) + word(1) + b"\xff",
    word(32) + word(3) + b"abc",
    encode(["bytes"], [b"hello"]),
    word(1) + bytes(33),
    word(64) + word(123) + word(1) + b"z",
    word(2**64) + word(0),
    word(2**256 - 1) + word(0),
    word(32) + word(2**64),
]


@pytest.mark.parametrize("version", ["0.8.10", "0.8.27"])
@pytest.mark.parametrize(
    "type_,location", [("bytes", "calldata"), ("bytes", "memory"), ("string", "calldata"), ("string", "memory")]
)
@pytest.mark.parametrize("payload", PAYLOADS)
def test_dynamic_bytes_bounds_aliases_and_contents(anvil, tmp_path, version, type_, location, payload):
    source = (
        """pragma solidity VERSION;
    contract C {uint saved;function act(TYPE LOCATION x)external{
      bytes LOCATION data=bytes(x);saved=data.length;
      if(data.length>0)saved=1000+uint8(data[0]);
    }}""".replace("VERSION", version)
        .replace("TYPE", type_)
        .replace("LOCATION", location)
    )
    d = O.deployment(anvil[0], tmp_path, source, version=version)
    at = d.deploy("C")
    known = d.contracts("C")
    f = generate_function(
        d.slither["C"], O.function(d, "C", "act"), at, d.chain(), known, own_code=known.get, steps=30000
    )
    assert isinstance(f, Formula), f
    tr = Translation(
        d.chain(), known, at, f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: payload}
    )
    predicted = tr.truth(f.success)
    writes = [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True]
    actual = O.transact_data(d, at, f.selector.to_bytes(4, "big") + payload)
    saved = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    assert predicted is actual, (version, type_, location, payload.hex(), predicted, actual, tr.issues)
    assert saved == (writes[-1] if writes else 0), (saved, writes)
    assert not tr.issues


@pytest.mark.parametrize("alias", [False, True])
def test_overlapping_input_offsets_copy_memory_independently(anvil, tmp_path, alias):
    source = """pragma solidity 0.8.27;
    contract C {uint saved;function act(bytes memory a,bytes memory b)external{
        require(a.length>0&&b.length>0);a[0]=0xff;saved=uint8(b[0]);
    }}"""
    d = O.deployment(anvil[0], tmp_path, source)
    at = d.deploy("C")
    known = d.contracts("C")
    payload = (word(64) + word(64) + word(1) + b"z") if alias else encode(["bytes", "bytes"], [b"a", b"b"])
    f = generate_function(d.slither["C"], O.function(d, "C", "act"), at, d.chain(), known, own_code=known.get)
    assert isinstance(f, Formula), f
    tr = Translation(
        d.chain(), known, at, f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: payload}
    )
    assert tr.truth(f.success) is True
    value = [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True]
    assert O.transact_data(d, at, f.selector.to_bytes(4, "big") + payload)
    saved = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    assert value == [saved] == [ord("z") if alias else ord("b")]


def test_string_bytes_memory_conversion_keeps_the_alias(anvil, tmp_path):
    source = """pragma solidity 0.8.27;
    contract C {uint saved;function act(string memory a)external{
        bytes memory b=bytes(a);require(b.length>0);b[0]=0xff;saved=uint8(bytes(a)[0]);
    }}"""
    d = O.deployment(anvil[0], tmp_path, source)
    at = d.deploy("C")
    known = d.contracts("C")
    payload = encode(["string"], ["abc"])
    f = generate_function(d.slither["C"], O.function(d, "C", "act"), at, d.chain(), known, own_code=known.get)
    assert isinstance(f, Formula), f
    tr = Translation(
        d.chain(), known, at, f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: payload}
    )
    assert tr.truth(f.success) is True
    assert [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True] == [255]
    assert O.transact_data(d, at, f.selector.to_bytes(4, "big") + payload)
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16) == 255
