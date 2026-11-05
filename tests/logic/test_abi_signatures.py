"""Canonical signatures are checked against solc and deployed dispatch."""

import json
import subprocess

import pytest
from eth_abi import encode
from eth_utils import keccak

from services.logic.abi_values import abi_signature
from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity ^0.8.20;
type Credit is uint128;
interface Parent {function inherited() external;}
interface I is Parent {struct S {address a;address b;} function act(S calldata p) external;}
contract G {
 mapping(G=>mapping(G=>uint)) public byContract;
 mapping(Mode=>mapping(Mode=>uint)) public byEnum;
 uint[][2] public arraysGetter;
 struct Pair { G first; G second; }
 enum Mode {A,B}
 function inspect(Pair calldata p) external view returns(bool) {
  return msg.sig==this.inspect.selector && address(p.first)==address(p.second);
 }
}
library L {
 struct Rec { uint value; }
 function same(G) external pure returns(uint){return 1;}
 function directAlias(Credit a) external pure returns(Credit) {return a;}
 function callback(function(uint) external returns(uint)) external pure returns(uint) {return 1;}
 function direct(G a) external pure returns(G) {return a;}
 function aliases(mapping(G=>Credit) storage a,G who) external view returns(Credit) {return a[who];}
 function enumMap(mapping(G.Mode=>G) storage a,G.Mode who) external view returns(G) {return a[who];}
 function memoryStruct(Rec memory a) external pure returns(uint) {return a.value;}
 function stored(Rec storage a) external view returns(uint) {return a.value;}
 function mappingRef(mapping(address=>G) storage a,address who) external view returns(G) {return a[who];}
}
contract C {
 struct Nested { G.Pair a; G.Pair b; G[] c; G[2] d; G.Mode e; G.Mode f; }
 event Seen(G first,G second);
 error Bad(G.Pair first,G.Pair second);
 uint public value;
 function same(G) external pure returns(uint){return 2;}
 function overload(mapping(address=>bool) storage) internal pure returns(uint){return 0;}
 function overload(address) external pure returns(uint){return 1;}
 function interfaceIdentifier(I.S calldata) external {
  require(type(I).interfaceId==bytes4(keccak256("act((address,address))")));value=8;
 }
 function selectorLiterals() external {
  require(this.overload.selector==bytes4(keccak256("overload(address)")));
  require(G.inspect.selector==bytes4(keccak256("inspect((address,address))")));
  require(L.same.selector==bytes4(keccak256("same(G)")));
  require(this.same.selector==bytes4(keccak256("same(address)")));
  require(L.memoryStruct.selector==bytes4(keccak256("memoryStruct(L.Rec)")));
  require(L.stored.selector==bytes4(keccak256("stored(L.Rec storage)")));
  require(Seen.selector==keccak256("Seen(address,address)"));
  require(Bad.selector==bytes4(keccak256("Bad((address,address),(address,address))")));
  value=7;
 }
 function repeated(G.Pair calldata p) external {
  require(address(p.first)==msg.sender && address(p.second)==msg.sender);value=1; }
 function nested(Nested calldata) external {value=2;}
 function arrays(G[2][] calldata) external {value=3;}
 function aliasType(Credit, Credit) external {value=4;}
 function functionType(function(uint) external returns(uint)) external {value=5;}
 function through(G target) external {require(target.inspect(G.Pair(G(msg.sender),G(msg.sender))));value=6;}
}"""


@pytest.fixture
def d(anvil, tmp_path):
    deployed = O.deployment(anvil[0], tmp_path, SOURCE)
    deployed.deploy("G")
    deployed.deploy("C")
    return deployed


def test_signatures_and_selectors_match_solc_for_repeated_and_nested_types(d):
    source = d.slither["C"].source_mapping.filename.absolute
    raw = subprocess.run(
        [str(solc_path("0.8.27")), "--combined-json", "hashes", source], capture_output=True, text=True, check=True
    )
    expected = {key.split(":")[-1]: value["hashes"] for key, value in json.loads(raw.stdout)["contracts"].items()}
    for name in ("C", "G", "L"):
        entries = [
            *d.slither[name].functions_entry_points,
            *(v for v in d.slither[name].state_variables if v.visibility == "public"),
        ]
        for fn in entries:
            signature = abi_signature(fn)
            assert signature in expected[name], (name, signature, expected[name])
            assert keccak(text=signature)[:4].hex() == expected[name][signature]


def test_canonical_entry_preserves_address_arguments_and_dispatch(d):
    fn = O.function(d, "C", "repeated")
    reads = d.chain()
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C", "G"))
    assert f.signature == "repeated((address,address))"
    assert f.selector == int.from_bytes(keccak(text=f.signature)[:4], "big")
    result = expand_formula(f, reads, d.contracts("C", "G")).callers
    assert result.complete and result.representation == "cofinite" and result.excluded == (0,)
    for sender in O.ACCOUNTS[:2]:
        data = keccak(text=f.signature)[:4] + encode(["(address,address)"], [(O.hex20(sender), O.hex20(sender))])
        assert (
            rpc(
                d.url,
                "eth_call",
                [{"to": O.hex20(d.at["C"]), "from": O.hex20(sender), "data": "0x" + data.hex()}, "latest"],
            )
            == "0x"
        )


def test_followed_callee_uses_the_same_canonical_selector(d):
    fn = O.function(d, "C", "through")
    reads = d.chain()
    # Bind target for this projection; target discovery remains separate from caller enumeration.
    from services.logic.lower import parameter

    target = parameter(fn.parameters[0], 0)
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C", "G"), bindings={target: d.at["G"]})
    result = expand_formula(f, reads, d.contracts("C", "G")).callers
    assert result.complete and result.representation == "cofinite" and result.excluded == (0,), result
    for sender in O.ACCOUNTS[:2]:
        assert O.chain_says(d, fn, (d.at["G"],), sender=sender)


def test_folded_function_library_error_and_event_selectors_match_the_chain(d):
    fn = O.function(d, "C", "selectorLiterals")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "G"))
    result = expand_formula(f, d.chain(), d.contracts("C", "G")).callers
    assert result.complete and result.representation == "cofinite" and result.excluded == (0,), result
    assert O.chain_says(d, fn, (), sender=O.OWNER)


@pytest.mark.parametrize("version", ["0.5.14", "0.8.10"])
def test_nested_repeated_contract_types_match_older_compilers(anvil, tmp_path, version):
    source = """pragma solidity >=0.5.0 <0.9.0; pragma experimental ABIEncoderV2;
contract G {}
contract C {
 struct Pair {G a; G b;}
 struct Nested {Pair one; Pair two; G[] others;}
 function read(Nested calldata) external pure returns(bool){return true;}
}
"""
    d = O.deployment(anvil[0], tmp_path, source, version)
    fn = O.function(d, "C", "read")
    sig = abi_signature(fn)
    assert sig == "read(((address,address),(address,address),address[]))"
    raw = subprocess.run(
        [str(solc_path(version)), "--combined-json", "hashes", fn.source_mapping.filename.absolute],
        capture_output=True,
        text=True,
        check=True,
    )
    hashes = next(v["hashes"] for k, v in json.loads(raw.stdout)["contracts"].items() if k.endswith(":C"))
    assert hashes[sig] == keccak(text=sig)[:4].hex()


def test_interface_identifier_uses_declared_canonical_selectors(d):
    fn = O.function(d, "C", "interfaceIdentifier")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "G"))
    result = expand_formula(f, d.chain(), d.contracts("C", "G")).callers
    assert result.complete and result.representation == "cofinite" and result.excluded == (0,), result
    data = keccak(text=f.signature)[:4] + encode(["(address,address)"], [(O.hex20(O.OWNER), O.hex20(O.OWNER))])
    assert (
        rpc(
            d.url,
            "eth_call",
            [{"to": O.hex20(d.at["C"]), "from": O.hex20(O.OWNER), "data": "0x" + data.hex()}, "latest"],
        )
        == "0x"
    )
