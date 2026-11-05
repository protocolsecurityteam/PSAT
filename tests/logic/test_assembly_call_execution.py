"""Assembly regions are actual bytes; pointer shape alone does not prove an ABI call."""

import pytest
from eth_abi import decode

from services.logic.continuation import generate_function
from services.logic.lower import parameter
from services.logic.model import Formula
from services.logic.solver import Translation, number
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity 0.8.27;
contract D {
 uint public foreignSlot;
 function put(uint n) external payable returns(bytes4){foreignSlot=n;return 0x12345678;}
 function flag(bool n) external {foreignSlot=n?17:19;}
 function fail() external {foreignSlot=99;revert();}
}
contract C {
 uint public stored;address target;uint public result;
 constructor(address a){target=a;}
 function go(uint n) external payable returns(uint,uint){
  bytes memory data=abi.encodeWithSelector(D.put.selector,n);address d=target;bool ok;uint ret;
  assembly {mstore(0,not(0)) ok:=delegatecall(gas(),d,add(data,32),SIZE,0,OUT) ret:=mload(0)}
  require(ok);result=ret;return(stored,result);
 }
 function rawBool() external {
  address d=target;bool ok;
  assembly {mstore(0,shl(224,SELECTOR)) mstore(4,DIRTY) ok:=delegatecall(gas(),d,0,36,0,0)}
  require(ok);result=stored;
 }
 function caught() external {
  stored=5;bytes memory data=abi.encodeWithSignature("fail()");address d=target;bool ok;
  assembly {ok:=delegatecall(gas(),d,add(data,32),mload(data),0,0)}
  require(!ok);result=stored;
 }
}
"""


def fixture(anvil, tmp_path, size=36, out=32, dirty=1):
    from eth_utils.crypto import keccak

    source = SOURCE.replace("SIZE", str(size)).replace("OUT", str(out)).replace("DIRTY", str(dirty))
    source = source.replace("SELECTOR", str(int.from_bytes(keccak(text="flag(bool)")[:4], "big")))
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("D"),))
    return d


def evaluate(d, name, args=(), value=0):
    fn = O.function(d, "C", name)
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "D"), steps=10000)
    assert isinstance(f, Formula), f
    bindings = {CALLER: O.OWNER, ORIGIN: O.OWNER, mk("callvalue"): value}
    bindings.update({parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))})
    terms = [f.success, *(u.value for t in f.transitions for u in t.updates)]
    for term in terms:
        bindings.update({t: True for t in subterms(term, "unknown") if t[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), d.contracts("C", "D"), d.at["C"], f.selector, bindings=bindings)
    return fn, f, tr


@pytest.mark.parametrize("size,passed", [(4, False), (35, False), (36, True), (68, True)])
def test_calldata_length_controls_decoder(anvil, tmp_path, size, passed):
    d = fixture(anvil, tmp_path, size=size)
    fn, f, tr = evaluate(d, "go", (7,), value=5)
    assert O.passes(d, "C", fn, (7,), value=5) is passed
    assert tr.truth(f.success) is passed, tr.issues
    if passed:
        values = {u.location[1]: number(tr.translate(u.value)) for t in f.transitions for u in t.updates}
        assert values["foreignSlot"] == 7 and values["result"] == 0x12345678 << 224, (values, tr.issues)


@pytest.mark.parametrize("out", [0, 1, 4, 17, 32, 64])
def test_return_copy_preserves_unwritten_bytes(anvil, tmp_path, out):
    d = fixture(anvil, tmp_path, out=out)
    fn, f, tr = evaluate(d, "go", (8,))
    assert tr.truth(f.success) is True, tr.issues
    raw = bytes.fromhex("12345678") + bytes(28)
    count = min(out, 32)
    expected = int.from_bytes(raw[:count] + b"\xff" * (32 - count), "big")
    values = [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"]
    assert values == [expected], (values, tr.issues)
    actual = rpc(
        d.url,
        "eth_call",
        [{"to": O.hex20(d.at["C"]), "from": O.hex20(O.OWNER), "data": "0x" + O.calldata(fn, (8,)).hex()}, "latest"],
    )
    assert decode(["uint", "uint"], bytes.fromhex(actual[2:])) == (8, expected)


@pytest.mark.parametrize("dirty", [0, 1, 2, 2**255])
def test_raw_words_use_callee_decoder(anvil, tmp_path, dirty):
    d = fixture(anvil, tmp_path, dirty=dirty)
    fn, f, tr = evaluate(d, "rawBool")
    actual = O.passes(d, "C", fn, ())
    assert actual is (dirty < 2) and tr.truth(f.success) is actual, tr.issues


def test_assembly_revert_keeps_pre_call_storage(anvil, tmp_path):
    d = fixture(anvil, tmp_path)
    fn, f, tr = evaluate(d, "caught")
    assert tr.truth(f.success) is True and O.passes(d, "C", fn, ())
    values = {u.location[1]: number(tr.translate(u.value)) for t in f.transitions for u in t.updates}
    assert values["stored"] == values["result"] == 5
