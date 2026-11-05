"""Fallback bodies execute through the same frames, including writes around delegation."""

import json

import pytest
from eth_abi import decode

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.lower import parameter
from services.logic.model import Formula, encode
from services.logic.solver import Translation, number
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity 0.8.27;
contract D {
 uint x;
 function put(uint n,address sender,address here) external payable returns(uint){
  require(msg.sender==sender && address(this)==here);
  x=n;return n+msg.value;
 }
 function fail() external {x=99;revert();}
}
contract P {
 constructor(address code){assembly{sstore(100,code)}}
 fallback() external payable {
  assembly {
   sstore(7,add(sload(7),1))
   calldatacopy(0,0,calldatasize())
   let ok:=delegatecall(gas(),sload(100),0,calldatasize(),0,0)
   returndatacopy(0,0,returndatasize())
   switch ok case 0 {revert(0,returndatasize())}
   default {sstore(8,91) return(0,returndatasize())}
  }
 }
}
contract C {
 uint stored=3;address target;uint result;
 constructor(address p,address code){target=p;assembly{sstore(100,code)}}
 function go(uint n) external payable returns(uint){
  (bool ok,bytes memory data)=target.MODE(abi.encodeWithSignature(
   "put(uint256,address,address)",n,SENDER,HERE));
  require(ok);result=abi.decode(data,(uint));return result;
 }
 function caught() external returns(uint){
  (bool ok,)=target.MODE(abi.encodeWithSignature("fail()"));
  require(!ok);result=stored;return result;
 }
}
"""


def deploy(anvil, tmp_path, mode="delegatecall"):
    source = SOURCE.replace("MODE", mode).replace("SENDER", "msg.sender" if mode == "delegatecall" else "address(this)")
    source = source.replace("HERE", "address(this)" if mode == "delegatecall" else "target")
    d = O.deployment(anvil[0], tmp_path, source)
    logic = d.deploy("D")
    d.deploy("C", ("address", "address"), (d.deploy("P", ("address",), (logic,)), logic))
    return d


def generate(d, name, **kwargs):
    return generate_function(
        d.slither["C"],
        O.function(d, "C", name),
        d.at["C"],
        d.chain(),
        d.contracts("C", "P", "D"),
        steps=kwargs.pop("steps", 20000),
        **kwargs,
    )


def evaluator(d, f, args=(), value=0):
    fn = O.function(d, "C", f.signature.split("(")[0])
    bindings = {CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): value}
    bindings.update({parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, args))})
    for term in [f.success, *(u.value for t in f.transitions for u in t.updates)]:
        bindings.update({u: True for u in subterms(term, "unknown") if u[1] == "unsupported:raw_call_resources"})
    return Translation(
        d.chain(), d.contracts(*(n for n in ("C", "P", "D") if n in d.at)), d.at["C"], f.selector, bindings=bindings
    )


@pytest.mark.parametrize("mode", ["call", "delegatecall"])
@pytest.mark.parametrize("value", [0, 7])
def test_fallback_executes_writes_and_forwards_bytes(anvil, tmp_path, mode, value):
    d = deploy(anvil, tmp_path, mode)
    f = generate(d, "go")
    assert isinstance(f, Formula), f
    tr = evaluator(d, f, (13,), value=value)
    assert tr.truth(f.success) is True, tr.issues
    fn = O.function(d, "C", "go")
    output = rpc(
        d.url,
        "eth_call",
        [
            {
                "to": O.hex20(d.at["C"]),
                "from": O.hex20(O.ACCOUNTS[1]),
                "value": hex(value),
                "data": "0x" + O.calldata(fn, (13,)).hex(),
            },
            "latest",
        ],
    )
    expected = 13 + (value if mode == "delegatecall" else 0)
    assert decode(["uint"], bytes.fromhex(output[2:])) == (expected,)
    values = [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"]
    assert values == [expected], (values, tr.issues)
    at = d.at["C"] if mode == "delegatecall" else d.at["P"]
    raw = {
        number(tr.translate(u.location[2])): number(tr.translate(u.value))
        for t in f.transitions
        for u in t.updates
        if u.location[0] == "raw" and number(tr.translate(u.location[1])) == at
    }
    assert raw[7] == 1 and raw[8] == 91, (raw, tr.issues)


@pytest.mark.parametrize("mode", ["call", "delegatecall"])
def test_failed_fallback_rolls_back_its_pre_delegate_write(anvil, tmp_path, mode):
    d = deploy(anvil, tmp_path, mode)
    f = generate(d, "caught")
    assert isinstance(f, Formula), f
    tr = evaluator(d, f)
    assert tr.truth(f.success) is True, tr.issues
    assert O.passes(d, "C", O.function(d, "C", "caught"), (), sender=O.ACCOUNTS[1])
    assert [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"] == [3]
    assert not any(u.location[0] == "raw" for t in f.transitions for u in t.updates)


def test_fallback_resume_matches_uninterrupted(anvil, tmp_path):
    d = deploy(anvil, tmp_path)
    full = generate(d, "go")
    assert isinstance(full, Formula), full
    checkpoint = None
    for _ in range(200):
        result = generate(d, "go", steps=5, checkpoint=checkpoint)
        if isinstance(result, Formula):
            break
        assert isinstance(result, PendingCompilation), result
        checkpoint = json.loads(json.dumps(result.checkpoint))
    assert isinstance(result, Formula) and encode(result) == encode(full)


@pytest.mark.parametrize("payload,expected", [('bytes("")', 2), ('hex"01"', 1), ('hex"aabbccdd"', 1)])
def test_receive_and_fallback_selection(anvil, tmp_path, payload, expected):
    source = """pragma solidity 0.8.27;
    contract P {uint public mark;
      fallback() external payable {mark=1;}
      receive() external payable {mark=2;}
    }
    contract C {P p;uint result;constructor(address a){p=P(payable(a));}
      function go() external { (bool ok,)=address(p).call(PAYLOAD); require(ok); result=p.mark(); }
    }
    """.replace("PAYLOAD", payload)
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("P"),))
    fn = O.function(d, "C", "go")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "P"), steps=20000)
    assert isinstance(f, Formula), f
    tr = evaluator(d, f)
    assert tr.truth(f.success) is True and O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    assert [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"] == [
        expected
    ]


def test_fallback_bytes_return_decodes_at_the_interface(anvil, tmp_path):
    from eth_utils.crypto import keccak

    selector = int.from_bytes(keccak(text="missing(uint256)")[:4], "big")
    source = """pragma solidity 0.8.27;
    interface I {function missing(uint n) external returns(uint32,uint);}
    contract P {fallback(bytes calldata input) external returns(bytes memory){
      return abi.encode(uint32(msg.sig),input.length);
    }}
    contract C {I p;uint result;constructor(address a){p=I(a);}
      function go() external { (uint32 selector,uint size)=p.missing(9);
        require(selector==SELECTOR && size==36);result=1;
      }
    }
    """.replace("SELECTOR", str(selector))
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("P"),))
    fn = O.function(d, "C", "go")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "P"), steps=20000)
    assert isinstance(f, Formula), f
    tr = evaluator(d, f)
    assert tr.truth(f.success) is True and O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1]), tr.issues


def test_unknown_selector_without_fallback_reverts(anvil, tmp_path):
    source = """pragma solidity 0.8.27;
    contract P {function onlyEntry() external{}}
    contract C {address p;uint result;constructor(address a){p=a;}
      function go() external {(bool ok,)=p.call(hex"aabbccdd");require(!ok);result=1;}
    }"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("P"),))
    fn = O.function(d, "C", "go")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "P"), steps=20000)
    assert isinstance(f, Formula), f
    tr = evaluator(d, f)
    assert tr.truth(f.success) is True and O.passes(d, "C", fn, ()), tr.issues
    assert not subterms(f.success, "unknown")
