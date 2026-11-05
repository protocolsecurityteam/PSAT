"""Independent dispatch, frame and resumability regressions against the EVM."""

import json

import pytest
from eth_utils import keccak

from services.logic.continuation import generate_function
from services.logic.model import Formula, encode
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc


def evaluate(d, at, known, f, payload, sender=O.OWNER, value=0):
    assert isinstance(f, Formula), f
    bind = {CALLER: sender, ORIGIN: sender, mk("callvalue"): value}
    if f.parameters:
        bind[f.parameters[0]] = payload
    for t in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        bind.update({u: True for u in subterms(t, "unknown") if u[1] == "unsupported:raw_call_resources"})
    return Translation(d.chain(), known, at, f.selector, bindings=bind)


def formula(d, name="P", fnname="fallback", **kw):
    known = d.contracts(*d.at)
    fn = O.function(d, name, fnname)
    at = d.at[name]
    f = generate_function(d.slither[name], fn, at, d.chain(), known, own_code=known.get, steps=30000, **kw)
    return at, known, f


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.27"])
@pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 5, 35, 36])
def test_zero_selector_short_inputs_do_not_enter_named(anvil, tmp_path, version, size):
    fb = "fallback()" if version == "0.8.27" else "function()"
    source = """pragma solidity VERSION;contract P {uint saved;
function blockHashAddendsInexpansible(uint256 x) external {saved=x+100;}
FALLBACK external payable {saved=300;}}""".replace("VERSION", version).replace("FALLBACK", fb)
    assert keccak(text="blockHashAddendsInexpansible(uint256)")[:4] == bytes(4)
    d = O.deployment(anvil[0], tmp_path, source, version=version)
    d.deploy("P")
    at, k, f = formula(d)
    payload = bytes(size)
    tr = evaluate(d, at, k, f, payload)
    pred = tr.truth(f.success)
    actual = O.transact_data(d, at, payload)
    assert pred is (size < 4), (version, size, pred, tr.issues)
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    assert (stored == 300) is (size < 4)
    assert actual is (size < 4 or version == "0.4.19" or size >= 36)
    assert not tr.issues


STATIC = """pragma solidity 0.8.27;
contract T {
 uint public word=55;
 function a() external pure returns(uint,uint){return (11,22);}
 function b(uint x) external view returns(uint){require(msg.sender==tx.origin?false:true);return x;}
 receive() external payable {}
 fallback() external {assembly {mstore(0,33) return(0,32)}}
}
contract P {uint saved;address target;address owner;
constructor(address t){target=t;owner=msg.sender;}
fallback() external payable {require(msg.sender==owner); assembly{
 mstore(0,99) calldatacopy(128,0,calldatasize())
 let ok:=staticcall(gas(),sload(1),128,calldatasize(),0,32)
 if iszero(ok){revert(0,0)}
 sstore(0,mload(0))
}}}
"""
INPUTS = [
    b"",
    b"\x01",
    b"\xff" * 4,
    keccak(text="a()")[:4],
    keccak(text="b(uint256)")[:4],
    keccak(text="b(uint256)")[:4] + (7).to_bytes(32, "big"),
    keccak(text="word()")[:4],
]


@pytest.mark.parametrize("payload", INPUTS)
@pytest.mark.parametrize("sender", O.ACCOUNTS[:2])
def test_symbolic_dispatch_static_returns_and_outer_sender(anvil, tmp_path, payload, sender):
    d = O.deployment(anvil[0], tmp_path, STATIC)
    d.deploy("P", ("address",), (d.deploy("T"),))
    at, k, f = formula(d)
    tr = evaluate(d, at, k, f, payload, sender)
    pred = tr.truth(f.success)
    vals = [
        int(str(tr.translate(e.value)))
        for e in f.effects
        if tr.truth(e.guard) is True and e.target[0] == "raw" and e.target[2][1] == 0
    ]
    actual = O.transact_data(d, at, payload, sender=sender)
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    assert pred is actual, (payload, pred, actual, tr.issues)
    assert stored == (vals[-1] if vals else 0), (payload, stored, vals, f.effects, tr.issues)
    assert not tr.issues


@pytest.mark.parametrize("runtime", [False, True])
@pytest.mark.parametrize("sender", O.ACCOUNTS[:2])
@pytest.mark.parametrize("value", [0, 1])
def test_outer_sig_value_sender_stay_outer_through_two_calls(anvil, tmp_path, runtime, sender, value):
    source = """pragma solidity 0.8.27;
 contract D {function deep(bytes4 s, address who) external view returns(bool){
 return s==bytes4(keccak256("act()"))&&who==tx.origin&&msg.sig==this.deep.selector&&msg.value==0;}}
 contract B {D d;constructor(address t){d=D(t);}function check(bytes4 s,address who) external view returns(bool){
 require(msg.sig==this.check.selector);return d.deep(s,who);}}
 contract P {B b;uint saved;address owner;constructor(address t){b=B(t);owner=msg.sender;}
 function act() external payable {require(msg.sender==owner&&msg.value==1&&msg.sig==this.act.selector);
 require(b.check(msg.sig,msg.sender));saved=88;}}
 """.replace("&&msg.value==0", "")
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("P", ("address",), (d.deploy("B", ("address",), (d.deploy("D"),)),))
    at = d.at["P"]
    k = d.contracts(*d.at)
    fn = O.function(d, "P", "act")
    f = generate_function(d.slither["P"], fn, at, d.chain(), k, **({"own_code": k.get} if runtime else {}))
    tr = evaluate(d, at, k, f, b"", sender, value)
    pred = tr.truth(f.success)
    actual = O.transact_data(d, at, keccak(text="act()")[:4], sender=sender, value=value)
    assert pred is actual, (runtime, sender, value, pred, actual, tr.issues)
    assert actual is (sender == O.OWNER and value == 1)
    assert not tr.issues


@pytest.mark.parametrize("steps", [1, 3, 7])
def test_symbolic_dispatch_checkpoint(anvil, tmp_path, steps):
    source = """pragma solidity 0.8.27;
 contract T {uint saved;function a(uint x) external {saved=x;}
 function z() external {uint n;while(n<3)n++;saved=n;}
 fallback() external {saved=99;}}
 contract P {uint saved;address target;constructor(address t){target=t;}
 fallback() external {assembly{calldatacopy(0,0,calldatasize())
 let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)if iszero(ok){revert(0,0)}}}}
 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("P", ("address",), (d.deploy("T"),))
    at = d.at["P"]
    known = d.contracts(*d.at)
    fn = O.function(d, "P", "fallback")
    reads = d.chain()
    cp = None
    for _ in range(100):
        f = generate_function(
            d.slither["P"], fn, at, reads, known, own_code=known.get, steps=steps, loop_iterations=4, checkpoint=cp
        )
        if isinstance(f, Formula):
            break
        cp = json.loads(json.dumps(f.checkpoint))
    assert isinstance(f, Formula), f
    fresh = generate_function(d.slither["P"], fn, at, reads, known, own_code=known.get, steps=30000, loop_iterations=4)
    assert encode(f) == encode(fresh)
    payload = keccak(text="z()")[:4]
    tr = evaluate(d, at, known, f, payload)
    assert tr.truth(f.success) is True
    assert O.transact_data(d, at, payload)
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16) == 3


def test_excluded_native_selector_does_not_require_dynamic_decoder(anvil, tmp_path):
    source = """pragma solidity 0.8.27;
 contract I {uint saved;function blocked(bytes calldata) external{} fallback() external {saved=77;}}
 contract P {uint saved;address target;constructor(address t){target=t;}function blocked(bytes calldata)external{}
 fallback() external {assembly {calldatacopy(0,0,calldatasize())
 let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)if iszero(ok){revert(0,0)}}}}
 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("P", ("address",), (d.deploy("I"),))
    at, k, f = formula(d)
    assert isinstance(f, Formula), f
    tr = evaluate(d, at, k, f, b"\xff" * 4)
    assert tr.truth(f.success) is True
    assert O.transact_data(d, at, b"\xff" * 4)
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16) == 77


def test_excluded_getter_does_not_require_a_synthetic_body(anvil, tmp_path):
    source = """pragma solidity 0.8.27;
    contract I {uint saved;struct S{uint x;} S public s;
      fallback()external{saved=77;}}
    contract P {uint saved;address target;struct S{uint x;} S public s;
      constructor(address t){target=t;}
      fallback()external{assembly{
        calldatacopy(0,0,calldatasize())
        let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)
        if iszero(ok){revert(0,0)}
      }}
    }"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("P", ("address",), (d.deploy("I"),))
    at, known, f = formula(d)
    assert isinstance(f, Formula), f
    tr = evaluate(d, at, known, f, b"\xff" * 4)
    assert tr.truth(f.success) is True
    assert O.transact_data(d, at, b"\xff" * 4)
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16) == 77
