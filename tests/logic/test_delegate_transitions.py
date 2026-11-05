"""Delegate execution uses the caller's cells and environment, with independent memory."""

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
contract Logic {
 uint foreignName; address administrator;
 function change(uint n,address expected) external payable returns(uint){
  require(msg.sender==administrator && address(this)==expected);
  require(msg.sig==bytes4(keccak256("change(uint256,address)")));
  foreignName+=n; return foreignName+msg.value;
 }
 function abort() external {foreignName=999;revert();}
 function noValue() external {foreignName=77;}
 function memoryWork() external pure {uint[] memory b=new uint[](1);b[0]=99;require(b[0]==99);}
 function nested(address code,uint n,address expected) external payable returns(uint){
  (bool ok,bytes memory data)=code.delegatecall(abi.encodeWithSignature("change(uint256,address)",n,expected));
  require(ok);return abi.decode(data,(uint));
 }

}
contract C {
 uint public stored=3; address owner=msg.sender; address implementation; uint public result;
 constructor(address target){implementation=target;}
 function required(uint n) external payable returns(uint,uint){
  stored=5;
  (bool ok,bytes memory data)=implementation.delegatecall(
    abi.encodeWithSignature("change(uint256,address)",n,address(this)));
  require(ok);result=abi.decode(data,(uint));return(stored,result);
 }
 function nested(uint n) external payable returns(uint,uint){
  (bool ok,bytes memory data)=implementation.delegatecall(
    abi.encodeWithSignature("nested(address,uint256,address)",implementation,n,address(this)));
  require(ok);result=abi.decode(data,(uint));return(stored,result);
 }
 function memoryIsolation() external returns(uint){
  uint[] memory a=new uint[](1);a[0]=17;
  (bool ok,)=implementation.delegatecall(abi.encodeWithSignature("memoryWork()"));
  require(ok && a[0]==17);result=a[0];return result;
 }
 function publicEntry(uint n) external {
  if(msg.sender!=owner)return;
  (bool ok,)=implementation.delegatecall(abi.encodeWithSignature("change(uint256,address)",n,address(this)));
  require(ok);result=stored;
 }
 function caught() external returns(uint){
  stored=5;(bool ok,)=implementation.delegatecall(abi.encodeWithSignature("abort()"));
  require(!ok);result=stored;return result;
 }
 function ignored(uint n) external returns(uint){
  implementation.delegatecall(abi.encodeWithSignature("change(uint256,address)",n,address(this)));
  result=stored;return result;
 }
 function nonpayableTarget() external payable returns(uint){
  (bool ok,)=implementation.delegatecall(abi.encodeWithSignature("noValue()"));
  require(ok);result=stored;return result;
 }
}
"""


@pytest.fixture(scope="module")
def deployed(anvil):
    d = O.deployment(anvil[0], anvil[1], SOURCE)
    d.deploy("C", ("address",), (d.deploy("Logic"),))
    return d


def compile_case(d, name, args=(), sender=O.OWNER, value=0, resource=True):
    fn = O.function(d, "C", name)
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "Logic"), steps=10000)
    assert isinstance(f, Formula), f
    bindings = {CALLER: sender, ORIGIN: sender, mk("callvalue"): value}
    bindings.update({parameter(p, i): arg for i, (p, arg) in enumerate(zip(fn.parameters, args))})
    terms = [f.success, *(u.value for t in f.transitions for u in t.updates)]
    for term in terms:
        bindings.update({u: resource for u in subterms(term, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), d.contracts("C", "Logic"), d.at["C"], f.selector, bindings=bindings)
    return fn, f, tr


@pytest.mark.parametrize("value", [0, 7])
@pytest.mark.parametrize("n", [0, 19])
def test_delegate_context_and_physical_writes_match_evm(deployed, value, n):
    d = deployed
    fn, f, tr = compile_case(d, "required", (n,), value=value)
    result = rpc(
        d.url,
        "eth_call",
        [
            {
                "to": O.hex20(d.at["C"]),
                "from": O.hex20(O.OWNER),
                "value": hex(value),
                "data": "0x" + O.calldata(fn, (n,)).hex(),
            },
            "latest",
        ],
    )
    actual = decode(["uint", "uint"], bytes.fromhex(result[2:]))
    assert actual == (5 + n, 5 + n + value)
    assert tr.truth(f.success) is True, tr.issues
    observed = {
        u.location[1]: number(tr.translate(u.value))
        for t in f.transitions
        for u in t.updates
        if u.location[0] != "heap"
    }
    assert observed["stored"] == actual[0] and observed["result"] == actual[1], (observed, tr.issues)
    assert all(number(tr.translate(u.location[0])) == d.at["C"] for t in f.transitions for u in t.updates)


def test_delegate_authorization_rejects_stranger(deployed):
    d = deployed
    fn, f, tr = compile_case(d, "required", (4,), sender=O.ACCOUNTS[1])
    assert tr.truth(f.success) is False, tr.issues
    assert not O.passes(d, "C", fn, (4,), sender=O.ACCOUNTS[1])


def test_delegate_revert_rolls_back_only_callee_writes(deployed):
    d = deployed
    fn, f, tr = compile_case(d, "caught")
    assert tr.truth(f.success) is True and O.passes(d, "C", fn, (), sender=O.OWNER)
    values = {u.location[1]: number(tr.translate(u.value)) for t in f.transitions for u in t.updates}
    assert values["stored"] == values["result"] == 5, (values, tr.issues)


@pytest.mark.parametrize("resource,want", [(False, 3), (True, 12)])
def test_ignored_delegate_retains_success_and_failure_states(deployed, resource, want):
    _, f, tr = compile_case(deployed, "ignored", (9,), resource=resource)
    assert tr.truth(f.success) is True
    assert [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"] == [
        want
    ]


@pytest.mark.parametrize("value,passes", [(0, True), (7, False)])
def test_nonpayable_delegate_checks_inherited_value(deployed, value, passes):
    fn, f, tr = compile_case(deployed, "nonpayableTarget", value=value)
    assert O.passes(deployed, "C", fn, (), sender=O.OWNER, value=value) is passes
    assert tr.truth(f.success) is passes, tr.issues


def test_delegate_memory_does_not_replace_caller_heap(deployed):
    d = deployed
    fn, f, tr = compile_case(d, "memoryIsolation")
    assert O.passes(d, "C", fn, (), sender=O.OWNER)
    assert tr.truth(f.success) is True, tr.issues
    assert [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"] == [
        17
    ]


@pytest.mark.parametrize("value", [0, 7])
def test_nested_delegate_keeps_original_environment(deployed, value):
    d = deployed
    fn, f, tr = compile_case(d, "nested", (9,), value=value)
    result = rpc(
        d.url,
        "eth_call",
        [
            {
                "to": O.hex20(d.at["C"]),
                "from": O.hex20(O.OWNER),
                "value": hex(value),
                "data": "0x" + O.calldata(fn, (9,)).hex(),
            },
            "latest",
        ],
    )
    assert decode(["uint", "uint"], bytes.fromhex(result[2:])) == (12, 12 + value)
    assert tr.truth(f.success) is True, tr.issues
    assert [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"] == [
        12 + value
    ]


@pytest.mark.parametrize("sender", [O.OWNER, O.ACCOUNTS[1]])
def test_public_entry_does_not_make_delegated_effect_public(deployed, sender):
    d = deployed
    fn, f, tr = compile_case(d, "publicEntry", (9,), sender=sender)
    assert O.passes(d, "C", fn, (9,), sender=sender)
    assert tr.truth(f.success) is True
    effects = [e for e in f.effects if e.target[1] == "result"]
    assert effects and all(tr.truth(e.guard) is (sender == O.OWNER) for e in effects)


def test_delegate_resume_preserves_mode_and_frames(deployed):
    d = deployed
    fn, full, _ = compile_case(d, "nested", (9,))
    checkpoint = None
    for _ in range(100):
        result = generate_function(
            d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "Logic"), steps=5, checkpoint=checkpoint
        )
        if isinstance(result, Formula):
            break
        assert isinstance(result, PendingCompilation), result
        checkpoint = json.loads(json.dumps(result.checkpoint))
    assert isinstance(result, Formula) and encode(result) == encode(full)


def test_delegate_uses_available_own_code_instead_of_proxy_implementation(anvil, tmp_path):
    source = """pragma solidity 0.8.27;
    contract D {uint x;function set(uint n) external {x=n+1;}}
    contract P {uint x;function set(uint n) external {x=n+100;}fallback() external {revert();}}
    contract C {uint x;address target;uint observed;
      constructor(address a){target=a;}
      function go() external {
        (bool ok,)=target.delegatecall(abi.encodeWithSignature("set(uint256)",uint(17)));
        require(ok);observed=x;require(observed==117);
      }
    }
    """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    d.deploy("C", ("address",), (d.deploy("P"),))
    known = d.contracts("C", "D")
    known[d.at["P"]] = d.slither["D"]
    fn = O.function(d, "C", "go")
    f = generate_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        steps=10000,
        code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
        own_code={d.at["P"]: d.slither["P"]}.get,
    )
    assert isinstance(f, Formula), f
    bindings = {CALLER: O.OWNER, ORIGIN: O.OWNER, mk("callvalue"): 0}
    bindings.update({u: True for u in subterms(f.success, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, d.at["C"], f.selector, bindings=bindings)
    assert tr.truth(f.success) is True, tr.issues
    assert O.passes(d, "C", fn, (), sender=O.OWNER)
