import pytest
from eth_abi import encode as abi_encode

from services.logic.formula import compile_function
from services.logic.lower import parameter
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

TARGET = """contract T {
struct S{
bytes3 b;
int16 n;

}function f()external pure returns(S memory,uint[2] memory,uint8){
S memory s=S(0x112233,-2);
uint[2] memory a=[uint(41),uint(42)];
return(s,a,99);

}function g()external pure returns(uint){
return 77;

}function fail()external pure returns(uint){
revert("bad");

}
}"""
RET = abi_encode(["(bytes3,int16)", "uint256[2]", "uint8"], [(bytes.fromhex("112233"), -2), [41, 42], 99])


def inspect(anvil, tmp_path, body, params="", args=()):
    source = (
        "pragma solidity 0.8.27;"
        + TARGET
        + "contract C{address owner=msg.sender;T t;uint observed;constructor(address a){t=T(a);}function act("
        + params
        + ')external{address target=address(t);bytes memory data=abi.encodeWithSignature("f()");uint v;'
        + body
        + "observed=v;}}"
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "T"))
    tr = Translation(
        d.chain(),
        d.contracts("C", "T"),
        d.at["C"],
        f.selector,
        bindings={
            CALLER: O.ACCOUNTS[1],
            ORIGIN: O.ACCOUNTS[1],
            mk("callvalue"): 0,
            **{parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))},
        },
    )
    actual = O.passes(d, "C", fn, args, sender=O.ACCOUNTS[1])
    predicted = tr.truth(f.success)
    assert predicted is None or predicted is actual, (body, args, actual, predicted, tr.issues)
    return d, fn, f, tr


@pytest.mark.parametrize(
    "src,dest,count,read",
    [
        (0, 0, 0, 0),
        (0, 0, 1, 0),
        (0, 0, 31, 0),
        (0, 0, 32, 0),
        (0, 1, 31, 0),
        (1, 0, 32, 0),
        (31, 0, 32, 0),
        (30, 1, 33, 0),
        (32, 0, 32, 0),
        (64, 0, 64, 32),
        (96, 0, 64, 32),
        (128, 0, 32, 0),
        (159, 31, 1, 0),
    ],
)
@pytest.mark.parametrize("match", [False, True])
def test_copy_fragments(anvil, tmp_path, src, dest, count, read, match):
    initial = int.from_bytes(b"\xa5" * 32, "big")
    mem = bytearray(b"\xa5" * 64)
    mem[dest : dest + count] = RET[src : src + count]
    expected = int.from_bytes(mem[read : read + 32], "big")
    body = """assembly{
mstore(0,INITIAL)mstore(32,INITIAL)pop(staticcall(gas(),target,add(data,32),mload(data),0,0))returndatacopy(DEST,SRC,COUNT)v:=mload(READ)
}require(v==EXPECTED||msg.sender==owner);
"""
    for k, v in {
        "INITIAL": initial,
        "DEST": dest,
        "SRC": src,
        "COUNT": count,
        "READ": read,
        "EXPECTED": expected if match else expected ^ 1,
    }.items():
        body = body.replace(k, str(v))
    d, fn, f, tr = inspect(anvil, tmp_path, body)
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    assert actual is match


@pytest.mark.parametrize("flag", [False, True])
@pytest.mark.parametrize("want", [32, 160])
def test_branch_last_call(anvil, tmp_path, flag, want):
    body = """bytes memory other=abi.encodeWithSignature("g()");
assembly{
pop(staticcall(gas(),target,add(data,32),mload(data),0,0))
}if(flag){
assembly{
pop(staticcall(gas(),target,add(other,32),mload(other),0,0))
}
}assembly{
v:=returndatasize()
}require(v==160||msg.sender==owner);
"""
    body = body.replace("v==160", "v==" + str(want))
    inspect(anvil, tmp_path, body, "bool flag", (flag,))


@pytest.mark.parametrize(
    "stale",
    [
        "recovered=ecrecover(bytes32(0),27,bytes32(uint(1)),bytes32(uint(2)));",
        "bytes32 h=sha256(data);require(h!=bytes32(0));",
    ],
)
def test_stale_precompile(anvil, tmp_path, stale):
    body = (
        "address recovered;assembly{pop(staticcall(gas(),target,add(data,32),mload(data),0,0))}"
        + stale
        + "assembly{v:=returndatasize()}require(v==160||msg.sender==owner);"
    )
    inspect(anvil, tmp_path, body)


def test_revert_data(anvil, tmp_path):
    body = """data=abi.encodeWithSignature("fail()");
assembly{
pop(staticcall(gas(),target,add(data,32),mload(data),0,0))v:=returndatasize()
}require(v==32||msg.sender==owner);
"""
    inspect(anvil, tmp_path, body)


@pytest.mark.parametrize("creation", ["new T();", "assembly{pop(create(0,0,0))}", "assembly{pop(create2(0,0,0,17))}"])
def test_creation_clears_return_buffer(anvil, tmp_path, creation):
    body = (
        "assembly{pop(staticcall(gas(),target,add(data,32),mload(data),0,0))}"
        + creation
        + "assembly{v:=returndatasize()}require(v==160||msg.sender==owner);"
    )
    inspect(anvil, tmp_path, body)


def test_caught_call_keeps_its_revert_buffer(anvil, tmp_path):
    source = """pragma solidity 0.8.27;

 contract T{
function f()external pure returns(uint,uint,uint,uint,uint){
return(1,2,3,4,5);
}
function fail()external pure{
revert("bad");
}
}

 contract H{
T t;
constructor(address a){
t=T(a);
}
function test()external view returns(uint n){
address target=address(t);
bytes memory data=abi.encodeWithSignature("f()");
assembly{
pop(staticcall(gas(),target,add(data,32),mload(data),0,0))}
try t.fail(){
}
catch{
}
assembly{
n:=returndatasize()}
}
}

 contract C{
H h;
address owner=msg.sender;
uint controlled;
constructor(address a){
h=H(a);
}
function act()external{
address target=address(h);
bytes memory data=abi.encodeWithSignature("test()");
uint n;
uint ok;
assembly{
ok:=staticcall(gas(),target,add(data,32),mload(data),0,32)n:=mload(0)}
require(n==160||msg.sender==owner);
controlled=9;
}
}

 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("H", ("address",), (d.deploy("T"),))
    d.deploy("C", ("address",), (d.at["H"],))
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "H", "T"))
    tr = Translation(
        d.chain(),
        d.contracts("C", "H", "T"),
        d.at["C"],
        f.selector,
        bindings={CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): 0},
    )
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    predicted = tr.truth(f.success)
    assert predicted is None or predicted is actual
