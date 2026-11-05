"""Independent EVM boundary probes for assembly decoding, frames and buffers."""

import json

import pytest
from eth_utils.crypto import keccak

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.model import Formula, encode
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


def check(anvil, tmp_path, source, name="act", params=(), args=(), value=0, exact=False):
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("D"),))
    fn = O.function(d, "C", name)
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "D"), steps=20000)
    if isinstance(f, PendingCompilation):
        assert not exact, f.blocker
        return d, fn, f, None
    bindings = {CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): value}
    from services.logic.lower import parameter

    bindings.update({parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))})
    for term in [f.success, *(u.value for t in f.transitions for u in t.updates)]:
        bindings.update({u: True for u in subterms(term, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), d.contracts("C", "D"), d.at["C"], f.selector, bindings=bindings)
    actual = O.passes(d, "C", fn, args, sender=O.ACCOUNTS[1], value=value)
    predicted = tr.truth(f.success)
    assert predicted is None or predicted is actual
    if exact:
        assert predicted is actual, tr.issues
    return d, fn, f, tr


@pytest.mark.parametrize(
    "type_,word,good",
    [
        ("bool", 0, True),
        ("bool", 1, True),
        ("bool", 2, False),
        ("bytes3", 0x112233 << 232, True),
        ("bytes3", (0x112233 << 232) + 1, False),
        ("int8", 2**256 - 1, True),
        ("int8", 255, False),
        ("int8", 127, True),
        ("uint8", 255, True),
        ("uint8", 256, False),
        ("address", 2**160 - 1, True),
        ("address", 2**160, False),
    ],
)
@pytest.mark.parametrize("start", [0, 1, 31])
def test_scalar_raw_decoder(anvil, tmp_path, type_, word, good, start):
    selector = int.from_bytes(keccak(text="put(" + type_ + ")")[:4], "big")
    source = """pragma solidity 0.8.27;
contract D{
uint saved;
function put(TYPE n)external{
saved=1;
}
}

 contract C{
uint saved;
address d;
uint observed;
constructor(address a){
d=a;
}
function act()external{
address target=d;
bool ok;
assembly{
mstore(START,shl(224,SELECTOR))mstore(add(START,4),WORD)ok:=delegatecall(gas(),target,START,36,0,0)}
require(ok);
observed=saved;
}
}
"""
    for k, v in {"TYPE": type_, "START": start, "SELECTOR": selector, "WORD": word}.items():
        source = source.replace(k, str(v))
    d, fn, f, tr = check(anvil, tmp_path, source, exact=True)
    assert tr.truth(f.success) is good


@pytest.mark.parametrize(
    "out,size,want", [(0, 1, 0x12), (1, 4, 0x12345678), (31, 3, 0x123456), (64, 32, 0x12345678 << 224)]
)
@pytest.mark.parametrize("match", [True, False])
def test_output_shift(anvil, tmp_path, out, size, want, match):
    # read the copied bytes by shifting a word beginning exactly at the requested output.
    expected = want if match else want ^ 1
    source = """pragma solidity 0.8.27;
contract D{
function get()external pure returns(bytes4){
return 0x12345678;
}
}

 contract C{
address d;
address owner=msg.sender;
uint saved;
constructor(address a){
d=a;
}
function act()external{
address target=d;
bytes memory b=abi.encodeWithSignature("get()");
bool ok;
uint x;
assembly{
mstore(OUT,0)ok:=staticcall(gas(),target,add(b,32),mload(b),OUT,SIZE)x:=shr(SHIFT,mload(OUT))}
require(ok);
require(x==WANT||msg.sender==owner);
saved=1;
}
}
"""
    for k, v in {"OUT": out, "SIZE": size, "SHIFT": 256 - 8 * size, "WANT": expected}.items():
        source = source.replace(k, str(v))
    check(anvil, tmp_path, source, exact=out < 64)


@pytest.mark.parametrize("kind", ["array", "tuple"])
@pytest.mark.parametrize("match", [True, False])
def test_static_aggregates(anvil, tmp_path, kind, match):
    if kind == "array":
        decl = """function f(uint[2] calldata a,uint b)external pure returns(uint){
return a[0]+a[1]+b;
}
"""
        setup = "uint[2] memory a=[uint(3),uint(7)];bytes memory data=abi.encodeWithSelector(D.f.selector,a,uint(11));"
    else:
        decl = """struct S{
bytes3 a;
int8 b;
}
function f(S calldata a,uint b)external pure returns(uint){
require(a.a==0x112233&&a.b==-2);
return b;
}
"""
        setup = "D.S memory a=D.S(0x112233,-2);bytes memory data=abi.encodeWithSelector(D.f.selector,a,uint(21));"
    source = (
        """pragma solidity 0.8.27;
contract D{
"""
        + decl
        + """}
contract C{
address d;
address owner=msg.sender;
uint saved;
constructor(address x){
d=x;
}
function act()external{
"""
        + setup
        + """address target=d;
uint r;
bool ok;
assembly{
ok:=staticcall(gas(),target,add(data,32),mload(data),0,32)r:=mload(0)}
require(ok);
require(r=="""
        + str(21 if match else 20)
        + "||msg.sender==owner);saved=1;}}"
    )
    check(anvil, tmp_path, source, exact=True)


@pytest.mark.parametrize("trailing", [0, 32])
def test_calldata_and_value(anvil, tmp_path, trailing):
    source = """pragma solidity 0.8.27;
contract D{
uint stored;
function f(uint x)external payable returns(uint){
require(msg.sig==bytes4(keccak256("f(uint256)")));
require(msg.data.length==SIZE);
return x+msg.value;
}
}

 contract C{
uint stored;
address d;
address owner=msg.sender;
constructor(address a){
d=a;
}
function act()external payable{
bytes memory data=abi.encodeWithSelector(D.f.selector,uint(9));
address target=d;
bool ok;
uint x;
assembly{
ok:=delegatecall(gas(),target,add(data,32),SIZE,0,32)x:=mload(0)}
require(ok);
require(x==16||msg.sender==owner);
stored=1;
}
}
""".replace("SIZE", str(36 + trailing))
    check(anvil, tmp_path, source, value=7, exact=True)


@pytest.mark.parametrize("kind", ["array", "tuple"])
@pytest.mark.parametrize("match", [True, False])
def test_raw_static_aggregates(anvil, tmp_path, kind, match):
    if kind == "array":
        decl = """function f(uint[2] calldata a,uint b)external pure returns(uint){
return a[0]+a[1]+b;
}
"""
        sig = "f(uint256[2],uint256)"
        words = [3, 7, 11]
    else:
        decl = """struct S{
bytes3 a;
int8 b;
}
function f(S calldata a,uint b)external pure returns(uint){
require(a.a==0x112233&&a.b==-2);
return b;
}
"""
        sig = "f((bytes3,int8),uint256)"
        words = [0x112233 << 232, 2**256 - 2, 21]
    stores = (
        "mstore(0,shl(224,"
        + str(int.from_bytes(keccak(text=sig)[:4], "big"))
        + "))"
        + "".join("mstore(" + str(4 + 32 * i) + "," + str(w) + ")" for i, w in enumerate(words))
    )
    source = (
        """pragma solidity 0.8.27;
contract D{
"""
        + decl
        + """}
contract C{
address d;
address owner=msg.sender;
uint saved;
constructor(address x){
d=x;
}
function act()external{
address target=d;
uint r;
bool ok;
assembly{
"""
        + stores
        + "ok:=staticcall(gas(),target,0,100,0,32)r:=mload(0)}require(ok);require(r=="
        + str(21 if match else 20)
        + "||msg.sender==owner);saved=1;}}"
    )
    check(anvil, tmp_path, source, exact=True)


@pytest.mark.parametrize("mode", ["call", "staticcall", "delegatecall"])
@pytest.mark.parametrize("value", [0, 7])
def test_modes_environment_and_return_buffers(anvil, tmp_path, mode, value):
    sig = "f(address,address,uint256)"
    selector = int.from_bytes(keccak(text=sig)[:4], "big")
    # Calls use C as sender and D as this; delegates inherit outsider, value and C storage.
    sender = "caller()" if mode == "delegatecall" else "address()"
    target_context = "address()" if mode == "delegatecall" else "target"
    inherited = "callvalue()" if mode == "delegatecall" else "0"
    args = "gas(),target," + ("0," if mode == "call" else "") + "0,100,0,0"
    source = """pragma solidity 0.8.27;
contract D{
function f(address sender,address context,uint amount)external payable returns(bytes3,int8,uint[2] memory){
require(msg.sender==sender&&address(this)==context&&msg.value==amount);
uint[2] memory a=[uint(11),uint(19)];
return(0x112233,-2,a);
}
}

 contract C{
address d;
address owner=msg.sender;
uint saved;
constructor(address x){
d=x;
}
function act()external payable{
address target=d;
uint n;
uint v;
bool ok;
assembly{
STORES ok:=MODE(ARGS)n:=returndatasize()returndatacopy(0,64,32)v:=mload(0)}
require(ok);
require(n==128&&v==11||msg.sender==owner);
saved=1;
}
}
"""
    stores = (
        "mstore(0,shl(224,"
        + str(selector)
        + "))mstore(4,"
        + sender
        + ")mstore(36,"
        + target_context
        + ")mstore(68,"
        + inherited
        + ")"
    )
    source = source.replace("STORES", stores).replace("MODE", mode).replace("ARGS", args)
    check(anvil, tmp_path, source, value=value, exact=True)


@pytest.mark.parametrize("shift", [1, 4, 31])
def test_shifted_input_never_uses_unshifted_signature(anvil, tmp_path, shift):
    source = """pragma solidity 0.8.27;
contract D{
function f(uint x)external pure returns(uint){
return x;
}
fallback()external{
revert();
}
}

 contract C{
address d;
address owner=msg.sender;
uint saved;
constructor(address x){
d=x;
}
function act()external{
bytes memory data=abi.encodeWithSelector(D.f.selector,uint(17));
address target=d;
bool ok;
assembly{
ok:=staticcall(gas(),target,add(data,SHIFT),36,0,0)}
require(ok||msg.sender==owner);
saved=1;
}
}
""".replace("SHIFT", str(32 + shift))
    check(anvil, tmp_path, source, exact=False)


@pytest.mark.parametrize("poison", ["mstore(64,0)", "mstore(64,32)", "mstore(96,0)"])
def test_poisoned_heap_is_not_seeded_as_valid(anvil, tmp_path, poison):
    source = """pragma solidity 0.8.27;
contract D{
function f(uint x)external pure returns(uint){
return x;
}
}

 contract C{
address d;
address owner=msg.sender;
uint saved;
constructor(address x){
d=x;
}
function act()external{
assembly{
POISON}
bytes memory data=abi.encodeWithSelector(D.f.selector,uint(17));
address target=d;
bool ok;
uint v;
assembly{
ok:=staticcall(gas(),target,add(data,32),36,0,32)v:=mload(0)}
require(ok&&v==17||msg.sender==owner);
saved=1;
}
}
""".replace("POISON", poison)
    check(anvil, tmp_path, source, exact=False)


def test_checkpoint_assembly(anvil, tmp_path):
    source = """pragma solidity 0.8.27;
contract D{
uint x;
function f(uint n)external returns(uint){
x=n;
return n+1;
}
}

 contract C{
uint x;
address d;
uint saved;
constructor(address a){
d=a;
}
function act()external{
bytes memory data=abi.encodeWithSelector(D.f.selector,uint(17));
address target=d;
bool ok;
uint v;
assembly{
ok:=delegatecall(gas(),target,add(data,32),mload(data),0,32)v:=mload(0)}
require(ok);
saved=v;
}
}
"""
    d, fn, full, _ = check(anvil, tmp_path, source, exact=True)
    checkpoint = None
    for _ in range(100):
        f = generate_function(
            d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "D"), steps=5, checkpoint=checkpoint
        )
        if isinstance(f, Formula):
            break
        assert isinstance(f, PendingCompilation)
        checkpoint = json.loads(json.dumps(f.checkpoint))
    assert isinstance(f, Formula) and encode(f) == encode(full)


def test_short_huge_static_array_is_rejected_before_expansion(anvil, tmp_path, monkeypatch):
    import services.logic.calls as calls

    original = calls.decode_static
    counts = []

    def bounded(words, type_, strict=True):
        counts.append(len(words))
        assert len(words) < 100, "attempted to materialize absent huge array"
        return original(words, type_, strict)

    monkeypatch.setattr(calls, "decode_static", bounded)
    selector = int.from_bytes(keccak(text="f(uint256[1000000])")[:4], "big")
    source = """pragma solidity 0.8.27;
contract D{
function f(uint[1000000] calldata a)external pure returns(uint){
return a[0];
}
}

 contract C{
address d;
uint saved;
constructor(address a){
d=a;
}
function act()external{
address target=d;
bool ok;
assembly{
mstore(0,shl(224,SELECTOR))ok:=staticcall(gas(),target,0,4,0,0)}
require(ok);
saved=1;
}
}
""".replace("SELECTOR", str(selector))
    d, fn, f, tr = check(anvil, tmp_path, source, exact=True)
    assert tr.truth(f.success) is False and not counts
