"""Legacy text assembly uses the shared memory operations and never guesses control flow."""

import pytest
from eth_abi import decode

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.formula import compile_function
from services.logic.lower import parameter
from services.logic.model import Formula
from services.logic.solver import Translation, number
from services.logic.terms import CALLER, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

BODIES = {
    "word": """assembly {
mstore(0,n) sstore(0,7) return(0,32)}
 saved=99;
""",
    "byte": """assembly {
mstore(0,0) mstore8(31,n) return(0,32)}
""",
    "arena": """assembly {
let p:=mload(64) mstore(p,n) return(p,32)}
""",
    "scope": """assembly {
let x:=3 {
let n:=7 x:=add(x,n)}
 mstore(0,add(x,n)) return(0,32)}
""",
    "signed": """uint x;
assembly {
x:=gt(sdiv(not(0),1),0)}
 return x;
""",
    "zero_copy": """assembly {
mstore(0,n) returndatacopy(0,0,0) return(0,32)}
""",
}


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14"])
@pytest.mark.parametrize("name", BODIES)
@pytest.mark.parametrize("n", [19, 0x123])
def test_memory_and_words_match_evm(anvil, tmp_path, version, name, n):
    (tmp_path / "target").mkdir()
    (tmp_path / "caller").mkdir()
    source = (
        "pragma solidity "
        + version
        + """;
contract T {
uint saved;
function f(uint n) public returns(uint){
"""
        + BODIES[name]
        + "}}"
    )
    target = O.deployment(anvil[0], tmp_path / "target", source, version)
    address = target.deploy("T")
    d = O.deployment(
        anvil[0],
        tmp_path / "caller",
        """pragma solidity 0.8.27;

        interface I {
function f(uint n) external returns(uint);
}

        contract C {
I t;
uint result;
constructor(address a){
t=I(a);
}

          function act(uint n) external returns(uint){
result=t.f(n);
return result;
}

        }
""",
    )
    d.deploy("C", ("address",), (address,))
    known = d.contracts("C")
    known[address] = target.slither["T"]
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), known, steps=20000)
    assert isinstance(f, Formula), f
    tr = Translation(
        d.chain(),
        known,
        d.at["C"],
        f.selector,
        bindings={CALLER: O.OWNER, mk("callvalue"): 0, parameter(fn.parameters[0], 0): n},
    )
    assert tr.truth(f.success) is True, tr.issues
    result = rpc(
        d.url,
        "eth_call",
        [{"to": O.hex20(d.at["C"]), "from": O.hex20(O.OWNER), "data": "0x" + O.calldata(fn, (n,)).hex()}, "latest"],
    )
    actual = decode(["uint"], bytes.fromhex(result[2:]))[0]
    expected = n % 256 if name == "byte" else n + 10 if name == "scope" else 1 if name == "signed" else n
    assert actual == expected
    values = [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"]
    assert values == [actual], (values, tr.issues)
    if name == "word":
        stores = [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[0] == "raw"]
        assert stores == [7]  # No execution after assembly RETURN.


@pytest.mark.parametrize("who,writes", [(O.OWNER, True), (O.ACCOUNTS[1], False)])
def test_unsupported_control_flow_is_retained_before_later_effects(anvil, tmp_path, who, writes):
    d = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity 0.5.14;

        contract C {
address owner=msg.sender;
uint saved;

          function act() public {

            assembly {
if iszero(eq(caller(),sload(0))) {
return(0,0)}
}

            saved=1;

          }

        }
""",
        "0.5.14",
    )
    d.deploy("C")
    fn = O.function(d, "C", "act")
    pending = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), steps=20000)
    assert isinstance(pending, PendingCompilation)
    assert pending.reason == "operation" and pending.blocker == "unsupported:legacy_assembly"
    diagnostic = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"))
    assert subterms(diagnostic.success, "unknown")
    assert O.transact(d, d.at["C"], "act()", sender=who)
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(d.at["C"]), "0x1", "latest"]), 16) == int(writes)


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14"])
def test_allocator_floor_does_not_hide_a_literal_heap_alias(anvil, tmp_path, version):
    (tmp_path / "target").mkdir()
    (tmp_path / "caller").mkdir()
    source = (
        "pragma solidity "
        + version
        + """;
contract T{
function f()public returns(uint){
assembly{
let p:=mload(64) mstore(p,1) mstore(96,2) mstore(0,mload(p)) return(0,32)}
}
}
"""
    )
    target = O.deployment(anvil[0], tmp_path / "target", source, version)
    address = target.deploy("T")
    root = O.deployment(
        anvil[0],
        tmp_path / "caller",
        """pragma solidity 0.8.27;

        interface I {
function f()external returns(uint);
}

        contract C {
I t;
uint result;
constructor(address a){
t=I(a);
}
function act()external returns(uint){
result=t.f();
return result;
}
}

    """,
    )
    root.deploy("C", ("address",), (address,))
    known = root.contracts("C")
    known[address] = target.slither["T"]
    fn = O.function(root, "C", "act")
    f = compile_function(root.slither["C"], fn, root.at["C"], root.chain(), known)
    actual = int(
        rpc(root.url, "eth_call", [{"to": O.hex20(root.at["C"]), "data": "0x" + O.calldata(fn, ()).hex()}, "latest"]),
        16,
    )
    assert actual == (2 if version == "0.4.19" else 1)
    tr = Translation(root.chain(), known, root.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
    values = [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"]
    assert values and all(v is None or v == actual for v in values), (values, tr.issues)
    if version == "0.5.14":
        assert values == [actual] and not tr.issues
    else:
        assert values == [None] and tr.issues


@pytest.mark.parametrize(
    "fields,body,want",
    [
        (
            "int constant K=-1;",
            """uint x;
assembly{
x:=gt(K,0)}
return x;
""",
            1,
        ),
        (
            "bytes2 constant K=0xabcd;",
            """uint x;
assembly{
x:=byte(0,K)}
return x;
""",
            171,
        ),
        (
            "uint constant K=8;",
            """uint x;
{
uint K=2;
assembly{
x:=K}
}
{
uint K=3;
assembly{
x:=add(x,K)}
}
return x;
""",
            5,
        ),
    ],
)
def test_compiler_references_resolve_local_and_constant_words(anvil, tmp_path, fields, body, want):
    source = (
        """pragma solidity 0.5.14;
contract T{
"""
        + fields
        + """function f()public returns(uint){
"""
        + body
        + "}}"
    )
    _check_legacy_constant(anvil, tmp_path, source, want)


@pytest.mark.parametrize("private", ["", "private"])
def test_inherited_constant_uses_its_declaration_scope(anvil, tmp_path, private):
    source = (
        """pragma solidity 0.5.14;
contract B{
uint """
        + private
        + """ constant K=1;
function f()public returns(uint){
uint x;
assembly{
x:=K}
return x;
}
}
contract T is B{
uint """
        + private
        + " constant K=2;}"
    )
    _check_legacy_constant(anvil, tmp_path, source, 1)


def _check_legacy_constant(anvil, tmp_path, source, want):
    target = O.deployment(anvil[0], tmp_path, source, "0.5.14")
    at = target.deploy("T")
    root = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity 0.8.27;

        interface I {
function f()external returns(uint);
}

        contract C {
I t;
uint result;
constructor(address a){
t=I(a);
}
function act()external returns(uint){
result=t.f();
return result;
}
}

    """,
    )
    root.deploy("C", ("address",), (at,))
    known = root.contracts("C")
    known[at] = target.slither["T"]
    fn = O.function(root, "C", "act")
    f = generate_function(root.slither["C"], fn, root.at["C"], root.chain(), known, steps=20000)
    assert isinstance(f, Formula), f
    tr = Translation(root.chain(), known, root.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
    assert tr.truth(f.success) is True and not tr.issues
    values = [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"]
    actual = int(
        rpc(root.url, "eth_call", [{"to": O.hex20(root.at["C"]), "data": "0x" + O.calldata(fn, ()).hex()}, "latest"]),
        16,
    )
    assert values == [actual] == [want] and not tr.issues
