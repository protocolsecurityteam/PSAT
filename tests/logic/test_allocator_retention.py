"""Unsafe allocator operations remain pending before narrow values escape."""

import json

import pytest

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.formula import compile_function
from services.logic.model import decode_value
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

BODIES = {
    "scalar_zero": """assembly{
mstore8(95,0)}
 saved=9;
return 1;
""",
    "scalar_self": """assembly{
mstore(64,64)}
 saved=9;
return 1;
""",
    "scalar_unaligned": """assembly{
mstore(64,31)}
 saved=9;
return 7;
""",
    "alias_alloc": """uint[] memory a=new uint[](1);
a[0]=1;
assembly{
mstore(64,a)}
uint[] memory b=new uint[](1);
b[0]=2;
saved=9;
return a[0];
""",
    "implicit_alloc": """assembly{
mstore(64,0)}
uint[1] memory a;
a[0]=1;
saved=9;
return a[0];
""",
    "explicit_alloc": """assembly{
mstore8(95,0)}
uint[] memory a=new uint[](1);
a[0]=1;
saved=9;
return a[0];
""",
}


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.27"])
@pytest.mark.parametrize("case", BODIES)
def test_allocator_boundary(anvil, tmp_path, version, case):
    src = (
        "pragma solidity "
        + version
        + """;
contract T{
uint saved;
function f()public returns(uint){
saved=7;
"""
        + BODIES[case]
        + "}}"
    )
    d = O.deployment(anvil[0], tmp_path, src, version)
    a = d.deploy("T")
    tfn = O.function(d, "T", "f")
    actual = O.passes(d, "T", tfn, ())
    expected = None
    if actual:
        raw = bytes.fromhex(
            rpc(
                d.url,
                "eth_call",
                [{"from": O.hex20(O.OWNER), "to": O.hex20(a), "data": "0x" + O.calldata(tfn, ()).hex()}, "latest"],
            )[2:]
        )
        expected = int.from_bytes(raw[:32], "big") if len(raw) >= 32 else 1
    caller = """pragma solidity 0.8.27;
interface I{
function f() external returns(uint);
}
contract C{
I t;
uint result;
constructor(address a){
t=I(a);
}
function act()external {
require(t.f()==EXPECTED);
result=7;
}
}
""".replace("EXPECTED", str(expected if expected is not None else 1))
    c = O.deployment(anvil[0], tmp_path, caller)
    c.deploy("C", ("address",), (a,))
    fn = O.function(c, "C", "act")
    known = c.contracts("C")
    known[a] = d.slither["T"]
    reads = c.chain()

    def run(**kw):
        return generate_function(c.slither["C"], fn, c.at["C"], reads, known, steps=20000, **kw)

    p = run()
    assert isinstance(p, PendingCompilation), p
    label = "unsupported:abi_return_allocator" if case.startswith("scalar") else "unsupported:memory_allocator"
    assert p.reason == "operation" and p.blocker == label
    op = dict(decode_value(p.checkpoint["body"])["pending"]["operation"]["$map"])
    state = dict(op["state"]["$state"]["$map"])
    assert state["store"]["$map"]
    saved = [
        v for k, v in state["store"]["$map"] if isinstance(k, dict) and k.get("$tuple", [None, None])[1] == "saved"
    ]
    assert saved and saved[-1][1] == (9 if case.startswith("scalar") else 7), saved
    assert op["kind"] == ("abi_return_encoding" if case.startswith("scalar") else "memory_allocation")
    repeated = run(checkpoint=json.loads(json.dumps(p.checkpoint)))
    assert isinstance(repeated, PendingCompilation) and repeated.blocker == label
    f = compile_function(c.slither["C"], fn, c.at["C"], reads, known)
    tr = Translation(reads, known, c.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
    predicted = tr.truth(f.success)
    actualcaller = O.passes(c, "C", fn, ())
    assert predicted is None or predicted is actualcaller
    assert predicted is None
