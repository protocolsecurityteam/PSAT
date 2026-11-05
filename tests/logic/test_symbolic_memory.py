import pytest

from services.logic.formula import compile_function
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

CASES = {
    "byte_scratch": ("uint v;assembly{mstore(0,0)mstore8(31,1)v:=mload(0)}require(v==0||msg.sender==owner);", False),
    "byte_arena": (
        """uint v;
assembly{
let p:=mload(64)mstore(p,0)mstore8(add(p,31),1)v:=mload(p)
}require(v==0||msg.sender==owner);
""",
        False,
    ),
    "byte_header": (
        "uint p;uint q;assembly{p:=mload(64)mstore8(95,0)q:=mload(64)}require(p==q||msg.sender==owner);",
        False,
    ),
    "copy_scratch": (
        "uint v;assembly{mstore(0,0)mstore(32,1)mcopy(0,32,32)v:=mload(0)}require(v==0||msg.sender==owner);",
        False,
    ),
    "code_scratch": ("uint v;assembly{mstore(0,0)codecopy(0,0,32)v:=mload(0)}require(v==0||msg.sender==owner);", False),
    "alias_abs": (
        """uint v;
assembly{
let p:=mload(64)mstore(p,1)mstore(128,2)v:=mload(p)
}require(v==1||msg.sender==owner);
""",
        False,
    ),
    "alias_reverse": (
        """uint v;
assembly{
mstore(128,1)let p:=mload(64)mstore(p,2)v:=mload(128)
}require(v==1||msg.sender==owner);
""",
        False,
    ),
    "advance": (
        """uint v;
assembly{
let p:=mload(64)mstore(p,1)mstore(64,add(p,32))mstore(mload(64),2)v:=mload(p)
}require(v==1||msg.sender==owner);
""",
        True,
    ),
    "backward": (
        """uint[] memory a=new uint[](1);
a[0]=1;
assembly{
mstore(64,128)
}uint[] memory b=new uint[](1);
b[0]=2;
require(a[0]==1||msg.sender==owner);
""",
        False,
    ),
    "stale": (
        """uint p;
assembly{
p:=mload(64)
}uint[] memory a=new uint[](1);
a[0]=1;
assembly{
mstore(add(p,32),2)
}require(a[0]==1||msg.sender==owner);
""",
        False,
    ),
}


@pytest.mark.parametrize("mode", list(CASES))
def test_semantics(anvil, tmp_path, mode):
    body, expected = CASES[mode]
    source = (
        "pragma solidity 0.8.27;contract C{address owner=msg.sender;uint controlled;function act()external{"
        + body
        + "controlled=9;}}"
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"))
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        f.selector,
        bindings={CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): 0},
    )
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    predicted = tr.truth(f.success)
    assert actual is expected
    assert predicted is None or predicted is actual


@pytest.mark.parametrize("copy_size", [0, 1, 31, 32])
def test_return_copy_extent(anvil, tmp_path, copy_size):
    source = """pragma solidity 0.8.27;
 contract T{
function f()external pure returns(uint){
return 77;

}
}
 contract C {
address owner=msg.sender;
uint controlled;
T t;
constructor(address a){
t=T(a);

}function act()external{

 address target=address(t);
bytes memory data=abi.encodeWithSignature("f()");
uint n;

 assembly{
mstore(0,0)pop(staticcall(gas(),target,add(data,32),mload(data),0,0))returndatacopy(0,0,SIZE)n:=mload(0)
}
 require(n==77||msg.sender==owner);
controlled=9;

}
}""".replace("SIZE", str(copy_size))
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "T"))
    tr = Translation(
        d.chain(),
        d.contracts("C", "T"),
        d.at["C"],
        f.selector,
        bindings={CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): 0},
    )
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    predicted = tr.truth(f.success)
    assert actual is (copy_size == 32)
    assert predicted is None or predicted is actual


@pytest.mark.parametrize("branch", [False, True])
@pytest.mark.parametrize(
    "body",
    [
        "assembly{let p:=mload(64)mstore(p,1)if flag{mstore(p,2)}v:=mload(p)}",
        """uint p;
assembly{
p:=mload(64)mstore(p,1)
}if(flag){
assembly{
mstore(64,add(p,32))
}
}assembly{
v:=mload(p)
}""",
        """uint p;
assembly{
p:=mload(64)mstore(p,1)
}if(flag){
uint[] memory a=new uint[](1);
a[0]=7;

}assembly{
v:=mload(p)
}""",
        "uint p;assembly{p:=mload(64)mstore(p,1)mstore(0,2)mstore(32,3)v:=mload(p)}",
    ],
)
def test_branch_resume(anvil, tmp_path, branch, body):
    import json

    from services.logic.continuation import PendingCompilation, generate_function
    from services.logic.lower import parameter
    from services.logic.model import Formula, encode

    source = (
        """pragma solidity 0.8.27;
contract C{
address owner=msg.sender;
uint controlled;
function act(bool flag)external{
uint v;
"""
        + body
        + "require(v==1||msg.sender==owner);controlled=9;}}"
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")

    def run(**kw):
        return generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), **kw)

    f = run(steps=10000)
    assert isinstance(f, Formula), f
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        f.selector,
        bindings={
            CALLER: O.ACCOUNTS[1],
            ORIGIN: O.ACCOUNTS[1],
            mk("callvalue"): 0,
            parameter(fn.parameters[0], 0): branch,
        },
    )
    actual = O.passes(d, "C", fn, (branch,), sender=O.ACCOUNTS[1])
    predicted = tr.truth(f.success)
    assert predicted is None or predicted is actual
    checkpoint = None
    for _ in range(100):
        resumed = run(steps=3, checkpoint=checkpoint)
        if isinstance(resumed, Formula):
            break
        assert isinstance(resumed, PendingCompilation)
        checkpoint = json.loads(json.dumps(resumed.checkpoint))
    assert isinstance(resumed, Formula)
    assert encode(f) == encode(resumed)


@pytest.mark.parametrize(
    "action",
    [
        "emit Ping(7);",
        "recovered=ecrecover(bytes32(0),27,bytes32(uint(1)),bytes32(uint(2)));",
        "recovered=address(this);emit Ping(7);",
    ],
)
def test_implicit_buffer_bad_allocator(anvil, tmp_path, action):
    source = (
        """pragma solidity 0.8.27;
contract C{
event Ping(uint n);
address recovered;
uint controlled;
function act()external{
assembly{
mstore(64,not(0))
}"""
        + action
        + "controlled=9;}}"
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"))
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        f.selector,
        bindings={CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): 0},
    )
    try:
        actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    except RuntimeError as exc:
        assert "OOG" in str(exc)
        actual = False
    predicted = tr.truth(f.success)
    assert predicted is None or predicted is actual
