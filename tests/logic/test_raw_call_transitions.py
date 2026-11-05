"""Low-level calls keep rollback, return encoding and independent resource outcomes."""

import json

import pytest
from eth_abi.abi import encode as abi_encode

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.formula import compile_function
from services.logic.model import Formula, encode
from services.logic.solver import Translation, number
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;

contract T {uint public x;

function set(uint n) external returns(bytes4,uint8){x=n;
return(bytes4(0x12345678),7);
}
function fail() external {x=99;
revert();
}
function read() external view returns(uint){return x;
}
}
contract C {T t;
uint public bound=3;
uint public result;

constructor(address a){t=T(a);
}
function called() external {result=2;
(bool ok,)=address(t).call(abi.encodeWithSelector(T.set.selector,uint(7)));
require(ok);
require(t.x()==7);
uint n;
for(uint i=0;
i<bound;
i++)n++;
result=n;
require(n==3);
}
function caught() external {t.set(5);
(bool ok,)=address(t).call(abi.encodeWithSignature("fail()"));
require(!ok);
require(t.x()==5);
result=11;
}
function ignored() external {address(t).call(abi.encodeWithSignature("set(uint256)",uint(9)));
result=t.x();
}
function twice() external {(bool a,)=address(t).call(abi.encodeWithSignature("set(uint256)",uint(9)));
(bool b,)=address(t).call(abi.encodeWithSignature("set(uint256)",uint(9)));
require(a && !b);
result=1;
}
function staticMutation() external {(bool ok,)=address(t).staticcall(abi.encodeWithSignature("set(uint256)",uint(9)));
require(ok);
}
function extraData() external {(bool ok,)=address(t).call(abi.encodeWithSignature("read()",uint(9)));
require(ok);
}
function capped() external {(bool ok,)=address(t).call{gas:0}(abi.encodeWithSignature("set(uint256)",uint(9)));
require(ok);
}
function failureBytes() external {(bool ok,bytes memory data)=address(t).call(abi.encodeWithSignature("fail()"));
require(!ok);
result=abi.decode(data,(uint));
}
}"""


@pytest.fixture
def d(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C", ("address",), (d.deploy("T"),))
    return d


def generate(d, name, **kwargs):
    return generate_function(
        d.slither["C"], O.function(d, "C", name), d.at["C"], d.chain(), d.contracts("C", "T"), **kwargs
    )


def evaluator(d, f, success=True):
    bindings = {CALLER: O.OWNER, ORIGIN: O.OWNER, mk("callvalue"): 0}
    # This binds the documented missing resource outcome, not callee authorization or state.
    bindings.update({t: success for t in subterms(f.success, "unknown") if t[1] == "unsupported:raw_call_resources"})
    for transition in f.transitions:
        for update in transition.updates:
            bindings.update(
                {t: success for t in subterms(update.value, "unknown") if t[1] == "unsupported:raw_call_resources"}
            )
    return Translation(d.chain(), d.contracts("C", "T"), d.at["C"], f.selector, bindings=bindings)


def test_required_raw_call_preserves_unrelated_stored_loop_bound(d):
    f = generate(d, "called", steps=10000, loop_iterations=4)
    assert isinstance(f, Formula), f
    assert O.chain_says(d, O.function(d, "C", "called"), [], sender=O.OWNER)
    tr = evaluator(d, f)
    assert tr.truth(f.success) is True, tr.issues
    assert not any(u.location[0] == "havoc" for t in f.transitions for u in t.updates)
    assert any(x[1] == "unsupported:raw_call_resources" for x in subterms(f.success, "unknown"))


def test_definite_revert_rolls_back_callee_writes_but_keeps_earlier_write(d):
    f = generate(d, "caught", steps=10000)
    assert isinstance(f, Formula)
    tr = evaluator(d, f)
    assert tr.truth(f.success) is True and O.chain_says(d, O.function(d, "C", "caught"), [], sender=O.OWNER)
    writes = {
        u.location[1]: number(tr.translate(u.value))
        for t in f.transitions
        if tr.truth(t.guard) is True
        for u in t.updates
    }
    assert writes["x"] == 5 and writes["result"] == 11


def test_ignored_call_retains_both_poststates(d):
    f = generate(d, "ignored", steps=10000)
    assert isinstance(f, Formula)
    for succeeds, want in [(True, 9), (False, 0)]:
        tr = evaluator(d, f, succeeds)
        values = [number(tr.translate(u.value)) for t in f.transitions for u in t.updates if u.location[1] == "result"]
        assert values == [want], tr.issues


def test_distinct_call_resource_outcomes_do_not_collapse(d):
    f = generate(d, "twice", steps=10000)
    assert isinstance(f, Formula)
    resources = sorted(subterms(f.success, "unknown"), key=str)
    resources = [t for t in resources if t[1] == "unsupported:raw_call_resources"]
    assert len(resources) == 2
    tr = evaluator(d, f)
    tr.bindings[resources[0]] = True
    tr.bindings[resources[1]] = False
    a = tr.truth(f.success)
    tr = evaluator(d, f)
    tr.bindings[resources[0]] = False
    tr.bindings[resources[1]] = True
    assert a is True or tr.truth(f.success) is True


@pytest.mark.parametrize("name", ["staticMutation", "capped", "failureBytes"])
def test_unmodeled_raw_boundary_stays_qualified(d, name):
    f = generate(d, name, steps=10000)
    if name != "failureBytes":
        assert isinstance(f, PendingCompilation) and f.reason == "call"
        assert (
            f.blocker
            == {
                "staticMutation": "unsupported:static_effect",
                "capped": "unsupported:explicit_call_gas",
            }[name]
        )
        f = compile_function(d.slither["C"], O.function(d, "C", name), d.at["C"], d.chain(), d.contracts("C", "T"))
    assert isinstance(f, Formula)
    assert subterms(f.success, "unknown")


def test_raw_return_encoding_retains_fixed_bytes_and_integer_width(d):
    from services.logic.calls import CallExecutor
    from services.logic.model import CallRequest, Limits
    from services.logic.terms import TRUE, const

    c = CallExecutor(d.chain(), d.contracts("C", "T"), d.at["C"], Limits())
    call = mk(
        "call",
        const(d.at["T"], "address"),
        "set(uint256)",
        (const(7),),
        False,
        const(d.at["C"], "address"),
        None,
        (("abi_type", "uint256"),),
        True,
    )
    result = c.handler(0)(CallRequest(call, (), const(0), raw=TRUE))
    tr = evaluator(
        d, compile_function(d.slither["C"], O.function(d, "C", "caught"), d.at["C"], d.chain(), d.contracts("C", "T"))
    )
    assert tr.truth(result.returns[0]) is True
    assert tr.translate(result.returns[1]) == abi_encode(["bytes4", "uint8"], [bytes.fromhex("12345678"), 7])


def test_raw_call_checkpoint_matches_uninterrupted(d):
    full = generate(d, "called", steps=10000, loop_iterations=4)
    checkpoint = None
    f = None
    for _ in range(100):
        f = generate(d, "called", steps=5, loop_iterations=4, checkpoint=checkpoint)
        if isinstance(f, Formula):
            break
        assert isinstance(f, PendingCompilation)
        checkpoint = json.loads(json.dumps(f.checkpoint))
    assert isinstance(f, Formula) and encode(f) == encode(full)


@pytest.mark.parametrize("helper", ["internal", "external"])
@pytest.mark.parametrize("write", ["mstore(add(b,36),1)", "mstore8(add(b,67),1)", "mstore(0xa4,1)"])
def test_assembly_mutated_payload_cannot_reuse_original_bytes(anvil, tmp_path, helper, write):
    source = """pragma solidity ^0.8.10;
contract T {uint public x;function set(uint n) external {x=n;}}
contract C {T t;constructor(address a){t=T(a);}
function act() external {bytes memory b=abi.encodeWithSignature("set(uint256)",uint(9));
assembly {WRITE} INVOKE(b);require(t.x()==1);}
function inside(bytes memory b) internal {(bool ok,)=address(t).call(b);require(ok);}
function outside(bytes memory b) external {(bool ok,)=address(t).call(b);require(ok);}
}""".replace("WRITE", write).replace("INVOKE", "inside" if helper == "internal" else "this.outside")
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    pending = generate(d, "act", steps=10000)
    assert isinstance(pending, PendingCompilation) and pending.reason in ("call", "operation")
    assert pending.blocker in ("unsupported:raw_call_payload", "unsupported:memory_allocator")
    f = compile_function(d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), d.contracts("C", "T"))
    assert O.chain_says(d, O.function(d, "C", "act"), [], sender=O.OWNER)
    tr = evaluator(d, f)
    assert tr.truth(f.success) is not False, tr.issues
    assert any("assembly_heap_alias" in str(t[1]) for t in subterms(f.success, "opaque")) or tr.issues


@pytest.mark.parametrize("expected", [0x12345678, 0])
def test_successful_raw_return_decodes_in_the_caller(anvil, tmp_path, expected):
    source = """pragma solidity ^0.8.10;
contract T {function get() external pure returns(bytes4,uint8){return(0x12345678,7);}}
contract C {address t;constructor(address a){t=a;}function act() external {
(bool ok,bytes memory b)=t.staticcall(abi.encodeWithSignature("get()"));require(ok);
(bytes4 x,uint8 y)=abi.decode(b,(bytes4,uint8));require(x==bytes4(uint32(EXPECTED)) && y==7);}}
""".replace("EXPECTED", str(expected))
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    f = generate(d, "act", steps=10000)
    assert isinstance(f, Formula)
    actual = O.chain_says(d, O.function(d, "C", "act"), [], sender=O.OWNER)
    tr = evaluator(d, f)
    assert tr.truth(f.success) is actual is (expected == 0x12345678), tr.issues


def test_uncapped_raw_call_can_fail_from_resources_while_caller_continues(anvil, tmp_path):
    from eth_utils.crypto import keccak

    from tests.support.anvil import rpc

    source = """pragma solidity ^0.8.10;
contract T {uint x;function work() external {for(uint i=0;i<1000;i++){x+=i;}}}
contract C {address t;constructor(address a){t=a;}function act() external returns(bool){
(bool ok,)=t.call(abi.encodeWithSignature("work()"));return ok;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    data = "0x" + keccak(text="act()")[:4].hex()
    outcomes = []
    for gas in (100000, 2000000):
        result = rpc(
            d.url,
            "eth_call",
            [{"from": O.hex20(O.OWNER), "to": O.hex20(d.at["C"]), "data": data, "gas": hex(gas)}, "latest"],
        )
        outcomes.append(int(result, 16))
    assert outcomes == [0, 1]


def test_allocator_scratch_preserves_existing_objects_and_loop_bound(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract C {uint public result;function act() external {
uint[] memory a=new uint[](3);a[0]=7;
assembly {let saved:=mload(0x40) mstore(0x34,123) mstore(0x40,saved)}
uint sum;for(uint i=0;i<a.length;i++){sum+=a[i];}require(sum==7);result=sum;
}}"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    f = generate_function(
        d.slither["C"],
        O.function(d, "C", "act"),
        d.at["C"],
        d.chain(),
        d.contracts("C"),
        steps=10000,
        loop_iterations=4,
    )
    assert isinstance(f, Formula)
    tr = Translation(d.chain(), d.contracts("C"), d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
    assert tr.truth(f.success) is True and O.chain_says(d, O.function(d, "C", "act"), [], sender=O.OWNER)


def test_rewound_allocator_new_object_invalidates_older_object(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract C {uint public result;function act() external {
uint[] memory a=new uint[](3);a[0]=7;
assembly {mstore(0x40,a)}
uint[] memory b=new uint[](1);b[0]=9;require(a.length==1 && a[0]==9);result=a[0];
}}"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    f = generate_function(
        d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), d.contracts("C"), steps=10000
    )
    assert isinstance(f, PendingCompilation) and f.reason == "operation"
    assert f.blocker in ("unsupported:memory_allocator", "unsupported:abi_return_allocator")
    f = compile_function(d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), d.contracts(*d.at))
    assert O.chain_says(d, O.function(d, "C", "act"), [], sender=O.OWNER)
    tr = Translation(d.chain(), d.contracts("C"), d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
    assert tr.truth(f.success) is not False
    assert subterms(f.success, "unknown")


@pytest.mark.parametrize("operation", ["emit E(9);", "t.ping(9);", "who=ecrecover(bytes32(uint(1234)),27,0,0);"])
def test_implicit_encoding_under_rewound_allocator_invalidates_heap(anvil, tmp_path, operation):
    source = """pragma solidity ^0.8.10;
contract T {function ping(uint) external {}}
contract C {T t;address who;event E(uint value);constructor(address a){t=T(a);}
function act() external {uint[] memory a=new uint[](1);a[0]=7;
assembly {mstore(0x40,0x80)} OPERATION require(a.length!=1);}}
""".replace("OPERATION", operation)
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    f = generate(d, "act", steps=10000)
    assert isinstance(f, PendingCompilation) and f.reason == "operation"
    assert f.blocker in ("unsupported:memory_allocator", "unsupported:abi_return_allocator")
    f = compile_function(d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), d.contracts(*d.at))
    assert O.chain_says(d, O.function(d, "C", "act"), [], sender=O.OWNER)
    tr = evaluator(d, f)
    assert tr.truth(f.success) is not False
    assert subterms(f.success, "unknown")


def test_modifier_allocator_change_precedes_external_return_encoding(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract T {modifier rewind(){_;assembly{mstore(0x40,0x80)}}
function values() external rewind returns(uint[] memory a){a=new uint[](1);a[0]=7;}}
contract C {T t;constructor(address a){t=T(a);}function act() external {
uint[] memory a=t.values();require(a.length>1);}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    f = generate(d, "act", steps=10000)
    assert isinstance(f, PendingCompilation) and f.reason == "operation"
    assert f.blocker in ("unsupported:memory_allocator", "unsupported:abi_return_allocator")
    f = compile_function(d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), d.contracts(*d.at))
    assert O.chain_says(d, O.function(d, "C", "act"), [], sender=O.OWNER)
    assert evaluator(d, f).truth(f.success) is not False
    assert subterms(f.success, "unknown")


def test_reverting_allocator_branch_does_not_poison_other_path(anvil, tmp_path):
    from services.logic.lower import parameter

    source = """pragma solidity ^0.8.10;
contract C {uint public result;function act(bool stop) external {
uint[] memory a=new uint[](3);a[0]=7;
if(stop){assembly {mstore(0x40,0x80)}revert();}
uint[] memory b=new uint[](1);b[0]=9;
uint sum;for(uint i=0;i<a.length;i++){sum+=a[i];}require(sum==7);result=sum+b[0];
}}"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), steps=10000, loop_iterations=4)
    assert isinstance(f, Formula)
    for stop in (False, True):
        tr = Translation(
            d.chain(),
            d.contracts("C"),
            d.at["C"],
            f.selector,
            bindings={CALLER: O.OWNER, mk("callvalue"): 0, parameter(fn.parameters[0], 0): stop},
        )
        assert tr.truth(f.success) is O.chain_says(d, fn, [stop], sender=O.OWNER) is (not stop)


def test_trailing_raw_calldata_is_accepted_by_the_real_decoder(d):
    f = generate(d, "extraData", steps=10000)
    assert isinstance(f, Formula), f
    tr = evaluator(d, f)
    assert tr.truth(f.success) is True and O.chain_says(d, O.function(d, "C", "extraData"), [], sender=O.OWNER)
    assert {t[1] for t in subterms(f.success, "unknown")} == {"unsupported:raw_call_resources"}
