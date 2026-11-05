"""Followed calls share storage changes, not memory or msg.sender/msg.value frames."""

import pytest
from eth_utils import keccak

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from services.logic.lower import parameter
from services.logic.solver import Translation, number
from services.logic.terms import CALLER, ORIGIN, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity ^0.8.10;
interface IC {function saved() external view returns(uint);function callback(uint n) external;}
contract Target {address public authority;uint public value;
 function bind(address a) external {authority=a;}
 function set(uint n) external {require(msg.sender==authority);value=n;}
 function bump() external returns(uint) {require(msg.sender==authority);value+=1;return value;}
 function checkSaved(uint n) external payable {require(msg.value==0);require(IC(msg.sender).saved()==n);value=n;}
 function fail() external {value=99;revert();}
 function callBack(uint n) external {require(msg.sender==authority);IC(msg.sender).callback(n);}
 function touch() external returns(bool) {value=77;return true;}
 function receiveValue() external payable {value=msg.value;}
}
interface StaticTarget {function touch() external view returns(bool);}
contract C {address public owner;Target public target;uint public saved;
 constructor(address t){owner=msg.sender;target=Target(t);}
 modifier auth(){require(msg.sender==owner);_;}
 function single(uint n) external auth {target.set(n);}
 function sequential(uint n) external auth {target.set(n);require(target.value()==n);
saved=target.bump();require(saved==n+1);}
 function conditional(bool first) external auth {if(first)target.set(3);else target.set(8);saved=target.value();}
 function rollback() external auth {saved=5;target.set(6);require(false);}
 function nestedRollback() external auth {saved=5;target.fail();saved=6;}
 function frames() external payable auth {saved=msg.value;target.checkSaved(msg.value);require(saved==msg.value);}
 function callback(uint n) external {require(msg.sender==address(target));saved=n;}
 function withCallback(uint n) external auth {target.callBack(n);require(saved==n);}
 function caught() external auth {try target.fail() {} catch {saved=7;}}
 function boundedGas() external auth {target.set{gas:0}(1);}
 function etherValue() external payable auth {target.receiveValue{value:1}();}
 function staticMutation() external auth {require(StaticTarget(address(target)).touch());}
 function rawAfterWrite(uint n) external auth {
  target.set(n);
  (bool ok,bytes memory data)=address(target).staticcall(abi.encodeWithSignature("value()"));
  require(ok);require(abi.decode(data,(uint))==n);saved=n;
 }
}
"""


@pytest.fixture
def d(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    target = d.deploy("Target")
    caller = d.deploy("C", ("address",), (target,))
    assert O.transact(d, target, "bind(address)", ("address",), (O.hex20(caller),))
    return d


def compiled(d, name):
    fn = O.function(d, "C", name)
    known = d.contracts("C", "Target")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), known)
    return fn, f, known


def predicted(d, fn, f, known, args=(), sender=O.OWNER, value=0):
    bindings = {
        CALLER: sender,
        ORIGIN: sender,
        mk("callvalue"): value,
        **{parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))},
    }
    tr = Translation(d.chain(), known, d.at["C"], f.selector, bindings=bindings)
    return tr.truth(f.success), tr


def read(d, at, signature):
    data = "0x" + keccak(text=signature)[:4].hex()
    return int(rpc(d.url, "eth_call", [{"to": O.hex20(at), "data": data}, "latest"]), 16)


@pytest.mark.parametrize(
    "name,args,types,final_target,final_saved",
    [
        ("single", (9,), ("uint256",), 9, 0),
        ("sequential", (9,), ("uint256",), 10, 10),
        ("conditional", (True,), ("bool",), 3, 3),
        ("conditional", (False,), ("bool",), 8, 8),
        ("withCallback", (9,), ("uint256",), 0, 9),
    ],
)
def test_state_transitions_match_committed_execution(d, name, args, types, final_target, final_saved):
    fn, f, known = compiled(d, name)
    callers = expand_formula(f, d.chain(), known).callers
    assert callers.complete and callers.members == (O.OWNER,), callers
    for sender in (O.OWNER, O.ACCOUNTS[1]):
        actual = O.chain_says(d, fn, args, sender=sender)
        answer, tr = predicted(d, fn, f, known, args, sender)
        assert answer is actual is (sender == O.OWNER), tr.issues
    _, tr = predicted(d, fn, f, known, args)
    writes = {}
    for transition in f.transitions:
        if tr.truth(transition.guard) is True:
            for update in transition.updates:
                if update.location[0][0] == "const":
                    writes[(update.location[0][1], update.location[1])] = number(tr.translate(update.value))
    assert O.transact(d, d.at["C"], fn.solidity_signature, types, args)
    assert read(d, d.at["Target"], "value()") == final_target
    assert read(d, d.at["C"], "saved()") == final_saved
    for (at, field), value in writes.items():
        assert value is not None and read(d, at, field + "()") == value


@pytest.mark.parametrize("name", ["rollback", "nestedRollback"])
def test_outer_and_inner_reverts_discard_all_writes(d, name):
    fn, f, known = compiled(d, name)
    answer, _ = predicted(d, fn, f, known)
    assert answer is False and not O.chain_says(d, fn, [], sender=O.OWNER)
    assert not O.transact(d, d.at["C"], fn.solidity_signature)
    assert read(d, d.at["Target"], "value()") == read(d, d.at["C"], "saved()") == 0


def test_callee_zero_value_does_not_rewrite_caller_values(d):
    fn, f, known = compiled(d, "frames")
    for value in (0, 7):
        answer, tr = predicted(d, fn, f, known, value=value)
        assert answer is True and O.passes(d, d.at["C"], fn, value=value), tr.issues
    assert O.transact(d, d.at["C"], fn.solidity_signature, value=7)
    assert read(d, d.at["Target"], "value()") == read(d, d.at["C"], "saved()") == 7


def test_external_summary_keeps_caller_heap_and_copies_returned_memory(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract T {function work(uint[] memory values) external pure returns(uint[] memory){
values[0]=9;return values;}}
contract C {T t;constructor(address a){t=T(a);}
function act() external view {uint[] memory mine=new uint[](1);mine[0]=3;
uint[] memory theirs=t.work(mine);require(mine[0]==3 && theirs[0]==9);
theirs[0]=7;require(mine[0]==3);}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    _, answer = O.engine_says(d, fn, (), contracts=d.contracts("C", "T"))
    assert answer is True and O.passes(d, "C", fn)


@pytest.mark.parametrize("aligned", [True, False])
def test_fixed_bytes_crossing_call_frame_preserve_yul_word_alignment(anvil, tmp_path, aligned):
    expected = "uint256(bytes32(bytes4(0x12345678)))" if aligned else "0x12345678"
    source = """pragma solidity ^0.8.10;
contract T {function set(uint key,bytes4 value) external {assembly{sstore(key,value)}}
function get(uint key) external view returns(uint value){assembly{value:=sload(key)}}}
contract C {T t;constructor(address a){t=T(a);}
function act() external {t.set(1,0x12345678);require(t.get(1)==EXPECTED);}}
""".replace("EXPECTED", expected)
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    _, answer = O.engine_says(d, fn, (), contracts=d.contracts("C", "T"))
    assert answer is aligned and O.passes(d, "C", fn) is aligned


@pytest.mark.parametrize(
    "name,args,value,actual",
    [
        ("caught", (), 0, True),
        ("boundedGas", (), 0, False),
        ("etherValue", (), 1, True),
        ("staticMutation", (), 0, False),
        ("rawAfterWrite", (9,), 0, True),
    ],
)
def test_unmodeled_call_modes_do_not_inherit_a_stale_answer(d, name, args, value, actual):
    fn, f, known = compiled(d, name)
    answer, tr = predicted(d, fn, f, known, args, value=value)
    assert O.passes(d, d.at["C"], fn, args, value=value) is actual
    assert answer is None, tr.issues
    callers = expand_formula(f, d.chain(), known).callers
    if name == "rawAfterWrite":  # only its success is required: complete under the ample-gas assumption
        O.assumes_gas(callers, {O.OWNER})
        assert not O.passes(d, d.at["C"], fn, args, sender=O.ACCOUNTS[1])
    else:
        assert not callers.complete


@pytest.mark.parametrize("style", ["raw", "bounded"])
@pytest.mark.parametrize("expected", [1, 2])
def test_repeated_unknown_calls_invalidate_after_intervening_writes(anvil, tmp_path, style, expected):
    call = 'address(t).call(abi.encodeWithSignature("change()"));' if style == "raw" else "t.change{gas:100000}();"
    source = """pragma solidity ^0.8.10;
interface IC {function set() external;}
contract T {function change() external {IC(msg.sender).set();}}
contract C {T t;uint public x;constructor(address a){t=T(a);}function set() external {x=2;}
function act() external {CALL x=1; CALL require(x==EXPECTED);}}
""".replace("CALL", call).replace("EXPECTED", str(expected))
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    known = d.contracts("C", "T")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), known)
    actual = O.passes(d, "C", fn)
    assert actual is (expected == 2)
    answer, _ = predicted(d, fn, f, known)
    assert answer is None or answer is actual
    assert not expand_formula(f, d.chain(), known).callers.complete


def test_explicit_write_after_unknown_call_supersedes_its_uncertainty(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract T {function change() external {}}
contract C {address t;uint public x;constructor(address a){t=a;}
function inner() internal {t.call(abi.encodeWithSignature("change()"));x=1;}
function act() external {inner();require(x==2);}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    _, answer = O.engine_says(d, fn, (), contracts=d.contracts("C", "T"))
    assert answer is False and not O.passes(d, "C", fn)


@pytest.mark.parametrize("mode", ["delegate", "loop", "recursion"])
def test_unmodeled_execution_invalidates_foreign_state(anvil, tmp_path, mode):
    from eth_utils import to_checksum_address

    target_source = "pragma solidity ^0.8.10; contract T {uint public x;function set(uint n) external {x=n;}}"
    target_deployment = O.deployment(anvil[0], tmp_path, target_source)
    target = target_deployment.deploy("T")
    literal = to_checksum_address(O.hex20(target))
    bodies = {
        "delegate": """bytes memory data=abi.encodeWithSignature("change(address)",address(TARGET));
address chosen=d;assembly{pop(delegatecall(gas(),chosen,add(data,32),mload(data),0,0))}""",
        "loop": "for(uint i=0;i<n;i++){if(i==3)T(TARGET).set(3);else T(TARGET).set(1);}",
        "recursion": "inner(n);",
    }
    source = (
        target_source
        + """
contract D {function change(address t) external {T(t).set(3);}}
contract C {address d; constructor(address a){d=a;}
function inner(uint n) internal {if(n==0){T(TARGET).set(3);return;}inner(n-1);}
function act(uint n) external {T(TARGET).set(1);BODY require(T(TARGET).x()==3);}}
""".replace("BODY", bodies[mode]).replace("TARGET", literal)
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.at["T"] = target
    d.deploy("C", ("address",), (d.deploy("D"),))
    fn = O.function(d, "C", "act")
    known = d.contracts("C", "T", "D")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), known)
    assert O.passes(d, "C", fn, (4,))
    answer, _ = predicted(d, fn, f, known, (4,))
    assert answer is None or answer is True
    callers = expand_formula(f, d.chain(), known).callers
    assert not (callers.complete and callers.representation == "finite" and not callers.members)


def test_unknown_internal_recursion_invalidates_shared_memory(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract C {uint value;
function inner(uint n,uint[] memory a) internal {if(n==0){a[0]=3;return;}inner(n-1,a);}
function act() external {uint[] memory a=new uint[](1);a[0]=1;inner(4,a);require(a[0]==3);value=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    _, answer = O.engine_says(d, fn, (), contracts=d.contracts("C"))
    assert O.passes(d, "C", fn)
    assert answer is None or answer is True


@pytest.mark.parametrize("changed,initial", [(True, False), (True, True), (False, False), (False, True)])
def test_proxy_dispatch_reads_current_foreign_beacon_state(anvil, tmp_path, changed, initial):
    source = """pragma solidity ^0.8.10;
contract Old {function allowed() external pure returns(bool){return false;}}
contract New {function allowed() external pure returns(bool){return true;}}
contract Beacon {address public current;constructor(address a){current=a;}function set(address a) external {current=a;}}
contract Proxy {Beacon beacon;constructor(address b){beacon=Beacon(b);}
fallback() external {address target=beacon.current();assembly{
calldatacopy(0,0,calldatasize())
let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
returndatacopy(0,0,returndatasize())
if iszero(ok){revert(0,returndatasize())}return(0,returndatasize())}}}
interface I {function allowed() external view returns(bool);}
contract C {Beacon beacon;address next;I proxy;uint value;
constructor(address b,address n,address p){beacon=Beacon(b);next=n;proxy=I(p);}
function act() external {beacon.set(next);require(proxy.allowed());value=1;}}
"""
    if initial:
        source = (
            source.replace("return false", "return OLD_TRUE")
            .replace("return true", "return false")
            .replace("OLD_TRUE", "true")
        )
    d = O.deployment(anvil[0], tmp_path, source)
    old = d.deploy("Old")
    new = d.deploy("New")
    beacon = d.deploy("Beacon", ("address",), (old,))
    proxy = d.deploy("Proxy", ("address",), (beacon,))
    d.deploy("C", ("address", "address", "address"), (beacon, new if changed else old, proxy))
    known = d.contracts("C", "Old", "New", "Beacon")
    known[proxy] = d.slither["Old"]
    fn = O.function(d, "C", "act")
    f = compile_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        code_of=lambda at: old if at == proxy else at,
        own_code={proxy: d.slither["Proxy"]}.get,
    )
    answer, _ = predicted(d, fn, f, known)
    assert O.passes(d, "C", fn) is (not initial if changed else initial)
    assert answer is None or answer is (not initial if changed else initial)
    if answer is None:
        callers = expand_formula(f, d.chain(), known).callers
        O.assumes_gas(callers)
        assert callers.representation == "cofinite" and O.passes(d, "C", fn, sender=O.ACCOUNTS[1])


def test_packed_beacon_and_unrelated_caller_writes_preserve_dispatch(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract Impl {function allowed() external pure returns(bool){return true;}}
contract Beacon {address public current;bool flag;uint8 mode;
constructor(address a){current=a;}function change() external {flag=true;mode=2;}}
contract Proxy {Beacon beacon;constructor(address b){beacon=Beacon(b);}
fallback() external {address target=beacon.current();assembly{
calldatacopy(0,0,calldatasize()) let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
returndatacopy(0,0,returndatasize())
if iszero(ok){revert(0,returndatasize())}return(0,returndatasize())}}}
interface I {function allowed() external view returns(bool);}
contract C {Beacon beacon;I proxy;uint value;
constructor(address b,address p){beacon=Beacon(b);proxy=I(p);}
function act() external {value=1;beacon.change();require(proxy.allowed());}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    impl = d.deploy("Impl")
    beacon = d.deploy("Beacon", ("address",), (impl,))
    proxy = d.deploy("Proxy", ("address",), (beacon,))
    d.deploy("C", ("address", "address"), (beacon, proxy))
    known = d.contracts("C", "Impl", "Beacon")
    known[proxy] = d.slither["Impl"]
    fn = O.function(d, "C", "act")
    f = compile_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        code_of=lambda at: impl if at == proxy else at,
        own_code={proxy: d.slither["Proxy"]}.get,
    )
    answer, tr = predicted(d, fn, f, known)
    assert O.passes(d, "C", fn)
    assert answer is None or answer is True, tr.issues
    if answer is None:
        callers = expand_formula(f, d.chain(), known).callers
        O.assumes_gas(callers)
        assert callers.representation == "cofinite" and O.passes(d, "C", fn, sender=O.ACCOUNTS[1])
