"""Calls and loops remain executable continuations, not invented post-call state."""

import json
from typing import Any

import pytest

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.model import CallFrame, Formula, decode_value, encode
from services.logic.terms import CALLER, FALSE, TRUE, const, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
interface I {function poke(uint n) external returns(uint);}
contract T is I {uint public x;function poke(uint n) external returns(uint){x=n;return n;}}
contract M {uint public beforeCall;function relay(address chosen) external {beforeCall=5;I(chosen).poke(3);}}
contract C {address public owner;I t;uint public beforeCall;uint public afterCall;
constructor(address a){owner=msg.sender;t=I(a);}
function dynamic(address chosen) external {require(msg.sender==owner);beforeCall=7;I(chosen).poke(3);
for(uint i=0;i<100;i++){afterCall++;}}
function known() external {require(msg.sender==owner);beforeCall=7;afterCall=t.poke(4)+beforeCall;}
function nested(M middle,address chosen) external {beforeCall=7;middle.relay(chosen);afterCall=9;}
function region(address chosen,bytes memory data) external payable {beforeCall=7;
assembly {mstore(0,41) pop(delegatecall(gas(),chosen,add(data,32),mload(data),0,32))}afterCall=9;}
function loops() external {beforeCall=0;for(uint i=0;i<3;i++){beforeCall++;}afterCall=9;}
}"""


@pytest.fixture
def d(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C", ("address",), (d.deploy("T"),))
    d.deploy("M")
    return d


def run(d, name, known=None, **kwargs):
    return generate_function(
        d.slither["C"],
        O.function(d, "C", name),
        d.at["C"],
        d.chain(),
        known if known is not None else d.contracts("C", "T", "M"),
        steps=10000,
        **kwargs,
    )


def operation(pending):
    assert isinstance(pending, PendingCompilation)
    return decode_value(pending.checkpoint["body"])["pending"]["operation"]["$map"]


def mapping(value):
    return dict(value["$map"])


def test_unresolved_call_retains_path_and_writes_before_downstream_loop(d):
    p = run(d, "dynamic", loop_iterations=2)
    assert isinstance(p, PendingCompilation) and p.reason == "call" and p.blocker == "unresolved:call_target"
    saved = dict(operation(p))
    assert saved["kind"] == "call"
    assert any(t[1] == "chosen" for t in subterms(saved["target"], "arg"))
    state = mapping(saved["state"]["$state"])
    assert CALLER in subterms(state["pc"], "caller") and state["pc"] not in (TRUE, FALSE)
    writes = state["store"]["$map"]
    assert any(key["$tuple"][1] == "beforeCall" for key, _ in writes)
    assert not any(key["$tuple"][1] == "afterCall" for key, _ in writes)
    repeated = run(d, "dynamic", loop_iterations=128, checkpoint=json.loads(json.dumps(p.checkpoint)))
    assert isinstance(repeated, PendingCompilation) and repeated.blocker == p.blocker


def test_new_source_resumes_retained_call_at_same_snapshot(d):
    p = run(d, "known", known=d.contracts("C"))
    assert isinstance(p, PendingCompilation) and p.blocker == f"unverified:{d.at['T']:#x}"
    resumed = run(d, "known", checkpoint=json.loads(json.dumps(p.checkpoint)))
    full = run(d, "known")
    assert isinstance(resumed, Formula) and encode(resumed) == encode(full)
    assert O.chain_says(d, O.function(d, "C", "known"), [], sender=O.OWNER)
    assert not O.chain_says(d, O.function(d, "C", "known"), [], sender=O.ACCOUNTS[1])


def test_nested_call_retains_invoking_frame_not_root_frame(d):
    from services.logic.lower import parameter

    fn = O.function(d, "C", "nested")
    p = run(d, "nested", bindings={parameter(fn.parameters[0], 0): d.at["M"]})
    assert isinstance(p, PendingCompilation) and p.blocker == "unresolved:call_target"
    frame = mapping(dict(operation(p))["caller_frame"])
    assert frame["storage"] == frame["code"] == const(d.at["M"], "address")
    assert frame["sender"] == const(d.at["C"], "address")
    assert frame["value"] == const(0) and frame["static"] is False
    assert frame["calldata"][0] == "enc"


def test_assembly_call_retains_input_and_memory_before_output_clobber(d):
    p = run(d, "region")
    assert isinstance(p, PendingCompilation) and p.reason == "call"
    saved = dict(operation(p))
    assert saved["mode"] == "delegatecall" and saved["calldata"][:2] == ("opaque", "memory_region")
    assert any(t[1] == "chosen" for t in subterms(saved["target"], "arg"))
    assert saved["operands"]["$tuple"][-2:] == [const(0), const(32)]
    state = saved["state"]
    fields = mapping(state["$state"])
    assert fields["mem"]["$tuple"] == [{"$tuple": [0, const(41)]}]
    frame = mapping(saved["caller_frame"])
    assert frame["storage"] == const(d.at["C"], "address") and frame["sender"] == CALLER
    assert frame["value"] == mk("callvalue")


def test_loop_retains_program_state_and_resumes(d):
    p = run(d, "loops", loop_iterations=1)
    assert isinstance(p, PendingCompilation) and p.reason == "loop_iterations"
    saved = dict(operation(p))
    assert saved["kind"] == "loop" and saved["iterations"] == 1
    assert "/node/" in saved["entry"]["$ref"] and "/fn/" in saved["function"]["$ref"]
    assert saved["state"]["$state"] and mapping(saved["frame"])["storage"] == const(d.at["C"], "address")
    complete = run(d, "loops", loop_iterations=4, checkpoint=json.loads(json.dumps(p.checkpoint)))
    assert isinstance(complete, Formula) and encode(complete) == encode(run(d, "loops", loop_iterations=4))
    assert O.chain_says(d, O.function(d, "C", "loops"), [], sender=O.OWNER)


def test_frame_derivation_separates_code_and_storage():
    f = CallFrame(const(10), const(11), const(12), const(13), const(b"outer", "bytes"))
    target, code, data, value = const(20), const(21), const(b"child", "bytes"), const(3)
    normal = f.enter("call", target, code, data, value)
    assert (normal.code, normal.storage, normal.sender, normal.value) == (code, target, f.storage, value)
    delegated = f.enter("delegatecall", target, code, data, value)
    assert (delegated.code, delegated.storage, delegated.sender, delegated.value) == (
        code,
        f.storage,
        f.sender,
        f.value,
    )
    static = f.enter("staticcall", target, code, data, value)
    assert static.static and static.value == const(0)
    assert static.enter("call", target, code, data, const(0)).static
    with pytest.raises(ValueError):
        f.enter("typo", target, code, data, value)


def test_retained_call_resumes_in_a_fresh_process_after_source_is_available(d, tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    from tests.fuzz.authority import solc_path

    p = run(d, "known", known=d.contracts("C"))
    assert isinstance(p, PendingCompilation)
    fn = O.function(d, "C", "known")
    payload = {
        "checkpoint": p.checkpoint,
        "url": d.url,
        "block": p.block,
        "addresses": d.at,
        "source": fn.source_mapping.filename.absolute,
        "solc": str(solc_path("0.8.27")),
    }
    infile = tmp_path / "pending.json"
    infile.write_text(json.dumps(payload))
    outfile = tmp_path / "resumed.json"
    script = tmp_path / "resume.py"
    script.write_text("""import json,sys
from pathlib import Path
from slither import Slither
from services.clients.logic_reads import ChainReads
from services.logic.continuation import generate_function
from services.logic.model import Formula,encode
from tests.support.anvil import rpc
p=json.loads(Path(sys.argv[1]).read_text())
cs={c.name:c for c in Slither(p['source'],solc=p['solc']).contracts}
reads=ChainReads(lambda method,params:rpc(p['url'],method,params),p['block'])
known={p['addresses'][name]:cs[name] for name in ('C','T','M')}
fn=next(f for f in cs['C'].functions_entry_points if f.name=='known')
f=generate_function(cs['C'],fn,p['addresses']['C'],reads,known,steps=10000,checkpoint=p['checkpoint'])
assert isinstance(f,Formula)
Path(sys.argv[2]).write_text(json.dumps(encode(f)))
""")
    subprocess.run(
        [sys.executable, str(script), str(infile), str(outfile)],
        check=True,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(Path.cwd())},
    )
    assert json.loads(outfile.read_text()) == encode(run(d, "known"))


def test_legacy_view_call_uses_ordinary_call_and_records_actual_writes(anvil, tmp_path):
    from services.logic.solver import Translation, number

    source = """pragma solidity 0.4.19;
contract T {uint public x;function bump() external constant returns(uint){x++;return x;}}
contract C {T t;uint public saved;function C(address a) public {t=T(a);}
function act() external {saved=t.bump();}}
"""
    d = O.deployment(anvil[0], tmp_path, source, version="0.4.19")
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    reads = d.chain()
    f = generate_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C", "T"), steps=10000)
    assert isinstance(f, Formula)
    tr = Translation(
        reads, d.contracts("C", "T"), d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0}
    )
    assert tr.truth(f.success) is True and O.chain_says(d, fn, [], sender=O.OWNER)
    changes = {u.location[1]: number(tr.translate(u.value)) for t in f.transitions for u in t.updates}
    assert changes["x"] == changes["saved"] == 1
    assert O.transact(d, d.at["C"], "act()")
    assert d.chain().storage(d.at["T"], 0) == 1


@pytest.mark.parametrize("kind", ["call", "staticcall", "delegatecall", "callcode"])
def test_frame_context_matches_evm_call_modes(anvil, tmp_path, kind):
    from eth_abi.abi import decode
    from eth_utils.crypto import keccak

    from tests.support.anvil import rpc

    source = """pragma solidity ^0.8.10;
contract T {function inspect() external payable returns(address,address,uint,uint){
uint size;assembly{size:=codesize()}return(address(this),msg.sender,msg.value,size);}}
contract C {address t;constructor(address a){t=a;}
function act() external payable returns(address,address,uint,uint){
bytes memory b=abi.encodeWithSignature("inspect()");bool ok;bytes memory out;
BODY require(ok);return abi.decode(out,(address,address,uint,uint));}}
"""
    bodies = {
        "call": "(ok,out)=t.call{value:2}(b);",
        "staticcall": "(ok,out)=t.staticcall(b);",
        "delegatecall": "(ok,out)=t.delegatecall(b);",
        "callcode": """out=new bytes(128);address target=t;
assembly{ok:=callcode(gas(),target,2,add(b,32),mload(b),add(out,32),128)}""",
    }
    d = O.deployment(anvil[0], tmp_path, source.replace("BODY", bodies[kind]))
    d.deploy("C", ("address",), (d.deploy("T"),))
    data = "0x" + keccak(text="act()")[:4].hex()
    raw = rpc(
        d.url,
        "eth_call",
        [{"from": O.hex20(O.OWNER), "to": O.hex20(d.at["C"]), "data": data, "value": hex(5)}, "latest"],
    )
    storage, sender, value, size = decode(["address", "address", "uint256", "uint256"], bytes.fromhex(raw[2:]))
    caller = CallFrame(
        const(d.at["C"], "address"),
        const(d.at["C"], "address"),
        const(O.OWNER, "address"),
        const(5),
        const(b"", "bytes"),
    )
    frame = caller.enter(
        kind,
        const(d.at["T"], "address"),
        const(d.at["T"], "address"),
        const(keccak(text="inspect()")[:4], "bytes"),
        const(2),
    )
    assert (frame.storage[1], frame.sender[1], frame.value[1]) == (int(storage, 16), int(sender, 16), value)
    assert len(d.chain().code(frame.code[1])) == size


@pytest.mark.parametrize("evm", ["homestead", "byzantium"])
def test_explicit_evm_target_controls_view_call_mode(anvil, tmp_path, evm):
    import subprocess

    from crytic_compile.crytic_compile import CryticCompile
    from crytic_compile.platform.solc_standard_json import SolcStandardJson
    from slither import Slither

    from tests.fuzz.authority import solc_path

    source = """pragma solidity ^0.5.0;
interface I {function bump() external view returns(uint);}
contract T {uint public x;function bump() external returns(uint){x++;return x;}}
contract C {I t;uint public saved;constructor(address a) public {t=I(a);}
function act() external {saved=t.bump();}}
"""
    d = O.deployment(anvil[0], tmp_path, source, version="0.5.14")
    source_path = tmp_path / "target.sol"
    source_path.write_text(source)
    standard = {
        "language": "Solidity",
        "sources": {str(source_path): {"content": source}},
        "settings": {"evmVersion": evm, "outputSelection": {"*": {"*": ["*"], "": ["ast"]}}},
    }
    solc = str(solc_path("0.5.14"))
    result = json.loads(
        subprocess.run(
            [solc, "--standard-json"], input=json.dumps(standard), text=True, capture_output=True, check=True
        ).stdout
    )
    d.compiled = {
        name: {"bin": body["evm"]["bytecode"]["object"], "abi": body["abi"]}
        for name, body in result["contracts"][str(source_path)].items()
    }
    slither = Slither(CryticCompile(SolcStandardJson(standard), solc=solc))
    for unit in slither.compilation_units:
        unit.context["psat_evm_version"] = evm
    d.slither = {c.name: c for c in slither.contracts}
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "T"), steps=10000)
    actual = O.chain_says(d, fn, [], sender=O.OWNER)
    if evm == "homestead":
        assert isinstance(f, Formula) and actual
    else:
        assert isinstance(f, PendingCompilation) and f.blocker == "unsupported:static_effect" and not actual


def test_assessment_describes_unresolved_calls_without_suggesting_more_budget(d, tmp_path):
    from dataclasses import asdict

    from services.resolution.logic_assessment import assess_formulas
    from services.resolution.logic_impact import JudgmentCache

    p = run(d, "dynamic")
    artifact = {
        "schema": 2,
        "kind": "formulas",
        "chain_id": 1,
        "address": O.hex20(d.at["C"]),
        "block": p.block,
        "status": "incomplete",
        "functions": {},
        "pending_functions": {"dynamic(address)": asdict(p)},
    }
    report = assess_formulas(
        artifact, reads=d.chain(), contracts=d.contracts("C", "T", "M"), cache=JudgmentCache(tmp_path)
    )
    assert report["pending_functions"]["dynamic(address)"] == {
        "reason": "call",
        "blocker": "unresolved:call_target",
        "action": "resolve_call",
    }


@pytest.mark.parametrize("native", ["send", "transfer"])
def test_native_value_call_is_retained_before_following_code(anvil, tmp_path, native):
    source = """pragma solidity ^0.8.10;
contract C {uint public beforeCall;uint public afterCall;
function act(address payable target) external payable {beforeCall=7;target.NATIVE(msg.value);afterCall=9;}}
""".replace("NATIVE", native)
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    f = generate_function(
        d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), d.contracts("C"), steps=10000
    )
    assert isinstance(f, PendingCompilation) and f.blocker == "unsupported:native_value_call"
    saved = dict(operation(f))
    assert saved["mode"] == "call" and saved["intrinsic"] == native
    assert saved["calldata"] == const(b"", "bytes") and saved["gas"] == const(2300)
    assert saved["value"] == mk("callvalue")
    assert not any(key["$tuple"][1] == "afterCall" for key, _ in mapping(saved["state"]["$state"])["store"]["$map"])


def test_proxy_proof_loop_retains_static_frame_and_input_data(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
interface I {function val() external view returns(uint);}
contract T {function val() external pure returns(uint){return 2;}}
contract P {address impl;constructor(address a){impl=a;}fallback() external {
uint n;for(uint i=0;i<3;i++){n+=i;}require(n==3);address target=impl;
assembly {calldatacopy(0,0,calldatasize()) let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
returndatacopy(0,0,returndatasize()) if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())}}}
contract C {I p;uint public result;constructor(address a){p=I(a);}function act() external {result=p.val();}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    t = d.deploy("T")
    proxy = d.deploy("P", ("address",), (t,))
    d.deploy("C", ("address",), (proxy,))
    known = d.contracts("C", "T", "P")
    own = dict(known)
    known[proxy] = d.slither["T"]
    args: dict[str, Any] = dict(code_of=lambda at: t if at == proxy else at, own_code=own.get)
    f = generate_function(
        d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), known, steps=10000, loop_iterations=1, **args
    )
    assert isinstance(f, PendingCompilation) and f.reason == "loop_iterations"
    frame = mapping(dict(operation(f))["frame"])
    assert frame["static"] is True and frame["storage"] == const(proxy, "address")
    assert frame["sender"] == const(d.at["C"], "address") and frame["calldata"][0] == "enc"
    resumed = generate_function(
        d.slither["C"],
        O.function(d, "C", "act"),
        d.at["C"],
        d.chain(),
        known,
        steps=10000,
        loop_iterations=4,
        checkpoint=f.checkpoint,
        **args,
    )
    assert isinstance(resumed, Formula) and O.chain_says(d, O.function(d, "C", "act"), [], sender=O.OWNER)


def test_state_false_short_circuit_does_not_retain_an_unreachable_call(anvil, tmp_path):
    from services.logic.solver import Translation

    source = """pragma solidity ^0.8.10;
interface I {function allowed(address) external view returns(bool);}
contract C {address public owner;I public authority;uint public value;
constructor(){owner=msg.sender;}function act() external {
require(msg.sender==owner || (address(authority)!=address(0) && authority.allowed(msg.sender)));value=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), steps=10000)
    assert isinstance(f, Formula), f
    for caller in (O.OWNER, O.ACCOUNTS[1]):
        tr = Translation(
            d.chain(), d.contracts("C"), d.at["C"], f.selector, bindings={CALLER: caller, mk("callvalue"): 0}
        )
        assert tr.truth(f.success) is O.chain_says(d, fn, [], sender=caller)


@pytest.mark.parametrize("mode", ["and", "or", "memory"])
def test_short_circuit_keeps_the_already_evaluated_left_value(anvil, tmp_path, mode):
    bodies = {
        "and": ("bool enabled=true;", "enabled=false;return true;", "require(enabled && flip());require(!enabled);"),
        "or": ("bool enabled;", "enabled=true;return false;", "require(!(enabled || flip()));require(enabled);"),
        "memory": ("", "", "bool[] memory a=new bool[](1);a[0]=true;require(a[0] && flipMemory(a));require(!a[0]);"),
    }
    state, flip, body = bodies[mode]
    source = (
        "pragma solidity ^0.8.10;contract C {uint result;"
        + state
        + "function flip() internal returns(bool){"
        + (flip or "return true;")
        + "}"
        + "function flipMemory(bool[] memory a) internal returns(bool){a[0]=false;return true;}"
        + "function act() external {"
        + body
        + "result=1;}}"
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), steps=10000)
    assert isinstance(f, Formula)
    from services.logic.solver import Translation

    tr = Translation(d.chain(), d.contracts("C"), d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
    assert tr.truth(f.success) is O.chain_says(d, fn, [], sender=O.OWNER) is True


@pytest.mark.parametrize(
    "name,args",
    [("localOr", (True,)), ("localOr", (False,)), ("stateOr", ()), ("localAnd", (True,)), ("localAnd", (False,))],
)
def test_assignment_rhs_runs_only_when_selected(anvil, tmp_path, name, args):
    from services.logic.lower import parameter
    from services.logic.solver import Translation

    source = """pragma solidity ^0.8.10;contract C {bool flag=true;uint result;
function localOr(bool a) external {require(a || (a=false));require(a);result=1;}
function stateOr() external {require(flag || (flag=false));require(flag);result=1;}
function localAnd(bool a) external {require(!(a && (a=false)));require(!a);result=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", name)
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), steps=10000)
    assert isinstance(f, Formula)
    bindings = {
        CALLER: O.OWNER,
        mk("callvalue"): 0,
        **{parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))},
    }
    tr = Translation(d.chain(), d.contracts("C"), d.at["C"], f.selector, bindings=bindings)
    assert tr.truth(f.success) is O.chain_says(d, fn, args, sender=O.OWNER)


@pytest.mark.parametrize("op,skip", [("||", True), ("&&", False)])
def test_ambiguous_rhs_does_not_erase_the_valid_skipped_path(anvil, tmp_path, monkeypatch, op, skip):
    import services.logic.lower as lower
    from services.logic.solver import Translation

    original = lower._short_circuits

    def ambiguous(irs):
        if len(irs) == 1 and type(irs[0]).__name__ == "InternalCall":
            return {-1: (0, irs[0])}
        return original(irs)

    monkeypatch.setattr(lower, "_short_circuits", ambiguous)
    source = """pragma solidity ^0.8.10;contract C {uint result;
function mark() internal returns(bool){return true;}
function act(bool a) external {bool r=a OP mark();require(r==WANT);result=1;}}
""".replace("OP", op).replace("WANT", "true" if skip else "false")
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), steps=10000)
    assert isinstance(f, Formula)
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        f.selector,
        bindings={CALLER: O.OWNER, mk("callvalue"): 0, lower.parameter(fn.parameters[0], 0): skip},
    )
    assert O.chain_says(d, fn, [skip], sender=O.OWNER)
    assert tr.truth(f.success) is True
