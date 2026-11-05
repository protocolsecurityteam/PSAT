"""Lossless budget cutoffs: JSON checkpoints reuse completed symbolic steps."""

import json

import pytest

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.model import Formula, Limits, encode
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
contract T {uint public x;function set(uint v) external {x=v;}
function twice(uint v) external pure returns(uint){return v*2;}}
contract C {T t;uint public value;constructor(address a){t=T(a);}
modifier repeat(){_;_;}
function calls() external {uint[] memory a=new uint[](1);a[0]=4;t.set(a[0]);value=t.twice(t.x());require(a[0]==4);}
function loops() external {uint sum=0;for(uint i=0;i<7;i++){if(i==2)continue;
for(uint j=0;j<4;j++){if(j==2)break;sum+=i;}}value=sum;}
function frames() external repeat {value++;uint[] memory a=new uint[](1);a[0]=value;value=t.twice(a[0]);}
function early(bool stop) external {for(uint i=0;i<6;i++){value=i;if(i==3 && stop)return;}require(!stop);}
function rollback() external {for(uint i=0;i<6;i++){t.set(i);}revert();}
function unsupported() external {try t.set(1) {} catch {value=1;}}
function rec(uint n) internal pure returns(uint){if(n==0)return 1;return rec(n-1)+1;}
function recursive() external {value=rec(5);}
}"""


@pytest.fixture
def d(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C", ("address",), (d.deploy("T"),))
    return d


def run(d, name, **kwargs):
    return generate_function(
        d.slither["C"], O.function(d, "C", name), d.at["C"], d.chain(), d.contracts("C", "T"), **kwargs
    )


@pytest.mark.parametrize("name", ["calls", "loops", "frames", "early", "rollback", "recursive"])
def test_resumed_compilation_matches_uninterrupted_and_chain(d, name):
    full = run(d, name, steps=10000)
    assert isinstance(full, Formula)
    checkpoint = None
    for _ in range(200):
        result = run(d, name, steps=7, checkpoint=checkpoint)
        if isinstance(result, Formula):
            break
        assert isinstance(result, PendingCompilation)
        checkpoint = json.loads(json.dumps(result.checkpoint))
    assert isinstance(result, Formula)
    assert encode(result) == encode(full)
    fn = O.function(d, "C", name)
    args = (False,) if name == "early" else ()
    from services.logic.lower import parameter

    tr = Translation(
        d.chain(),
        d.contracts("C", "T"),
        d.at["C"],
        full.selector,
        bindings={
            CALLER: O.OWNER,
            ORIGIN: O.OWNER,
            mk("callvalue"): 0,
            **{parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))},
        },
    )
    assert tr.truth(result.success) is O.passes(d, "C", fn, args)


def test_zero_budget_is_pending_not_a_formula_and_does_not_lose_work(d):
    result = run(d, "calls", steps=0)
    assert isinstance(result, PendingCompilation)
    after = run(d, "calls", steps=1000, checkpoint=json.loads(json.dumps(result.checkpoint)))
    assert isinstance(after, Formula)


def test_loop_bound_is_resumable_instead_of_widened(d):
    result = run(d, "loops", steps=10000, loop_iterations=2)
    assert isinstance(result, PendingCompilation) and result.reason == "loop_iterations"
    after = run(d, "loops", steps=10000, loop_iterations=32, checkpoint=result.checkpoint)
    assert isinstance(after, Formula) and encode(after) == encode(run(d, "loops", steps=10000))


def test_call_depth_is_resumable(d):
    result = run(d, "calls", steps=1000, limits=Limits(callee_depth=0))
    assert isinstance(result, PendingCompilation) and result.reason == "callee_depth"
    after = run(d, "calls", steps=1000, limits=Limits(callee_depth=8), checkpoint=result.checkpoint)
    assert isinstance(after, Formula)


def test_unsupported_call_is_retained_without_being_labeled_a_budget_cut(d):
    from services.logic.formula import compile_function
    from services.logic.terms import subterms

    result = run(d, "unsupported", steps=1000)
    assert isinstance(result, PendingCompilation) and result.reason == "call"
    assert result.blocker == "unsupported:stateful_try"
    # The one-shot semantic test still requires an explicit gap, never a guessed answer.
    formula = compile_function(
        d.slither["C"], O.function(d, "C", "unsupported"), d.at["C"], d.chain(), d.contracts("C", "T")
    )
    assert any("stateful_try" in t[1] for t in subterms(formula.success, "unknown"))


def test_checkpoint_rejects_block_or_entry_change(d):
    result = run(d, "calls", steps=3)
    assert isinstance(result, PendingCompilation)
    with pytest.raises(ValueError, match="identity"):
        run(d, "loops", steps=100, checkpoint=result.checkpoint)
    reads = d.chain()
    reads.block += 1
    with pytest.raises(ValueError, match="identity"):
        generate_function(
            d.slither["C"],
            O.function(d, "C", "calls"),
            d.at["C"],
            reads,
            d.contracts("C", "T"),
            checkpoint=result.checkpoint,
        )


def test_checkpoint_rejects_tampering(d):
    result = run(d, "calls", steps=3)
    checkpoint = json.loads(json.dumps(result.checkpoint))
    checkpoint["hash"] = "0" * 64
    with pytest.raises(ValueError, match="hash"):
        run(d, "calls", checkpoint=checkpoint)


def test_json_checkpoint_rebinds_rebuilt_ir_and_skips_completed_operations(d, monkeypatch):
    from slither import Slither

    from services.logic.continuation import Journal
    from tests.fuzz.authority import solc_path

    pending = run(d, "calls", steps=12)
    assert isinstance(pending, PendingCompilation)
    saved = json.loads(json.dumps(pending.checkpoint))
    expected = run(d, "calls", steps=10000)
    # Fresh frontend objects have different Python identities. Reuse only compiler-verified references.
    source = next(iter(d.slither["C"].compilation_unit.core.source_code))
    rebuilt = {c.name: c for c in Slither(source, solc=str(solc_path("0.8.27"))).contracts}
    d.slither = rebuilt
    used = []
    original = Journal.restore

    def restore(self, lowerer, state):
        used.append(True)
        return original(self, lowerer, state)

    monkeypatch.setattr(Journal, "restore", restore)
    result = run(d, "calls", steps=10000, checkpoint=saved)
    assert used and encode(result) == encode(expected)


def test_completed_semantic_prefix_is_not_lowered_again(d, monkeypatch):
    from services.logic.lower import Lowerer

    first = run(d, "calls", steps=8)
    assert isinstance(first, PendingCompilation)
    # The first caller constructor-stored target load / memory allocation already ran.
    # Compare semantic-operation work rather than merely accepting identical output.
    executed = []
    original = Lowerer._exec_ir

    def observe(self, ir, state, depth):
        executed.append((self.contract.name, str(ir)))
        return original(self, ir, state, depth)

    monkeypatch.setattr(Lowerer, "_exec_ir", observe)
    run(d, "calls", steps=10000)
    full = len(executed)
    executed.clear()
    run(d, "calls", steps=10000, checkpoint=first.checkpoint)
    assert len(executed) < full


def test_fresh_process_can_resume_without_relowering_completed_prefix(d, tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    pending = run(d, "calls", steps=12)
    assert isinstance(pending, PendingCompilation)
    input_path = tmp_path / "checkpoint.json"
    output_path = tmp_path / "resumed.json"
    source = next(iter(d.slither["C"].compilation_unit.core.source_code))
    input_path.write_text(
        json.dumps(
            {"checkpoint": pending.checkpoint, "source": source, "url": d.url, "at": d.at, "block": d.chain().block}
        )
    )
    script = """import json,sys
from pathlib import Path
from slither import Slither
from slither.slithir.operations import NewArray
from tests.fuzz.authority import solc_path
from tests.support.anvil import rpc
from services.clients.logic_reads import ChainReads
from services.logic.continuation import generate_function
from services.logic.lower import Lowerer
from services.logic.model import Formula,encode
p=json.loads(Path(sys.argv[1]).read_text())
cs={c.name:c for c in Slither(p['source'],solc=str(solc_path('0.8.27'))).contracts}
fn=next(f for f in cs['C'].functions_entry_points if f.name=='calls')
original=Lowerer._exec_ir
def check(self,ir,st,depth):
 if isinstance(ir,NewArray):raise AssertionError('completed allocation was lowered again')
 return original(self,ir,st,depth)
Lowerer._exec_ir=check
reads=ChainReads(lambda m,ps:rpc(p['url'],m,ps),p['block'])
r=generate_function(cs['C'],fn,p['at']['C'],reads,{p['at'][n]:c for n,c in cs.items()},
 steps=10000,checkpoint=p['checkpoint'])
assert isinstance(r,Formula)
Path(sys.argv[2]).write_text(json.dumps(encode(r)))
"""
    script_path = tmp_path / "resume.py"
    script_path.write_text(script)
    env = {**os.environ, "PYTHONPATH": str(Path.cwd())}
    subprocess.run(
        [sys.executable, str(script_path), str(input_path), str(output_path)],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(output_path.read_text()) == encode(run(d, "calls", steps=10000))


def test_generation_pipeline_preserves_pending_functions_and_resumes_them(d, monkeypatch):
    from contextlib import contextmanager

    from services.logic import deployment
    from services.resolution.logic_assessment import assess_formulas
    from services.resolution.logic_impact import JudgmentCache

    class Contracts(dict):
        def own_code(self, address):
            return self.get(address)

        def code_address(self, address):
            return address

    known = Contracts(d.contracts("C", "T"))

    @contextmanager
    def inputs(*args):
        yield d.chain(), known

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    params = dict(signatures={"calls()", "loops()"}, block=d.chain().block)
    first = deployment.deployment_formulas(None, O.hex20(d.at["C"]), 1, "unused", expansion_steps=2, **params)
    assert first["status"] == "incomplete" and set(first["pending_functions"]) == params["signatures"]
    assert not first["functions"]
    assessment = assess_formulas(first, cache=JudgmentCache(d.root / "jev"))
    assert assessment["assessment"]["status"] == "incomplete"
    assert set(assessment["pending_functions"]) == params["signatures"]
    assert not assessment["suggested_expansions"]
    final = deployment.deployment_formulas(
        None, O.hex20(d.at["C"]), 1, "unused", resume=json.loads(json.dumps(first)), expansion_steps=10000, **params
    )
    assert final["status"] == "available" and not final["pending_functions"]
    assert set(final["functions"]) == params["signatures"]
    original = deployment.deployment_formulas(None, O.hex20(d.at["C"]), 1, "unused", expansion_steps=10000, **params)
    assert final["functions"] == original["functions"]


def test_bindings_are_part_of_the_checkpoint_query(d):
    pending = run(d, "calls", steps=4, bindings={CALLER: 7})
    assert isinstance(pending, PendingCompilation)
    with pytest.raises(ValueError, match="identity"):
        run(d, "calls", steps=1000, bindings={CALLER: 8}, checkpoint=pending.checkpoint)
    assert isinstance(run(d, "calls", steps=1000, bindings={CALLER: 7}, checkpoint=pending.checkpoint), Formula)


def test_read_only_linker_loop_has_the_same_checkpoint_boundary(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract T{function sum() external pure returns(uint s){for(uint i=0;i<12;i++){s+=i;}}}
contract C{address t;uint value;constructor(address a){t=a;}function act() external{
(bool ok,bytes memory data)=t.staticcall(abi.encodeWithSignature("sum()"));
require(ok);require(abi.decode(data,(uint))==66);value=1;}}"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    pending = run(d, "act", steps=10000, loop_iterations=2)
    assert isinstance(pending, PendingCompilation) and pending.reason == "loop_iterations"
    resumed = run(d, "act", steps=10000, loop_iterations=32, checkpoint=json.loads(json.dumps(pending.checkpoint)))
    full = run(d, "act", steps=10000, loop_iterations=32)
    assert isinstance(resumed, Formula) and encode(resumed) == encode(full)
    assert O.passes(d, "C", O.function(d, "C", "act"))


def test_proxy_checkpoint_accepts_partial_own_code_lookup(anvil, tmp_path):
    from tests.logic.test_proxy_dispatch import SOURCE as PROXY_SOURCE
    from tests.logic.test_proxy_dispatch import _proxy, _views

    d = O.deployment(anvil[0], tmp_path, PROXY_SOURCE)
    proxy, impl = _proxy(d, "P1967")
    d.proxy_name = "P1967"
    d.deploy("C", ("address",), (proxy,))
    contracts, code_of, own = _views(d, proxy, impl)
    fn = O.function(d, "C", "act")

    def generate(**kwargs):
        return generate_function(
            d.slither["C"], fn, d.at["C"], d.chain(), contracts, code_of=code_of, own_code=own, **kwargs
        )

    pending = generate(steps=5)
    assert isinstance(pending, PendingCompilation)
    after = generate(steps=10000, checkpoint=json.loads(json.dumps(pending.checkpoint)))
    assert isinstance(after, Formula) and after.state_specialized
    assert encode(after) == encode(generate(steps=10000))


def test_reorg_identity_change_rejects_cached_state(d, monkeypatch):
    pending = run(d, "calls", steps=4)
    assert isinstance(pending, PendingCompilation)
    from services.clients.logic_reads import ChainReads

    original = ChainReads.snapshot_identity
    monkeypatch.setattr(
        ChainReads, "snapshot_identity", lambda self: {**original(self), "block_hash": "0x" + "12" * 32}
    )
    with pytest.raises(ValueError, match="identity"):
        run(d, "calls", steps=10000, checkpoint=pending.checkpoint)


def test_indirect_call_target_memo_is_restored_with_completed_steps(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract U {uint public x;function touch() external{x++;}}
contract T {address u;constructor(address a){u=a;}function which() external view returns(address){return u;}}
contract C {address t;uint value;constructor(address a){t=a;}
function act() external {(bool ok,bytes memory data)=t.staticcall(abi.encodeWithSignature("which()"));require(ok);
address a=abi.decode(data,(address));U(a).touch();U(a).touch();for(uint i=0;i<4;i++){value+=i;}}}"""
    d = O.deployment(anvil[0], tmp_path, source)
    u = d.deploy("U")
    t = d.deploy("T", ("address",), (u,))
    d.deploy("C", ("address",), (t,))
    fn = O.function(d, "C", "act")
    known = d.contracts("C", "T", "U")

    def generate(**kw):
        return generate_function(d.slither["C"], fn, d.at["C"], d.chain(), known, **kw)

    full = generate(steps=10000)
    for cutoff in (12, 25, 40):
        pending = generate(steps=cutoff)
        assert isinstance(pending, PendingCompilation)
        result = generate(steps=10000, checkpoint=json.loads(json.dumps(pending.checkpoint)))
        assert isinstance(result, Formula) and encode(result) == encode(full)
    assert O.passes(d, "C", fn)


@pytest.mark.parametrize("kind,cutoff", [("struct", 8), ("array", 11)])
def test_compiler_references_inside_conditional_terms_rebind(anvil, tmp_path, kind, cutoff):
    from slither import Slither

    from tests.fuzz.authority import solc_path

    if kind == "struct":
        declare = "struct R {uint id;}"
        body = "R memory r=R(7);if(take){value=r.id;}"
    else:
        declare = ""
        body = "uint[] memory r=new uint[](1);r[0]=7;if(take){value=r[0];}"
    source = (
        "pragma solidity ^0.8.10; contract C {"
        + declare
        + "uint value;function act(bool take) external {"
        + body
        + "for(uint i=0;i<5;i++){value+=i;}}}"
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")

    def generate(contract, **kw):
        function = next(f for f in contract.functions_entry_points if f.name == "act")
        return generate_function(contract, function, d.at["C"], d.chain(), {d.at["C"]: contract}, **kw)

    full = generate(d.slither["C"], steps=10000)
    pending = generate(d.slither["C"], steps=cutoff)
    assert isinstance(pending, PendingCompilation)
    source_path = next(iter(d.slither["C"].compilation_unit.core.source_code))
    other = next(c for c in Slither(source_path, solc=str(solc_path("0.8.27"))).contracts if c.name == "C")
    restored = generate(other, steps=10000, checkpoint=json.loads(json.dumps(pending.checkpoint)))
    assert isinstance(restored, Formula) and encode(restored) == encode(full)
    for take in (False, True):
        assert O.passes(d, "C", fn, (take,))


def test_ir_fingerprint_preserves_nested_operand_identity_without_python_repr(anvil, tmp_path):
    from slither import Slither

    from services.logic.continuation import References
    from tests.fuzz.authority import solc_path

    source = """pragma solidity ^0.8.10;
interface I {function f(uint a,uint b) external;}
contract C {uint value;
function encode(I t,uint x,uint y) internal pure returns(bytes memory){return abi.encodeCall(t.f,(x,y));}
function act() external {for(uint i=0;i<5;i++){value+=i;}}}"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    c = d.slither["C"]
    at = d.at["C"]
    fn = O.function(d, "C", "act")
    pending = generate_function(c, fn, at, d.chain(), {at: c}, steps=8)
    assert isinstance(pending, PendingCompilation)
    path = next(iter(c.compilation_unit.core.source_code))
    other = next(c for c in Slither(path, solc=str(solc_path("0.8.27"))).contracts if c.name == "C")
    first, second = References(), References()
    key1, key2 = first.register(c, at), second.register(other, at)
    assert first.manifests[key1] == second.manifests[key2]
    result = generate_function(
        other,
        next(f for f in other.functions_entry_points if f.name == "act"),
        at,
        d.chain(),
        {at: other},
        steps=10000,
        checkpoint=json.loads(json.dumps(pending.checkpoint)),
    )
    assert isinstance(result, Formula)
    assert encode(result) == encode(generate_function(c, fn, at, d.chain(), {at: c}, steps=10000))
    # A fingerprint must still distinguish the order and aliasing of nested arguments.
    function = next(f for f in c.functions if f.name == "encode")
    x, y = function.parameters[1:]
    assert first.operand([x, y]) != first.operand([y, x])
    assert first.operand([x, x]) != first.operand([x, y])
