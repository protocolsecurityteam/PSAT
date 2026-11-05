import pytest
from eth_utils import keccak

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.source_context import ContextContracts
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

BASE = """pragma solidity 0.8.27;
contract I {address owner; uint saved; address target;
function act(uint x) external payable {require(msg.sender==owner);saved=x; require(x!=13);}
receive() external payable {saved=101;}
fallback() external payable {saved=102;}
}
contract P {address owner;uint saved;address target;
constructor(address t,address o){target=t;owner=o;}
BODY
}
"""
FORWARD = """fallback() external payable {assembly {
calldatacopy(0,0,calldatasize())
let ok:=delegatecall(gas(),sload(2),0,calldatasize(),0,0)
if iszero(ok){sstore(1,99)}
}}"""


def make(d, fnname="act", selected="I"):
    i = d.deploy("I")
    p = d.deploy("P", ("address", "address"), (i, O.OWNER))
    known = ContextContracts({i: d.slither["I"], p: d.slither[selected]}, p, d.slither[selected])
    fn = next(f for f in d.slither[selected].functions_entry_points if f.name == fnname)
    f = generate_function(
        d.slither[selected],
        fn,
        p,
        d.chain(),
        known,
        code_of=lambda a: i if a == p else a,
        own_code={i: d.slither["I"], p: d.slither["P"]}.get,
        steps=30000,
    )
    return p, known, f


def evaluate(d, p, known, f, tail, sender=O.OWNER, value=0, origin=None):
    assert isinstance(f, Formula), f
    bind = {CALLER: sender, ORIGIN: origin or sender, mk("callvalue"): value}
    if f.parameters:
        bind[f.parameters[0]] = tail
    for term in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        bind.update({t: True for t in subterms(term, "unknown") if t[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, p, f.selector, bindings=bind)
    return tr


@pytest.mark.parametrize("x", [0, 1, 13, 2**256 - 1])
@pytest.mark.parametrize("sender", O.ACCOUNTS[:2])
def test_rollback_and_caught_failure(anvil, tmp_path, x, sender):
    d = O.deployment(anvil[0], tmp_path, BASE.replace("BODY", FORWARD))
    p, k, f = make(d)
    tail = x.to_bytes(32, "big")
    tr = evaluate(d, p, k, f, tail, sender)
    predicted = tr.truth(f.success)
    vals = [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True]
    actual = O.transact_data(d, p, f.selector.to_bytes(4, "big") + tail, sender=sender)
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(p), "0x1", "latest"]), 16)
    assert predicted is actual is True
    assert stored == (vals[-1] if vals else 0), (stored, vals, tr.issues, f.effects)
    assert not tr.issues


@pytest.mark.parametrize("payload", [b"", b"\x01", b"\x01\x02\x03", b"\x01\x02\x03\x04"])
def test_fallback_query_domain(anvil, tmp_path, payload):
    body = """receive() external payable {saved=111;}
    fallback() external payable {require(msg.data.length<4);saved=222;}"""
    d = O.deployment(anvil[0], tmp_path, BASE.replace("BODY", body))
    p, k, f = make(d, "fallback")
    assert isinstance(f, Formula), f
    tr = evaluate(d, p, k, f, payload)
    engine = tr.truth(f.success)
    actual = O.transact_data(d, p, payload)
    assert engine is (actual and bool(payload)), (payload, engine, actual, f.signature, f.parameters, tr.issues)
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(p), "0x1", "latest"]), 16)
    assert stored == (111 if not payload else 222 if len(payload) < 4 else 0)


def test_receive_query_domain(anvil, tmp_path):
    body = """receive() external payable {saved=111;}
    fallback() external payable {revert();}"""
    d = O.deployment(anvil[0], tmp_path, BASE.replace("BODY", body))
    p, k, f = make(d, "receive")
    tr = evaluate(d, p, k, f, b"", value=1)
    engine = tr.truth(f.success)
    actual = O.transact_data(d, p, b"", value=1)
    assert engine is actual, (engine, actual, f.signature, f.parameters, tr.issues)


@pytest.mark.parametrize("value", [0, 1, 13])
def test_root_value_is_preserved_across_delegate(anvil, tmp_path, value):
    body = """fallback() external payable {assembly {calldatacopy(0,0,calldatasize())
    let ok:=delegatecall(gas(),sload(2),0,calldatasize(),0,0)
    if iszero(ok){revert(0,0)}}}"""
    src = BASE.replace("BODY", body).replace(
        "require(msg.sender==owner);saved=x; require(x!=13);", "require(msg.value==13 && msg.sender==owner);saved=x;"
    )
    d = O.deployment(anvil[0], tmp_path, src)
    p, k, f = make(d)
    tail = (7).to_bytes(32, "big")
    tr = evaluate(d, p, k, f, tail, value=value)
    engine = tr.truth(f.success)
    actual = O.transact_data(d, p, f.selector.to_bytes(4, "big") + tail, value=value)
    assert engine is actual, (engine, actual, tr.issues)
    assert not tr.issues


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.27"])
@pytest.mark.parametrize("tail", [b"", b"\xff", bytes(31) + b"\x09", b"\x01" + bytes(30) + b"\x09"])
def test_versioned_runtime_input_decoder(anvil, tmp_path, monkeypatch, version, tail):
    from tests.logic import _anvil as A

    monkeypatch.setattr(A, "SOLC", version)
    source = """pragma solidity VERSION;
    contract I {function act(uint8) external {}}
    contract P {uint saved;function act(uint8 x) external {require(x==9);saved=x;}}
    """.replace("VERSION", version)
    d = O.deployment(anvil[0], tmp_path, source, version=version)
    i = d.deploy("I")
    p = d.deploy("P")
    known = ContextContracts({i: d.slither["I"], p: d.slither["I"]}, p, d.slither["I"])
    fn = O.function(d, "I", "act")
    f = generate_function(
        d.slither["I"],
        fn,
        p,
        d.chain(),
        known,
        code_of=lambda a: i if a == p else a,
        own_code={i: d.slither["I"], p: d.slither["P"]}.get,
    )
    tr = evaluate(d, p, known, f, tail)
    engine = tr.truth(f.success)
    actual = O.transact_data(d, p, f.selector.to_bytes(4, "big") + tail)
    assert engine is actual, (version, tail, engine, actual, tr.issues)
    assert not tr.issues


@pytest.mark.parametrize("returned", ["return(0,0)", "mstore(0,999) return(31,1)", "mstore(0,7) return(0,32)"])
def test_no_outer_return_decoder(anvil, tmp_path, returned):
    body = "fallback() external payable {assembly {sstore(1,77) " + returned + "}}"
    d = O.deployment(anvil[0], tmp_path, BASE.replace("BODY", body))
    p, k, f = make(d)
    tr = evaluate(d, p, k, f, b"")
    assert tr.truth(f.success) is True
    assert O.transact_data(d, p, f.selector.to_bytes(4, "big"))
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(p), "0x1", "latest"]), 16) == 77
    assert not tr.issues


@pytest.mark.parametrize("value", [0, 1, 99, 100])
def test_native_proxy_entry_is_routed_by_production_generation(monkeypatch, anvil, tmp_path, value):
    from contextlib import contextmanager

    from services.logic import deployment
    from services.logic.model import decode_formula

    source = """pragma solidity 0.8.27;
    contract I {function act() external {}}
    contract P {uint saved;address target;
    constructor(address t){target=t;}
    function act() external {assembly {if eq(calldataload(4),99){sstore(0,77)}}}
    fallback() external payable {assembly {
    calldatacopy(0,0,calldatasize())
    let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)
    if iszero(ok){revert(0,0)} }} }
    """
    d = O.deployment(anvil[0], tmp_path, source)
    i = d.deploy("I")
    p = d.deploy("P", ("address",), (i,))
    reads = d.chain()

    @contextmanager
    def inputs(*args):
        builds = deployment.Builds(lambda a: None, lambda a: None, tmp_path, reads)
        builds._built.update({O.hex20(at): d.slither[name] for name, at in d.at.items()})
        yield reads, builds

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    artifact = deployment.deployment_formulas(None, O.hex20(p), 1, "unused", block=reads.block, signatures={"act()"})
    f = decode_formula(artifact["functions"]["act()"])
    tr = Translation(
        reads,
        d.contracts("P", "I"),
        p,
        f.selector,
        bindings={CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: value.to_bytes(32, "big")},
    )
    effects = [e for e in f.effects if tr.truth(e.guard) is True]
    assert O.transact_data(d, p, keccak(text="act()")[:4] + value.to_bytes(32, "big"))
    actual = int(rpc(d.url, "eth_getStorageAt", [O.hex20(p), "0x0", "latest"]), 16)
    assert actual == (77 if value == 99 else 0)
    assert bool(effects) is (value == 99), (f.effects, f.parameters, tr.issues)
    assert not tr.issues


def test_runtime_checkpoint_resumes_raw_inputs(anvil, tmp_path):
    import json

    from services.logic.model import encode

    source = """pragma solidity 0.8.27;
    contract I {function act(uint) external {}}
    contract P {uint saved;function act(uint x) external {uint n;while(n<3){x+=n;n++;}saved=x;}}
    """
    d = O.deployment(anvil[0], tmp_path, source)
    i = d.deploy("I")
    p = d.deploy("P")
    known = ContextContracts({i: d.slither["I"], p: d.slither["I"]}, p, d.slither["I"])
    fn = O.function(d, "I", "act")
    reads = d.chain()
    kw = dict(
        code_of=lambda a: i if a == p else a, own_code={i: d.slither["I"], p: d.slither["P"]}.get, loop_iterations=4
    )
    pending = generate_function(d.slither["I"], fn, p, reads, known, steps=2, **kw)
    assert isinstance(pending, PendingCompilation)
    done = generate_function(
        d.slither["I"], fn, p, reads, known, steps=5000, checkpoint=json.loads(json.dumps(pending.checkpoint)), **kw
    )
    fresh = generate_function(d.slither["I"], fn, p, reads, known, steps=5000, **kw)
    assert isinstance(done, Formula), done
    assert encode(done) == encode(fresh)
    tr = evaluate(d, p, known, done, (7).to_bytes(32, "big"))
    assert tr.truth(done.success) is True
    vals = [int(str(tr.translate(e.value))) for e in done.effects if tr.truth(e.guard) is True]
    assert vals == [10]
    assert O.transact_data(d, p, done.selector.to_bytes(4, "big") + (7).to_bytes(32, "big"))
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(p), "0x0", "latest"]), 16) == 10
