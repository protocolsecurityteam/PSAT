"""Execution-backed boundaries for calls, storage aliases, and unsupported same-frame control flow."""

import json
from pathlib import Path

import pytest

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

CASES = json.loads((Path(__file__).parent / "fixtures/transition_boundaries.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_transition_boundary(case, anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, case["source"])
    d.deploy("C", ("address",), (d.deploy("T"),))
    known = d.contracts("C", "T")
    for name, expected in case["functions"].items():
        fn = O.function(d, "C", name)
        formula, answer = O.engine_says(d, fn, (), contracts=known)
        assert O.passes(d, "C", fn) is expected
        assert answer is None or answer is expected, formula
        if case["name"] == "raw_word":
            assert answer is expected
        f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), known)
        result = expand_formula(f, d.chain(), known).callers
        if expected:
            assert not (result.complete and result.representation == "finite" and not result.members)


@pytest.mark.parametrize(
    "body",
    [
        "uint[] memory a=new uint[](1);a[0]=1;function(uint[] memory) internal f=write;f(a);require(a[0]==3);",
        "function() internal f=stop;f();require(false);",
    ],
)
def test_unknown_internal_call_does_not_trust_its_continuation(anvil, tmp_path, body):
    source = """pragma solidity ^0.8.10;
contract C {uint value;
function write(uint[] memory a) internal {a[0]=3;}
function stop() internal {assembly{return(0,0)}}
function act() external {value=1;BODY}}
""".replace("BODY", body)
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    assert O.passes(d, "C", fn)
    _, answer = O.engine_says(d, fn, (), contracts=d.contracts("C"))
    assert answer is None or answer is True


@pytest.mark.parametrize("change_first", [False, True])
def test_dispatch_never_enumerates_a_symbolic_guard(anvil, tmp_path, monkeypatch, change_first):
    from services.logic.solver import Translation
    from services.logic.terms import CALLER, ORIGIN, mk

    source = """pragma solidity ^0.8.10;
contract Impl {function allowed() external pure returns(bool){return true;}}
contract Beacon {address public current;mapping(address=>bool) allowed;
constructor(address a){current=a;allowed[msg.sender]=true;}
function change() external {allowed[tx.origin]=true;}
function enabled(address a) external view returns(bool){return allowed[a];}}
contract Proxy {Beacon beacon;constructor(address b){beacon=Beacon(b);}
fallback() external {require(beacon.enabled(tx.origin));address target=beacon.current();assembly{
calldatacopy(0,0,calldatasize()) let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
returndatacopy(0,0,returndatasize())
if iszero(ok){revert(0,returndatasize())}return(0,returndatasize())}}}
interface I {function allowed() external view returns(bool);}
contract C {Beacon beacon;I proxy;uint value;constructor(address b,address p){beacon=Beacon(b);proxy=I(p);}
function act() external {CHANGE require(proxy.allowed());value=1;}}
""".replace("CHANGE", "beacon.change();" if change_first else "")
    d = O.deployment(anvil[0], tmp_path, source)
    impl = d.deploy("Impl")
    beacon = d.deploy("Beacon", ("address",), (impl,))
    proxy = d.deploy("Proxy", ("address",), (beacon,))
    d.deploy("C", ("address", "address"), (beacon, proxy))
    known = d.contracts("C", "Impl", "Beacon")
    known[proxy] = d.slither["Impl"]
    reads = d.chain()

    def forbidden(*args, **kwargs):
        raise AssertionError("generation enumerated a symbolic guard")

    monkeypatch.setattr(reads, "storage_dump", forbidden)
    fn = O.function(d, "C", "act")
    f = compile_function(
        d.slither["C"],
        fn,
        d.at["C"],
        reads,
        known,
        code_of=lambda a: impl if a == proxy else a,
        own_code={proxy: d.slither["Proxy"]}.get,
    )
    for sender in (O.OWNER, O.ACCOUNTS[1]):
        actual = O.passes(d, "C", fn, sender=sender)
        tr = Translation(
            d.chain(), known, d.at["C"], f.selector, bindings={CALLER: sender, ORIGIN: sender, mk("callvalue"): 0}
        )
        answer = tr.truth(f.success)
        assert answer is None or answer is actual
        assert actual is (change_first or sender == O.OWNER)


def test_transient_dispatch_changes_remain_qualified(anvil, tmp_path):
    source = """pragma solidity ^0.8.27;
contract Old {function arm() external {assembly{tstore(0,1)}} function allowed() external pure returns(bool){return false;}}
contract New {function allowed() external pure returns(bool){return true;}}
contract Proxy {address first;address second;constructor(address a,address b){first=a;second=b;}
fallback() external {address target=first;address other=second;assembly{
if tload(0){target:=other} calldatacopy(0,0,calldatasize())
let ok:=delegatecall(gas(),target,0,calldatasize(),0,0) returndatacopy(0,0,returndatasize())
if iszero(ok){revert(0,returndatasize())}return(0,returndatasize())}}}
interface I {function arm() external;function allowed() external view returns(bool);}
contract C {I proxy;uint value;constructor(address p){proxy=I(p);}
function act() external {proxy.arm();require(proxy.allowed());value=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    old = d.deploy("Old")
    new = d.deploy("New")
    proxy = d.deploy("Proxy", ("address", "address"), (old, new))
    d.deploy("C", ("address",), (proxy,))
    known = d.contracts("C", "Old", "New")
    known[proxy] = d.slither["Old"]
    fn = O.function(d, "C", "act")
    f = compile_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        code_of=lambda a: old if a == proxy else a,
        own_code={proxy: d.slither["Proxy"]}.get,
    )
    assert O.passes(d, "C", fn)
    result = expand_formula(f, d.chain(), known).callers
    assert not result.complete and result.issues
