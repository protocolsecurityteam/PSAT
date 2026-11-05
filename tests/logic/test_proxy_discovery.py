"""Address-first generation discovers code and preserves both dispatch and implementation entrypoints."""

from contextlib import contextmanager

import pytest

from services.logic import deployment
from services.logic.expansion import Selection
from services.logic.model import decode_formula
from tests.logic import _anvil as A
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
contract Impl {address owner; uint value;
function act() external {require(msg.sender==owner);value=1;}}
contract Proxy {uint private padding0; uint private padding1; address private admin;
uint256 constant POSITION=1234567;
constructor(address implementation,address a){admin=a;assembly{sstore(POSITION,implementation) sstore(0,caller())}}
function upgrade(address implementation) external {require(msg.sender==admin);assembly{sstore(POSITION,implementation)}}
fallback() external payable {assembly{
 let implementation:=sload(POSITION)
 calldatacopy(0,0,calldatasize())
 let success:=delegatecall(gas(),implementation,0,calldatasize(),0,0)
 returndatacopy(0,0,returndatasize())
 if iszero(success){revert(0,returndatasize())} return(0,returndatasize())
}}
}
"""


@pytest.mark.parametrize("stale_hint", [False, True])
def test_new_address_discovers_target_and_keeps_native_admin(monkeypatch, anvil, tmp_path, stale_hint):
    d = A.Deployment(anvil[0], tmp_path, SOURCE)
    impl = d.deploy("Impl")
    proxy = d.deploy("Proxy", ("address", "address"), (impl, O.ACCOUNTS[1]))
    reads = d.chain()
    built = {O.hex20(at): d.slither[name] for name, at in d.at.items()}
    instances = []

    @contextmanager
    def inputs(*args):
        builds = deployment.Builds(
            lambda at: None, lambda at: O.hex20(O.ACCOUNTS[2]) if stale_hint else None, tmp_path, reads
        )
        builds._built.update(built)
        instances.append(builds)
        yield reads, builds

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    output = deployment.deployment_formulas(None, O.hex20(proxy), 1, "unused", block=reads.block)
    assert "act()" in output["functions"] and "upgrade(address)" in output["functions"]
    assert output["code_locations"][O.hex20(proxy)] == O.hex20(impl)
    assert output["entry_code_addresses"]["upgrade(address)"] == O.hex20(proxy)
    assert output["entry_code_addresses"]["act()"] == O.hex20(impl)
    dispatch = [c for c in output["source_bundle"]["deployments"] if c.get("role") == "dispatcher"]
    assert O.hex20(proxy) in {c["code_address"] for c in dispatch}
    from services.logic.terms import subterms

    resources = subterms(decode_formula(output["functions"]["act()"]).success, "unknown")
    assert resources and all(t[1] == "unsupported:raw_call_resources" for t in resources)

    def no_relower(*args, **kwargs):
        raise AssertionError("saved expansion attempted formula generation")

    monkeypatch.setattr("services.logic.lower.Lowerer.success", no_relower)
    from services.resolution.logic_selection import selection_report

    # Offline assessment and caller-supplied plain mappings remain supported.
    offline = selection_report(output)
    assert offline["rows"]
    plain = selection_report(output, contracts={})
    assert plain["rows"] == offline["rows"]
    with inputs() as (assessment_reads, assessment_builds):
        report = selection_report(output, reads=assessment_reads, contracts=assessment_builds)
    native = [r for r in report["rows"] if r["function"] == "upgrade(address)"]
    assert native and all(r["access"]["status"] == "restricted" for r in native)
    expanded = deployment.deployment_expansions(
        None, output, "unused", {"act()": Selection(), "upgrade(address)": Selection()}
    )
    for name, expected in (("act()", O.OWNER), ("upgrade(address)", O.ACCOUNTS[1])):
        members = expanded["functions"][name]["expansion"]["value"]["callers"]
        formula = decode_formula(output["functions"][name])
        if name == "act()":
            O.assumes_gas(members, {expected})
        else:
            assert members["representation"] == "finite" and members["members"] == {"tuple": [expected]}, members
        fn = O.function(d, "Proxy" if name.startswith("upgrade") else "Impl", name.split("(")[0])
        args = (impl,) if fn.parameters else ()
        for sender in (O.OWNER, O.ACCOUNTS[1]):
            assert O.passes(d, proxy, fn, args, sender=sender) is (sender == expected)
        assert formula.address == proxy
    assert instances[-1].discover is False

    legacy = {k: v for k, v in output.items() if k not in ("code_locations", "entry_code_addresses")}
    with pytest.raises(ValueError, match="saved code locations"):
        deployment.deployment_expansions(None, legacy, "unused", {"act()": Selection()})
    with inputs() as (assessment_reads, assessment_builds):
        with pytest.raises(ValueError, match="saved code locations"):
            selection_report(legacy, reads=assessment_reads, contracts=assessment_builds)


MIXED = """pragma solidity ^0.8.10;
contract Impl {address owner; uint value;
function act() external {require(msg.sender==owner);value=1;}
function route(address) external {value=2;}}
contract MixedProxy {
uint constant POSITION=1234567;
constructor(address implementation){assembly{sstore(POSITION,implementation) sstore(0,caller())}}
fallback() external payable {
 if(msg.sig==bytes4(keccak256("route(address)"))) {
  assembly {let target:=calldataload(4) calldatacopy(0,0,calldatasize())
   let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
   returndatacopy(0,0,returndatasize())
   if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())}
 } else {
  assembly {let target:=sload(POSITION) calldatacopy(0,0,calldatasize())
   let ok:=delegatecall(gas(),target,0,calldatasize(),0,0)
   returndatacopy(0,0,returndatasize())
   if iszero(ok){revert(0,returndatasize())} return(0,returndatasize())}
 }
}}
"""


def test_symbolic_alternate_route_does_not_hide_known_inventory_or_prove_dispatch(monkeypatch, anvil, tmp_path):
    d = A.Deployment(anvil[0], tmp_path, MIXED)
    impl = d.deploy("Impl")
    proxy = d.deploy("MixedProxy", ("address",), (impl,))
    reads = d.chain()

    @contextmanager
    def inputs(*args):
        builds = deployment.Builds(lambda at: None, lambda at: None, tmp_path, reads)
        builds._built.update({O.hex20(at): d.slither[name] for name, at in d.at.items()})
        yield reads, builds

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    result = deployment.deployment_formulas(None, O.hex20(proxy), 1, "unused", block=reads.block)
    assert result["code_locations"][O.hex20(proxy)] == O.hex20(impl)
    for signature in ("act()", "route(address)"):
        assert signature in result["pending_functions"], result
        assert result["pending_functions"][signature]["reason"] == "call"
    # An unresolved alternate target is retained, not discarded using inventory hints.
    assert O.passes(d, proxy, O.function(d, "Impl", "act"), (), sender=O.OWNER)
    assert not O.passes(d, proxy, O.function(d, "Impl", "act"), (), sender=O.ACCOUNTS[1])
    assert O.passes(d, proxy, O.function(d, "Impl", "route"), (impl,), sender=O.ACCOUNTS[1])


def test_metadata_pointer_without_fallback_does_not_import_other_entrypoints(monkeypatch, anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract Impl {uint value;function act() external {value=1;}}
contract Registry {address public implementation;address owner;
constructor(address i){implementation=i;owner=msg.sender;}
function set(address i) external {require(msg.sender==owner);implementation=i;}}
"""
    d = A.Deployment(anvil[0], tmp_path, source)
    impl = d.deploy("Impl")
    root = d.deploy("Registry", ("address",), (impl,))
    reads = d.chain()

    def hint(at):
        raise AssertionError("verified non-forwarder queried implementation metadata")

    @contextmanager
    def inputs(*args):
        builds = deployment.Builds(lambda at: None, hint, tmp_path, reads)
        builds._built.update({O.hex20(at): d.slither[name] for name, at in d.at.items()})
        yield reads, builds

    monkeypatch.setattr(deployment, "_deployment_inputs", inputs)
    artifact = deployment.deployment_formulas(None, O.hex20(root), 1, "unused", block=reads.block)
    assert set(artifact["functions"]) == {"set(address)"}
    assert artifact["code_locations"][O.hex20(root)] == O.hex20(root)
    assert O.passes(d, root, O.function(d, "Registry", "set"), (impl,), sender=O.OWNER)
    assert not O.passes(d, root, O.function(d, "Impl", "act"), (), sender=O.OWNER)
