"""Dispatch domains are checked against mined storage effects, including short calldata."""

import pytest
from eth_utils import keccak

from services.logic.continuation import generate_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity 0.8.27;
contract C {
    uint saved;
    function named(uint x) external {saved=x+100;}
    receive() external payable {saved=200;}
    fallback() external payable {saved=300;}
}
contract I {
    uint saved;
    function named(uint x) external {saved=x+100;}
    receive() external payable {saved=200;}
    fallback() external payable {saved=300;}
}
contract P {
    uint saved;address target;
    constructor(address t){target=t;}
    fallback() external payable {assembly {
        calldatacopy(0,0,calldatasize())
        let ok:=delegatecall(gas(),sload(1),0,calldatasize(),0,0)
        if iszero(ok){revert(0,0)}
    }}
}
"""

SELECTOR = keccak(text="named(uint256)")[:4]
INPUTS = [
    b"",
    b"\x01",
    SELECTOR[:3],
    b"\xff" * 4,
    SELECTOR,
    SELECTOR + (7).to_bytes(32, "big"),
    SELECTOR + bytes(32) + b"extra",
]


@pytest.mark.parametrize("name", ["C", "P"])
@pytest.mark.parametrize("payload", INPUTS)
def test_fallback_domain_and_delegated_dispatch(anvil, tmp_path, name, payload):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    target = d.deploy("I")
    at = d.deploy(name, ("address",) if name == "P" else (), (target,) if name == "P" else ())
    known = d.contracts(name, "I")
    fn = O.function(d, name, "fallback")
    f = generate_function(d.slither[name], fn, at, d.chain(), known, own_code=known.get, steps=30000)
    assert isinstance(f, Formula), f
    binds = {CALLER: O.OWNER, ORIGIN: O.OWNER, mk("callvalue"): 0, f.parameters[0]: payload}
    for t in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        binds.update({u: True for u in subterms(t, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, at, f.selector, bindings=binds)
    predicted = tr.truth(f.success)
    writes = [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True]
    actual = O.transact_data(d, at, payload)
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    enters = name == "P" or (bool(payload) and not payload.startswith(SELECTOR))
    assert predicted is (actual and enters), (f.success, tr.issues)
    if enters:
        assert stored == (writes[-1] if writes else 0), (stored, writes, f.effects)
    else:
        assert not writes
    assert not tr.issues, tr.issues


@pytest.mark.parametrize("payload", INPUTS)
def test_missing_fallback_is_not_success(anvil, tmp_path, payload):
    source = SOURCE.replace("fallback() external payable {saved=300;}", "")
    d = O.deployment(anvil[0], tmp_path, source)
    at = d.deploy("P", ("address",), (d.deploy("I"),))
    known = d.contracts("P", "I")
    f = generate_function(
        d.slither["P"], O.function(d, "P", "fallback"), at, d.chain(), known, own_code=known.get, steps=30000
    )
    assert isinstance(f, Formula), f
    binds = {CALLER: O.OWNER, mk("callvalue"): 0, f.parameters[0]: payload}
    binds.update({u: True for u in subterms(f.success, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, at, f.selector, bindings=binds)
    assert tr.truth(f.success) is O.transact_data(d, at, payload), tr.issues
