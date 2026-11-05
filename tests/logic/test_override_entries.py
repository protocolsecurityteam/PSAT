"""Dispatch reaches the deployed entry: overriding fallbacks/receives and getters that override functions."""

import pytest

from services.logic.continuation import generate_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity 0.8.27;
contract Base {
 address owner; uint x;
 constructor() { owner = msg.sender; }
 fallback() external payable virtual { require(msg.sender == owner); x = 1; }
 receive() external payable virtual { require(msg.sender == owner); x = 5; }
}
contract D is Base {
 fallback() external payable override { x = 2; }
 receive() external payable override { x = 6; }
}
contract A { function owner() external view virtual returns (address) { return address(0); } }
contract B is A { address public override owner; constructor(address o) { owner = o; } }
contract G {
 B r; uint y;
 constructor(address a) { r = B(a); }
 function act() external { require(msg.sender == r.owner()); y = 1; }
}
"""


@pytest.fixture
def d(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("D")
    d.deploy("G", ("address",), (d.deploy("B", ("address",), (O.OWNER,)),))
    return d


@pytest.mark.parametrize("name,payload,stored", [("fallback", bytes(5), 2), ("receive", b"", 6)])
def test_overridden_fallback_and_receive_run_the_derived_body(d, name, payload, stored):
    at, known = d.at["D"], d.contracts("D")
    listed = O.function(d, "D", name)  # for fallback, Slither lists the overridden Base.fallback first
    f = generate_function(d.slither["D"], listed, at, d.chain(), known, own_code=known.get, steps=30000)
    assert isinstance(f, Formula), f
    stranger = O.ACCOUNTS[2]
    bindings = {CALLER: stranger, mk("callvalue"): 0, **({f.parameters[0]: payload} if f.parameters else {})}
    for t in (f.success, *(e.guard for e in f.effects), *(e.value for e in f.effects)):
        bindings.update({u: True for u in subterms(t, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, at, f.selector, bindings=bindings)
    assert O.eth_call(d.url, at, payload, stranger)
    assert tr.truth(f.success) is True, tr.issues
    assert [int(str(tr.translate(e.value))) for e in f.effects if tr.truth(e.guard) is True] == [stored]
    assert O.transact_data(d, at, payload, sender=stranger)
    assert int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x1", "latest"]), 16) == stored


def test_public_variable_overriding_a_function_is_read_as_the_getter(d):
    fn = O.function(d, "G", "act")
    reads, known = d.chain(), d.contracts("G", "B")
    f = generate_function(d.slither["G"], fn, d.at["G"], reads, known, steps=10000)
    assert isinstance(f, Formula), f
    for caller in (O.OWNER, O.ACCOUNTS[1]):
        tr = Translation(reads, known, d.at["G"], f.selector, bindings={CALLER: caller, mk("callvalue"): 0})
        assert tr.truth(f.success) is O.chain_says(d, fn, (), contract="G", sender=caller), tr.issues
