"""Root proxy queries execute deployed runtime over raw selector-prefixed calldata."""

import pytest

from services.logic.continuation import generate_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.source_context import ContextContracts
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity 0.8.27;
contract Impl {
    address owner; uint saved;
    function act(uint8 x) external returns(uint) {require(msg.sender==owner);saved=x;return x;}
}
contract Forward {
    address owner; uint saved; address target;
    constructor(address t,address o){target=t;owner=o;}
    fallback() external payable {assembly {
        calldatacopy(0,0,calldatasize())
        let ok:=delegatecall(gas(),sload(2),0,calldatasize(),0,0)
        returndatacopy(0,0,returndatasize())
        switch ok case 0 {revert(0,returndatasize())} default {return(0,returndatasize())}
    }}
}
contract Clash {
    address owner; uint saved;
    constructor(address,address o){owner=o;}
    function act(uint8) external payable {saved=77;}
}
contract Early {
    address owner; uint saved; address target;
    constructor(address t,address o){target=t;owner=o;}
    fallback() external payable {
        if(msg.sender!=owner)return;
        assembly {sstore(1,88)}
    }
}
contract RawGate {
    address owner; uint saved;
    constructor(address,address o){owner=o;}
    fallback() external payable {
        require(msg.data.length==5 && uint8(msg.data[4])==0xff);
        assembly {sstore(1,99)}
    }
}
"""


def setup(d, name):
    impl = d.deploy("Impl")
    root = d.deploy(name, ("address", "address"), (impl, O.OWNER))
    known = ContextContracts({impl: d.slither["Impl"], root: d.slither["Impl"]}, root, d.slither["Impl"])
    fn = O.function(d, "Impl", "act")
    row = generate_function(
        d.slither["Impl"],
        fn,
        root,
        d.chain(),
        known,
        code_of=lambda at: impl if at == root else at,
        own_code={root: d.slither[name], impl: d.slither["Impl"]}.get,
        steps=30000,
    )
    assert isinstance(row, Formula), row
    return root, known, row


@pytest.mark.parametrize("name", ["Forward", "Clash", "Early", "RawGate"])
@pytest.mark.parametrize(
    "tail", [b"", b"\xff", bytes(31) + b"\x09", b"\x01" + bytes(31), bytes(31) + b"\x09" + b"trailing"]
)
@pytest.mark.parametrize("sender", O.ACCOUNTS[:2])
def test_actual_runtime_success_and_effects(anvil, tmp_path, name, tail, sender):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    root, known, row = setup(d, name)
    bindings = {CALLER: sender, ORIGIN: sender, mk("callvalue"): 0, row.parameters[0]: tail}
    for term in (row.success, *(e.guard for e in row.effects), *(e.value for e in row.effects)):
        bindings.update({t: True for t in subterms(term, "unknown") if t[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, root, row.selector, bindings=bindings)
    predicted = tr.truth(row.success)
    writes = [e for e in row.effects if e.kind == "write" and tr.truth(e.guard) is True]
    assert predicted is not None, tr.issues
    expected = [int(str(tr.translate(e.value))) for e in writes]
    actual = O.transact_data(d, root, row.selector.to_bytes(4, "big") + tail, sender=sender)
    assert predicted is actual, (name, tail, sender, tr.issues)
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(root), hex(1), "latest"]), 16)
    assert stored == (expected[-1] if expected else 0), (row.effects, expected, stored)
    assert not tr.issues, tr.issues


def test_runtime_payability_comes_from_executed_entry(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    root, known, row = setup(d, "Clash")
    tail = bytes(32)
    tr = Translation(
        d.chain(), known, root, row.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 1, row.parameters[0]: tail}
    )
    assert tr.truth(row.success) is True
    assert O.transact_data(d, root, row.selector.to_bytes(4, "big") + tail, value=1)
