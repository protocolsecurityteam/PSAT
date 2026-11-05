"""Proxy shapes that look like a forward and aren't one: never a complete answer the chain disagrees with."""

import pytest
from eth_utils import keccak

from services.logic.expansion import expand_formula
from services.logic.formula import compile_function
from services.logic.model import Limits
from tests.logic import _anvil as A
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity ^0.8.10;
contract Impl {
    address public owner; uint public value; bool public open;
    function init(address o) external { require(owner == address(0)); owner = o; }
    function act() external { require(msg.sender == owner); value = 1; }
    function once() external { require(msg.sender == owner); require(value == 0); value = 1; }
    function burn(uint256) external { require(msg.sender == owner); value = 2; }
    function ping() external {}
    function dec() external { abi.decode(msg.data, (bool)); require(msg.sender == owner); value = 3; }
}
abstract contract Base {
    bytes32 internal constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    function _impl() internal view virtual returns (address i) { assembly { i := sload(IMPL) } }
    function _delegate(address i) internal virtual {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    function _fallback() internal virtual { _delegate(_impl()); }
    fallback() external payable { _fallback(); }
}
contract PClash is Base {
    constructor(address i) { assembly { sstore(IMPL, i) } }
    function collate_propagate_storage(bytes16) external {}
}
contract PLayout is Base {
    uint256[50] private __gap; bool internal open;
    constructor(address i) { assembly { sstore(IMPL, i) } open = true; }
    function _fallback() internal override { require(open); super._fallback(); }
}
contract PTwice is Base {
    constructor(address i, address o) { assembly { sstore(IMPL, i) sstore(0, o) } }
    function _delegate(address i) internal override {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            let s := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            if iszero(and(r, s)) { revert(0, 0) }
            return(0, 0)
        }
    }
}
contract Oracle {
    fallback() external {
        bytes4 s = bytes4(keccak256("ping()"));
        assembly { mstore(0x200, s) return(0, 0x220) }
    }
}
contract PCopy is Base {
    constructor(address i, address o) { assembly { sstore(IMPL, i) sstore(0x99, o) } }
    function _delegate(address i) internal override {
        bytes memory q = abi.encodeWithSignature("q()");
        assembly {
            calldatacopy(0x200, 0, calldatasize())
            let o := sload(0x99)
            pop(staticcall(gas(), o, add(q, 0x20), mload(q), 0, 0))
            returndatacopy(0, 0, returndatasize())
            let r := delegatecall(gas(), i, 0x200, calldatasize(), 0, 0)
            if iszero(r) { revert(0, 0) }
            return(0, 0)
        }
    }
}
interface IQ { function q() external view returns (uint256); }
contract PCopy2 is Base {
    constructor(address i, address o) { assembly { sstore(IMPL, i) sstore(0x99, o) } }
    function _delegate(address i) internal override {
        address o; assembly { o := sload(0x99) }
        (bool ok,) = o.staticcall(abi.encodeWithSignature("q()"));
        assembly {
            calldatacopy(0x200, 0, calldatasize())
            returndatacopy(0, 0, returndatasize())
            let r := delegatecall(gas(), i, 0x200, calldatasize(), 0, 0)
            if iszero(r) { revert(0, 0) }
            return(0, 0)
        }
    }
}
contract PCopy3 is Base {
    constructor(address i, address o) { assembly { sstore(IMPL, i) sstore(0x99, o) } }
    function _delegate(address i) internal override {
        address o; assembly { o := sload(0x99) }
        IQ(o).q();
        assembly {
            calldatacopy(0x200, 0, calldatasize())
            returndatacopy(0, 0, returndatasize())
            let r := delegatecall(gas(), i, 0x200, calldatasize(), 0, 0)
            if iszero(r) { revert(0, 0) }
            return(0, 0)
        }
    }
}
"""


@pytest.fixture(params=["0.8.10", "0.8.27"])
def d(request, anvil, monkeypatch, tmp_path):
    monkeypatch.setattr(A, "SOLC", request.param)
    return A.Deployment(anvil[0], tmp_path, SOURCE)


def _selector(signature):
    return "0x" + keccak(text=signature)[:4].hex()


def _check(d, name, fname, extra=()):
    impl = d.deploy("Impl")
    proxy = d.deploy(name, ("address", *(t for t, _ in extra)), (impl, *(v for _, v in extra)))
    d.at["proxy"] = proxy
    if name != "PTwice":
        d.send("proxy", _selector("init(address)") + f"{O.OWNER:064x}", sender=O.hex20(O.ACCOUNTS[2]))
    contracts = {a: c for a, c in d.contracts(*(n for n in d.at if n not in ("proxy", name))).items() if a != proxy}
    contracts[proxy] = d.slither["Impl"]  # what ``Builds`` gives for a proxy: its implementation's code
    fn = next(f for f in d.slither["Impl"].functions_entry_points if f.name == fname)
    formula = compile_function(
        d.slither["Impl"],
        fn,
        proxy,
        d.chain(),
        contracts,
        code_of=lambda a: impl if a == proxy else a,
        own_code={proxy: d.slither[name]}.get,
    )
    callers = expand_formula(formula, d.chain(), contracts, limits=Limits(solver_ms=3000)).callers
    data = _selector(fn.solidity_signature) + "00" * 32 * len(fn.parameters)
    admitted = set()
    for sender in O.ACCOUNTS:
        try:
            rpc(d.url, "eth_call", [{"to": O.hex20(proxy), "from": O.hex20(sender), "data": data}, "latest"])
            admitted.add(sender)
        except RuntimeError:
            pass
    if callers.complete:
        for sender in O.ACCOUNTS:
            assert (
                sender in callers.members if callers.representation == "finite" else sender not in callers.excluded
            ) is (sender in admitted)
    else:
        case = O.callers_with_resources(formula, d.chain(), contracts)
        if case.complete:
            for sender in O.ACCOUNTS:
                assert (sender in case.members if case.representation == "finite" else sender not in case.excluded) is (
                    sender in admitted
                )
    return callers, admitted


def test_proxy_storage_reads_through_the_proxy_s_own_layout(d):
    callers, admitted = _check(d, "PLayout", "act")
    O.assumes_gas(callers, {O.OWNER})
    assert admitted == {O.OWNER}


def test_a_selector_clash_under_another_signature_is_the_proxy_s(d):
    callers, admitted = _check(d, "PClash", "burn")
    assert admitted == set(O.ACCOUNTS)
    if callers.complete:
        assert callers.representation == "cofinite"
    else:
        # Raw decoder constraints may exceed the projection watchdog; that is
        # an incomplete result, not a reason to claim the implementation ran.
        assert callers.issues and {i.kind for i in callers.issues} <= {"solver", "budget"}


def test_a_second_forward_is_not_the_call_made(d):
    callers, _ = _check(d, "PTwice", "once", extra=(("address", O.OWNER),))
    assert not callers.complete  # ``and(r, s)`` mixes the outcomes as words: no ample-gas assumption


@pytest.mark.parametrize("name", ["PCopy", "PCopy2"])
def test_return_data_copied_over_the_calldata_is_not_a_forward(d, name):
    callers, admitted = _check(d, name, "act", extra=(("address", d.deploy("Oracle")),))
    assert not callers.complete and admitted == set(O.ACCOUNTS)


def test_decoding_msg_data_is_not_caller_chosen(d):
    callers, admitted = _check(d, "PClash", "dec")
    assert not callers.complete and not admitted
