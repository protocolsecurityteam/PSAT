"""Proxy dispatch is read from the proxy's own fallback at the block, never taken from implementation metadata."""

from dataclasses import replace

import pytest
from eth_utils import keccak

from services.logic.expansion import Selection, expand_formula
from services.logic.formula import compile_function
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, TRUE, mk, replace_terms, subterms
from tests.logic import _anvil as A
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity ^0.8.10;
contract Impl {
    address public owner; uint public value;
    function init(address o) external { require(owner == address(0)); owner = o; }
    function act() external { require(msg.sender == owner); value = 1; }
    function allowed(address who) external view returns (bool) { return who == owner; }
}
abstract contract Base {
    bytes32 internal constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant ADMIN = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 internal constant BEACON = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
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
contract P1967 is Base { constructor(address i) { assembly { sstore(IMPL, i) } } }
contract PTransparent4 is Base {
    constructor(address i, address a) { assembly { sstore(IMPL, i) sstore(ADMIN, a) } }
    function _admin() internal view returns (address a) { assembly { a := sload(ADMIN) } }
    function _fallback() internal override { require(msg.sender != _admin(), "admin"); super._fallback(); }
}
contract PTransparent5 is Base {
    constructor(address i, address a) { assembly { sstore(IMPL, i) sstore(ADMIN, a) } }
    function _admin() internal view returns (address a) { assembly { a := sload(ADMIN) } }
    function _fallback() internal override {
        if (msg.sender == _admin()) {
            if (msg.sig != bytes4(keccak256("upgradeToAndCall(address,bytes)"))) revert("admin");
            (address n,) = abi.decode(msg.data[4:], (address, bytes));
            assembly { sstore(IMPL, n) }
        } else { super._fallback(); }
    }
}
interface IBeacon { function implementation() external view returns (address); }
contract Beacon is IBeacon { address public override implementation; constructor(address i) { implementation = i; } }
contract PBeacon is Base {
    constructor(address b) { assembly { sstore(BEACON, b) } }
    function _impl() internal view override returns (address i) {
        address b; assembly { b := sload(BEACON) }
        return IBeacon(b).implementation();
    }
}
contract PClash is Base {
    constructor(address i) { assembly { sstore(IMPL, i) } }
    function act() external {}
}
contract PRewrite is Base {
    constructor(address i) { assembly { sstore(IMPL, i) } }
    function _delegate(address i) internal override {
        assembly {
            calldatacopy(0, 0, calldatasize())
            mstore(4, caller())
            let r := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch r case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}
contract PTrue is Base {
    constructor(address i) { assembly { sstore(IMPL, i) } }
    function _delegate(address i) internal override {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let r := delegatecall(gas(), i, 0, calldatasize(), 0, 0)
            mstore(0, 1)
            switch r case 0 { revert(0, 0) } default { return(0, 32) }
        }
    }
}
contract PSkip is Base {
    constructor(address i, address a) { assembly { sstore(IMPL, i) sstore(ADMIN, a) } }
    function _fallback() internal override {
        address a; assembly { a := sload(ADMIN) }
        if (msg.sender == a) return;
        super._fallback();
    }
}
contract Upgrades is Base {
    address owner;
    constructor() { owner = msg.sender; }
    function upgrade(address n) external { require(msg.sender == owner); assembly { sstore(IMPL, n) } }
}
contract PWrites is Base {
    constructor(address i) { assembly { sstore(IMPL, i) } }
    function _fallback() internal override {
        assembly { sstore(0x1234, add(sload(0x1234), 1)) }
        super._fallback();
    }
}
interface IM { function allowed(address who) external view returns (bool); }
contract C {
    IM m; uint public value;
    constructor(address a) { m = IM(a); }
    function act() external { require(m.allowed(msg.sender)); value = 1; }
}
"""
STRANGER = O.ACCOUNTS[1]


@pytest.fixture(params=["0.8.10", "0.8.27"])
def d(request, anvil, monkeypatch, tmp_path):
    monkeypatch.setattr(A, "SOLC", request.param)
    return A.Deployment(anvil[0], tmp_path, SOURCE)


def _init(d, proxy, owner=O.OWNER):
    d.at["proxy"] = proxy
    sender = O.hex20(O.ACCOUNTS[2])  # never the admin: a transparent proxy refuses it the implementation
    d.send("proxy", "0x" + keccak(text="init(address)")[:4].hex() + f"{owner:064x}", sender=sender)


def _proxy(d, name, types=(), values=(), owner=O.OWNER):
    impl = d.deploy("Impl")
    _init(d, d.deploy(name, ("address", *types), (impl, *values)), owner)
    return d.at["proxy"], impl


def _views(d, proxy, impl, *, own=None):
    own = {proxy: d.slither[d.proxy_name]} if own is None else own
    contracts = {a: c for a, c in d.contracts(*(n for n in d.at if n != "proxy")).items() if a != proxy}
    contracts[proxy] = d.slither["Impl"]
    return contracts, (lambda a: impl if a == proxy else a), own.get


def _compile(d, contract, at, proxy, impl, own=None):
    contracts, code_of, own_code = _views(d, proxy, impl, own=own)
    fn = next(f for f in d.slither[contract].functions_entry_points if f.name == "act")
    formula = compile_function(d.slither[contract], fn, at, d.chain(), contracts, code_of=code_of, own_code=own_code)
    return formula, expand_formula(formula, d.chain(), contracts).callers


def _resource_case(d, formula, proxy, impl):
    """EVM oracle case with ample gas; production lets the sender choose each resource outcome."""
    resources = subterms(formula.success, "unknown")
    assert all(t[1] == "unsupported:raw_call_resources" for t in resources), resources
    known, _, _ = _views(d, proxy, impl)
    case = replace(formula, success=replace_terms(formula.success, {t: TRUE for t in resources}))
    return expand_formula(case, d.chain(), known).callers


def _chain_admits(d, at, sender):
    try:
        rpc(
            d.url,
            "eth_call",
            [{"to": O.hex20(at), "from": O.hex20(sender), "data": "0x" + keccak(text="act()")[:4].hex()}, "latest"],
        )
        return True
    except RuntimeError as exc:
        assert "revert" in str(exc)
        return False


def _admitted(d, at):
    return {s for s in O.ACCOUNTS if _chain_admits(d, at, s)}


@pytest.mark.parametrize("name", ["P1967", "PBeacon"])
def test_forwarding_proxy_proves_the_implementation_gate(d, name):
    if name == "PBeacon":
        impl = d.deploy("Impl")
        proxy = d.deploy("PBeacon", ("address",), (d.deploy("Beacon", ("address",), (impl,)),))
        _init(d, proxy)
    else:
        proxy, impl = _proxy(d, name)
    d.proxy_name = name
    formula, callers = _compile(d, "Impl", proxy, proxy, impl)
    O.assumes_gas(callers, {O.OWNER})
    assert _resource_case(d, formula, proxy, impl).members == callers.members
    assert set(callers.members) == _admitted(d, proxy)


@pytest.mark.parametrize("name", ["PTransparent4", "PTransparent5"])
@pytest.mark.parametrize("admin", ["owner", "stranger"])
def test_transparent_admin_is_kept_out_of_the_implementation(d, name, admin):
    proxy, impl = _proxy(d, name, ("address",), (O.OWNER if admin == "owner" else STRANGER,), owner=O.OWNER)
    d.proxy_name = name
    formula, callers = _compile(d, "Impl", proxy, proxy, impl)
    # PTransparent5's own branch for its admin returns without delegating, on a selector ``act()`` isn't.
    callers = _resource_case(d, formula, proxy, impl)
    assert callers.complete and set(callers.members) == _admitted(d, proxy)
    assert set(callers.members) == (set() if admin == "owner" else {O.OWNER})


def _unsupported(formula, label):
    found = {t[1] for t in subterms(formula.success, "unknown")}
    assert any(label in f for f in found), found


def test_selector_the_proxy_answers_itself_is_not_dispatched(d):
    proxy, impl = _proxy(d, "PClash")
    d.proxy_name = "PClash"
    formula, callers = _compile(d, "Impl", proxy, proxy, impl)
    assert callers.complete and callers.representation == "cofinite"
    assert not formula.effects
    assert _admitted(d, proxy) == set(O.ACCOUNTS)  # the proxy's own act() runs, for anyone


def test_rewritten_calldata_preserves_runtime_authorization(d):
    proxy, impl = _proxy(d, "PRewrite")
    d.proxy_name = "PRewrite"
    formula, case = _compile(d, "Impl", proxy, proxy, impl)
    O.assumes_gas(case)
    # The proxy also rewrote init(owner): the initializer's sender became owner.
    owner = int(rpc(d.url, "eth_getStorageAt", [O.hex20(proxy), "0x0", "latest"]), 16)
    assert owner == O.ACCOUNTS[2]
    assert case.complete and set(case.members) == _admitted(d, proxy) == {owner}


def test_implementation_metadata_must_match_the_chain(d):
    proxy, impl = _proxy(d, "P1967")
    d.proxy_name = "P1967"
    other = d.deploy("Impl")
    formula, callers = _compile(d, "Impl", proxy, proxy, other)
    assert not callers.complete
    assert callers.issues  # The actual target is absent from this deliberately stale source inventory.
    assert _admitted(d, proxy) == {O.OWNER}


def test_proxy_without_its_own_source_stays_unsupported(d):
    proxy, impl = _proxy(d, "P1967")
    d.proxy_name = "P1967"
    formula, callers = _compile(d, "Impl", proxy, proxy, impl, own={})
    _unsupported(formula, "unverified:")
    assert not callers.complete


@pytest.mark.parametrize("name", ["P1967", "PTrue"])
def test_callee_behind_a_proxy(d, name):
    proxy, impl = _proxy(d, name)
    d.proxy_name = name
    caller = d.deploy("C", ("address",), (proxy,))
    formula, callers = _compile(d, "C", caller, proxy, impl)
    resources = subterms(formula.success, "unknown")
    assert resources and {t[1] for t in resources} == {"unsupported:raw_call_resources"}
    O.assumes_gas(callers)
    admitted = {s for s in O.ACCOUNTS if _chain_admits(d, caller, s)}
    assert {s for s in O.ACCOUNTS if (s in callers.members) is (callers.representation == "finite")} == admitted
    contracts, _, _ = _views(d, proxy, impl)
    for sender in O.ACCOUNTS:
        tr = Translation(
            d.chain(),
            contracts,
            caller,
            formula.selector,
            bindings={CALLER: sender, ORIGIN: sender, mk("callvalue"): 0, **{term: True for term in resources}},
        )
        expected = sender == O.OWNER if name == "P1967" else True
        assert _chain_admits(d, caller, sender) is expected
        assert tr.truth(formula.success) is expected, tr.issues


def test_a_return_without_the_delegate_is_not_the_implementation(d):
    proxy, impl = _proxy(d, "PSkip", ("address",), (STRANGER,))
    d.proxy_name = "PSkip"
    formula, actual = _compile(d, "Impl", proxy, proxy, impl)
    O.assumes_gas(actual, {O.OWNER, STRANGER})
    assert any(e.kind == "write" for e in formula.effects)
    assert _admitted(d, proxy) == {O.OWNER, STRANGER}


def test_assembly_store_to_a_constant_slot_is_a_guarded_write(d):
    # Slither renders Yul ``sstore(IMPL, n)`` as an assignment to the constant: still the write, at IMPL's slot.
    at = d.deploy("Upgrades")
    fn = next(f for f in d.slither["Upgrades"].functions_entry_points if f.name == "upgrade")
    formula = compile_function(d.slither["Upgrades"], fn, at, d.chain(), d.contracts("Upgrades"))
    impl_slot = int(SOURCE.split("IMPL = ")[1][:66], 16)
    writes = [i for i, e in enumerate(formula.effects) if e.kind == "write" and e.target[0] == "raw"]
    assert [formula.effects[i].target[2][1] for i in writes] == [impl_slot]
    analysis = expand_formula(
        formula, d.chain(), d.contracts("Upgrades"), selection=Selection(effect_indices=tuple(writes))
    )
    assert analysis.effects[0].complete and set(analysis.effects[0].members) == {O.OWNER}


def test_a_fallback_that_writes_before_forwarding_is_not_a_plain_forward(d):
    proxy, impl = _proxy(d, "PWrites")
    d.proxy_name = "PWrites"
    formula, actual = _compile(d, "Impl", proxy, proxy, impl)
    O.assumes_gas(actual, {O.OWNER})
    assert set(actual.members) == _admitted(d, proxy)
    assert any(e.kind == "write" and e.target[0] == "raw" and e.target[2][1] == 0x1234 for e in formula.effects)
