"""Where a callee's ``tx.origin`` check can hide: behind a short-circuit, in a value only stored, behind a low-level
call or an action in followed code; and an admin delegating by EIP-7702, which still sends. Against anvil."""

from __future__ import annotations

import pytest

from services.logic.decide import Chain, Verdict
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import calldata, rpc

SOURCE = """
pragma solidity 0.8.27;

contract Registry {
    address public guard;
    function setGuard(address g) external { guard = g; }
    function req() external view returns (uint256) { require(guard == address(0)); return 1; }
}

contract Deep {
    address admin;
    constructor(address a) { admin = a; }
    function okAdmin(address who) external view returns (bool) { who; return tx.origin == admin; }
}

contract Guard {
    address public admin;
    Deep deep;
    constructor(address a, address d) { admin = a; deep = Deep(d); }
    function originReq() external view returns (bool) { require(tx.origin == admin); return true; }
    function capFor() external view returns (uint256) { require(tx.origin == admin); return 100; }
    function lowStatic() external view returns (bool) {
        (bool s, bytes memory r) = address(deep).staticcall(abi.encodeWithSignature("okAdmin(address)", address(0)));
        require(s && abi.decode(r, (bool)));
        return true;
    }
}

interface IDeepNV { function okAdmin(address who) external returns (bool); }
contract GuardNV {
    address deep;
    constructor(address d) { deep = d; }
    function nv() external returns (bool) { return IDeepNV(deep).okAdmin(address(0)); }
}
interface IGuardV { function nv() external view returns (bool); }

contract C {
    address admin;
    Guard guard;
    address gnv;
    address reg;
    uint256 total;
    constructor(address a, address g, address n, address r) { admin = a; guard = Guard(g); gnv = n; reg = r; }
    function a7(uint256 x) external { require(!(x > 5 && guard.originReq())); total += 1; }
    function a7b(uint256 x) external { bool b = x > 5 && guard.originReq(); require(!b); total += 1; }
    function a7c(uint256 x) external { require((x > 5 && guard.originReq()) == false); total += 1; }
    function a5(uint256 x) external { require(guard.originReq()); require(guard.capFor() >= x); total += 1; }
    function a10(uint256 x) external { x; require(guard.lowStatic()); total += 1; }
    function a11(uint256 x) external { x; require(IGuardV(gnv).nv()); total += 1; }
    function a12(uint256 x) external { total += guard.capFor() + x; }
    function a15(uint256 x) external { total += Registry(reg).req() + x; }
    function a16(uint256 x) external { total += guard.capFor() + x; require(x < 1000); }
    function d1(uint256 x) external { x; require(tx.origin == admin); total += 1; }
}
"""

ADMIN = int("ab" * 20, 16)


def _deploy(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    registry = d.deploy("Registry")
    deep = d.deploy("Deep", ("address",), (ADMIN,))
    guard = d.deploy("Guard", ("address", "address"), (ADMIN, deep))
    nv = d.deploy("GuardNV", ("address",), (deep,))
    d.send("Registry", calldata("setGuard(address)", ("0x" + format(guard, "040x"),)))  # req() now reverts
    d.deploy("C", ("address", "address", "address", "address"), (ADMIN, guard, nv, registry))
    return d


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    return _deploy(anvil)


def _verdict(d, name, followed) -> Verdict:
    from services.logic.terms import reset_terms

    reset_terms()
    contract = d.slither["C"]
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    chain = Chain(lambda m, p: rpc(d.url, m, p), int(rpc(d.url, "eth_blockNumber", []), 16))
    return function_verdict(contract, fn, d.at["C"], chain, d.contracts("C", *followed))[0]


@pytest.mark.parametrize("name", ["a7", "a7b", "a7c"])
def test_a_check_behind_a_short_circuit_holds_back_no_one(deployed, name):
    # Anyone gets through with x = 0: the guard is never asked.
    verdict = _verdict(deployed, name, ("Guard",))
    assert verdict.openness == "open"


@pytest.mark.parametrize("name", ["a12", "a16"])
def test_a_call_whose_value_is_only_stored_still_has_to_return(deployed, name):
    # The admin, whose own call goes through on the chain; over every ``x`` the inlined code's list isn't complete.
    verdict = _verdict(deployed, name, ("Guard",))
    assert verdict.openness != "open" and verdict.principals == {ADMIN} and not verdict.complete


def test_a_stored_value_from_a_call_that_always_reverts_lets_no_one_through(deployed):
    for followed in ((), ("Registry",)):
        assert _verdict(deployed, "a15", followed).openness != "open"


def test_a_low_level_staticcall_in_followed_code_is_the_view_call_its_data_encodes(deployed):
    # ``staticcall(abi.encodeWithSignature("okAdmin(address)", ...))`` asks ``Deep.okAdmin``: its origin check is the
    # caller's when followed, an unfollowed callee reading the origin otherwise; never the chain's word.
    verdict = _verdict(deployed, "a10", ("Guard",))
    assert verdict.openness == "not_determined"
    assert "origin:okAdmin(address)" in verdict.gaps
    verdict = _verdict(deployed, "a10", ("Guard", "Deep"))
    assert verdict.openness != "open" and verdict.principals == {ADMIN} and not verdict.complete


def test_an_action_in_followed_code_is_not_taken_at_the_chains_word(deployed):
    verdict = _verdict(deployed, "a11", ("GuardNV",))
    assert verdict.openness == "not_determined"
    assert "unfollowed:nv()" in verdict.gaps


def test_an_admin_delegating_by_7702_still_sends(anvil):  # noqa: F811
    d = _deploy(anvil)
    designator = "0xef0100" + format(d.at["Registry"], "040x")
    rpc(d.url, "anvil_setCode", ["0x" + format(ADMIN, "040x"), designator])
    for name, followed in (("d1", ()), ("a5", ("Guard",))):
        verdict = _verdict(d, name, followed)
        assert verdict.openness != "open" and verdict.principals == {ADMIN}
    assert _verdict(d, "d1", ()).openness == "restricted"
