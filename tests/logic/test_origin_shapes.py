"""Where a callee's ``tx.origin`` check can hide: behind a short-circuit, in a value only stored, behind a low-level
call or an action in followed code; and an admin delegating by EIP-7702, which still sends. Each verdict is checked
against ``eth_call`` on anvil (``_oracle.check``): the admin listed passes from its own address (the origin too), an
open one passes for every stranger, a refusal for none."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

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

ADMIN = O.ACCOUNTS[1]
X = ({"x": 0}, {"x": 6}, {"x": 100})


def _setup(d):
    d.deploy("Registry")
    d.deploy("Deep", ("address",), (ADMIN,))
    d.deploy("Guard", ("address", "address"), (ADMIN, d.at["Deep"]))
    d.deploy("GuardNV", ("address",), (d.at["Deep"],))
    assert O.transact(d, "Registry", "setGuard(address)", ("address",), (d.at["Guard"],))  # req() now reverts
    d.deploy("C", ("address",) * 4, (ADMIN, d.at["Guard"], d.at["GuardNV"], d.at["Registry"]))


PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        (*(("C", n, ("Guard",)) for n in ("a7", "a7b", "a7c", "a5", "a10", "a12", "a16")),
         ("C", "a10", ("Guard", "Deep")), ("C", "a11", ("GuardNV",)), ("C", "a15", ()), ("C", "a15", ("Registry",)),
         ("C", "d1", ())),
    )
]  # fmt: skip


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def _verdict(d, name, followed):
    return O.verdict(d, "C", name, *followed)


@pytest.mark.parametrize("name", ["a7", "a7b", "a7c"])
def test_a_check_behind_a_short_circuit_holds_back_no_one(deployed, name):
    # Anyone gets through with x = 0: the guard is never asked.
    O.check(deployed, "C", name, _verdict(deployed, name, ("Guard",)), open_at={"x": 0})


@pytest.mark.parametrize("name", ["a12", "a16"])
def test_a_call_whose_value_is_only_stored_still_has_to_return(deployed, name):
    # The admin, whose own call goes through on the chain; over every ``x`` the inlined code's list isn't complete.
    v = O.check(deployed, "C", name, _verdict(deployed, name, ("Guard",)), samples=X, open_at=False)
    assert set(v.principals) == {ADMIN} and not v.complete


@pytest.mark.parametrize("followed", [(), ("Registry",)], ids=["unfollowed", "followed"])
def test_a_stored_value_from_a_call_that_always_reverts_lets_no_one_through(deployed, followed):
    v = O.check(deployed, "C", "a15", _verdict(deployed, "a15", followed), samples=X, open_at=False)
    O.sound(v, set())
    for who in {*O.ACCOUNTS, *O.STRANGERS}:
        assert not O.passes(deployed, "C", O.function(deployed, "C", "a15"), {"x": 0}, sender=who)


def test_a_low_level_staticcall_in_followed_code_is_the_view_call_its_data_encodes(deployed):
    # ``staticcall(abi.encodeWithSignature("okAdmin(address)", ...))`` asks ``Deep.okAdmin``: its origin check is the
    # caller's when followed, an unfollowed callee reading the origin otherwise; never the chain's word.
    v = O.check(deployed, "C", "a10", _verdict(deployed, "a10", ("Guard",)), samples=X, open_at=False)
    O.sound(v, {ADMIN})
    assert v.openness == "not_determined" and "origin:okAdmin(address)" in v.gaps
    v = O.check(deployed, "C", "a10", _verdict(deployed, "a10", ("Guard", "Deep")), samples=X, open_at=False)
    assert set(v.principals) == {ADMIN} and not v.complete


def test_an_action_in_followed_code_is_not_taken_at_the_chains_word(deployed):
    v = O.check(deployed, "C", "a11", _verdict(deployed, "a11", ("GuardNV",)), samples=X, open_at=False)
    O.sound(v, {ADMIN})
    assert v.openness == "not_determined" and "unfollowed:nv()" in v.gaps
    assert O.passes(deployed, "C", O.function(deployed, "C", "a11"), sender=ADMIN)


@pytest.mark.parametrize(("name", "followed"), [("d1", ()), ("a5", ("Guard",))])
def test_an_admin_delegating_by_7702_still_sends(deployed, name, followed):
    with O.snapshot(deployed):
        designator = "0xef0100" + format(deployed.at["Registry"], "040x")
        O.rpc(deployed.url, "anvil_setCode", [O.hex20(ADMIN), designator])
        v = O.check(deployed, "C", name, _verdict(deployed, name, followed), samples=X, open_at=False)
        assert set(v.principals) == {ADMIN}
        if name == "d1":
            assert v.openness == "restricted"
