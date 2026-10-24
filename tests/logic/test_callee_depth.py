"""Depth into other contracts is spent only on the calls the caller's identity reaches: a check handed the caller is
followed four contracts deep, and a callee no identity reaches is a condition, never followed at all. Who a callee's
code lets through names the holders, each confirmed by the chain, but never shows they are all
(``callee_code_list:<signature>``)."""

from __future__ import annotations

from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import calldata

SOURCE = """
pragma solidity 0.8.27;

interface ICheck { function check(address who) external view returns (bool); }
interface IValue { function read(uint256 v) external view returns (uint256); }

contract Roles is ICheck {
    mapping(address => bool) roles;
    address admin;
    event Granted(address indexed who);
    constructor() { admin = msg.sender; }
    function grant(address who) external { require(msg.sender == admin); roles[who] = true; emit Granted(who); }
    function check(address who) external view returns (bool) { return roles[who]; }
}

contract Relay is ICheck {
    ICheck next;
    constructor(ICheck n) { next = n; }
    function check(address who) external view returns (bool) { return next.check(who); }
}

contract Value is IValue {
    IValue next;
    constructor(IValue n) { next = n; }
    function read(uint256 v) external view returns (uint256) {
        return address(next) == address(0) ? v : next.read(v);
    }
}

// Roles of its own, then a value read through a chain of contracts no identity reaches.
contract Gate is ICheck {
    mapping(address => bool) roles;
    address admin;
    IValue values;
    event Granted(address indexed who);
    constructor(IValue v) { admin = msg.sender; values = v; }
    function grant(address who) external { require(msg.sender == admin); roles[who] = true; emit Granted(who); }
    function check(address who) external view returns (bool) { return roles[who] && values.read(5) > 0; }
}

contract Guarded {
    ICheck checker;
    uint256 count;
    constructor(ICheck c) { checker = c; }
    function act() external { require(checker.check(msg.sender)); count += 1; }
}
"""

HOLDERS = ("0x" + "c3" * 20, "0x" + "d4" * 20)


def _verdict(deployment, guarded, names):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = deployment.slither["Guarded"]
    fn = next(f for f in contract.functions_entry_points if f.name == "act")
    contracts = {guarded: contract, **deployment.contracts(*names)}
    return function_verdict(contract, fn, guarded, deployment.chain(), contracts)[0]


def _relayed(anvil, relays: int):
    """``Guarded`` asking ``relays`` relays in turn, the last asking ``Roles``, which two hold."""
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    at = d.deploy("Roles")
    for who in HOLDERS:
        d.send("Roles", calldata("grant(address)", [who]))
    names = ["Roles"]
    for i in range(relays):
        at = d.deploy("Relay", ("address",), (at,))
        d.at[f"Relay{i}"], d.slither[f"Relay{i}"] = at, d.slither["Relay"]
        names.append(f"Relay{i}")
    return d, d.deploy("Guarded", ("address",), (at,)), names


def test_identity_followed_four_contracts_deep(anvil):  # noqa: F811
    d, guarded, names = _relayed(anvil, 3)
    verdict = _verdict(d, guarded, names)
    assert verdict.openness == "restricted"
    assert verdict.principals == {int(h, 16) for h in HOLDERS}
    assert not verdict.complete and "callee_code_list:check(address)" in verdict.gaps


def test_identity_handed_on_further_names_where_it_stopped(anvil):  # noqa: F811
    d, guarded, names = _relayed(anvil, 4)
    verdict = _verdict(d, guarded, names)
    assert verdict.openness == "restricted" and not verdict.complete
    assert f"depth:call:check(address):arg0@0x{d.at['Roles']:040x}" in verdict.gaps


def test_values_no_identity_reaches_are_never_followed(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    at = 0
    for _ in range(3):
        at = d.deploy("Value", ("address",), (at,))
    gate = d.deploy("Gate", ("address",), (at,))
    for who in HOLDERS:
        d.send("Gate", calldata("grant(address)", [who]))
    guarded = d.deploy("Guarded", ("address",), (gate,))
    verdict = _verdict(d, guarded, ["Gate"])  # the values' code isn't given: not needed
    assert verdict.openness == "restricted"
    assert verdict.principals == {int(h, 16) for h in HOLDERS}
    assert not verdict.complete and "callee_code_list:check(address)" in verdict.gaps


def test_an_unavailable_callee_handed_the_caller_is_named(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    roles = d.deploy("Roles")
    guarded = d.deploy("Guarded", ("address",), (roles,))
    verdict = _verdict(d, guarded, [])
    assert verdict.openness == "restricted" and not verdict.complete
    assert f"call:check(address):arg0@0x{roles:040x}" in verdict.gaps
