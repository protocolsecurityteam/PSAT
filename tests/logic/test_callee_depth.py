"""Depth into other contracts is spent only on the calls the caller's identity reaches: a check handed the caller is
followed four contracts deep, and a callee no identity reaches is a condition, never followed at all. Who a callee's
code lets through names the holders, each confirmed by the chain, but never shows they are all
(``callee_code_list:<signature>``). Each verdict is checked against ``eth_call`` on anvil (``_oracle.check``): every
listed holder passes from its own address, no stranger does."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

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

HOLDERS = set(O.ACCOUNTS[1:3])


def _alias(d, name, contract, at):
    d.at[name], d.slither[name] = at, d.slither[contract]
    return at


def _setup(d):
    """``Guarded3``/``Guarded4`` ask three/four relays in turn, the last asking ``Roles`` (two holders);
    ``GuardedV`` asks ``Gate``, whose check reads a value through three ``Value`` contracts; ``GuardedU`` asks a
    ``Roles`` nobody holds, its code not given."""
    roles = d.deploy("Roles")
    for who in sorted(HOLDERS):
        assert O.transact(d, "Roles", "grant(address)", ("address",), (who,))
    at = roles
    for i in range(4):
        at = _alias(d, f"Relay{i}", "Relay", d.deploy("Relay", ("address",), (at,)))
        if i >= 2:
            _alias(d, f"Guarded{i + 1}", "Guarded", d.deploy("Guarded", ("address",), (at,)))
    at = 0
    for _ in range(3):
        at = d.deploy("Value", ("address",), (at,))
    d.deploy("Gate", ("address",), (at,))
    for who in sorted(HOLDERS):
        assert O.transact(d, "Gate", "grant(address)", ("address",), (who,))
    _alias(d, "GuardedV", "Guarded", d.deploy("Guarded", ("address",), (d.at["Gate"],)))
    _alias(d, "Empty", "Roles", d.deploy("Roles"))
    d.at["Roles"] = roles
    _alias(d, "GuardedU", "Guarded", d.deploy("Guarded", ("address",), (d.at["Empty"],)))


RELAYS3 = ("Roles", "Relay0", "Relay1", "Relay2")
RELAYS4 = (*RELAYS3, "Relay3")
PROBES = [
    O.Probe(
        SOURCE,
        _setup,
        (("Guarded3", "act", RELAYS3), ("Guarded4", "act", RELAYS4), ("GuardedV", "act", ("Gate",)),
         ("GuardedU", "act", ())),
    )
]  # fmt: skip


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_identity_followed_four_contracts_deep(d):
    v = O.check(d, "Guarded3", "act", O.verdict(d, "Guarded3", "act", *RELAYS3), open_at=False)
    assert v.openness == "restricted" and set(v.principals) == HOLDERS
    assert not v.complete and "callee_code_list:check(address)" in v.gaps


def test_identity_handed_on_further_names_where_it_stopped(d):
    v = O.check(d, "Guarded4", "act", O.verdict(d, "Guarded4", "act", *RELAYS4), open_at=False)
    O.sound(v, HOLDERS)
    assert not v.complete
    assert f"depth:call:check(address):arg0@0x{d.at['Roles']:040x}" in v.gaps
    assert all(O.passes(d, "Guarded4", O.function(d, "Guarded4", "act"), sender=h) for h in HOLDERS)


def test_values_no_identity_reaches_are_never_followed(d):
    # The values' code isn't given: not needed.
    v = O.check(d, "GuardedV", "act", O.verdict(d, "GuardedV", "act", "Gate"), open_at=False)
    assert v.openness == "restricted" and set(v.principals) == HOLDERS
    assert not v.complete and "callee_code_list:check(address)" in v.gaps


def test_an_unavailable_callee_handed_the_caller_is_named(d):
    clean = O.check(d, "GuardedU", "act", O.verdict(d, "GuardedU", "act", "Empty"), open_at=False)
    v = O.check(d, "GuardedU", "act", O.verdict(d, "GuardedU", "act"), open_at=False)
    assert v.openness == "restricted" and not v.complete
    assert f"call:check(address):arg0@0x{d.at['Empty']:040x}" in v.gaps
    O.never_bolder(clean, v)
