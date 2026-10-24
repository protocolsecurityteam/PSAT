"""A ``selfdestruct`` ends the call successfully and sends the contract's ether: a path that reaches it is a way
through, not a refusal. Checked against ``eth_call`` on anvil: the open one passes for every stranger, the guarded one
for exactly the holders its constructor allowed."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Killable {
    mapping(address => uint256) balances;
    mapping(address => bool) allowed;
    event Allowed(address indexed who, bool ok);

    constructor(address a, address b) {
        allowed[a] = true;
        allowed[b] = true;
        emit Allowed(a, true);
        emit Allowed(b, true);
    }

    function allow(address who, bool ok) external {
        require(allowed[msg.sender]);
        allowed[who] = ok;
        emit Allowed(who, ok);
    }

    function killOpen() external {
        selfdestruct(payable(msg.sender));
    }

    function kill() external {
        require(allowed[msg.sender]);
        selfdestruct(payable(msg.sender));
    }
}
"""
ALLOWED = set(O.ACCOUNTS[1:3])


def _setup(d):
    d.deploy("Killable", ("address", "address"), tuple(sorted(ALLOWED)))


PROBES = [O.Probe(SOURCE, _setup, (("Killable", "killOpen", ()), ("Killable", "kill", ())))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_an_unguarded_selfdestruct_is_open(d):
    v = O.check(d, "Killable", "killOpen", O.verdict(d, "Killable", "killOpen"), open_at={})
    assert v.allowed == "now"


def test_a_guarded_selfdestruct_lists_who_may_destroy(d):
    v = O.check(d, "Killable", "kill", O.verdict(d, "Killable", "kill"))
    assert v.openness == "restricted" and v.complete and set(v.principals) == ALLOWED
