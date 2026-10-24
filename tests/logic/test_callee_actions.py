"""A state-changing call handed the caller is read for whether it returns: its callee's checks on the caller list who
may pass, never its return value (Maple's ``processRedeem(shares, owner, msg.sender)``). A pass only the callee's
code shows is confirmed by running the holder's own call on the chain. Deployed on anvil and checked against
``eth_call`` (``_oracle.check``): the holder listed passes from its own address, no stranger does."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Manager {
    mapping(address => bool) allowed;
    event Allowed(address indexed who);

    constructor() { allowed[msg.sender] = true; emit Allowed(msg.sender); }

    function allow(address who) external {
        require(allowed[msg.sender]);
        allowed[who] = true;
        emit Allowed(who);
    }

    function process(address who) external returns (uint256) {
        require(allowed[who]);
        return 1;
    }
}

contract Pool {
    Manager manager;

    constructor(address m) { manager = Manager(m); }

    function redeem() external {
        manager.process(msg.sender);
    }
}

contract Registry {
    event Granted(address indexed who);

    function grant(address who) external {
        assembly {
            mstore(0, 7)
            mstore(32, caller())
            if iszero(sload(keccak256(0, 64))) { revert(0, 0) }
            mstore(32, who)
            sstore(keccak256(0, 64), 1)
        }
        emit Granted(who);
    }

    function onlyGranted(address who) external {
        assembly {
            mstore(0, 7)
            mstore(32, who)
            if iszero(sload(keccak256(0, 64))) { revert(0, 0) }
            sstore(1, add(sload(1), 1))
        }
    }
}

contract Guarded {
    Registry registry;
    bool paused;

    constructor(address r) { registry = Registry(r); }

    function pause() external {
        registry.onlyGranted(msg.sender);
        paused = true;
    }
}
"""

ALLOWED = O.ACCOUNTS[1]


def _setup(d):
    d.deploy("Manager")
    d.deploy("Pool", ("address",), (d.at["Manager"],))
    assert O.transact(d, "Manager", "allow(address)", ("address",), (ALLOWED,))
    d.deploy("Registry")
    d.deploy("Guarded", ("address",), (d.at["Registry"],))
    O.set_storage(d, "Registry", O.slot(7, O.OWNER), 1)  # as an earlier version left it: the deployer granted
    assert O.transact(d, "Registry", "grant(address)", ("address",), (ALLOWED,))


PROBES = [O.Probe(SOURCE, _setup, (("Pool", "redeem", ("Manager",)), ("Guarded", "pause", ("Registry",))))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


def test_an_action_that_checks_the_caller_lists_whom_its_callee_lets_through(d):
    # Whom the callee's check lets through (an allowed address it logged) is listed once that holder's own call goes
    # through on the chain; no stranger passes.
    v = O.check(d, "Pool", "redeem", O.verdict(d, "Pool", "redeem", "Manager"), open_at=False)
    assert ALLOWED in v.principals
    assert v.openness != "open"


def test_a_check_its_callee_keeps_in_an_assembly_slot_is_never_open(d):
    # The grant sits at ``keccak(7, who)``, written in assembly: over RPC no log history names its holders
    # (``Chain.all_log_words`` reads none), so none is listed, and no stranger is let through.
    v = O.check(d, "Guarded", "pause", O.verdict(d, "Guarded", "pause", "Registry"), open_at=False)
    assert v.openness == "not_determined" and not v.complete
    assert O.passes(d, "Guarded", O.function(d, "Guarded", "pause"), sender=ALLOWED)
