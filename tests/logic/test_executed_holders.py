"""Holders the reasoning can only show passing with business logic set aside (a callee's check it takes on trust) are
settled by their own call run on the chain, every one of them, not the first few: a controller whose call goes
through now is a holder now, never listed as holding only on business conditions. Checked against ``eth_call`` on
anvil (``_oracle.check``)."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = r"""
pragma solidity 0.8.27;

contract Token {
    address masterMinter;
    bool paused;
    mapping(address => bool) minters;
    mapping(address => uint256) allowed;
    constructor(address m) { masterMinter = m; }
    function configureMinter(address minter, uint256 amount) external returns (bool) {
        require(!paused);
        require(msg.sender == masterMinter);
        minters[minter] = true;
        allowed[minter] = amount;
        return true;
    }
    function decrementMinterAllowance(address minter, uint256 decrement) external returns (bool) {
        require(msg.sender == masterMinter);
        require(decrement > 0);
        allowed[minter] = allowed[minter] > decrement ? allowed[minter] - decrement : 0;
        return true;
    }
}

// Each controller configures its own minter at the token, through this contract.
contract Master {
    address owner;
    Token public manager;
    mapping(address => address) controllers;
    event ControllerConfigured(address indexed controller, address indexed worker);
    constructor() { owner = msg.sender; }
    function setManager(address t) external { require(msg.sender == owner); manager = Token(t); }
    function configureController(address controller, address worker) external {
        require(msg.sender == owner);
        require(worker != address(0));
        controllers[controller] = worker;
        emit ControllerConfigured(controller, worker);
    }
    function configureMinter(uint256 amount) external returns (bool) {
        address minter = controllers[msg.sender];
        require(minter != address(0));
        return manager.configureMinter(minter, amount);
    }
    // Refused at all-zero arguments: a holder's call goes through only with a decrement of at least one.
    function decrementMinterAllowance(uint256 decrement) external returns (bool) {
        address minter = controllers[msg.sender];
        require(minter != address(0));
        return manager.decrementMinterAllowance(minter, decrement);
    }
}
"""

CONTROLLERS = tuple((0xC0 << 152) + i for i in range(1, 21))  # more than are run one by one with a search


def _setup(d):
    d.deploy("Master")
    d.deploy("Token", ("address",), (d.at["Master"],))
    assert O.transact(d, "Master", "setManager(address)", ("address",), (d.at["Token"],))
    for i, controller in enumerate(CONTROLLERS):
        worker = (0xD0 << 152) + i + 1
        assert O.transact(
            d, "Master", "configureController(address,address)", ("address", "address"), (controller, worker)
        )


FUNCTIONS = ("configureMinter", "decrementMinterAllowance")
PROBES = [O.Probe(SOURCE, _setup, tuple(("Master", f, others) for f in FUNCTIONS for others in (("Token",), ())))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.mark.parametrize("followed", [True, False])
@pytest.mark.parametrize("name", FUNCTIONS)
def test_every_controller_whose_call_goes_through_now_is_a_holder_now(d, name, followed):
    v = O.verdict(d, "Master", name, *(("Token",) if followed else ()))
    samples = ({"amount": 0, "decrement": 0}, {"amount": 1, "decrement": 1})
    O.check(d, "Master", name, v, samples=samples, open_at=False)
    for controller in CONTROLLERS:
        assert O.passes(d, "Master", O.function(d, "Master", name), samples[1], sender=controller)
    assert v.openness == "restricted", v
    assert set(v.principals) == set(CONTROLLERS), v
    assert not v.conditions, v
