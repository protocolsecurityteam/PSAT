"""A ``when`` condition the function itself consumes (an initializer's version, a one-shot flag), false now: "nobody,
ever" holds only where no entry point can write it back, which latching proves (``verdict.latched_atoms``: such a
condition is read as it stands, never reaches this). Where latching couldn't prove it, a stranger let through once the
condition allows makes no confident "nobody", whether the formula may single someone out (``initUnbanned``, which
fell through to "nobody") or not (``initAnyone``): ``decide._decide``'s two branches. Checked on anvil: the owner
writes the version back, and then every stranger passes."""

from __future__ import annotations

import pytest

from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract I {
    uint8 public version = 3;
    address public owner;
    mapping(address => bool) public banned;
    uint256 public x;
    constructor() { owner = msg.sender; }
    // Whoever calls, once the version is below 3 again.
    function initAnyone(uint256 v) external { require(version < 3); version = 3; x = v; }
    // The same, unless banned: the formula may single someone out.
    function initUnbanned(uint256 v) external {
        require(version < 3);
        require(!banned[msg.sender]);
        version = 3;
        x = v;
    }
    // Another writer: the version may come back below 3.
    function setVersion(uint8 v) external { require(msg.sender == owner); version = v; }
}
"""


def _setup(d):
    d.deploy("I")


PROBES = [O.Probe(SOURCE, _setup, (("I", "initAnyone", ()), ("I", "initUnbanned", ())))]


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    _setup(d)
    return d


@pytest.mark.parametrize("name", ["initAnyone", "initUnbanned"])
def test_a_consumed_condition_another_writer_may_restore_is_no_confident_nobody(d, name):
    v = O.check(d, "I", name, O.verdict(d, "I", name), samples=({"v": 1},), open_at=False)
    assert not O.nobody(v), v
    with O.snapshot(d):
        assert O.transact(d, "I", "setVersion(uint8)", ("uint8",), (2,))
        assert O.strangers_passing(d, "I", O.function(d, "I", name), {"v": 1}) == {True}
