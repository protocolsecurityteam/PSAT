"""A ``when`` condition the function itself consumes (an initializer's version, a one-shot flag), false now: "nobody,
ever" holds only where no entry point can write it back, which latching proves (``verdict.latched_atoms``: such a
condition is read as it stands, never reaches this). Where latching couldn't prove it, a stranger let through once the
condition allows makes no confident "nobody": not determined, ``inert_when_allowed``, the same whether the formula
may single someone out (``initUnbanned``, which fell through to "nobody") or not (``initAnyone``): ``decide._decide``'s
two branches."""

from __future__ import annotations

import pytest

from services.logic.terms import reset_terms
from services.logic.verdict import function_verdict
from tests.logic._anvil import Deployment, anvil  # noqa: F401

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


@pytest.fixture(scope="module")
def d(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("I")
    return d


@pytest.mark.parametrize("name", ["initAnyone", "initUnbanned"])
def test_a_consumed_condition_another_writer_may_restore_is_no_confident_nobody(d, name):
    reset_terms()
    c = d.slither["I"]
    fn = next(f for f in c.functions_entry_points if f.name == name)
    verdict = function_verdict(c, fn, d.at["I"], d.chain(), d.contracts("I"))[0]
    assert not (verdict.openness == "restricted" and verdict.complete and not verdict.principals), verdict
    assert verdict.openness == "not_determined" and "inert_when_allowed" in verdict.gaps, verdict
