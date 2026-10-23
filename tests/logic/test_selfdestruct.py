"""A ``selfdestruct`` ends the call successfully and sends the contract's ether: a path that reaches it is a way
through, not a refusal."""

from __future__ import annotations

import pytest

from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic.test_scope import ALLOWED, AT, _Deployed

SOURCE = """
pragma solidity 0.8.27;

contract Killable {
    mapping(address => uint256) balances;
    mapping(address => bool) allowed;
    event Allowed(address indexed who, bool ok);

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


@pytest.fixture(scope="module")
def killable(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("killable") / "K.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Killable")


def _verdict(contract, name):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(contract, fn, AT, _Deployed(), {AT: contract})
    return verdict


def test_an_unguarded_selfdestruct_is_open(killable):
    verdict = _verdict(killable, "killOpen")
    assert verdict.openness == "open"


def test_a_guarded_selfdestruct_lists_who_may_destroy_and_is_shared(killable):
    verdict = _verdict(killable, "kill")
    assert verdict.openness == "restricted" and verdict.scope == "shared"
    assert verdict.principals == set(ALLOWED) and verdict.complete
