"""Writes that look like the caller's own but aren't: each makes the function shared, so its holders are listed."""

from __future__ import annotations

import pytest

from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic.test_scope import AT, _Deployed

SOURCE = """
pragma solidity 0.8.27;

contract Child {}

contract Probe {
    mapping(address => uint256) balances;
    mapping(address => bool) allowed;
    uint256 moved;
    uint256 supply;
    mapping(bytes32 => mapping(address => bool)) roles;
    mapping(address => mapping(address => bool)) operators;
    mapping(address => mapping(address => bool)) blocked;
    mapping(address => address) vaults;
    mapping(address => uint256) counters;
    mapping(bytes32 => bool) hashed;
    mapping(address => mapping(bytes32 => uint256)) approvedHashes;
    bool paused;

    // Value created in the caller's own entry: no debit pays for it.
    function selfMint(uint256 a) external { require(allowed[msg.sender]); balances[msg.sender] += a; }
    // A privilege granted to oneself.
    function selfGrant(bytes32 role) external { require(allowed[msg.sender]); roles[role][msg.sender] = true; }
    // The caller keyed second: an operator of someone else's position.
    function selfOperator(address victim) external {
        require(allowed[msg.sender]);
        operators[victim][msg.sender] = true;
    }
    // The caller hashed in second: the same, hashed.
    function hashOperator(address victim) external {
        require(allowed[msg.sender]);
        hashed[keccak256(abi.encode(victim, msg.sender))] = true;
    }
    // Reads ``[from][caller]`` but requires it unset: no grant from ``from``.
    function blockedDrain(address from) external {
        require(allowed[msg.sender]);
        require(!blocked[from][msg.sender]);
        balances[from] = 0;
    }
    // Deploys code.
    function makeVault() external { require(allowed[msg.sender]); vaults[msg.sender] = address(new Child()); }
    // A path that destroys the contract.
    function kill(bool f) external {
        require(allowed[msg.sender]);
        balances[msg.sender] = 0;
        if (f) selfdestruct(payable(msg.sender));
    }
    // A global flag, whatever it holds at the block.
    function pauseIfNot() external { require(allowed[msg.sender]); paused = false; balances[msg.sender] = 0; }
    // Gnosis Safe's ``approveHash``: the caller's own entry, which another function's caller check reads.
    function approveHash(bytes32 h) external { require(allowed[msg.sender]); approvedHashes[msg.sender][h] = 1; }
    function execute(bytes32 h, address owner) external {
        require(approvedHashes[owner][h] != 0 && owner == msg.sender);
        moved += 1;
    }
    // A balance moved out of one's own entry: self-scoped.
    function transfer(address to, uint256 d) external {
        require(allowed[msg.sender]);
        balances[msg.sender] -= d;
        balances[to] += d;
    }
}
"""


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("probes") / "P.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Probe")


def _verdict(contract, name):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    verdict, _ = function_verdict(contract, fn, AT, _Deployed(), {AT: contract})
    return verdict


@pytest.mark.parametrize(
    "name",
    [
        "selfMint",
        "selfGrant",
        "selfOperator",
        "hashOperator",
        "blockedDrain",
        "makeVault",
        "kill",
        "pauseIfNot",
        "approveHash",
    ],
)
def test_a_write_that_only_looks_like_the_callers_own_is_shared(probe, name):
    verdict = _verdict(probe, name)
    assert verdict.scope == "shared"
    assert "self_scoped" not in verdict.gaps


def test_a_balance_moved_out_of_ones_own_entry_stays_self_scoped(probe):
    verdict = _verdict(probe, "transfer")
    # Nothing ever writes the allowlist here: shown empty, nobody passes, which a self-scoped row still says.
    assert verdict.scope == "self" and verdict.openness == "restricted" and verdict.complete
