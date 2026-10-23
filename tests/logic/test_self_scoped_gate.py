"""A self-scoped function still says who can pass: nobody, when the list of holders is shown empty; else its whole
condition (not only the part about who calls) and how many the list names."""

from __future__ import annotations

import pytest
from eth_utils import keccak

from services.logic.decide import Chain
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path

SOURCE = """
pragma solidity 0.8.27;

// Lido CSM's ``changeNodeOperatorRewardAddress``: an operator's manager names its reward address.
contract Operators {
    struct Op { address manager; address reward; bool active; }
    address owner;
    mapping(uint256 => Op) ops;
    event ManagerSet(uint256 indexed id, address manager);

    function setManager(uint256 id, address manager) external {
        require(msg.sender == owner);
        ops[id].manager = manager;
        ops[id].active = true;
        emit ManagerSet(id, manager);
    }

    function changeReward(uint256 id, address reward) external {
        require(ops[id].active && ops[id].manager == msg.sender);
        ops[id].reward = reward;
    }
}
"""

AT = 0xA1 << 152
MANAGER = 0xB1 << 152
_SET = int.from_bytes(keccak(b"ManagerSet(uint256,address)"), "big")


def _slot(key: int, base: int) -> int:
    return int.from_bytes(keccak(key.to_bytes(32, "big") + base.to_bytes(32, "big")), "big")


class _Deployed(Chain):
    """``managers``: operator id -> manager, set (and logged) through ``setManager``."""

    def __init__(self, managers: dict):
        self.managers = managers
        self.words = {}
        for i, who in managers.items():
            self.words[_slot(i, 1)] = who
            self.words[_slot(i, 1) + 1] = 1 << 160  # ``active``, packed after ``reward``
        super().__init__(self._answer, 100, lambda calls: [self._safe(m, p) for m, p in calls])

    def _safe(self, method, params):
        try:
            return self._answer(method, params)
        except RuntimeError:
            return None

    def _answer(self, method, params):
        if method == "eth_getStorageAt":
            return hex(self.words.get(int(params[1], 16), 0) if int(params[0], 16) == AT else 0)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(1_700_000_000), "number": hex(100)}
        raise RuntimeError("execution reverted")

    def code(self, address):
        return b"\x60" if address == AT else b""

    def logs(self, address, topics):
        return [([_SET, i], [who]) for i, who in self.managers.items()] if address == AT else []


@pytest.fixture(scope="module")
def operators(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("operators") / "O.sol"
    path.write_text(SOURCE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Operators")


def _verdict(contract, chain):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "changeReward")
    verdict, _ = function_verdict(contract, fn, AT, chain, {AT: contract})
    return verdict


def test_with_no_operator_ever_set_nobody_can_name_a_reward(operators):
    verdict = _verdict(operators, _Deployed({}))
    assert verdict.scope == "self"
    assert verdict.openness == "restricted" and verdict.complete and not verdict.principals


def test_the_gate_reported_is_the_whole_condition_with_the_count_of_holders(operators):
    verdict = _verdict(operators, _Deployed({7: MANAGER}))
    assert verdict.scope == "self" and verdict.gaps == ("self_scoped",)
    assert any("active" in g for g in verdict.gate) and any("caller" in g for g in verdict.gate)
    assert verdict.members == 1
