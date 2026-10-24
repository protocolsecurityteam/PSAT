"""The scope classifier (``scope.py``, off by default and unverified: ``SCOPE.md``) under a cut budget: facts it
couldn't finish are cached as "everything checked", the conservative side, and the contract isn't lowered again."""

from __future__ import annotations

import pytest

from tests.fuzz.authority import solc_path

BOUNDED = """
pragma solidity 0.8.27;
contract Bounded {
    mapping(address => uint256) balances; mapping(address => bool) allowed;
    mapping(address => uint256) dep;
    function bounded(address to, uint256 a) external {
        require(allowed[msg.sender]);
        require(a <= dep[msg.sender]);
        unchecked { dep[msg.sender] -= a; }
        dep[to] += a;
    }
}
"""


def test_facts_cut_off_by_the_budget_are_cached_as_everything_checked(tmp_path, monkeypatch):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    from services.logic import lower, scope

    path = tmp_path / "B.sol"
    path.write_text(BOUNDED)
    contract = next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "Bounded")
    calls = []

    def timeout(self, fn):
        calls.append(fn)
        raise TimeoutError("function budget")

    monkeypatch.setattr(lower.Lowerer, "success", timeout)
    with pytest.raises(TimeoutError):
        scope.contract_facts(contract)
    assert scope.contract_facts(contract).everything and len(calls) == 1
