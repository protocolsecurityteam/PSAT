"""A contract-level reentrancy guard var must never license a function that doesn't carry the guard.

Closes one fail-open: a reentrancy guard var declared on a contract must never license a function
that does not carry the guard. Each refusal fixture removes exactly one conjunct of the proof
and has a positive sibling differing in that one construct, so ``not_determined`` cannot pass
because the analysis never reached the code. Assertions are on the whole verdict dict.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.reentrancy_pause import (  # noqa: E402
    W2_REASON_AMBIGUOUS_DECLARATION,
    W2_REASON_GUARD_NOT_APPLIED,
    W2_REASON_NO_VERIFIED_GUARD,
    W2_VERIFIED_GUARD_BASIS,
    reentrancy_guard_modifiers,
    verified_guard_verdicts,
)


def _compile(tmp_path: Path, source: str, name: str = "C.sol") -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / name
    f.write_text(src)
    return Slither(str(f))


def _contract(tmp_path: Path, source: str, name: str):
    sl = _compile(tmp_path, source)
    for contract in sl.contracts:
        if contract.name == name:
            return contract
    raise AssertionError(f"no contract {name} in fixture")


def _refusal(reason: str, declaration: str | None = None) -> dict:
    return {
        "state": "not_determined",
        "basis": None,
        "reason": reason,
        "declaration": declaration,
        "guard_vars": [],
        "guard_modifiers": [],
    }


_OZ_V5 = """
pragma solidity ^0.8.19;
contract C {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    function _nonReentrantBefore() private {
        require(_status != 2);
        _status = 2;
    }
    function _nonReentrantAfter() private {
        _status = 1;
    }
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }
    function withdraw() external nonReentrant {
        uint256 a = bal[msg.sender];
        bal[msg.sender] = 0;
        payable(msg.sender).transfer(a);
    }
}
"""


def test_oz_v5_split_guard_is_proven(tmp_path):
    """Neither write is visible in the modifier's own IRs."""
    verdicts = verified_guard_verdicts(_contract(tmp_path, _OZ_V5, "C"))
    assert verdicts["withdraw()"] == {
        "state": "proven",
        "basis": W2_VERIFIED_GUARD_BASIS,
        "reason": None,
        "declaration": "C.withdraw()",
        "guard_vars": ["_status"],
        "guard_modifiers": ["C.nonReentrant()"],
    }


_A13_FAKE_GUARD_NO_REVERT = """
pragma solidity ^0.8.19;
contract C {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    modifier notAGuard() {
        _status = 2;
        _;
        _status = 1;
    }
    function payout() external notAGuard {
        bal[msg.sender] = 0;
    }
}
"""


# ---------------------------------------------------------------------------
# A14 — no name drives an effect
# ---------------------------------------------------------------------------


_DIAMOND = """
pragma solidity ^0.8.19;
contract Base {
    uint256 private _status = 1;
    mapping(address => uint256) public bal;
    modifier nonReentrant() {
        require(_status != 2);
        _status = 2;
        _;
        _status = 1;
    }
    function payout() external virtual nonReentrant {
        bal[msg.sender] = 0;
    }
}
contract L is Base {
    function payout() external virtual override nonReentrant {
        bal[msg.sender] = 1;
    }
}
contract R is Base {
    function payout() external virtual override nonReentrant {
        bal[msg.sender] = 2;
    }
}
contract D is L, R {
    function payout() external override(L, R) {
        bal[msg.sender] = 0;
    }
}
"""


def test_diamond_join_reads_the_most_derived_body_not_the_three_guarded_ones(tmp_path):
    contract = _contract(tmp_path, _DIAMOND, "D")
    verdicts = verified_guard_verdicts(contract)
    assert verdicts["payout()"] == _refusal(W2_REASON_GUARD_NOT_APPLIED, "D.payout()")
    guarded_ancestors = [
        f for f in contract.functions if f.full_name == "payout()" and f.canonical_name != "D.payout()"
    ]
    assert len(guarded_ancestors) == 3
    assert all(f.is_shadowed and f.modifiers for f in guarded_ancestors)


class _Fn:
    is_constructor = False

    def __init__(self, canonical_name: str, full_name: str, is_shadowed: bool, modifiers=()):
        self.canonical_name = canonical_name
        self.full_name = full_name
        self.is_shadowed = is_shadowed
        self.modifiers = list(modifiers)


class _Contract:
    def __init__(self, functions):
        self.functions = functions
        self.modifiers = []


def test_two_live_declarations_of_one_signature_refuse(tmp_path):
    """Solidity won't compile this shape, so it runs on a stub."""
    contract = _Contract(
        [
            _Fn("A.payout()", "payout()", is_shadowed=False),
            _Fn("B.payout()", "payout()", is_shadowed=False),
            _Fn("A.solo()", "solo()", is_shadowed=False),
        ]
    )
    verdicts = verified_guard_verdicts(contract)
    assert verdicts["payout()"] == _refusal(W2_REASON_AMBIGUOUS_DECLARATION)
    assert verdicts["solo()"] == _refusal(W2_REASON_NO_VERIFIED_GUARD, "A.solo()")


def test_proven_dict_is_empty_when_no_modifier_earns_it(tmp_path):
    contract = _contract(tmp_path, _A13_FAKE_GUARD_NO_REVERT, "C")
    assert reentrancy_guard_modifiers(contract) == {}
    assert [m.canonical_name for m in contract.modifiers] == ["C.notAGuard()"]
