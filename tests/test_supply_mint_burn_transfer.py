"""The name-independent mint/burn idiom: a zero-address-endpoint ERC-20
``Transfer`` corroborated by a monotone state-var write.

A rebasing token (etherfi ``EETH``) tracks supply in a differently-named var
(``totalShares``) and computes ``totalSupply()`` externally, so the
``total_supply_sign`` name set never resolves its ``mintShares`` / ``burnShares``
and they carried no supply claim at all. This drives the real static stack —
Slither compile -> ``build_effects`` -> ``build_claims`` — on a synthetic
rebasing share token that reproduces exactly that shape.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")

from tests.support.label_corpus import (  # noqa: E402
    SolcNotInstalled,
    _foundry_env,
    _run_static_sequence,
    _solc_select_binary,
)

# A minimal ERC-20 whose supply lives in ``totalShares`` (not ``totalSupply``),
# with a share-accounting mint/burn: the standard zero-address ``Transfer`` plus
# a monotone ``totalShares`` write. ``totalSupply()`` is a computed external view
# so ``total_supply_sign`` cannot see the write — only the Transfer idiom can.
_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

contract RebasingShareToken {
    string public name = "Rebase";
    string public symbol = "RBS";
    uint8 public decimals = 18;

    uint256 public totalShares;
    mapping(address => uint256) public shares;
    mapping(address => mapping(address => uint256)) public allowance;
    address public pool;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function totalSupply() external view returns (uint256) {
        return totalShares * 2;
    }

    function balanceOf(address a) external view returns (uint256) {
        return shares[a] * 2;
    }

    function mintShares(address user, uint256 amount) external {
        require(msg.sender == pool);
        shares[user] += amount;
        totalShares += amount;
        emit Transfer(address(0), user, amount);
    }

    function burnShares(address user, uint256 amount) external {
        require(msg.sender == pool);
        shares[user] -= amount;
        totalShares -= amount;
        emit Transfer(user, address(0), amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        shares[msg.sender] -= amount;
        shares[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        shares[from] -= amount;
        shares[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}
"""


def _rebasing_claims() -> dict[str, list[Any]]:
    from slither import Slither

    binary = _solc_select_binary("0.8.27")
    if not binary.exists():
        raise SolcNotInstalled(f"solc 0.8.27 is not installed via solc-select (expected {binary})")
    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "RebasingShareToken.sol"
        source.write_text(_SOURCE)
        with _foundry_env(binary):
            slither = Slither(str(source), solc=str(binary))
            _subject, _effects, _trees, claims_artifact = _run_static_sequence(slither, {"name": "RebasingShareToken"})
    return claims_artifact["functions"]


def _ids(claims: list[Any]) -> set[str]:
    return {c["claim_id"] for c in claims}


def _one(claims: list[Any], claim_id: str) -> dict[str, Any]:
    matches = [c for c in claims if c["claim_id"] == claim_id]
    assert len(matches) == 1, f"expected exactly one {claim_id}, got {[c['claim_id'] for c in claims]}"
    return matches[0]


@pytest.fixture(scope="module")
def rebasing_claims() -> dict[str, list[Any]]:
    try:
        return _rebasing_claims()
    except SolcNotInstalled as exc:  # pragma: no cover - only when a solc version is absent
        pytest.skip(str(exc))


def test_mint_shares_carries_supply_mint(rebasing_claims):
    claim = _one(rebasing_claims["mintShares(address,uint256)"], "supply.mint")
    assert claim["tier"] == "idiom_structural"
    assert claim["witness"] == {"kind": "mint_burn_transfer", "supply": "mint"}
    # Direction is not crossed and the name-set path did not resolve it.
    assert "supply.burn" not in _ids(rebasing_claims["mintShares(address,uint256)"])


def test_burn_shares_carries_supply_burn(rebasing_claims):
    claim = _one(rebasing_claims["burnShares(address,uint256)"], "supply.burn")
    assert claim["tier"] == "idiom_structural"
    assert claim["witness"] == {"kind": "mint_burn_transfer", "supply": "burn"}
    assert "supply.mint" not in _ids(rebasing_claims["burnShares(address,uint256)"])


def test_plain_transfer_is_not_a_supply_change(rebasing_claims):
    """A ledger move emits ``Transfer`` with both endpoints non-zero, so the
    zero-endpoint gate keeps it out of the supply family — the guard against a
    forwarder re-emitting ``Transfer`` without changing its own supply."""
    for signature in ("transfer(address,uint256)", "transferFrom(address,address,uint256)"):
        assert not _ids(rebasing_claims[signature]) & {"supply.mint", "supply.burn"}, signature
