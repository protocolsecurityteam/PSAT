// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Adversarial near-miss NEGATIVE: a function literally named upgradeTo(address)
// with the exact upgrade selector, but the contract is not a proxy — no
// proxiableUUID sibling, no fallback delegatecall, no Upgraded/1967 marker. It
// merely rotates a bookkeeping pointer. No upgrade gate qualifies it, so no
// upgrade.implementation claim may be minted.

contract StrategyRegistry {
    address public owner;
    address public activeStrategy;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // Same name/selector as the ERC-1822 upgrade entry, different meaning.
    function upgradeTo(address newStrategy) external onlyOwner {
        activeStrategy = newStrategy;
    }

    function changeAdmin(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}
