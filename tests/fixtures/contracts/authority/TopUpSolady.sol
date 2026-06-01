// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// PSAT regression fixture for bug #6 (Solady-Ownable slot-constant authority).
// The `processTopUp` body below is transcribed VERBATIM from the on-chain
// ether.fi TopUp 0x5bdd4b0d644c0a573e0eb526ab7d7d332aaaa50e (Etherscan-verified,
// mainnet); only the surrounding imports (SafeERC20/WETH/Constants) are reduced
// to a local minimal IERC20 so the contract compiles offline. The authority
// gate — `address _owner = owner(); if (_owner != msg.sender) revert OnlyOwner()`
// — and its inheritance from the real Solady `Ownable` are unchanged, so the
// predicate builder produces the same `state_variable:_OWNER_SLOT` caller
// operand observed in production.

import {Ownable} from "./solady/Ownable.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract TopUpSolady is Ownable {
    error OnlyOwner();

    event ProcessTopUp(address token, uint256 amount);

    constructor(address initialOwner) {
        _initializeOwner(initialOwner);
    }

    // Verbatim gate from TopUp.processTopUp (transfer loop kept; SafeERC20/WETH
    // calls reduced to the local IERC20 interface).
    function processTopUp(address[] memory tokens) external {
        address _owner = owner();
        if (_owner != msg.sender) revert OnlyOwner();

        uint256 len = tokens.length;
        for (uint256 i = 0; i < len;) {
            uint256 balance = IERC20(tokens[i]).balanceOf(address(this));
            if (balance > 0) {
                IERC20(tokens[i]).transfer(_owner, balance);
                emit ProcessTopUp(tokens[i], balance);
            }
            unchecked {
                ++i;
            }
        }
    }
}
