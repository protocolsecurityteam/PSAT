// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

// A FIXED, nonview destination guard: the Safe/Zodiac transaction-guard idiom
// on the value-routing side. The guard call is a mandatory revert gate that
// references the caller-supplied destination, but it is NOT the op carrying
// the routed move — so the mandatory-gate walk must treat it as unevaluable
// (blocks the negative proof) rather than transparent.
interface IGuard {
    function checkDestination(address to) external;
}

contract RouterVault {
    uint256 public totalSupply;

    function exit(address to, IERC20 asset, uint256 assetAmount, address from, uint256 shareAmount) external {
        if (assetAmount > 0) {
            asset.transfer(to, assetAmount);
        }
        totalSupply -= shareAmount;
        require(from != address(0), "from");
    }
}

contract GuardedTeller {
    RouterVault public immutable vault;
    IGuard public guard;

    constructor(RouterVault v, IGuard g) {
        vault = v;
        guard = g;
    }

    // GUARDED: a fixed-destination, nonview guard vets `to` before the routed
    // move. The destination-constraint answer must stay OPEN (not_determined):
    // the guard's revert surface may confine `to`, and nothing in the tree
    // proves whether it does.
    function redeemGuarded(address to, IERC20 asset, uint256 amount) external {
        guard.checkDestination(to);
        vault.exit(to, asset, amount, msg.sender, amount);
    }

    // CONTROL: identical body without the guard. The only mandatory leaf is
    // the router call itself — the op carrying the move — so the negative
    // proof (unconstrained_proven) is earned here and only here.
    function redeemOpen(address to, IERC20 asset, uint256 amount) external {
        vault.exit(to, asset, amount, msg.sender, amount);
    }
}
