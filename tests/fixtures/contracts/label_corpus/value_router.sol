// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Synthetic router + vault pair: the entry point is neither the source nor the
// sink of the funds, it CALLS a second in-unit contract whose body moves them
// (`value_router`). The corpus had zero coverage of this shape, and the four
// distinct amount shapes below are exactly the ones that were being published
// wrongly or not at all:
//
//  * bridge — routes `vault.exit(..., 0, ...)`, and the vault guards
//    `if (assetAmount > 0)`. The transfer PROVABLY cannot execute, so a routed
//    flow published here is an invented one.
//  * redeem — the amount is `shares * rate / ONE`, i.e. library arithmetic over
//    an EXTERNAL call's return value with a caller parameter and a constant.
//    The ERC-4626 redemption shape, in every vault of this kind.
//  * deposit — payable; the amount parameter is REASSIGNED from `msg.value` on
//    the native branch, so the amount's origin set holds both a parameter and
//    msg.value. Both members are caller-supplied.
//  * depositFor — reaches the same vault sink through a helper WITHOUT the
//    reassignment, which is what proves the deposit shape above is caused by
//    the reassignment and not by the helper.
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IAccountant {
    function getRateInQuoteSafe(address quote) external view returns (uint256);
}

contract RouterVault {
    uint256 public constant ONE_SHARE = 1e18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    // The sink: sends the asset out only when the amount is non-zero. A router
    // passing a zero constant reaches this and moves nothing.
    function exit(address to, IERC20 asset, uint256 assetAmount, address from, uint256 shareAmount) external {
        if (assetAmount > 0) {
            asset.transfer(to, assetAmount);
        }
        totalSupply -= shareAmount;
        balanceOf[from] -= shareAmount;
        emit Transfer(from, address(0), shareAmount);
    }

    // The mirror sink: pulls the asset in and mints shares.
    function enter(address from, IERC20 asset, uint256 assetAmount, address to, uint256 shareAmount) external {
        if (assetAmount > 0) {
            asset.transferFrom(from, address(this), assetAmount);
        }
        totalSupply += shareAmount;
        balanceOf[to] += shareAmount;
        emit Transfer(address(0), to, shareAmount);
    }
}

library FixedPointMathLib {
    function mulDivDown(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256) {
        return (x * y) / denominator;
    }
}

contract Teller {
    using FixedPointMathLib for uint256;

    RouterVault public immutable vault;
    IAccountant public immutable accountant;
    address public immutable nativeWrapper;

    constructor(RouterVault vault_, IAccountant accountant_, address nativeWrapper_) {
        vault = vault_;
        accountant = accountant_;
        nativeWrapper = nativeWrapper_;
    }

    // Routes a zero asset amount: the vault's guard makes the transfer
    // unreachable, so there is no outflow to attribute to this function.
    function bridge(uint256 shareAmount) external {
        vault.exit(address(0), IERC20(address(0)), 0, msg.sender, shareAmount);
    }

    // param x external-rate / constant, under library math.
    function redeem(address to, IERC20 withdrawAsset, uint256 shareAmount) external {
        uint256 assetsOut = shareAmount.mulDivDown(accountant.getRateInQuoteSafe(address(withdrawAsset)), ONE());
        vault.exit(to, withdrawAsset, assetsOut, msg.sender, shareAmount);
    }

    function ONE() internal pure returns (uint256) {
        return 1e18;
    }

    // The amount parameter is reassigned from msg.value on the native branch.
    function deposit(IERC20 depositAsset, uint256 depositAmount) external payable {
        if (address(depositAsset) == nativeWrapper) {
            depositAmount = msg.value;
        }
        _enter(depositAsset, depositAmount, msg.sender);
    }

    // Same helper, same sink, no reassignment.
    function depositFor(IERC20 depositAsset, uint256 depositAmount, address to) external {
        _enter(depositAsset, depositAmount, to);
    }

    function _enter(IERC20 asset, uint256 amount, address to) internal {
        vault.enter(msg.sender, asset, amount, to, amount);
    }
}
