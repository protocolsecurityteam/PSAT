// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// G5: the token a pull moves is a STATE VARIABLE reached through a cast, so the
// receiver is a Slither temporary. safe_transfer_lib.sol takes the token as an
// IERC20 PARAMETER (head already clean) and cannot exercise this. Also carries a
// batch executor (address[]/bytes[] forwarding loop) so the exec.arbitrary "one
// array level up" shape has corpus coverage. Names are generic on purpose.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function shares(address account) external view returns (uint256);
}

library SafeERC20 {
    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        require(token.transferFrom(from, to, amount), "transfer failed");
    }
}

contract CastWrappedPull {
    using SafeERC20 for IERC20;

    address public owner;
    address public reserveAsset;   // a token the vault holds, stored as address

    modifier requiresAuth() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    // The pull: a DOUBLE cast of a state var through the safe-transfer library.
    // The receiver binds to a temporary; the head must resolve to reserveAsset.
    function deposit(uint256 amount) external {
        IERC20(address(reserveAsset)).safeTransferFrom(msg.sender, address(this), amount);
    }

    // A share read names the same token without pulling anything.
    function previewShares(address account) external view returns (uint256) {
        return IERC20(address(reserveAsset)).shares(account);
    }

    // exec.arbitrary, one array level up: a DIRECT low-level call whose
    // destination and calldata both trace to the array parameters, and the call
    // op reads an element reference. A true executor, not a fixed-destination
    // forwarder — so it legitimately mints the claim.
    function execBatch(address[] calldata targets, bytes[] calldata data) external requiresAuth {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, ) = targets[i].call(data[i]);
            require(ok, "call failed");
        }
    }
}
