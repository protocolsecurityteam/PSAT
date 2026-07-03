// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// exec.arbitrary idiom positive (BoringVault.manage-class): a body-origin
// external call whose destination AND calldata both trace to function
// parameters (address target, bytes data). No standard gate — the arbitrariness
// is proven by taint alone.

library Address {
    function functionCallWithValue(address target, bytes memory data, uint256 value)
        internal
        returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "Address: call failed");
        return ret;
    }
}

contract BoringVault {
    using Address for address;

    address public owner;

    modifier requiresAuth() {
        require(msg.sender == owner, "UNAUTHORIZED");
        _;
    }

    function manage(address target, bytes calldata data, uint256 value)
        external
        requiresAuth
        returns (bytes memory result)
    {
        result = target.functionCallWithValue(data, value);
    }

    function manageDirect(address target, bytes calldata data) external requiresAuth {
        (bool ok,) = target.call(data);
        require(ok, "manage failed");
    }
}
