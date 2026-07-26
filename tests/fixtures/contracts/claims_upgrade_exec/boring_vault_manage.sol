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

    // Same arbitrariness, one array level up: the batch overload every executor
    // of this class ships alongside the scalar one. The call op inside the loop
    // reads an element reference, not the parameter.
    function manageBatch(address[] calldata targets, bytes[] calldata data, uint256[] calldata values)
        external
        requiresAuth
    {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok,) = targets[i].call{value: values[i]}(data[i]);
            require(ok, "manage failed");
        }
    }

    // Batch through the library helper — the indirection the scalar `manage`
    // uses, so the two shapes are covered independently of the call op kind.
    function manageBatchViaLibrary(address[] calldata targets, bytes[] calldata data) external requiresAuth {
        for (uint256 i = 0; i < targets.length; i++) {
            targets[i].functionCallWithValue(data[i], 0);
        }
    }

    // Near miss: a batch of fixed-width digests is not arbitrary calldata, so
    // widening the element type must not sweep it in.
    function commitBatch(address[] calldata targets, bytes32[] calldata digests) external requiresAuth {
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok,) = targets[i].call(abi.encode(digests[i]));
            require(ok, "commit failed");
        }
    }
}
