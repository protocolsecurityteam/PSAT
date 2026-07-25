// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Safe positive (SafeL2-class): the gate is the getThreshold + getOwners +
// execTransaction sibling triple. Signer-set functions map to safe.signer_mgmt,
// module functions to safe.module_mgmt, setGuard to safe.set_guard, and the
// execute entries to exec.arbitrary (forward caller-supplied target + calldata).

contract SafeWallet {
    // Safe's `Enum.Operation`. Kept as a real enum so the fixture exercises the
    // canonical-signature lowering (enum -> uint8) the exec selectors need.
    enum Operation {
        Call,
        DelegateCall
    }

    address internal constant SENTINEL = address(0x1);

    mapping(address => address) internal owners;
    mapping(address => address) internal modules;
    uint256 internal ownerCount;
    uint256 internal threshold;
    address internal guard;
    uint256 public nonce;

    modifier authorized() {
        require(msg.sender == address(this), "only self");
        _;
    }

    // -- gate views --------------------------------------------------------
    function getThreshold() external view returns (uint256) {
        return threshold;
    }

    function getOwners() external view returns (address[] memory) {
        address[] memory arr = new address[](ownerCount);
        return arr;
    }

    // -- signer management -------------------------------------------------
    function addOwnerWithThreshold(address owner, uint256 _threshold) external authorized {
        owners[owner] = owners[SENTINEL];
        owners[SENTINEL] = owner;
        ownerCount++;
        threshold = _threshold;
    }

    function removeOwner(address prevOwner, address owner, uint256 _threshold) external authorized {
        owners[prevOwner] = owners[owner];
        owners[owner] = address(0);
        ownerCount--;
        threshold = _threshold;
    }

    function swapOwner(address prevOwner, address oldOwner, address newOwner) external authorized {
        owners[newOwner] = owners[oldOwner];
        owners[prevOwner] = newOwner;
        owners[oldOwner] = address(0);
    }

    function changeThreshold(uint256 _threshold) external authorized {
        threshold = _threshold;
    }

    // -- module management -------------------------------------------------
    function enableModule(address module) external authorized {
        modules[module] = modules[SENTINEL];
        modules[SENTINEL] = module;
    }

    function disableModule(address prevModule, address module) external authorized {
        modules[prevModule] = modules[module];
        modules[module] = address(0);
    }

    // -- guard -------------------------------------------------------------
    function setGuard(address _guard) external authorized {
        guard = _guard;
    }

    // -- execution ---------------------------------------------------------
    // The full published Safe parameter lists: the gate and the exec claims key
    // on the 4-byte selector, so a slimmed signature is a DIFFERENT function and
    // must not be recognized as Safe's.
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success) {
        nonce++;
        require(signatures.length > 0, "sig");
        (success,) = to.call{value: value}(data);
        require(success, "exec failed");
    }

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, Operation operation)
        external
        returns (bool success)
    {
        require(modules[msg.sender] != address(0), "not module");
        (success,) = to.call{value: value}(data);
    }

    function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, Operation operation)
        external
        returns (bool success, bytes memory returnData)
    {
        require(modules[msg.sender] != address(0), "not module");
        (success, returnData) = to.call{value: value}(data);
    }
}
