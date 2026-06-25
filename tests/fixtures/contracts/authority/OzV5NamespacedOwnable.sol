// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// PSAT regression fixture — OZ-v5 ERC-7201 namespaced ownership, the two forms
// observed in the ether.fi (protocol_id=1) controller audit:
//
//  * OzV5Ownable — verbatim-shaped OZ v5 OwnableUpgradeable: the owner lives in a
//    namespaced struct addressed by `OwnableStorageLocation`; the gate
//    (`_checkOwner` → `owner() != _msgSender()`) surfaces the slot constant with
//    member_path ["_owner"]. Reproduces EtherfiL1SyncPoolETH (cid 615), whose
//    owner() on-chain is the EtherFi timelock.
//
//  * OzV5AccessControlDefaultAdmin — verbatim-shaped OZ v5
//    AccessControlDefaultAdminRulesUpgradeable with the
//    `owner() => defaultAdmin()` override (CumulativeMerkleDrop, cid 462). The
//    `onlyOwner` gate inlines `owner()` → `defaultAdmin()` → the PRIVATE
//    `_getAccessControlDefaultAdminRulesStorage()` accessor, which has no external
//    selector. owner()/defaultAdmin() on-chain is the Gnosis Safe.
//
// The verbatim ERC-7201 slot constants, the namespaced accessors
// (`_getOwnableStorage`, `_getAccessControlDefaultAdminRulesStorage`), the
// `OwnershipTransferred` event and the transferOwnership/renounceOwnership
// writers are reproduced so the discovered operand shapes and effect sinks match
// the on-chain contracts. The standard reads `owner()` from the same namespaced
// root the slot constant locates.

abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }
}

abstract contract OwnableUpgradeable is Context {
    /// @custom:storage-location erc7201:openzeppelin.storage.Ownable
    struct OwnableStorage {
        address _owner;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Ownable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant OwnableStorageLocation =
        0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;

    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly {
            $.slot := OwnableStorageLocation
        }
    }

    error OwnableUnauthorizedAccount(address account);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function owner() public view virtual returns (address) {
        OwnableStorage storage $ = _getOwnableStorage();
        return $._owner;
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        _transferOwnership(newOwner);
    }

    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    function _transferOwnership(address newOwner) internal virtual {
        OwnableStorage storage $ = _getOwnableStorage();
        address oldOwner = $._owner;
        $._owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

// SyncPool form: owner lives in OZ-v5 namespaced storage; the setter is
// onlyOwner. There is no plain `_owner` state var, only the slot constant.
contract OzV5Ownable is OwnableUpgradeable {
    address public tokenOut;

    event TokenOutSet(address tokenOut);

    function setTokenOut(address newTokenOut) external onlyOwner {
        tokenOut = newTokenOut;
        emit TokenOutSet(newTokenOut);
    }
}

abstract contract AccessControlDefaultAdminRulesUpgradeable is Context {
    /// @custom:storage-location erc7201:openzeppelin.storage.AccessControlDefaultAdminRules
    struct AccessControlDefaultAdminRulesStorage {
        address _currentDefaultAdmin;
        address _pendingDefaultAdmin;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.AccessControlDefaultAdminRules")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant AccessControlDefaultAdminRulesStorageLocation =
        0xeef3dac4538c82c8ace4063ab0acd2d15cdb5883aa1dff7c2673abb3d8698400;

    function _getAccessControlDefaultAdminRulesStorage()
        private
        pure
        returns (AccessControlDefaultAdminRulesStorage storage $)
    {
        assembly {
            $.slot := AccessControlDefaultAdminRulesStorageLocation
        }
    }

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error OwnableUnauthorizedAccount(address account);

    function defaultAdmin() public view virtual returns (address) {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        return $._currentDefaultAdmin;
    }

    function transferOwnership(address) public virtual {
        revert OwnableUnauthorizedAccount(_msgSender());
    }

    function renounceOwnership() public virtual {
        AccessControlDefaultAdminRulesStorage storage $ = _getAccessControlDefaultAdminRulesStorage();
        address old = $._currentDefaultAdmin;
        delete $._currentDefaultAdmin;
        emit OwnershipTransferred(old, address(0));
    }
}

// CumulativeMerkleDrop form: owner() is OVERRIDDEN to read defaultAdmin(), which
// reads the AccessControlDefaultAdminRules namespace. The onlyOwner gate inlines
// owner() -> defaultAdmin() -> _getAccessControlDefaultAdminRulesStorage(), so
// the operand surfaces as a view_call of the private namespaced accessor (no
// external selector) rather than a slot-constant member read.
contract OzV5AccessControlDefaultAdmin is AccessControlDefaultAdminRulesUpgradeable {
    address public peer;

    event PeerSet(address peer);

    function owner() public view virtual returns (address) {
        return defaultAdmin();
    }

    function _checkOwner() internal view {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function setPeer(address newPeer) external onlyOwner {
        peer = newPeer;
        emit PeerSet(newPeer);
    }
}
