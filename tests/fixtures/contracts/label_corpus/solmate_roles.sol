// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Synthetic Solmate Auth + RolesAuthority: the compiled proof for the
// canonical-selector role/authority families. The owner-or-authority modifier
// gives a real caller_authority equality leaf on `owner`; the three
// role/capability setters plus `canCall` form the Solmate roles gate; and
// setAuthority writes the `authority` var the permission checks consult.
interface Authority {
    function canCall(address user, address target, bytes4 functionSig) external view returns (bool);
}

contract SolmateRoles is Authority {
    address public owner;
    Authority public authority;

    mapping(address => bytes32) public getUserRoles;
    mapping(address => mapping(bytes4 => bytes32)) public getRolesWithCapability;
    mapping(address => mapping(bytes4 => bool)) public isCapabilityPublic;

    event OwnershipTransferred(address indexed user, address indexed newOwner);
    event AuthorityUpdated(address indexed user, Authority indexed newAuthority);

    constructor() {
        owner = msg.sender;
    }

    modifier requiresAuth() {
        require(
            msg.sender == owner || authority.canCall(msg.sender, address(this), msg.sig),
            "UNAUTHORIZED"
        );
        _;
    }

    function setAuthority(Authority newAuthority) public requiresAuth {
        authority = newAuthority;
        emit AuthorityUpdated(msg.sender, newAuthority);
    }

    function transferOwnership(address newOwner) public requiresAuth {
        owner = newOwner;
        emit OwnershipTransferred(msg.sender, newOwner);
    }

    function setPublicCapability(address target, bytes4 functionSig, bool enabled) public requiresAuth {
        isCapabilityPublic[target][functionSig] = enabled;
    }

    function setRoleCapability(uint8 role, address target, bytes4 functionSig, bool enabled) public requiresAuth {
        getRolesWithCapability[target][functionSig] = enabled ? bytes32(uint256(role) + 1) : bytes32(0);
    }

    function setUserRole(address user, uint8 role, bool enabled) public requiresAuth {
        getUserRoles[user] = enabled ? bytes32(uint256(role) + 1) : bytes32(0);
    }

    function canCall(address user, address target, bytes4 functionSig) public view returns (bool) {
        return isCapabilityPublic[target][functionSig] || getUserRoles[user] == getRolesWithCapability[target][functionSig];
    }
}
