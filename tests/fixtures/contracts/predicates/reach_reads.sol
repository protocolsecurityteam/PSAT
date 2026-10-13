// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Reach conditions as reads: an OpenZeppelin-style open role, a flag read in a bool helper's connective return, a
// state condition beside a caller check, a parameter reassigned before its branch, a branch on storage written before
// it, a caller-referencing reach condition, and a state variable only compared with calldata.

contract ReachReads {
    struct RoleData { mapping(address => bool) members; bytes32 adminRole; }

    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    mapping(bytes32 => RoleData) private _roles;
    address public owner;
    address public admin;
    address public base;
    bool public executorRequired;
    bool public locked;
    bool public frozen;
    mapping(address => bool) public allowed;
    uint256 public hook;

    modifier onlyRoleOrOpenRole(bytes32 role) {
        if (!hasRole(role, address(0))) { _checkRole(role, msg.sender); }
        _;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) { return _roles[role].members[account]; }

    function _checkRole(bytes32 role, address account) internal view {
        if (!hasRole(role, account)) { revert("AccessControl: account is missing role"); }
    }

    function execute(uint256 v) external onlyRoleOrOpenRole(EXECUTOR_ROLE) { hook = v; }

    function canExecute(address sender) public view returns (bool) { return !executorRequired || sender == owner; }

    function executeTransaction(uint256 v) external {
        if (!canExecute(msg.sender)) revert("NOT_EXECUTOR");
        hook = v;
    }

    function unlessLocked(uint256 v) external {
        require(!locked || msg.sender == owner, "LOCKED");
        hook = v;
    }

    function eitherFlag(uint256 v) external {
        require(!locked || !frozen, "CLOSED");
        hook = v;
    }

    function reassigned(uint256 v, bool open) external {
        open = !open;
        if (!open) { require(msg.sender == owner, "UNAUTHORIZED"); }
        hook = v;
    }

    function writtenFirst(uint256 v) external {
        locked = true;
        if (locked) { require(msg.sender == owner, "UNAUTHORIZED"); }
        hook = v;
    }

    function callerBranch(uint256 v) external {
        if (msg.sender != admin) { require(allowed[msg.sender], "NOT_ALLOWED"); }
        hook = v;
    }

    function rateFor(address quote) external view returns (uint256) {
        if (quote == base) return hook;
        require(allowed[quote], "UNPEGGED");
        return hook * 2;
    }
}
