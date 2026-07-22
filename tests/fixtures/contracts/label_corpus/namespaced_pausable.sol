// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/// Namespaced (ERC-7201 style) pause latch: the flag lives in a struct at a
/// keccak-derived slot reached through assembly, so the write is recorded as a
/// `bytes32` slot pseudo-variable rather than a `bool` state variable. This is
/// the shape the etherfi money contracts use (`Pausable.sol` / `PausableUntil.sol`)
/// and the one a bool-only pause matcher cannot see.
contract NamespacedPausable {
    struct PausableStorage {
        bool paused;
    }

    // keccak256("pausable.storage")
    bytes32 private constant PAUSABLE_STORAGE_SLOT =
        0x78b0b9eaa76f2f3afc4ee6c17ac4a6b5c1dfd190bc39879fb866c5b50b872744;

    address public guardian;
    mapping(address => uint256) public balanceOf;

    error ContractPaused();
    error NotGuardian();
    error AlreadyPaused();
    error NotPaused();

    constructor() {
        guardian = msg.sender;
    }

    function _getPausableStorage() internal pure returns (PausableStorage storage $) {
        assembly {
            $.slot := PAUSABLE_STORAGE_SLOT
        }
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert NotGuardian();
        _;
    }

    modifier whenNotPaused() {
        if (paused()) revert ContractPaused();
        _;
    }

    function paused() public view returns (bool) {
        return _getPausableStorage().paused;
    }

    function pause() external onlyGuardian {
        PausableStorage storage $ = _getPausableStorage();
        if ($.paused) revert AlreadyPaused();
        $.paused = true;
    }

    function unpause() external onlyGuardian {
        PausableStorage storage $ = _getPausableStorage();
        if (!$.paused) revert NotPaused();
        $.paused = false;
    }

    /// Guarded by the namespaced latch — the blast radius a pause claim implies.
    function transfer(address to, uint256 amount) external whenNotPaused {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }

    /// Deliberately NOT pause-guarded: a pause claim must not imply this one.
    function approveSelf(uint256 amount) external {
        balanceOf[msg.sender] += amount;
    }
}
