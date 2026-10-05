// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// etherfi's PausableUntil: a timed pause stored as a uint timestamp in an ERC-7201 struct, beside the indefinite bool
// Pausable. `pauseUntil` arms the latch to block.timestamp + the configured window, `unpauseUntil` clears it, and every
// whenNotPaused entry point reverts while the latch is ahead of the clock. The window and the per-pauser cooldown live
// in the same struct.
contract NamespacedPauseUntil {
    struct PausableStorage {
        bool paused;
    }

    struct PausableUntilStorage {
        uint256 pausedUntil;
        uint256 pauseUntilDuration;
        mapping(address => uint256) lastPauseTimestamp;
    }

    // keccak256("pausable.storage")
    bytes32 private constant PAUSABLE_STORAGE_SLOT = 0x78b0b9eaa76f2f3afc4ee6c17ac4a6b5c1dfd190bc39879fb866c5b50b872744;
    // keccak256("pausableUntil.storage")
    bytes32 private constant PAUSABLE_UNTIL_STORAGE_SLOT =
        0x2c7e4bc092c2002f0baaf2f47367bc442b098266b43d189dafe4cb25f1e1fea2;

    uint256 public constant MIN_PAUSE_DURATION = 8 hours;
    uint256 public constant MAX_PAUSE_DURATION = 30 days;
    uint256 public constant PAUSER_UNTIL_COOLDOWN = 7 days;

    address public guardian;
    address public operatingMultisig;
    address public operatingTimelock;
    mapping(address => uint256) public balanceOf;

    error NotAuthorized();
    error ContractPaused();
    error ContractPausedUntil(uint256 pausedUntil);
    error ContractNotPausedUntil();
    error PauserCooldownStillActive();
    error InvalidPauseUntilDuration();

    constructor(address _guardian, address _multisig, address _timelock) {
        guardian = _guardian;
        operatingMultisig = _multisig;
        operatingTimelock = _timelock;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert NotAuthorized();
        _;
    }

    modifier onlyOperatingMultisig() {
        if (msg.sender != operatingMultisig) revert NotAuthorized();
        _;
    }

    modifier onlyOperatingTimelock() {
        if (msg.sender != operatingTimelock) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (_getPausableStorage().paused) revert ContractPaused();
        _requireNotPausedUntil();
        _;
    }

    function _getPausableStorage() internal pure returns (PausableStorage storage $) {
        assembly {
            $.slot := PAUSABLE_STORAGE_SLOT
        }
    }

    function _getPausableUntilStorage() internal pure returns (PausableUntilStorage storage $) {
        assembly {
            $.slot := PAUSABLE_UNTIL_STORAGE_SLOT
        }
    }

    function pause() external onlyGuardian {
        _getPausableStorage().paused = true;
    }

    function unpause() external onlyOperatingMultisig {
        _getPausableStorage().paused = false;
    }

    function pauseUntil() external onlyGuardian {
        _pauseUntil();
    }

    function unpauseUntil() external onlyOperatingMultisig {
        _requirePausedUntil();
        PausableUntilStorage storage $ = _getPausableUntilStorage();
        $.pausedUntil = 0;
    }

    function setPauseUntilDuration(uint256 _pauseUntilDuration) external onlyOperatingTimelock {
        if (_pauseUntilDuration < MIN_PAUSE_DURATION || _pauseUntilDuration > MAX_PAUSE_DURATION) {
            revert InvalidPauseUntilDuration();
        }
        _getPausableUntilStorage().pauseUntilDuration = _pauseUntilDuration;
    }

    function _requireNotPausedUntil() internal view {
        uint256 _pausedUntil = _getPausableUntilStorage().pausedUntil;
        if (_pausedUntil >= block.timestamp) revert ContractPausedUntil(_pausedUntil);
    }

    function _requirePausedUntil() internal view {
        uint256 _pausedUntil = _getPausableUntilStorage().pausedUntil;
        if (_pausedUntil < block.timestamp) revert ContractNotPausedUntil();
    }

    function _pauseUntil() internal {
        _requireNotPausedUntil();
        PausableUntilStorage storage $ = _getPausableUntilStorage();
        uint256 _pauseUntilDuration = $.pauseUntilDuration;
        if (_pauseUntilDuration == 0) _pauseUntilDuration = MIN_PAUSE_DURATION;
        if ($.lastPauseTimestamp[msg.sender] + _pauseUntilDuration + PAUSER_UNTIL_COOLDOWN > block.timestamp) {
            revert PauserCooldownStillActive();
        }
        $.pausedUntil = block.timestamp + _pauseUntilDuration;
        $.lastPauseTimestamp[msg.sender] = block.timestamp;
    }

    function pausedUntil() external view returns (uint256) {
        return _getPausableUntilStorage().pausedUntil;
    }

    function transfer(address to, uint256 amount) external whenNotPaused {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
