// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Bool flags read as revert gates. A write is a pause when the value it writes is the one another entry point's gate
// reverts on, and an unpause when it writes the other value of a flag something can set to the blocking one.

abstract contract Owned {
    address public owner;
    mapping(address => uint256) public balanceOf;

    event Shutdown();

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _move(address to, uint256 amount) internal {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}

// LiquidityPool escrowMigrationCompleted: the reader reverts while the flag is false and the writer only sets it.
contract MigrationFlag is Owned {
    error AlreadyMigrated();
    error MigrationNotComplete();

    bool public migrationCompleted;
    uint256 public locked;

    function completeMigration() external onlyOwner {
        if (migrationCompleted) revert AlreadyMigrated();
        migrationCompleted = true;
    }

    function lockFunds(uint256 amount) external {
        _lock(amount);
    }

    function _lock(uint256 amount) internal {
        if (!migrationCompleted) revert MigrationNotComplete();
        locked += amount;
    }
}

// BoosterOwner isForceTimerStarted: starting the timer is what lets the shutdown run.
contract ForceTimer is Owned {
    bool public isForceTimerStarted;
    uint256 public forceTimestamp;

    function queueForceShutdown() external onlyOwner {
        require(!isForceTimerStarted, "already started");
        isForceTimerStarted = true;
        forceTimestamp = block.timestamp + 30 days;
    }

    function forceShutdownSystem() external onlyOwner {
        require(isForceTimerStarted, "!timer start");
        require(block.timestamp > forceTimestamp, "!timer finish");
        emit Shutdown();
    }
}

// Cellar's share-price oracle: the upkeep trips its own kill switch, and no other state-changing entry point reads it.
contract SelfTrippedKillSwitch {
    error OnlyForwarder();
    error ContractKillSwitch();
    error NoUpkeepConditionMet();

    address public automationForwarder;
    bool public killSwitch;
    uint256 public answer;

    constructor(address forwarder) {
        automationForwarder = forwarder;
    }

    function performUpkeep(uint256 price) external {
        if (msg.sender != automationForwarder) revert OnlyForwarder();
        bool upkeepConditionMet;
        bool _killSwitch = killSwitch;
        if (_killSwitch) revert ContractKillSwitch();
        if (_checkIfKillSwitchShouldBeTriggered(price, answer)) return;
        if (price != answer) upkeepConditionMet = true;
        answer = price;
        if (!upkeepConditionMet) revert NoUpkeepConditionMet();
    }

    function getLatest() external view returns (uint256 ans, bool notSafeToUse) {
        if (killSwitch) return (0, true);
        return (answer, false);
    }

    function _checkIfKillSwitchShouldBeTriggered(uint256 proposed, uint256 current) internal returns (bool) {
        if (proposed > current * 2) {
            killSwitch = true;
            return true;
        }
        return false;
    }
}

// The writer is the flag's only reader.
contract SelfCheckOnly is Owned {
    error AlreadyFinalized();

    bool public finalized;

    function finalize() external onlyOwner {
        if (finalized) revert AlreadyFinalized();
        finalized = true;
    }

    function transfer(address to, uint256 amount) external {
        _move(to, amount);
    }
}

// LiquidityPool openEEthLiquidStaking/closeEEthLiquidStaking: closing is the pause.
contract OpenCloseFlag is Owned {
    bool public stakingOpened;

    modifier whenStakingOpen() {
        require(stakingOpened, "closed");
        _;
    }

    function openStaking() external onlyOwner {
        stakingOpened = true;
    }

    function closeStaking() external onlyOwner {
        stakingOpened = false;
    }

    function stake(address to, uint256 amount) external whenStakingOpen {
        _move(to, amount);
    }
}

// Gates written as comparisons with a bool literal.
contract EqualityGates is Owned {
    error NotLive();

    bool public frozen;
    bool public live;

    function freeze() external onlyOwner {
        frozen = true;
    }

    function thaw() external onlyOwner {
        frozen = false;
    }

    function goLive() external onlyOwner {
        live = true;
    }

    function halt() external onlyOwner {
        live = false;
    }

    function transfer(address to, uint256 amount) external {
        require(frozen == false, "frozen");
        if (live != true) revert NotLive();
        _move(to, amount);
    }
}

// A flag set true at deployment whose only write lowers it for good: lowering it is the pause.
contract InvertedKillSwitch is Owned {
    bool public active;

    constructor() {
        active = true;
    }

    function deactivate() external onlyOwner {
        active = false;
    }

    function transfer(address to, uint256 amount) external {
        require(active, "inactive");
        _move(to, amount);
    }
}

// AvsOperatorManager disableSlashingRegistration: a one-way kill switch, checked by a helper the victims call.
contract OneWayKillSwitch is Owned {
    error AlreadyDisabled();
    error RegistrationBlocked();

    bool public registrationDisabled;

    function disableRegistration() external onlyOwner {
        if (registrationDisabled) revert AlreadyDisabled();
        registrationDisabled = true;
    }

    function register(address to, uint256 amount) external {
        _enforceKillSwitch();
        _move(to, amount);
    }

    function _enforceKillSwitch() internal view {
        if (registrationDisabled) revert RegistrationBlocked();
    }
}

// OpenZeppelin v4 Pausable: the toggles gate each other, and the victims revert while paused.
contract PlainPausable is Owned {
    bool public paused;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    modifier whenPaused() {
        require(paused, "not paused");
        _;
    }

    function pause() external onlyOwner whenNotPaused {
        paused = true;
    }

    function unpause() external onlyOwner whenPaused {
        paused = false;
    }

    function transfer(address to, uint256 amount) external whenNotPaused {
        _move(to, amount);
    }
}

// The gate compares the flag with a caller-chosen value, so the reverting value isn't fixed.
contract ParameterComparedFlag is Owned {
    bool public locked;

    function lock() external onlyOwner {
        locked = true;
    }

    function unlock() external onlyOwner {
        locked = false;
    }

    function act(address to, uint256 amount, bool expected) external {
        require(locked == expected, "state");
        _move(to, amount);
    }
}

// Entry points on both sides of the flag: one runs only while paused.
contract TwoSidedFlag is Owned {
    bool public paused;

    function pause() external onlyOwner {
        paused = true;
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function transfer(address to, uint256 amount) external {
        require(!paused, "paused");
        _move(to, amount);
    }

    function emergencyWithdraw(address to, uint256 amount) external {
        require(paused, "not paused");
        _move(to, amount);
    }
}

// The victims read the flag through its getter, negated at the call: the reverting value carries through.
contract GetterGatedFlag is Owned {
    error Closed();

    bool private _open;

    function isOpen() public view returns (bool) {
        return _open;
    }

    function openPool() external onlyOwner {
        _open = true;
    }

    function closePool() external onlyOwner {
        _open = false;
    }

    function stake(address to, uint256 amount) external {
        if (!isOpen()) revert Closed();
        _move(to, amount);
    }
}

// OpenZeppelin v5 Pausable: ``if (paused()) revert`` through the getter. The predicate leaf lifted from the getter's
// return doesn't carry the revert's polarity, so the reverting value isn't determined.
contract GetterPausable is Owned {
    error EnforcedPause();

    bool private _paused;

    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    function paused() public view returns (bool) {
        return _paused;
    }

    function pause() external onlyOwner {
        _paused = true;
    }

    function unpause() external onlyOwner {
        _paused = false;
    }

    function transfer(address to, uint256 amount) external whenNotPaused {
        _move(to, amount);
    }

    function _requireNotPaused() internal view {
        if (paused()) revert EnforcedPause();
    }
}
