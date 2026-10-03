// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Timestamp state that is NOT a timed pause. Each contract is pause-shaped except where noted, so it isolates one
// conjunct of the timestamp-latch rule; none may mint pause.set or pause.unset.

abstract contract Owned {
    address public owner;
    mapping(address => uint256) public balanceOf;

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

// Timelock eta: keyed by operation and read only by execute.
contract TimelockEta is Owned {
    uint256 public constant DELAY = 2 days;
    mapping(bytes32 => uint256) public eta;

    event Executed(bytes32 id);

    function schedule(bytes32 id) external onlyOwner {
        eta[id] = block.timestamp + DELAY;
    }

    function execute(bytes32 id) external {
        require(eta[id] <= block.timestamp, "not ready");
        emit Executed(id);
    }
}

// Per-user cooldown: the timestamp is keyed by account.
contract PerUserCooldown is Owned {
    uint256 public constant COOLDOWN = 10 days;
    mapping(address => uint256) public cooldownUntil;

    function startCooldown(address user) external onlyOwner {
        cooldownUntil[user] = block.timestamp + COOLDOWN;
    }

    function redeem(address to, uint256 amount) external {
        require(cooldownUntil[msg.sender] < block.timestamp, "cooling down");
        _move(to, amount);
    }
}

// Global rate limit: one action per interval. The gated entry point re-arms the latch itself.
contract RateLimitInterval is Owned {
    uint256 public constant INTERVAL = 1 hours;
    uint256 public nextAllowed;

    function resetInterval() external onlyOwner {
        nextAllowed = block.timestamp + INTERVAL;
    }

    function consume(address to, uint256 amount) external {
        require(block.timestamp >= nextAllowed, "rate limited");
        nextAllowed = block.timestamp + INTERVAL;
        _move(to, amount);
    }
}

// A stored deadline: the window is open while the timestamp is ahead of the clock, the opposite of a pause.
contract DeadlineSale is Owned {
    uint256 public saleEnds;

    function openSale() external onlyOwner {
        saleEnds = block.timestamp + 7 days;
    }

    function buy(address to, uint256 amount) external {
        require(block.timestamp < saleEnds, "sale closed");
        _move(to, amount);
    }

    function swap(address to, uint256 amount, uint256 deadline) external {
        require(block.timestamp <= deadline, "expired");
        _move(to, amount);
    }
}

// Vesting cliff read with an offset: the gate compares start + CLIFF, and start is a bare clock stamp.
contract VestingCliff is Owned {
    uint256 public constant CLIFF = 365 days;
    uint256 public start;

    function startVesting() external onlyOwner {
        start = block.timestamp;
    }

    function release(address to, uint256 amount) external {
        require(block.timestamp >= start + CLIFF, "cliff");
        _move(to, amount);
    }
}

// A scheduled vesting start read with an offset. Only the offset read separates it from a pause: the comparison keeps
// one summand and loses the sign, so the gate's direction against the latch isn't proven.
contract VestingScheduled is Owned {
    uint256 public startTime;
    uint256 public vestingPeriod = 365 days;

    function scheduleVesting() external onlyOwner {
        startTime = block.timestamp + 7 days;
    }

    function release(address to, uint256 amount) external {
        require(block.timestamp >= startTime + vestingPeriod, "vesting");
        _move(to, amount);
    }
}

// Vesting lock fixed at deployment: nothing can re-arm it.
contract VestingLock is Owned {
    uint256 public cliffEnd;

    constructor() {
        cliffEnd = block.timestamp + 365 days;
    }

    function release(address to, uint256 amount) external {
        require(block.timestamp >= cliffEnd, "locked");
        _move(to, amount);
    }
}

// A clock stamp: the gate only blocks within the same block, and the latch is never armed ahead of the clock.
contract ClockStampGuard is Owned {
    uint256 public lastPoke;

    function poke() external onlyOwner {
        lastPoke = block.timestamp;
    }

    function act(address to, uint256 amount) external {
        require(block.timestamp > lastPoke, "same block");
        _move(to, amount);
    }
}

// A scalar delayed admin transfer (OZ AccessControlDefaultAdminRules): accept requires the schedule set and clears it.
contract DelayedAdminTransfer is Owned {
    uint48 public constant DELAY = 3 days;
    address public pendingOwner;
    uint48 public acceptSchedule;

    function beginTransfer(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        acceptSchedule = uint48(block.timestamp) + DELAY;
    }

    function accept() external {
        require(msg.sender == pendingOwner, "not pending");
        require(acceptSchedule != 0, "unset");
        require(acceptSchedule < block.timestamp, "not ready");
        owner = pendingOwner;
        delete acceptSchedule;
    }
}

// The same schedule whose accept leaves it in place: only the set-schedule requirement separates it from a pause.
contract ArmedSchedule is Owned {
    uint48 public constant DELAY = 3 days;
    address public pendingOwner;
    uint48 public acceptSchedule;

    function beginTransfer(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        acceptSchedule = uint48(block.timestamp) + DELAY;
    }

    function accept() external {
        require(msg.sender == pendingOwner, "not pending");
        require(acceptSchedule != 0, "unset");
        require(acceptSchedule < block.timestamp, "not ready");
        owner = pendingOwner;
    }
}

// Armed by the initializer only.
contract OneShotPauseUntil is Owned {
    bool private _initialized;
    uint256 public pausedUntil;

    modifier initializer() {
        require(!_initialized, "initialized");
        _initialized = true;
        _;
    }

    function initialize() external onlyOwner initializer {
        pausedUntil = block.timestamp + 1 days;
    }

    function unpauseUntil() external onlyOwner {
        pausedUntil = 0;
    }

    function transfer(address to, uint256 amount) external {
        require(pausedUntil < block.timestamp, "paused");
        _move(to, amount);
    }
}

// Only the writer itself reads the latch: nothing else is held by it.
contract NoOtherReader is Owned {
    uint256 public pausedUntil;

    function pauseUntil() external onlyOwner {
        require(pausedUntil < block.timestamp, "already paused");
        pausedUntil = block.timestamp + 1 days;
    }

    function unpauseUntil() external onlyOwner {
        pausedUntil = 0;
    }

    function transfer(address to, uint256 amount) external {
        _move(to, amount);
    }
}

// Anyone can arm it: the writer's only gate is the latch itself.
contract UnguardedPauseUntil is Owned {
    uint256 public pausedUntil;

    function pauseUntil() external {
        require(pausedUntil < block.timestamp, "already paused");
        pausedUntil = block.timestamp + 1 days;
    }

    function unpauseUntil() external onlyOwner {
        pausedUntil = 0;
    }

    function transfer(address to, uint256 amount) external {
        require(pausedUntil < block.timestamp, "paused");
        _move(to, amount);
    }
}

// Armed in seconds but compared against the block number: the units disagree, so no window is proven.
contract BlockNumberGate is Owned {
    uint256 public haltedUntil;

    function halt() external onlyOwner {
        haltedUntil = block.timestamp + 1 days;
    }

    function transfer(address to, uint256 amount) external {
        require(block.number > haltedUntil, "halted");
        _move(to, amount);
    }
}
