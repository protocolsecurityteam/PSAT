// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Timestamp state that is NOT a timed pause. Each contract is pause-shaped except where noted, so most isolate one
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

    function clearInterval() external onlyOwner {
        nextAllowed = 0;
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

    function closeSale() external onlyOwner {
        saleEnds = 0;
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

    function cancelVesting() external onlyOwner {
        startTime = 0;
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

    function resetPoke() external onlyOwner {
        lastPoke = 0;
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

// A cancellable schedule whose run leaves it in place: only the set-schedule requirement separates it from a pause.
contract ArmedSchedule is Owned {
    uint48 public constant DELAY = 3 days;
    uint48 public runSchedule;
    uint256 public runs;

    function scheduleRun() external onlyOwner {
        runSchedule = uint48(block.timestamp) + DELAY;
    }

    function cancelRun() external onlyOwner {
        runSchedule = 0;
    }

    function run() external {
        require(runSchedule != 0, "unset");
        require(runSchedule < block.timestamp, "not ready");
        runs += 1;
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

    function resume() external onlyOwner {
        haltedUntil = 0;
    }

    function transfer(address to, uint256 amount) external {
        require(block.number > haltedUntil, "halted");
        _move(to, amount);
    }
}


// Synthetix StakingRewards: the reward period can only run out, never be lifted early.
contract StakingRewardsPeriod is Owned {
    address public rewardsDistribution;
    uint256 public periodFinish;
    uint256 public rewardRate;
    uint256 public rewardsDuration = 7 days;
    uint256 public lastUpdateTime;

    modifier onlyRewardsDistribution() {
        require(msg.sender == rewardsDistribution, "not distribution");
        _;
    }

    function notifyRewardAmount(uint256 reward) external onlyRewardsDistribution {
        rewardRate = reward / rewardsDuration;
        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp + rewardsDuration;
    }

    function setRewardsDuration(uint256 duration) external onlyOwner {
        require(block.timestamp > periodFinish, "period active");
        rewardsDuration = duration;
    }
}

// Commit/apply timelock with a cancel: apply reads the value the commit staged.
contract CommitApplyCancel is Owned {
    uint256 public fee;
    uint256 public pendingFee;
    uint256 public feeUnlockTime;

    function commitFee(uint256 newFee) external onlyOwner {
        pendingFee = newFee;
        feeUnlockTime = block.timestamp + 3 days;
    }

    function cancelFee() external onlyOwner {
        delete feeUnlockTime;
        delete pendingFee;
    }

    function applyFee() external onlyOwner {
        require(block.timestamp >= feeUnlockTime, "locked");
        fee = pendingFee;
    }
}

// A sale window: buying is open only while the deadline is ahead; finalize waits for it.
contract SaleWindow is Owned {
    uint256 public saleEnds;
    bool public finalized;

    function openSale() external onlyOwner {
        saleEnds = block.timestamp + 7 days;
    }

    function cancelSale() external onlyOwner {
        saleEnds = 0;
    }

    function buy(address to, uint256 amount) external {
        require(block.timestamp < saleEnds, "closed");
        _move(to, amount);
    }

    function finalize() external {
        require(block.timestamp >= saleEnds, "open");
        finalized = true;
    }
}

// An ERC-7201 global rate limit re-armed inside the gated entry point's modifier.
contract NamespacedRateLimit is Owned {
    struct RateLimit {
        uint256 nextAllowed;
    }

    bytes32 private constant RATE_LIMIT_SLOT = 0x1111111111111111111111111111111111111111111111111111111111111111;

    function _rateLimit() internal pure returns (RateLimit storage $) {
        assembly {
            $.slot := RATE_LIMIT_SLOT
        }
    }

    modifier rateLimited() {
        RateLimit storage $ = _rateLimit();
        require($.nextAllowed < block.timestamp, "rate limited");
        $.nextAllowed = block.timestamp + 1 hours;
        _;
    }

    function resetInterval() external onlyOwner {
        _rateLimit().nextAllowed = block.timestamp + 1 hours;
    }

    function clearInterval() external onlyOwner {
        _rateLimit().nextAllowed = 0;
    }

    function consume(address to, uint256 amount) external rateLimited {
        _move(to, amount);
    }
}

// A per-user lock sharing the scalar latch's member name in the same namespace: only the scalar gates every caller,
// and nothing arms the scalar.
contract NamespacedMemberAlias is Owned {
    struct Info {
        uint256 pausedUntil;
    }

    struct Locks {
        uint256 pausedUntil;
        mapping(address => Info) infos;
    }

    bytes32 private constant LOCKS_SLOT = 0x2222222222222222222222222222222222222222222222222222222222222222;

    function _locks() internal pure returns (Locks storage $) {
        assembly {
            $.slot := LOCKS_SLOT
        }
    }

    function lockUser(address user) external onlyOwner {
        Locks storage $ = _locks();
        $.infos[user].pausedUntil = block.timestamp + 1 days;
    }

    function unlockAll() external onlyOwner {
        _locks().pausedUntil = 0;
    }

    function transfer(address to, uint256 amount) external {
        require(_locks().pausedUntil < block.timestamp, "paused");
        require(_locks().infos[msg.sender].pausedUntil < block.timestamp, "locked");
        _move(to, amount);
    }
}

// Two namespaces sharing a member name: the oracle's stamp is armed, the gating namespace's member never is.
contract NamespacedTwoSlots is Owned {
    struct Gate {
        uint256 lastUpdate;
    }

    struct Oracle {
        uint256 lastUpdate;
        uint256 price;
    }

    bytes32 private constant GATE_SLOT = 0x3333333333333333333333333333333333333333333333333333333333333333;
    bytes32 private constant ORACLE_SLOT = 0x4444444444444444444444444444444444444444444444444444444444444444;

    function _gate() internal pure returns (Gate storage $) {
        assembly {
            $.slot := GATE_SLOT
        }
    }

    function _oracle() internal pure returns (Oracle storage $) {
        assembly {
            $.slot := ORACLE_SLOT
        }
    }

    function postPrice(uint256 price) external onlyOwner {
        Oracle storage oracle = _oracle();
        oracle.price = price;
        oracle.lastUpdate = block.timestamp + 1 hours;
    }

    function clearGate() external onlyOwner {
        _gate().lastUpdate = 0;
    }

    function transfer(address to, uint256 amount) external {
        require(_gate().lastUpdate < block.timestamp, "gated");
        _move(to, amount);
    }
}

// OZ v4 TimelockController's read path, with a cancel that clears the eta: the eta reaches the gate through getters and
// is keyed by operation, so it is never a scalar latch.
contract TimelockGetterEta is Owned {
    uint256 internal constant _DONE_TIMESTAMP = uint256(1);
    mapping(bytes32 => uint256) private _timestamps;

    event Executed(bytes32 id);

    function getTimestamp(bytes32 id) public view virtual returns (uint256 timestamp) {
        return _timestamps[id];
    }

    function isOperationReady(bytes32 id) public view virtual returns (bool ready) {
        uint256 timestamp = getTimestamp(id);
        return timestamp > _DONE_TIMESTAMP && timestamp <= block.timestamp;
    }

    function schedule(bytes32 id) external onlyOwner {
        _timestamps[id] = block.timestamp + 2 days;
    }

    function cancel(bytes32 id) external onlyOwner {
        delete _timestamps[id];
    }

    function execute(bytes32 id) external {
        _beforeCall(id);
        emit Executed(id);
    }

    function _beforeCall(bytes32 id) private view {
        require(isOperationReady(id), "TimelockController: operation is not ready");
    }
}
