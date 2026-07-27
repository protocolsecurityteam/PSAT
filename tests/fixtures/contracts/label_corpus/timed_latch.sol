// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// A7: two pause latches in one contract — one with a duration bound the IR can
// read, one genuinely indefinite.
//
// ``read_max_pause_duration`` reports ``None`` for BOTH unless a guard leaf
// compares ``block.timestamp`` against a constant AND reads that latch's own
// state variable. Every test of that reader builds its predicate trees by hand,
// so nothing proved a real compiler ever produces the leaf shape it looks for —
// the un-hedged branch was reachable only in a fixture written to match the
// reader. Here the trees come from solc.
//
// The pair is the point. A reader that returns the timed latch's constant for
// the indefinite latch too publishes a bound it cannot prove, and that value is
// read downstream as a severity REDUCER on the most severe case there is.

contract TimedLatch {
    address public owner;

    // TIMED: freezes expire, and the window is a constant the guard compares
    // block.timestamp against.
    uint256 public pausedUntil;
    uint256 public constant MAX_PAUSE = 30 days;

    // INDEFINITE: a plain boolean latch with no expiry of any kind.
    bool public frozen;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function pauseTimed() external onlyOwner {
        pausedUntil = block.timestamp + MAX_PAUSE;
    }

    function unpauseTimed() external onlyOwner {
        pausedUntil = 0;
    }

    function freeze() external onlyOwner {
        frozen = true;
    }

    function unfreeze() external onlyOwner {
        frozen = false;
    }

    // The guard that makes the bound readable: the constant, the latch and
    // block.timestamp all meet in one leaf.
    function transferTimed(address to, uint256 amount) external {
        require(block.timestamp > pausedUntil, "timed pause");
        require(block.timestamp < pausedUntil + MAX_PAUSE, "window closed");
        _move(to, amount);
    }

    // The indefinite latch's guard reads no clock, so there is no bound to read
    // and ``None`` is the correct answer for it.
    function transferFreezable(address to, uint256 amount) external {
        require(!frozen, "frozen");
        _move(to, amount);
    }

    mapping(address => uint256) public balanceOf;

    function _move(address to, uint256 amount) internal {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
