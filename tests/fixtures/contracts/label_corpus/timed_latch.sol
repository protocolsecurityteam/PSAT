// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// A7: two pause latches in one contract — one timed against a declared window,
// one genuinely indefinite.
//
// ``read_max_pause_duration`` reports ``None`` for BOTH unless a guard leaf
// compares ``block.timestamp`` against a constant AND reads that latch's own
// state variable. Every test of that reader builds its predicate trees by hand,
// so nothing proved a real compiler ever produces the leaf shape it looks for —
// the un-hedged branch was reachable only in a fixture written to match the
// reader. Here the trees come from solc.
//
// AND THEY DO NOT PRODUCE IT. Measured, not assumed: a Solidity comparison
// lowers to a leaf with exactly TWO operands, and when one side is arithmetic
// the recorder keeps one sub-operand and DISCARDS the other. ``block.timestamp <
// pausedUntil + MAX_PAUSE`` yields ``{timestamp, MAX_PAUSE}`` — the latch is
// gone; ``block.timestamp - pausedUntil < 2592000`` yields ``{pausedUntil,
// 2592000}`` — the clock is gone. The reader wants three facts in one leaf and a
// binary comparison can carry two, so no source shape reaches it. This is a
// collapsed input in the operand recorder, not a missing fixture, and A7 has to
// widen the leaf before any source can feed that branch.
//
// So this pair does NOT today discriminate timed from indefinite: both publish
// ``None``. What it DOES gate is a reader that invents a bound — scraping a
// constant by name, or letting one latch inherit the other's window. That value
// is read downstream as a severity REDUCER on the most severe case there is.
// When A7 lands, ``tests/test_label_corpus_discrimination.py`` must be updated
// to the asymmetry (timed ⇒ 2592000, indefinite ⇒ None), not deleted.

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

    // The guard that would make the bound readable if a leaf could hold three
    // operands. It compiles to two leaves — {timestamp, pausedUntil} and
    // {timestamp, MAX_PAUSE} — and neither carries all three, so the reader
    // finds nothing. See the header.
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
