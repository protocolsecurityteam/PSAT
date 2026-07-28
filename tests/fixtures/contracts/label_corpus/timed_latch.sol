// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// A7: two pause latches in one contract — one timed against a declared window,
// one genuinely indefinite. The trees come from solc, not from a hand-built leaf.
//
// HISTORY, kept because it is the whole argument for the shape below. Before A7
// this pair did NOT discriminate: ``read_max_pause_duration`` reported ``None``
// for BOTH. A Solidity comparison lowers to a leaf with exactly TWO operands, and
// when one side is arithmetic the operand recorder kept one sub-operand and
// DISCARDED the rest — ``block.timestamp < pausedUntil + MAX_PAUSE`` yielded
// ``{timestamp, MAX_PAUSE}`` (the latch gone) and ``block.timestamp - pausedUntil
// < 2592000`` yielded ``{pausedUntil, 2592000}`` (the clock gone). The reader
// wanted three facts in one leaf and a binary comparison carries two, so no source
// shape reached its positive branch: a collapsed input in the operand recorder,
// not a missing fixture. Measured over 11 compiled guard shapes: 0/11 resolved.
//
// A7 widened the LEAF rather than the operand list: the builder now also records
// what the comparison absorbed (``absorbed_operands``), the reader takes the union,
// and 10/11 shapes resolve (the 11th, ``pausedUntil < block.timestamp``, carries no
// window at all and must stay unresolved — it is etherfi's real shape).
//
// So this pair NOW discriminates, and on three states rather than two:
//   * pausedUntil ⇒ (None, "not_determined")      — a clock DOES compare it, so the
//                                                   freeze expires; the window is not
//                                                   established (see below)
//   * frozen      ⇒ (None, "no_time_reference")   — PROVEN indefinite: a lowered
//                                                   guard reads it, no clock does
//   * any latch no lowered leaf reads ⇒ (None, "not_determined")
//
// WAVE 4 (L-58): ``pausedUntil`` read ``(2592000, "guard_constant")`` here until the
// harvest became side/operator-aware. Its guard is ``block.timestamp < pausedUntil +
// MAX_PAUSE``, whose absorbed group is ``{latch, constant}`` — and the recorder sorts
// both inner operands of an ADDITION *or* a SUBTRACTION into one list, keeping neither
// the sign nor the side. So this source and ``block.timestamp < pausedUntil -
// MAX_PAUSE`` (where MAX_PAUSE is a margin, not a window) leave byte-identical
// evidence, and the blind harvest also published a LEAD TIME
// (``block.timestamp + 3600 < pausedUntil`` → 3600) and a COOLDOWN offset
// (``block.timestamp > pausedUntil + 300`` → 300) as freeze windows. The provable
// shape — the clock and the latch inside ONE absorbed additive group, i.e. their time
// difference, bounded by a constant on the other side — still resolves, from compiled
// source, in ``tests/test_pause_duration_clock_opacity.py``. Stamping the additive
// sign in the static plane is what would restore this contract's bound provably.
// Only the middle one may render as "indefinite latch (no self-recovery bound)".
// What this fixture still gates is a reader that INVENTS a bound — scraping a
// constant by name, or letting one latch inherit the other's window — because that
// value is read downstream as a severity REDUCER on the most severe case there is.
// ``tests/test_label_corpus_discrimination.py`` holds the assertions.

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

    // It compiles to two leaves — {timestamp, pausedUntil} and {timestamp, MAX_PAUSE}
    // — and neither carries all three facts in its OPERANDS; the second one's
    // ``absorbed_operands`` carries the latch and MAX_PAUSE's resolved 2592000. That
    // union is what made the constant READABLE; what it does not carry is whether
    // MAX_PAUSE was ADDED to the latch or SUBTRACTED from it, which is what would make
    // it a window rather than a margin. See the header (L-58).
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
