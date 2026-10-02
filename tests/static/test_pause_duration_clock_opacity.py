"""``no_time_reference`` is a proof by absence of the most severe freeze, so it's tested against real compiler
output. Two earlier hand-built-leaf attempts missed shapes: a lowered ``||`` splitting latch from clock, and a
clock behind an internal view (``_clock()``, like Uniswap V3's ``_blockTimestamp()``). Hand-built leaf
assertions live in ``test_effects_calldata.py``.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.effects import calldata as cd
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    build_predicate_artifacts,
)

SOURCE = """
    pragma solidity ^0.8.19;

    interface ITime { function nowSeconds() external view returns (uint256); }

    contract HelperClock {
        bool public frozen;
        uint256 public unpauseAt;
        address public sink;

        // The mainstream indirection: Uniswap V3's pool reads `_blockTimestamp()`,
        // OZ Governor reads `clock()`.
        function _clock() internal view returns (uint256) { return block.timestamp; }

        function freeze(bool v) external { frozen = v; }

        function transferViewClock(address to) external {
            require(!frozen || _clock() > unpauseAt, "frozen");
            sink = to;
        }
    }

    contract OracleClock {
        bool public frozen;
        uint256 public unpauseAt;
        address public sink;
        ITime public oracle;

        function freeze(bool v) external { frozen = v; }

        function transferExtClock(address to) external {
            require(!frozen || oracle.nowSeconds() > unpauseAt, "frozen");
            sink = to;
        }
    }

    contract PlainLatch {
        bool public frozen;
        address public sink;

        function freeze(bool v) external { frozen = v; }

        // Nothing in this guard tree is unread and nothing in it is a clock: no
        // passage of time lifts this freeze. THE proven-indefinite shape.
        function transferFreezable(address to) external {
            require(!frozen, "frozen");
            sink = to;
        }
    }

    contract AbsorbedWindow {
        uint256 public pausedUntil;
        address public sink;

        // The window IS in the code, one subtraction deep. `operands` holds
        // {pausedUntil, 2592000} and `absorbed_operands` recovers the clock.
        function transferTimed(address to) external {
            require(block.timestamp - pausedUntil < 2592000, "window");
            sink = to;
        }
    }

    contract NumberTwin {
        bool public frozen;
        uint256 public unpauseAtBlock;
        address public sink;

        function freeze(bool v) external { frozen = v; }

        // Byte-identical to the timestamp shape one clock spelling over: the
        // freeze lifts when the chain reaches unpauseAtBlock, so proven-indefinite
        // is false.
        function transferBlockClock(address to) external {
            require(!frozen || block.number > unpauseAtBlock, "frozen");
            sink = to;
        }
    }

    contract BlockWindow {
        uint256 public pausedUntilBlock;
        address public sink;

        // The window constant is a BLOCK COUNT, not seconds.
        function transferBlockWindow(address to) external {
            require(block.number - pausedUntilBlock < 216000, "window");
            sink = to;
        }
    }

    // Every contract below puts a latch, a seconds clock and a
    // plausible constant in ONE leaf's `operands ∪ absorbed_operands` — the union the
    // harvest used to read blind — and in none of them is the constant the freeze
    // window. Compiled, not hand-built, because the arrangement of the union is
    // exactly what the defect turned on.
    contract WindowLeft {
        uint256 public pausedUntil;
        address public sink;

        // The AbsorbedWindow fact mirrored across the operator: still a ceiling on
        // the clock-to-latch gap, so it must still resolve.
        function transferMirrored(address to) external {
            require(2592000 > block.timestamp - pausedUntil, "window");
            sink = to;
        }
    }

    contract RemainingWindow {
        uint256 public pausedUntil;
        address public sink;

        // The REMAINING-time spelling of the same gap. Both subtraction orders bound
        // the gap by the same magnitude, which is why the sign the recorder drops does
        // not matter for this arm.
        function transferRemaining(address to) external {
            require(pausedUntil - block.timestamp < 2592000, "window");
            sink = to;
        }
    }

    contract LeadTime {
        uint256 public pausedUntil;
        address public sink;

        // 3600 is a LEAD TIME on the clock, not a window: the freeze ends at the
        // stored `pausedUntil` and nothing here bounds how far away that is.
        function transferLead(address to) external {
            require(block.timestamp + 3600 < pausedUntil, "lead");
            sink = to;
        }
    }

    contract Cooldown {
        uint256 public pausedUntil;
        address public sink;

        // 300 is an offset on the stored expiry. The freeze lasts until
        // `pausedUntil + 300` — an absolute timestamp — so 300 is not its length.
        function transferCooldown(address to) external {
            require(block.timestamp > pausedUntil + 300, "cool");
            sink = to;
        }
    }

    contract ElapsedCooldown {
        uint256 public pausedUntil;
        address public sink;

        // Same operand union as AbsorbedWindow, operator flipped: 600 is a MINIMUM
        // elapsed, and the region this guard blocks is unbounded above.
        function transferElapsed(address to) external {
            require(block.timestamp - pausedUntil > 600, "cool");
            sink = to;
        }
    }

    contract MinusWindow {
        uint256 public pausedUntil;
        address public sink;

        // Byte-identical evidence to `block.timestamp < pausedUntil + 300` — the
        // recorder sorts both inner operands of an ADDITION or a SUBTRACTION into one
        // list and keeps neither sign nor side — and here 300 is a safety margin
        // BEFORE an absolute expiry, not a window.
        function transferMinus(address to) external {
            require(block.timestamp < pausedUntil - 300, "margin");
            sink = to;
        }
    }

    contract LatchPlusWindow {
        uint256 public pausedUntil;
        uint256 public constant MAX_PAUSE = 30 days;
        address public sink;

        // The mainstream window shape, and the recall this narrowing costs: it is
        // indistinguishable HERE from MinusWindow above until the static plane stamps
        // the additive sign.
        function transferPlus(address to) external {
            require(block.timestamp < pausedUntil + MAX_PAUSE, "window");
            sink = to;
        }
    }
"""


@pytest.fixture(scope="module")
def compiled(tmp_path_factory) -> dict[str, cd.ContractFacts]:
    path = tmp_path_factory.mktemp("a7") / "A7.sol"
    path.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    slither = Slither(str(path))
    out: dict[str, cd.ContractFacts] = {}
    for contract in slither.contracts:
        artifacts = build_predicate_artifacts(contract) or {}
        out[contract.name] = cd.ContractFacts(
            address="0x" + "11" * 20,
            job_id=None,
            effects={},
            trees=artifacts.get("trees") or {},
            canonical_signatures=artifacts.get("canonical_signatures") or {},
        )
    return out


def _operand_sources(facts: cd.ContractFacts) -> set[str]:
    return {
        str(op.get("source"))
        for tree in facts.trees.values()
        for leaf in cd._all_leaves(tree)
        for op in cd._compared_operands(leaf)
    }


def _clock_operands(facts: cd.ContractFacts) -> int:
    return sum(
        1
        for tree in facts.trees.values()
        for leaf in cd._all_leaves(tree)
        for op in cd._compared_operands(leaf)
        if op.get("block_context_kind") == "timestamp"
    )


@pytest.mark.parametrize(
    ("contract_name", "opaque_source"),
    [("HelperClock", "view_call"), ("OracleClock", "external_call")],
)
def test_a_clock_behind_a_callee_denies_the_proven_indefinite_state(compiled, contract_name, opaque_source):
    """Time alone lifts this freeze.

    Both whole-tree preconditions are shown inert first, which is why it was a false proof.
    """
    facts = compiled[contract_name]
    assert facts.trees, contract_name
    assert _clock_operands(facts) == 0, "rule 1 cannot see this clock — that is the premise"
    assert opaque_source in _operand_sources(facts)
    assert all(cd._absorption_recorded(tree) for tree in facts.trees.values())

    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "not_determined")
    # The window is a timestamp in storage, not an offset in code (etherfi's real shape).
    assert cd.read_max_pause_duration(facts, {"unpauseAt"}) == (None, "not_determined")


@pytest.mark.parametrize(
    ("contract_name", "fabricated"),
    [
        ("LeadTime", 3600),
        ("Cooldown", 300),
        ("ElapsedCooldown", 600),
        ("MinusWindow", 300),
        ("LatchPlusWindow", 2592000),
    ],
)
def test_a_constant_the_comparison_shape_does_not_make_a_window_is_not_published(compiled, contract_name, fabricated):
    """The side/operator-blind harvest published lead times and cooldowns as the freeze window, reducing severity.

    ``LatchPlusWindow`` is the pinned recall cost: ``_stamp_absorbed_operands`` records neither sign nor side, so it's
    indistinguishable from ``MinusWindow``.
    """
    facts = compiled[contract_name]
    assert facts.trees, contract_name
    constants = {
        str(op.get("constant_value"))
        for tree in facts.trees.values()
        for leaf in cd._all_leaves(tree)
        for op in cd._compared_operands(leaf)
        if op.get("constant_value") is not None
    }
    assert str(fabricated) in constants, constants

    assert cd.read_max_pause_duration(facts, {"pausedUntil"}) == (None, "not_determined")
