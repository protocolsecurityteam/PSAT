"""The ``no_time_reference`` proof, gated against the PRODUCTION builder.

``duration_bound_source = "no_time_reference"`` is PROVEN indefinite, "the MOST
severe freeze" (``effects/config.py``, ``effects/claims_bridge.py``), and gates the
frontend copies in ``claimsVocab.js``. It is a proof BY ABSENCE, so every
precondition must hold against real compiler output, not a hand-built leaf.

Two earlier attempts used hand-built leaves only and both missed a compiler shape:
the first read one leaf, so a lowered ``||`` splitting latch from clock read as
proven-indefinite; the second walked the whole tree for a ``block_context`` clock but
kept OPACITY leaf-local with opaque set ``{computed, top}``, so
``require(!frozen || _clock() > unpauseAt)`` (``_clock()`` an internal view returning
``block.timestamp``, like Uniswap V3's ``_blockTimestamp()``) still published the
proven state for a freeze that expires.

Cases compile Solidity and run ``build_predicate_artifacts``, which also stamps the
``operand_absorption`` root marker the proof requires. Hand-built-leaf assertions
live in ``test_effects_calldata.py``.
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
    """``require(!frozen || <callee>() > unpauseAt)`` must not read as PROVEN indefinite:
    time alone lifts the freeze, so the honest answers are a resolved window or
    ``not_determined``.

    Both preconditions of the whole-tree walk are shown INERT first (that is why it
    was a false proof, not a near miss): no ``block_context`` operand exists in the
    tree, and the clock hides behind an operand that only NAMES a callee the
    absorption recorder never enters."""
    facts = compiled[contract_name]
    assert facts.trees, contract_name
    assert _clock_operands(facts) == 0, "rule 1 cannot see this clock — that is the premise"
    assert opaque_source in _operand_sources(facts)
    # The marker is present, so rule 2's completeness precondition cannot be what produces the answer.
    assert all(cd._absorption_recorded(tree) for tree in facts.trees.values())

    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "not_determined")
    # The stored expiry is not a latch this reader can bound either: the window is a
    # timestamp in storage, not an offset in the code (etherfi's real shape).
    assert cd.read_max_pause_duration(facts, {"unpauseAt"}) == (None, "not_determined")


def test_the_proven_indefinite_state_is_still_reachable_from_compiled_source(compiled):
    """POSITIVE CONTROL for the demotion above: a discrimination, not a blanket refusal.

    ``require(!frozen)`` has one leaf, one operand, no callee and no clock, so the
    proof stands and the "indefinite latch" copy stays reachable.

    R2: the firing proof for the ``no_time_reference`` branch. It has zero realised
    rows locally because no persisted tree carries the ``operand_absorption`` marker
    yet (static stage not re-run since A7): a lower bound, not a dead branch."""
    facts = compiled["PlainLatch"]
    assert _operand_sources(facts) == {"state_variable"}
    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "no_time_reference")


@pytest.mark.parametrize(
    ("contract_name", "latch"),
    [
        # ``require(!frozen || block.number > unpauseAtBlock)`` must not read as PROVEN indefinite:
        # the chain reaching the block lifts the freeze with no transaction.
        # ``block_context_kind == "number"`` is a clock spelling the demotion must count (its
        # ``block.timestamp`` twin lands here via the same rule).
        pytest.param("NumberTwin", "frozen", id="block-number-clock-denies-proven-indefinite"),
        # The units trap: ``require(block.number - pausedUntilBlock < 216000)`` carries latch + clock +
        # constant, but the constant is a block count while ``duration_bound_seconds`` is a severity
        # reducer in seconds; publishing 216000 would understate a ~30-day gate as 2.5 days. The
        # block clock only demotes the proven state.
        pytest.param("BlockWindow", "pausedUntilBlock", id="block-count-window-never-published-as-seconds"),
    ],
)
def test_a_block_clock_demotes_to_not_determined(compiled, contract_name, latch):
    facts = compiled[contract_name]
    assert facts.trees
    assert all(cd._absorption_recorded(tree) for tree in facts.trees.values())
    assert cd.read_max_pause_duration(facts, {latch}) == (None, "not_determined")


@pytest.mark.parametrize(
    "contract_name",
    [
        # ``guard_constant`` returns before both checks, so widening them cannot cost a resolved
        # window: ``require(block.timestamp - pausedUntil < 2592000)`` puts clock, latch and offset
        # in one leaf's ``operands | absorbed_operands``, which no lossy list or unentered callee
        # can fake; this keeps the conservative rules from eating the only positive answer.
        pytest.param("AbsorbedWindow", id="window-the-recorder-did-read"),
        # POSITIVE CONTROLS for the side/operator awareness of the harvest: narrowed to a shape,
        # not one spelling. ``2592000 > block.timestamp - pausedUntil`` (constant on the LEFT under
        # ``gt``) and ``pausedUntil - block.timestamp < 2592000`` (reversed subtraction) bound the
        # gap by the same magnitude and must keep resolving.
        pytest.param("WindowLeft", id="gap-ceiling-constant-on-left"),
        pytest.param("RemainingWindow", id="gap-ceiling-reversed-subtraction"),
    ],
)
def test_resolving_windows_still_resolve(compiled, contract_name):
    assert cd.read_max_pause_duration(compiled[contract_name], {"pausedUntil"}) == (2592000, "guard_constant")


@pytest.mark.parametrize(
    ("contract_name", "fabricated"),
    [
        # The two shapes that motivated narrowing the harvest.
        ("LeadTime", 3600),
        ("Cooldown", 300),
        # The same operand union as the resolving window, operator flipped.
        ("ElapsedCooldown", 600),
        # Sign unrecorded: a margin before an absolute expiry.
        ("MinusWindow", 300),
        # The mainstream window shape, refused for the SAME missing fact (see below).
        ("LatchPlusWindow", 2592000),
    ],
)
def test_a_constant_the_comparison_shape_does_not_make_a_window_is_not_published(compiled, contract_name, fabricated):
    """On compiled source, each guard puts a latch, a seconds clock and a plausible
    constant in one leaf's ``operands ∪ absorbed_operands``, and the side/operator-blind
    harvest published the constant as ``duration_bound_seconds``: a lead time, cooldown
    offset, minimum-elapsed or safety margin read as the freeze window, in the
    severity-REDUCING direction.

    ``fabricated`` is what each shape used to publish. The honest answer for all five
    is ``not_determined``: the freeze is timed but the window is not in this comparison.

    ``LatchPlusWindow`` is the recall cost, pinned deliberately: its constant IS the
    window, but the evidence is byte-identical to ``MinusWindow``'s because
    ``predicates._stamp_absorbed_operands`` records neither the additive sign nor the
    side. Stamping the sign in the static plane recovers it; this pin makes that
    change visible."""
    facts = compiled[contract_name]
    assert facts.trees, contract_name
    # The constant really is in the leaf's union, so the refusal is a shape judgment, not a missing operand.
    constants = {
        str(op.get("constant_value"))
        for tree in facts.trees.values()
        for leaf in cd._all_leaves(tree)
        for op in cd._compared_operands(leaf)
        if op.get("constant_value") is not None
    }
    assert str(fabricated) in constants, constants

    assert cd.read_max_pause_duration(facts, {"pausedUntil"}) == (None, "not_determined")
