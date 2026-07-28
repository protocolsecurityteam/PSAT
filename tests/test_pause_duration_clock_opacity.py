"""A7 round 3: the ``no_time_reference`` proof, gated against the PRODUCTION builder.

``duration_bound_source = "no_time_reference"`` is documented as PROVEN indefinite —
"the most severe freeze there is" (``effects/config.py``), "the MOST severe freeze"
(``effects/claims_bridge.py``) — and it gates both frontend prose copies
(``claimsVocab.js``: ``"(indefinite)"`` and ``"indefinite latch (no self-recovery
bound)"``). It is a proof BY ABSENCE, so every precondition it rests on has to hold
against real compiler output, not against a hand-built leaf.

Rounds 1 and 2 were both tested with hand-built leaves only, and both times the
defect was a shape the compiler produces and the hand-built fixture did not:

* round 1 read one leaf, so a lowered ``||`` that split the latch from the clock read
  as proven-indefinite;
* round 2 walked the whole tree for a ``block_context`` clock but kept the
  OPACITY test leaf-local and its opaque-source set at ``{computed, top}`` — so
  ``require(!frozen || _clock() > unpauseAt)``, where ``_clock()`` is an internal view
  returning ``block.timestamp`` (Uniswap V3's ``_blockTimestamp()``, OZ Governor's
  ``clock()``), still published the proven state for a freeze that expires.

So these cases compile Solidity and run ``build_predicate_artifacts`` — the same call
the static stage makes, which is also what stamps the ``operand_absorption`` root
marker the proof requires. Assertions on hand-built leaf shapes live in
``test_effects_calldata.py``; this file exists to keep the gate on the compiler.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.effects import calldata as cd  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
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
    """``require(!frozen || <callee>() > unpauseAt)`` must not read as PROVEN indefinite.

    The freeze expires at ``unpauseAt`` and time alone lifts it, so the only honest
    answers are a resolved window or ``not_determined``.

    Both preconditions round 2 relied on are shown INERT on this shape first, which
    is why it was a false proof rather than a near miss: there is no
    ``block_context`` operand anywhere in the tree (so the whole-tree clock walk
    cannot see it), and the clock hides behind an operand that only NAMES a callee
    the absorption recorder never enters."""
    facts = compiled[contract_name]
    assert facts.trees, contract_name
    assert _clock_operands(facts) == 0, "rule 1 cannot see this clock — that is the premise"
    assert opaque_source in _operand_sources(facts)
    # The marker is present, so rule 2's known-completeness precondition is satisfied
    # and cannot be what produces the answer.
    assert all(cd._absorption_recorded(tree) for tree in facts.trees.values())

    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "not_determined")
    # The stored expiry is not a latch this reader can bound either: the window is a
    # timestamp in storage, not an offset in the code (etherfi's real shape).
    assert cd.read_max_pause_duration(facts, {"unpauseAt"}) == (None, "not_determined")


def test_the_proven_indefinite_state_is_still_reachable_from_compiled_source(compiled):
    """POSITIVE CONTROL for the demotion above: a discrimination, not a blanket refusal.

    ``require(!frozen)`` compiles to a tree with one leaf, one operand, no callee and
    no clock. Every precondition holds, so the proof stands and the frontend's
    "indefinite latch (no self-recovery bound)" copy is still reachable.

    R2: this is the firing proof for the ``no_time_reference`` branch itself. It has
    zero realised rows in the local database because no persisted tree carries the
    ``operand_absorption`` marker yet (the static stage has not re-run since A7) — a
    lower bound, not a dead branch."""
    facts = compiled["PlainLatch"]
    assert _operand_sources(facts) == {"state_variable"}
    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "no_time_reference")


def test_a_block_number_clock_denies_the_proven_indefinite_state(compiled):
    """``require(!frozen || block.number > unpauseAtBlock)`` must not read as PROVEN
    indefinite: the chain reaching ``unpauseAtBlock`` lifts the freeze with no
    transaction. The static plane emits ``block_context_kind == "number"`` for it —
    a clock spelling the demotion must count (its ``block.timestamp`` twin already
    lands here via the same rule)."""
    facts = compiled["NumberTwin"]
    assert facts.trees
    assert all(cd._absorption_recorded(tree) for tree in facts.trees.values())
    assert cd.read_max_pause_duration(facts, {"frozen"}) == (None, "not_determined")


def test_a_block_count_window_is_never_published_as_seconds(compiled):
    """The units trap on compiled source: ``require(block.number - pausedUntilBlock
    < 216000)`` carries latch + clock + constant, but the constant is a block
    count. ``duration_bound_seconds`` is consumed as a severity reducer in seconds;
    publishing 216000 here would understate a ~30-day gate as 2.5 days. The
    block-number clock demotes the proven state and nothing more."""
    facts = compiled["BlockWindow"]
    assert facts.trees
    assert cd.read_max_pause_duration(facts, {"pausedUntilBlock"}) == (None, "not_determined")


def test_a_window_the_recorder_did_read_is_unaffected_by_either_precondition(compiled):
    """``guard_constant`` returns before both checks, so widening them cannot cost a
    resolved window.

    ``require(block.timestamp - pausedUntil < 2592000)`` puts all three facts —
    clock, latch, offset — in one leaf's ``operands ∪ absorbed_operands``, which no
    lossy list and no unentered callee can fake. This is the assertion that keeps the
    two conservative rules from eating the reader's only positive answer."""
    facts = compiled["AbsorbedWindow"]
    assert cd.read_max_pause_duration(facts, {"pausedUntil"}) == (2592000, "guard_constant")
