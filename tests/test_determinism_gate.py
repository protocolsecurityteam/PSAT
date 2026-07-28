"""The determinism gate, offline half.

Two defect classes wear the same word and a test covering one silently passes
the other:

* **string-hash** — ``set[str]`` iteration, pinnable by ``PYTHONHASHSEED``.
  Covered by ``test_effects_selection.py::test_reachable_value_is_identical_across_processes``
  (real child processes, four seeds) plus the seed sweep in
  ``scripts/determinism_gate.sh``.
* **allocation-order** — ``object.__hash__`` on Slither variables, so iteration
  follows ``id()``. **No seed pins it**, and before this file the offline suite
  had no test of the shape at all: nothing in the suite varied
  ``PYTHONHASHSEED``, and no test re-ran an aggregate in a fresh interpreter.

The tests below own the second class. They run the real static pipeline in
child processes under different allocation environments, because that is the
only place the class is expressible — a same-process assertion sees one heap,
and eight fresh processes under pymalloc see the same heap eight times
(measured: the pre-fix implementation was byte-identical across 20 of 20 such
runs while publishing a wrong destination on two functions).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("slither")

REPO = Path(__file__).resolve().parents[1]
PROBE = REPO / "scripts" / "determinism_probe_taint.py"
GATE = REPO / "scripts" / "determinism_gate.sh"

# Enough malloc runs that agreement by chance is negligible without making the
# suite slow. Measured at a fixed seed: pymalloc yields ONE control payload in 30
# consecutive runs, malloc two to four depending on the session, and in one
# session malloc's most common value coincided with pymalloc's on 7 runs of 20.
# Three malloc runs therefore agree with pymalloc by chance with p ≈ 0.04 —
# which is why the DISCRIMINATION check lives in the gate script (twelve runs)
# and this test asserts only the non-flaky half: that the published binding does
# not move. Binding stability itself was 1 distinct payload across 60 runs.
_MATRIX = [("pymalloc", ""), ("pymalloc", "boring,safe"), ("malloc", ""), ("malloc", ""), ("malloc", "safe")]


def _run(allocator: str, preamble: str) -> dict:
    env = dict(os.environ, PYTHONMALLOC=allocator, PYTHONHASHSEED="0")
    proc = subprocess.run(
        [sys.executable, str(PROBE), "--preamble", preamble],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    assert proc.returncode == 0, f"probe failed [{allocator}|{preamble}]: {proc.stderr[-2000:]}"
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def matrix() -> list[dict]:
    return [_run(alloc, pre) for alloc, pre in _MATRIX]


def _digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def test_exec_arbitrary_binding_is_identical_across_allocation_environments(matrix):
    """The published witness must not depend on where objects happened to land."""
    digests = {_digest(run["binding"]) for run in matrix}
    assert len(digests) == 1, (
        f"exec.arbitrary witness varies across allocation environments: {len(digests)} distinct payloads. "
        "This is the allocation-order class; no PYTHONHASHSEED value pins it."
    )


def test_the_proved_binding_is_present_and_not_hedged(matrix):
    """A gate that can be satisfied by emitting nothing is not a gate.

    ``singlyAssignedLocal`` has exactly one definition of its destination, so the
    honest answer is the parameter name — not ``not_determined``. Without this
    assertion every test in this file would stay green against an implementation
    that resolved everything to ``not_determined`` — which is how a positive
    control was nearly suppressed once before, by a proposal that passed its tests.
    """
    witness = matrix[0]["binding"]["singlyAssignedLocal(address,bytes)"]
    assert witness["destination_kind"] == "param"
    assert witness["destination_param"] == "a"
    assert witness["destination_basis"] == "call_destination"
    # And the hedge is still reachable on the function that earns it.
    branched = matrix[0]["binding"]["branchedParams(address,address,bytes,bool)"]
    assert branched["destination_kind"] == "not_determined"
    assert branched["destination_param"] is None


def test_the_control_instrument_is_wired_and_disagrees_with_the_binding(matrix):
    """The control instrument has to keep discriminating, or it is not evidence.

    The probe recomputes the *removed* ``next(iter(<set intersection>))`` idiom
    beside the real answer, and the gate requires that recomputation to vary. An
    instrument that silently stopped running would make the gate green forever.
    Here we pin the two facts a dead instrument would break: it produces picks at
    all, and on the functions where a choice exists it does not agree with the
    binding — so a run in which it varies is a run in which the old code would
    have published a different witness.
    """
    control = matrix[0]["unordered_control"]
    assert control, "the pre-fix idiom recomputation produced nothing; the gate's instrument is dead"

    # `compose(address from, address to, ...)` puts BOTH address parameters in the
    # call's read set and the destination is the second. The read-set pick names a
    # source; the operand-position binding names the destination.
    assert control["compose(address,address,bytes,bytes)"]["destination_param"] == "from"
    assert matrix[0]["binding"]["compose(address,address,bytes,bytes)"]["destination_param"] == "to"

    # `rebalance` has no parameter destination at all — the call goes to a storage
    # variable — so any read-set pick is wrong by construction. The pre-fix idiom
    # still names one of the two argument parameters; the current pipeline mints
    # NO claim here at all, because a proven state-variable destination is the
    # proof that the claim's sentence ("forwards a caller-supplied target") is
    # false. The proven-absent fact moved out of `binding` and into
    # `suppressed_state_var`, which is where the gate now watches it.
    assert control["rebalance(address,address,bytes)"]["destination_param"] in {"fromAsset", "toAsset"}
    assert "rebalance(address,address,bytes)" not in matrix[0]["binding"]
    suppressed = matrix[0]["suppressed_state_var"]
    assert suppressed["rebalance(address,address,bytes)"]["destination_kind"] == "state_var"
    assert suppressed["rebalance(address,address,bytes)"]["destination_param"] is None


def test_the_gate_still_carries_the_column_that_sees_the_allocation_class():
    """The cheapest way for this gate to die is for someone to drop the slow
    column. Repetition under pymalloc is inert here (1 distinct control payload
    in 20 measured runs); the allocator is the whole detector, so its presence is
    pinned rather than left to review."""
    assert GATE.exists() and os.access(GATE, os.X_OK), "determinism_gate.sh must exist and be executable"
    text = GATE.read_text()
    assert text.count('"malloc|') >= 4, "class-B matrix lost its PYTHONMALLOC=malloc runs"
    assert "class A" in text and "class B" in text, "the gate must name which class each check covers"
