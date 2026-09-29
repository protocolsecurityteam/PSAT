"""The determinism gate, offline half.

Two defect classes wear the same word: **string-hash** (``set[str]`` iteration,
pinnable by ``PYTHONHASHSEED``; covered by
``test_effects_selection.py::test_reachable_value_is_identical_across_processes``
and ``scripts/determinism_gate.sh``) and **allocation-order** (``object.__hash__``
on Slither variables, iteration follows ``id()``; no seed pins it).

These tests own the second class. They run the real pipeline in child processes
under different allocators because a same-process assertion sees one heap, and
fresh pymalloc processes see the same heap every time (the pre-fix implementation
was byte-identical across 20 of 20 such runs while publishing a wrong destination).
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

REPO = Path(__file__).resolve().parents[2]
PROBE = REPO / "scripts" / "determinism_probe_taint.py"
GATE = REPO / "scripts" / "determinism_gate.sh"

# Three malloc runs agree with pymalloc by chance with p ~ 0.04 (pymalloc yields
# ONE control payload in 30 runs, malloc two to four), so the DISCRIMINATION check
# lives in the gate script (twelve runs); this test asserts only the non-flaky
# half: that the published binding does not move (1 distinct payload in 60 runs).
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

    ``singlyAssignedLocal`` has one definition of its destination, so the honest
    answer is the parameter name, not ``not_determined``. Without this every other
    test stays green against an implementation that resolves everything to
    ``not_determined``.
    """
    witness = matrix[0]["binding"]["singlyAssignedLocal(address,bytes)"]
    assert witness["destination_kind"] == "param"
    assert witness["destination_param"] == "a"
    assert witness["destination_basis"] == "call_destination"
    branched = matrix[0]["binding"]["branchedParams(address,address,bytes,bool)"]
    assert branched["destination_kind"] == "not_determined"
    assert branched["destination_param"] is None


def test_the_control_instrument_is_wired_and_disagrees_with_the_binding(matrix):
    """The control instrument has to keep discriminating, or it is not evidence.

    The probe recomputes the removed ``next(iter(<set intersection>))`` idiom
    beside the real answer and the gate requires it to vary; a silently dead
    instrument would keep the gate green forever. Pin that it produces picks and,
    where a choice exists, disagrees with the binding.
    """
    control = matrix[0]["unordered_control"]
    assert control, "the pre-fix idiom recomputation produced nothing; the gate's instrument is dead"

    # `compose` has BOTH address params in the read set; the read-set pick names a
    # source, the operand-position binding names the destination (the second).
    assert control["compose(address,address,bytes,bytes)"]["destination_param"] == "from"
    assert matrix[0]["binding"]["compose(address,address,bytes,bytes)"]["destination_param"] == "to"

    # `rebalance` calls a storage-variable destination, so any read-set pick is
    # wrong by construction. The pipeline mints NO claim (a proven state-var
    # destination falsifies "forwards a caller-supplied target"); that fact lives in
    # `suppressed_state_var`, which is where the gate watches it.
    assert control["rebalance(address,address,bytes)"]["destination_param"] in {"fromAsset", "toAsset"}
    assert "rebalance(address,address,bytes)" not in matrix[0]["binding"]
    suppressed = matrix[0]["suppressed_state_var"]
    assert suppressed["rebalance(address,address,bytes)"]["destination_kind"] == "state_var"
    assert suppressed["rebalance(address,address,bytes)"]["destination_param"] is None
