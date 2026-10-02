"""String-hash nondeterminism is pinnable by ``PYTHONHASHSEED`` (see ``scripts/determinism_gate.sh``); these tests
own allocation-order nondeterminism (``object.__hash__`` on Slither variables). They run in child processes
under different allocators because fresh pymalloc processes share one heap layout: the pre-fix code was
byte-identical across 20 of 20 such runs while publishing a wrong destination.
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

# Three malloc runs agree with pymalloc by chance (p ~ 0.04), so the discrimination check lives in the gate script; this
# asserts only that the binding doesn't move.
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
    digests = {_digest(run["binding"]) for run in matrix}
    assert len(digests) == 1, (
        f"exec.arbitrary witness varies across allocation environments: {len(digests)} distinct payloads. "
        "This is the allocation-order class; no PYTHONHASHSEED value pins it."
    )


def test_the_proved_binding_is_present_and_not_hedged(matrix):
    """Without this, an implementation resolving everything to ``not_determined`` passes."""
    witness = matrix[0]["binding"]["singlyAssignedLocal(address,bytes)"]
    assert witness["destination_kind"] == "param"
    assert witness["destination_param"] == "a"
    assert witness["destination_basis"] == "call_destination"
    branched = matrix[0]["binding"]["branchedParams(address,address,bytes,bool)"]
    assert branched["destination_kind"] == "not_determined"
    assert branched["destination_param"] is None


def test_the_control_instrument_is_wired_and_disagrees_with_the_binding(matrix):
    """The gate requires the probe (the removed ``next(iter(<set intersection>))`` idiom) to vary; a dead instrument
    keeps it green forever.
    """
    control = matrix[0]["unordered_control"]
    assert control, "the pre-fix idiom recomputation produced nothing; the gate's instrument is dead"

    # The read-set pick names a source; operand position names the destination.
    assert control["compose(address,address,bytes,bytes)"]["destination_param"] == "from"
    assert matrix[0]["binding"]["compose(address,address,bytes,bytes)"]["destination_param"] == "to"

    # No claim is minted for a storage destination; the gate watches ``suppressed_state_var`` instead.
    assert control["rebalance(address,address,bytes)"]["destination_param"] in {"fromAsset", "toAsset"}
    assert "rebalance(address,address,bytes)" not in matrix[0]["binding"]
    suppressed = matrix[0]["suppressed_state_var"]
    assert suppressed["rebalance(address,address,bytes)"]["destination_kind"] == "state_var"
    assert suppressed["rebalance(address,address,bytes)"]["destination_param"] is None
