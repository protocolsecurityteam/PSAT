"""Pipeline stage advancement — observed sequence must be a prefix of the canonical order.

Canonical (single-address): discovery → static → resolution → policy → coverage → done.
``selection`` only fires for company jobs so is not included here.
"""

from __future__ import annotations

import time

import pytest

from tests.live.conftest import DEFAULT_SINGLE_TIMEOUT, WETH_ADDRESS, LiveClient

EXPECTED_ORDER = ["discovery", "static", "resolution", "policy", "coverage", "done"]


def _is_prefix(observed: list[str], canonical: list[str]) -> bool:
    """Every stage in ``observed`` must appear in ``canonical`` order, no skips backwards."""
    j = 0
    for stage in observed:
        while j < len(canonical) and canonical[j] != stage:
            j += 1
        if j >= len(canonical):
            return False
        j += 1
    return True


def test_stages_advance_in_order(live_client: LiveClient):
    # Poll every 1s (not default 5s) — cached static stage can be sub-2s.
    job_id = live_client.analyze(WETH_ADDRESS)["job_id"]
    seen_stages: list[str] = []
    deadline = time.time() + DEFAULT_SINGLE_TIMEOUT

    while time.time() < deadline:
        snap = live_client.job(job_id)
        stage = snap.get("stage")
        if stage and (not seen_stages or seen_stages[-1] != stage):
            seen_stages.append(stage)
        if snap["status"] in ("completed", "failed", "failed_terminal"):
            break
        time.sleep(1)
    else:
        pytest.fail(f"Job {job_id} did not reach a terminal status; stages seen: {seen_stages}")

    final = live_client.job(job_id)
    assert final["status"] == "completed", (
        f"Job did not complete: status={final['status']} error={final.get('error')} stages={seen_stages}"
    )
    assert final["stage"] == "done", f"Completed job not at done stage: {final['stage']}"

    assert seen_stages, "no stage observations recorded"
    assert _is_prefix(seen_stages, EXPECTED_ORDER), (
        f"observed stages {seen_stages} are not a prefix of canonical order {EXPECTED_ORDER}"
    )
    assert seen_stages[-1] == "done", f"final observed stage should be 'done', got {seen_stages[-1]}"
