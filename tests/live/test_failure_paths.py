"""End-to-end failure surfacing — asserts job.error/detail populate on guaranteed-fail inputs."""

from __future__ import annotations

import time

import pytest

from tests.live.conftest import DEFAULT_SINGLE_TIMEOUT, LiveClient

# Burn address: Etherscan returns "No verified source code"; discovery raises (services/clients/etherscan.py:182).
NO_CODE_ADDRESS = "0x0000000000000000000000000000000000000000"
# Non-trivial-looking undeployed address — guards against tests that only pass for the zero case.
UNVERIFIED_ADDRESS = "0xDeAdBeefDeadBeefDEADbEEFdEadbeEFDEADBeef"

# Both deterministic-from-the-start failures resolve to ``JobStatus.failed_terminal``
# (see db/models.py:JobStatus). ``failed`` is reserved for transient retryable
# errors. The poll loop and assertions accept either to stay tolerant of any
# future re-classification, but the canonical outcome here is terminal.
TERMINAL_STATUSES = ("failed", "failed_terminal")


def _wait_for_failure(live_client: LiveClient, job_id: str, timeout: float = DEFAULT_SINGLE_TIMEOUT) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = live_client.job(job_id)
        if snap["status"] in ("completed",) + TERMINAL_STATUSES:
            return snap
        time.sleep(3)
    raise TimeoutError(f"Job {job_id} did not terminate within {timeout}s")


def test_unverified_contract_fails_cleanly(live_client: LiveClient):
    job = live_client.analyze(NO_CODE_ADDRESS)
    final = _wait_for_failure(live_client, job["job_id"])

    assert final["status"] in TERMINAL_STATUSES, (
        f"unverified contract should fail, got status={final['status']} "
        f"stage={final['stage']} error={final.get('error')}"
    )
    assert final.get("error"), "failed job must populate error field for the frontend to display"
    # detail is set by db.queue.fail_job — confirms the canonical failure path ran.
    assert final.get("detail"), "failed job must populate detail field"


def test_no_code_address_fails_cleanly(live_client: LiveClient):
    job = live_client.analyze(UNVERIFIED_ADDRESS)
    final = _wait_for_failure(live_client, job["job_id"])

    assert final["status"] in TERMINAL_STATUSES, f"unverified address should fail, got status={final['status']}"
    error = final.get("error") or ""
    assert error, "error field must not be empty"


def test_failed_job_visible_via_jobs_endpoint(live_client: LiveClient):
    job = live_client.analyze(NO_CODE_ADDRESS)
    final = _wait_for_failure(live_client, job["job_id"])
    if final["status"] not in TERMINAL_STATUSES:
        pytest.skip("upstream failure-mode test already covers status; this only checks listing visibility")

    listing = live_client.jobs()
    matched = [j for j in listing if j.get("job_id") == job["job_id"]]
    assert matched, f"failed job {job['job_id']} missing from /api/jobs response"
    assert matched[0]["status"] in TERMINAL_STATUSES
