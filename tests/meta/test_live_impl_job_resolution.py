"""Offline regression test for the impl-job race in the live proxy-flow suite.

The live test ``tests/live/test_proxy_flow.py::test_implementation_job_completed``
asserted ``impl_job['status'] == 'completed'`` synchronously on a job
fetched from ``live_client.jobs()``. When the impl child was still
``processing`` at assertion time, the test failed on a healthy pipeline
that simply hadn't finished yet.

This race didn't fire on the slow live-test runs preceding the
mapping_enumeration_cache fix (commit e4b95d3) — the surrounding
concurrency tests took ~50 minutes, which gave the impl plenty of
wall-clock to settle. After PR-63's cache fix dropped the suite to
~19 minutes, the impl was no longer guaranteed to be terminal by the
time this test fired.

Fix: extract the impl-job-resolution-and-wait logic into
``_resolve_impl_job``; if the matched job isn't terminal, poll. This
file pins the helper's behaviour against a stub client so the race can
be reproduced — and a regression detected — without a deployed API.

Marker: offline. Lives at ``tests/`` (not ``tests/live/``) so the
auto-marker in ``tests/live/conftest.py:pytest_collection_modifyitems``
does not tag these as live.
"""

from __future__ import annotations

import time
from typing import Any

from tests.support.live_helpers import _resolve_impl_job  # noqa: E402


class _StubClient:
    """Minimal LiveClient stand-in for ``_resolve_impl_job``.

    Implements just ``children_of``, ``jobs``, and ``poll_job_until_done``.
    ``job_states`` lets a test sequence the responses ``poll_job_until_done``
    receives so a 'processing → processing → completed' transition can be
    exercised without real time passing.
    """

    def __init__(
        self,
        *,
        children: list[dict[str, Any]],
        all_jobs: list[dict[str, Any]],
        job_states: dict[str, list[str]] | None = None,
    ) -> None:
        self._children = children
        self._all_jobs = all_jobs
        self._states: dict[str, list[str]] = {jid: list(states) for jid, states in (job_states or {}).items()}
        self.job_calls: int = 0
        self.poll_calls: int = 0

    def children_of(self, _parent_job_id: str) -> list[dict[str, Any]]:
        return self._children

    def jobs(self) -> list[dict[str, Any]]:
        return self._all_jobs

    def _next_status(self, job_id: str) -> str:
        states = self._states.get(job_id)
        if not states:
            return "completed"
        # Pop until one remains; final status sticks (terminal-state semantics).
        return states.pop(0) if len(states) > 1 else states[0]

    def poll_job_until_done(
        self,
        job_id: str,
        timeout: float = 600,
        interval: float = 0.0,  # zero so the offline test isn't sleep-bound
    ) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.poll_calls += 1
            status = self._next_status(job_id)
            if status in ("completed", "failed", "failed_terminal"):
                return {"job_id": job_id, "address": None, "status": status}
            if interval:
                time.sleep(interval)
        raise TimeoutError(f"Job {job_id} did not reach a terminal status within {timeout}s")


# --- regression cases -------------------------------------------------------


def test_resolve_impl_job_waits_for_processing_to_terminate():
    """The race fix: when the matched impl_job is 'processing', the helper
    polls until terminal instead of returning the stale snapshot."""
    impl_addr = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
    impl_job_id = "impl-1"
    client = _StubClient(
        children=[],
        all_jobs=[{"job_id": impl_job_id, "address": impl_addr, "status": "processing"}],
        job_states={impl_job_id: ["processing", "processing", "completed"]},
    )

    impl_job = _resolve_impl_job(
        client,  # pyright: ignore[reportArgumentType]
        parent_job_id="parent-1",
        impl_address=impl_addr,
        timeout=10,
    )

    assert impl_job is not None
    assert impl_job["status"] == "completed"
    assert client.poll_calls >= 3, "helper should have polled until terminal, not returned the stale snapshot"


def test_resolve_impl_job_returns_immediately_when_already_completed():
    """Hot path: the parent's child is already completed. No polling
    overhead, no ``jobs()`` round-trip beyond the ``children_of`` hit."""
    impl_addr = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
    impl_job_id = "impl-2"
    client = _StubClient(
        children=[{"job_id": impl_job_id, "address": impl_addr, "status": "completed"}],
        all_jobs=[],
        job_states={},  # would crash if helper polled
    )

    impl_job = _resolve_impl_job(
        client,  # pyright: ignore[reportArgumentType]
        parent_job_id="parent-2",
        impl_address=impl_addr,
    )

    assert impl_job is not None
    assert impl_job["status"] == "completed"
    assert client.poll_calls == 0, "no polling should fire when the matched job is already terminal"


def test_resolve_impl_job_returns_failed_terminal_without_polling():
    """``failed_terminal`` is its own JobStatus enum value (db/models.py:49)
    and is just as terminal as ``completed``. The helper must not
    re-classify it as non-terminal and start polling — that was the
    sibling bug fixed in commit fff4cb2."""
    impl_addr = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
    impl_job_id = "impl-3"
    client = _StubClient(
        children=[{"job_id": impl_job_id, "address": impl_addr, "status": "failed_terminal"}],
        all_jobs=[],
        job_states={},
    )

    impl_job = _resolve_impl_job(
        client,  # pyright: ignore[reportArgumentType]
        parent_job_id="parent-3",
        impl_address=impl_addr,
    )

    assert impl_job is not None
    assert impl_job["status"] == "failed_terminal"
    assert client.poll_calls == 0


def test_resolve_impl_job_polls_through_processing_to_failed_terminal():
    """A processing impl that ultimately fails terminally should still
    return — the live test then surfaces the impl error in its message,
    rather than masking it as a poll timeout."""
    impl_addr = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
    impl_job_id = "impl-4"
    client = _StubClient(
        children=[],
        all_jobs=[{"job_id": impl_job_id, "address": impl_addr, "status": "processing"}],
        job_states={impl_job_id: ["processing", "failed_terminal"]},
    )

    impl_job = _resolve_impl_job(
        client,  # pyright: ignore[reportArgumentType]
        parent_job_id="parent-4",
        impl_address=impl_addr,
        timeout=5,
    )

    assert impl_job is not None
    assert impl_job["status"] == "failed_terminal"


def test_resolve_impl_job_returns_none_when_no_candidate_anywhere():
    """When no job matches the impl address, return None so the caller
    can assert with a 'No analysis job of any age found' message rather
    than blow up on indexing an empty list."""
    client = _StubClient(children=[], all_jobs=[])

    result = _resolve_impl_job(
        client,  # pyright: ignore[reportArgumentType]
        parent_job_id="parent-5",
        impl_address="0xdeadbeef",
        timeout=1,
    )

    assert result is None
    assert client.poll_calls == 0


def test_resolve_impl_job_prefers_terminal_candidate_over_processing():
    """When ``jobs()`` returns multiple candidates for the same impl
    address (warm DB with prior runs + a fresh sibling), prefer one
    that's already terminal so we skip polling entirely."""
    impl_addr = "0x43506849d7c04f9138d1a2050bbf3a0c054402dd"
    client = _StubClient(
        children=[],
        all_jobs=[
            {"job_id": "old-completed", "address": impl_addr, "status": "completed"},
            {"job_id": "new-processing", "address": impl_addr, "status": "processing"},
        ],
        job_states={},  # would crash if helper polled
    )

    impl_job = _resolve_impl_job(
        client,  # pyright: ignore[reportArgumentType]
        parent_job_id="parent-6",
        impl_address=impl_addr,
    )

    assert impl_job is not None
    assert impl_job["job_id"] == "old-completed"
    assert client.poll_calls == 0
