"""Offline regression test for the impl-job race in the live proxy-flow suite.

``tests/live/test_proxy_flow.py::test_implementation_job_completed`` asserted ``status == 'completed'``
synchronously; a still-``processing`` impl child failed a healthy pipeline. The race surfaced after PR-63's cache
fix cut the suite from ~50 to ~19 min. Fix: ``_resolve_impl_job`` polls when the match isn't terminal; this file
pins it against a stub client. Lives in ``tests/`` (not ``tests/live/``) so the live auto-marker skips it.
"""

from __future__ import annotations

import time
from typing import Any

from tests.support.live_helpers import _resolve_impl_job


class _StubClient:
    """Minimal LiveClient stand-in; ``job_states`` sequences ``poll_job_until_done`` responses without real time
    passing."""

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


def test_resolve_impl_job_waits_for_processing_to_terminate():
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
    """Hot path: already completed, so no polling and no ``jobs()`` round-trip beyond ``children_of``."""
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
    """``failed_terminal`` (db/models.py:49) is as terminal as ``completed``; the helper must not poll it
    (the sibling bug fixed in commit fff4cb2)."""
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
    """A processing impl that fails terminally must still return, so the live test surfaces the impl error, not a poll
    timeout."""
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
    """No match returns None so the caller can assert with a clear message instead of indexing an empty list."""
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
    """With several candidates for one impl address (warm DB + fresh sibling), prefer a terminal one and skip
    polling."""
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
