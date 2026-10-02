"""Outside ``tests/live/`` so offline tests can import them without the live auto-marker."""

from __future__ import annotations

from typing import Any, Protocol

from tests.live.conftest import DEFAULT_SINGLE_TIMEOUT

# Status values that signal the worker pipeline is finished with a job.
# ``failed_terminal`` is its own JobStatus enum value (db/models/jobs.py); a row
# in that state will never advance, so treating it as terminal here is
# correct and avoids a 600s wait on a row that's never going to flip.
_TERMINAL_STATUSES = ("completed", "failed", "failed_terminal")


class _ClientLike(Protocol):
    """A Protocol so ``tests/meta/test_live_impl_job_resolution.py`` can pass a stub."""

    def children_of(self, parent_job_id: str) -> list[dict[str, Any]]: ...
    def jobs(self) -> list[dict[str, Any]]: ...
    def poll_job_until_done(self, job_id: str, timeout: float = ..., interval: float = ...) -> dict[str, Any]: ...


def _resolve_impl_job(
    client: _ClientLike,
    *,
    parent_job_id: str,
    impl_address: str,
    timeout: float = DEFAULT_SINGLE_TIMEOUT,
) -> dict[str, Any] | None:
    """Searches the parent's children, then ``client.jobs()`` by address (the warm-cache reuse path), and waits for
    termination. Asserting ``completed`` synchronously failed on PR-63 once the suite got fast enough to catch the
    impl still processing.
    """
    children = client.children_of(parent_job_id)
    child_match = [c for c in children if (c.get("address") or "").lower() == impl_address]
    if child_match:
        impl_job = child_match[0]
    else:
        all_jobs = client.jobs()
        candidates = [j for j in all_jobs if (j.get("address") or "").lower() == impl_address]
        if not candidates:
            return None
        # Prefer a terminal candidate over a stale ``processing`` row.
        terminal = [j for j in candidates if j["status"] in _TERMINAL_STATUSES]
        impl_job = terminal[0] if terminal else candidates[0]

    if impl_job["status"] in _TERMINAL_STATUSES:
        return impl_job
    return client.poll_job_until_done(impl_job["job_id"], timeout=timeout)
