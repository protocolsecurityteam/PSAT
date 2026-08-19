"""Shared helpers for the live suite that the offline suite also pins.

Lives outside ``tests/live/`` so the offline regression tests can import them
without the live auto-marker in ``tests/live/conftest.py`` tagging those tests
as live."""

from __future__ import annotations

from typing import Any, Protocol

from tests.live.conftest import DEFAULT_SINGLE_TIMEOUT

# Status values that signal the worker pipeline is finished with a job.
# ``failed_terminal`` is its own JobStatus enum value (db/models.py); a row
# in that state will never advance, so treating it as terminal here is
# correct and avoids a 600s wait on a row that's never going to flip.
_TERMINAL_STATUSES = ("completed", "failed", "failed_terminal")


class _ClientLike(Protocol):
    """Subset of ``LiveClient`` that ``_resolve_impl_job`` needs.

    Declared as a Protocol so the offline regression test in
    ``tests/test_proxy_flow_logic.py`` can pass a stub without inheriting
    the full requests-based client. Keeps the helper testable without
    a deployed API.
    """

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
    """Locate the impl analysis job for ``impl_address`` and wait for it
    to terminate.

    Search order matches the previous in-test logic:
      1. Children of ``parent_job_id`` — the path the parent took when it
         spawned a fresh impl child.
      2. ``client.jobs()`` filtered by address — the warm-cache path where
         the static worker logged ``impl <addr> already has job <id>,
         skipping`` and reused an existing run.

    Returns ``None`` if no candidate exists at all (caller should assert
    this case to produce a useful failure message).

    The race this helper closes:
      Pre-fix the test asserted ``status == "completed"`` synchronously on
      the matched job. When the suite ran fast enough that the impl child
      was still ``processing``, the assertion failed even though the
      pipeline was healthy and would have finished moments later. This
      manifested on PR-63 once the mapping_enumeration_cache fix made the
      surrounding tests substantially faster — there was no longer enough
      wall-clock for the impl to settle before this test fired.
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
        # Prefer an already-terminal candidate so we don't poll a stale
        # ``processing`` row when a completed sibling exists. If none is
        # terminal yet, take the most recent (which is what callers want
        # to wait on anyway).
        terminal = [j for j in candidates if j["status"] in _TERMINAL_STATUSES]
        impl_job = terminal[0] if terminal else candidates[0]

    if impl_job["status"] in _TERMINAL_STATUSES:
        return impl_job
    return client.poll_job_until_done(impl_job["job_id"], timeout=timeout)
