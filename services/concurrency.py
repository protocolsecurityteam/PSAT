"""Worker-fleet concurrency primitives shared across pipeline stages.

The pipeline is dominated by JSON-RPC and Etherscan I/O — the few bits of CPU
work between requests don't justify processes, but the cumulative RTT cost on
serial loops is the dominant share of every worker's wall time. These helpers
give every fan-out site a uniform, threading-only way to stack RTTs while
keeping the request shape, ordering guarantees, and error semantics identical
to the sequential version.

``parallel_map`` is the generic per-item fan-out (one task = one item).
``RpcExecutor`` is the process-wide thread pool every site shares so we don't
spawn a new pool per call.
"""

from __future__ import annotations

import contextvars
import logging
import os
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any, TypeVar

from utils.logging import record_degraded

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


def _max_fanout() -> int:
    """Resolve ``PSAT_RPC_FANOUT`` at every call so tests can flip it via monkeypatch."""
    try:
        value = int(os.getenv("PSAT_RPC_FANOUT", "16"))
    except ValueError:
        return 16
    return max(1, value)


def _heartbeat_interval_s() -> float:
    """Resolve the max wait between job heartbeats while a fan-out is blocked."""
    try:
        value = float(os.getenv("PSAT_PARALLEL_HEARTBEAT_INTERVAL_S", "30"))
    except ValueError:
        return 30.0
    return max(0.1, value)


def _call_heartbeat(heartbeat: Callable[[], None] | None) -> None:
    if heartbeat is None:
        return
    try:
        heartbeat()
    except Exception as exc:
        if _is_lease_lost(exc):
            raise
        # Swallowed-continue: a failed heartbeat must not kill the fan-out, so
        # this is degraded-but-continuing (WARNING), not a job-failing ERROR.
        logger.warning(
            "parallel_map: heartbeat raised — continuing",
            extra={"exc_type": type(exc).__name__},
        )
        record_degraded(phase="parallel_heartbeat", exc=exc)


def parallel_map(
    fn: Callable[[T], R],
    items: Iterable[T],
    *,
    max_workers: int | None = None,
    heartbeat: Callable[[], None] | None = None,
) -> list[tuple[T, R | BaseException]]:
    """Apply *fn* to each item concurrently and return results in input order.

    Each entry in the returned list is ``(item, result)`` on success or
    ``(item, exc)`` on per-item failure, so callers can treat parallel
    failures the same way they'd treat per-item failures in a serial loop.

    *max_workers* falls back to ``PSAT_RPC_FANOUT`` (default 16). When set to 1
    the function executes sequentially in-thread, which is the parity mode
    tests use to assert behavioural equivalence with the serial path.

    *heartbeat*, if provided, is called on the submitting thread after task
    completions and while waiting on long-running fan-out work. DB sessions
    captured in the closure therefore stay on the worker's thread.
    """
    items_list = list(items)
    if not items_list:
        return []

    workers = max_workers if max_workers is not None else _max_fanout()
    workers = max(1, min(workers, len(items_list)))

    results: list[tuple[T, R | BaseException]] = [(item, None) for item in items_list]  # pyright: ignore[reportAssignmentType]

    if workers == 1 and heartbeat is None:
        for idx, item in enumerate(items_list):
            try:
                results[idx] = (item, fn(item))
            except BaseException as exc:  # noqa: BLE001 — preserve every exception type for callers
                results[idx] = (item, exc)
            _call_heartbeat(heartbeat)
        return results

    executor = RpcExecutor.get()
    futures: dict[Future[R], int] = {}
    # Cap concurrency by keeping at most ``workers`` submitted futures at a
    # time. Do not block during submission: long-running first-wave tasks
    # must still get heartbeat callbacks while the remaining items wait.

    def _submit(idx: int, item: T) -> Future[R]:
        # Per-submission ``copy_context`` is mandatory: a single Context
        # object cannot be entered by ``Context.run`` concurrently from
        # two threads. Each worker thread needs its own snapshot of the
        # caller's contextvars (trace_id, job_id, …) so the bind survives
        # the fan-out without serializing the pool on a shared context.
        ctx = contextvars.copy_context()

        def _wrapped() -> R:
            return ctx.run(fn, item)

        future = executor.submit(_wrapped)
        futures[future] = idx
        return future

    initial = min(workers, len(items_list))
    for idx in range(initial):
        _submit(idx, items_list[idx])
    next_submit_idx = initial

    pending = set(futures)
    heartbeat_interval = _heartbeat_interval_s() if heartbeat is not None else None

    while pending:
        done, pending = wait(pending, timeout=heartbeat_interval, return_when=FIRST_COMPLETED)
        if not done:
            try:
                _call_heartbeat(heartbeat)
            except Exception:
                for fut in pending:
                    fut.cancel()
                raise
            continue

        for fut in done:
            idx = futures[fut]
            try:
                results[idx] = (items_list[idx], fut.result())
            except BaseException as exc:  # noqa: BLE001
                results[idx] = (items_list[idx], exc)
            try:
                _call_heartbeat(heartbeat)
            except Exception:
                for pending_fut in pending:
                    pending_fut.cancel()
                raise
            if next_submit_idx < len(items_list):
                pending.add(_submit(next_submit_idx, items_list[next_submit_idx]))
                next_submit_idx += 1

    return results


def _is_lease_lost(exc: BaseException) -> bool:
    """Lazy import of ``db.queue.LeaseLost`` to keep this utility module
    free of an unconditional ``utils → db`` import. Returns False if the
    DB layer is unavailable (test/CLI contexts), letting the heartbeat
    swallow path stay defensive in those environments."""
    try:
        from db.queue import LeaseLost
    except Exception:
        return False
    return isinstance(exc, LeaseLost)


class RpcExecutor:
    """Process-wide ``ThreadPoolExecutor`` shared across every fan-out site.

    Sized from ``PSAT_RPC_FANOUT`` (default 16). Constructed lazily on first
    access, never shut down — the pool lives for the lifetime of the worker
    process and threads are reused across jobs so we never pay
    pthread-creation cost in the hot path.
    """

    _instance: ThreadPoolExecutor | None = None
    _lock = threading.Lock()

    @classmethod
    def get(cls) -> ThreadPoolExecutor:
        if cls._instance is not None:
            return cls._instance
        with cls._lock:
            if cls._instance is None:
                workers = _max_fanout()
                cls._instance = ThreadPoolExecutor(
                    max_workers=workers,
                    thread_name_prefix="psat-rpc",
                )
        return cls._instance

    @classmethod
    def submit(cls, fn: Callable[..., R], *args: Any, **kwargs: Any) -> Future[R]:
        return cls.get().submit(fn, *args, **kwargs)

    @classmethod
    def reset_for_tests(cls) -> None:
        """Drop the singleton so tests that change ``PSAT_RPC_FANOUT`` get a fresh pool."""
        with cls._lock:
            inst, cls._instance = cls._instance, None
        if inst is not None:
            inst.shutdown(wait=False, cancel_futures=False)


def submit_rpc(fn: Callable[..., R], *args: Any, **kwargs: Any) -> Future[R]:
    """Module-level shortcut for ``RpcExecutor.submit``."""
    return RpcExecutor.submit(fn, *args, **kwargs)


__all__ = [
    "RpcExecutor",
    "parallel_map",
    "submit_rpc",
]
