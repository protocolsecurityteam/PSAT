"""Thread-based fan-out for I/O-bound pipeline stages, preserving the serial version's ordering and error semantics.

``RpcExecutor`` is the shared process-wide pool.
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
    """Resolved per call so tests can monkeypatch."""
    try:
        value = int(os.getenv("PSAT_RPC_FANOUT", "16"))
    except ValueError:
        return 16
    return max(1, value)


def _heartbeat_interval_s() -> float:
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
        # A failed heartbeat must not kill the fan-out.
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
    """Apply *fn* concurrently, returning ``(item, result)`` or ``(item, exc)`` in input order.

    ``max_workers=1`` runs serially (the parity mode tests use). *heartbeat* runs on the submitting thread, so captured
    DB sessions stay on it.
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
    # Don't block during submission, so long first-wave tasks still get heartbeats.

    def _submit(idx: int, item: T) -> Future[R]:
        # A Context can't be entered by two threads at once; each task needs its own copy.
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
    """Lazy so this module doesn't import ``db`` unconditionally; False when the DB layer is unavailable."""
    try:
        from db.queue import LeaseLost
    except Exception:
        return False
    return isinstance(exc, LeaseLost)


class RpcExecutor:
    """Process-wide pool sized from ``PSAT_RPC_FANOUT`` (default 16), created lazily and never shut down."""

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
        with cls._lock:
            inst, cls._instance = cls._instance, None
        if inst is not None:
            inst.shutdown(wait=False, cancel_futures=False)


def submit_rpc(fn: Callable[..., R], *args: Any, **kwargs: Any) -> Future[R]:
    return RpcExecutor.submit(fn, *args, **kwargs)


__all__ = [
    "RpcExecutor",
    "parallel_map",
    "submit_rpc",
]
