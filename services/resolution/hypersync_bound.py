"""Process-wide bound for all HyperSync consumers.

Every resolution-time live HyperSync scan shares one Envio API token and one
60/min request budget. Without a shared limiter, concurrent resolutions (and the
multi-page folds inside a single resolution) collectively burst past that budget
and 429-storm. This module is the single seam through which every
``HypersyncClient`` is constructed, so the bound cannot be bypassed:

  * ``build_hypersync_client`` constructs a client with a bounded
    ``max_num_retries`` (clients that silently retry forever turn one 429 into a
    storm), keyed retry backoff left at the SDK default.
  * ``hypersync_slot`` is a process-wide semaphore keyed on the bearer token: at
    most ``PSAT_HYPERSYNC_MAX_CONCURRENCY`` (default 2) in-flight scans per token
    across all consumer modules.

Pacing only — accuracy-neutral. A scan that waits for a slot returns the same
logs it would have returned immediately.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Any, Iterator

_DEFAULT_MAX_CONCURRENCY = 2
_DEFAULT_MAX_RETRIES = 3

_SEMAPHORES: dict[str, threading.BoundedSemaphore] = {}
_SEMAPHORES_LOCK = threading.Lock()


def _max_concurrency() -> int:
    try:
        return max(1, int(os.getenv("PSAT_HYPERSYNC_MAX_CONCURRENCY", str(_DEFAULT_MAX_CONCURRENCY))))
    except ValueError:
        return _DEFAULT_MAX_CONCURRENCY


def _max_retries() -> int:
    try:
        return max(0, int(os.getenv("PSAT_HYPERSYNC_MAX_RETRIES", str(_DEFAULT_MAX_RETRIES))))
    except ValueError:
        return _DEFAULT_MAX_RETRIES


def _semaphore_for(token: str | None) -> threading.BoundedSemaphore:
    key = token or ""
    with _SEMAPHORES_LOCK:
        sem = _SEMAPHORES.get(key)
        if sem is None:
            sem = threading.BoundedSemaphore(_max_concurrency())
            _SEMAPHORES[key] = sem
        return sem


@contextmanager
def hypersync_slot(token: str | None) -> Iterator[None]:
    """Hold one of the per-token concurrency slots for the duration of a scan."""
    sem = _semaphore_for(token)
    sem.acquire()
    try:
        yield
    finally:
        sem.release()


def build_hypersync_client(
    hypersync_module: Any,
    *,
    url: str,
    bearer_token: str | None,
) -> Any:
    """Construct a ``HypersyncClient`` with a bounded retry count so a transient
    429 cannot fan out into an unbounded retry storm. All consumers route their
    client construction through here."""
    try:
        config = hypersync_module.ClientConfig(
            url=url,
            bearer_token=bearer_token,
            max_num_retries=_max_retries(),
        )
    except TypeError:
        # Older SDKs without max_num_retries — fall back to the plain config; the
        # shared semaphore still bounds concurrency.
        config = hypersync_module.ClientConfig(url=url, bearer_token=bearer_token)
    return hypersync_module.HypersyncClient(config)
