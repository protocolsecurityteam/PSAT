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


def hypersync_url_for_chain(chain_id: int) -> str | None:
    """Per-chain HyperSync endpoint from the registry.

    ``None`` means the chain has no proven HyperSync coverage — the repo is
    unavailable there (the same class as a missing token: a partial result, never
    a silent mainnet fallback). Unknown chain ids resolve to ``None`` too;
    failing loud on an unregistered chain is a caller's job, not this lookup's.
    """
    from utils.chains import UnknownChainError, chain_by_id

    try:
        return chain_by_id(chain_id).hypersync_url
    except UnknownChainError:
        return None


def logs_from_response(response: Any) -> list[Any]:
    data = getattr(response, "data", None)
    if data is not None and hasattr(data, "logs"):
        return list(getattr(data, "logs", None) or [])
    if isinstance(data, list):
        return data
    return list(getattr(response, "logs", None) or [])


def topics_from_log(log: Any) -> list[str]:
    topics = getattr(log, "topics", None)
    if isinstance(topics, (list, tuple)):
        return [str(topic).lower() for topic in topics if isinstance(topic, str) and topic.startswith("0x")]
    out: list[str] = []
    for attr in ("topic0", "topic1", "topic2", "topic3"):
        value = getattr(log, attr, None)
        if isinstance(value, str) and value.startswith("0x") and value not in {"0x", "0x0"}:
            out.append(value.lower())
    return out


def data_words_from_log(log: Any) -> list[str]:
    raw = getattr(log, "data", "0x") or "0x"
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return []
    body = raw[2:]
    if len(body) % 64 != 0:
        return []
    return ["0x" + body[i : i + 64].lower() for i in range(0, len(body), 64)]
