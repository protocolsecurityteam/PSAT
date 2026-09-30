"""Process-wide bound for all HyperSync consumers.

All live scans share one token and a 60/min budget, so every ``HypersyncClient`` is built here:

  * ``build_hypersync_client`` bounds ``max_num_retries`` (unbounded retries turn one 429 into a storm);
  * ``hypersync_slot`` is a per-token semaphore allowing ``PSAT_HYPERSYNC_MAX_CONCURRENCY`` (default 2) scans.

Pacing only; results are unchanged.
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
    """A ``HypersyncClient`` with bounded retries. All consumers construct clients here."""
    try:
        config = hypersync_module.ClientConfig(
            url=url,
            bearer_token=bearer_token,
            max_num_retries=_max_retries(),
        )
    except TypeError:
        # Older SDKs lack max_num_retries; the semaphore still bounds concurrency.
        config = hypersync_module.ClientConfig(url=url, bearer_token=bearer_token)
    return hypersync_module.HypersyncClient(config)


def hypersync_url_for_chain(chain_id: int) -> str | None:
    """Per-chain HyperSync endpoint, or ``None`` when the chain has no coverage (a partial result, never a mainnet
    fallback). Unknown ids also give ``None``.
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
