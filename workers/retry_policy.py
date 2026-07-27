"""Classify pipeline exceptions and compute backoff for transient retries.

The classifier feeds ``BaseWorker._execute_job``: a transient verdict means
"requeue with a backoff-set ``next_attempt_at``"; a terminal verdict means
"move to ``failed_terminal`` immediately, no retries". The split is type-only
— string-matching exception messages is the failure mode of every retry
system, so new transient cases must be added to the type tuples below or
through the ``HTTPError.response.status_code`` branch, never via substring.

``compute_next_attempt`` is a pure function (modulo jitter); ``now`` is
injectable so tests can pin time without monkeypatching ``datetime.now``.
"""

from __future__ import annotations

import os
import secrets
import socket
from datetime import datetime, timedelta, timezone
from typing import Literal

import requests
import urllib3.exceptions

from db.storage import (
    StorageContentAbsent,
    StorageContentNotDetermined,
    StorageKeyAbsent,
    StorageUnavailable,
)
from services.discovery.classifier import ClassificationIncompleteError
from services.effects.exceptions import AnvilSpawnError, ForkRpcTimeoutError

# psycopg2 wraps "connection lost mid-query" with OperationalError. Fold it
# into the transient set so a Neon idle-disconnect doesn't terminally fail
# an otherwise-fine job. Wrapped in try/except so test environments without
# psycopg2 (none today, but cheap insurance) still import this module.
try:
    import psycopg2  # type: ignore[import-untyped]

    _PSYCOPG2_OPERATIONAL: tuple[type[BaseException], ...] = (psycopg2.OperationalError,)
except Exception:  # pragma: no cover — psycopg2 is a hard dep in production
    _PSYCOPG2_OPERATIONAL = ()


Kind = Literal["transient", "terminal"]

# Defaults tuned to symmetry with the existing PSAT_STALE_JOB_TIMEOUT /
# PSAT_RECLAIM_INTERVAL_S knobs in workers/base.py — env-overridable here
# the same way.
_DEFAULT_MAX_RETRIES = 5
_DEFAULT_RETRY_BASE_S = 30.0
# Cap so a stuck worker doesn't bounce a job indefinitely. With
# base=30s/maxretries=5 the natural sequence (30s, 60s, 120s, 240s, 480s)
# hits this cap by the fifth attempt anyway; the cap matters under
# operator-overridden ``PSAT_JOB_MAX_RETRIES``.
_RETRY_CAP_S = 30 * 60


def max_retries() -> int:
    """Read ``PSAT_JOB_MAX_RETRIES`` once per call so tests can monkeypatch env."""
    raw = os.getenv("PSAT_JOB_MAX_RETRIES")
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return _DEFAULT_MAX_RETRIES


def retry_base_s() -> float:
    """Read ``PSAT_JOB_RETRY_BASE_S`` once per call (mirrors ``max_retries`` precedence)."""
    raw = os.getenv("PSAT_JOB_RETRY_BASE_S")
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return _DEFAULT_RETRY_BASE_S


# HTTP status codes that scream "retry later": gateway/server hiccups,
# rate-limit (429), request-timeout (408/425), Cloudflare-style 522/524.
_TRANSIENT_HTTP: frozenset[int] = frozenset({408, 425, 429, 500, 502, 503, 504, 522, 524})

# Exception types that uniformly indicate a network/IO blip. ``HTTPError``
# is intentionally NOT in here — the status code drives the verdict and is
# handled separately in ``classify``.
_TRANSIENT_TYPES: tuple[type[BaseException], ...] = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
    socket.timeout,
    urllib3.exceptions.ReadTimeoutError,
    urllib3.exceptions.NewConnectionError,
    urllib3.exceptions.ProtocolError,
    # A failed proxy-slot read is a transient RPC condition: the fail-closed
    # raise self-heals once the RPC recovers, so retry rather than terminally
    # kill the job (which would itself erase the implementation's surface).
    ClassificationIncompleteError,
    # Effects stage (EFFECTS_RESOLUTION_SPEC): an anvil fork that fails to spawn
    # or a fork-backing RPC timeout is an infra blip that self-heals on retry.
    # Type-based only, like every entry here. Inv. 15 composes on top: whatever
    # this classifier says, the effects stage's *exhaustion* outcome is
    # degrade-and-advance, never failed_terminal.
    AnvilSpawnError,
    ForkRpcTimeoutError,
    # Storage that could not answer. ``StorageUnavailable`` is the backend being
    # unreachable or unconfigured; ``StorageContentNotDetermined`` is a read that
    # could not establish content for at least one row it was asked about;
    # ``StorageKeyAbsent`` is a row that records no key and holds no inline body,
    # so the bucket was never asked at all. All three mean "we did not find out",
    # and a stage that re-runs is the only thing that can turn that into a fact.
    # ``StorageKeyAbsent`` in particular is written by the inline path when the
    # backend is unconfigured (``db/queue.py`` ``store_artifact``) — the same
    # condition ``StorageUnavailable`` already retries on, one row later.
    #
    # ``StorageKeyMissing`` and ``StorageContentAbsent`` are deliberately NOT
    # here: the first is the bucket answering "no object at this key", the second
    # is a collection read where every shortfall was one of those. Both are
    # determined, and re-asking a question already answered just burns the retry
    # budget before the same terminal verdict. The collection reads
    # (``get_all_artifacts`` / ``get_source_files`` / the ``hydrate_*`` family)
    # therefore raise by cause, not one flattened type — a lost object and an
    # unreachable bucket used to arrive here as the same class and this comment
    # was false for the first of them.
    StorageContentNotDetermined,
    StorageKeyAbsent,
    StorageUnavailable,
    *_PSYCOPG2_OPERATIONAL,
)

# Deterministic-from-the-start failures. ValueError / TypeError / KeyError
# / AssertionError almost always mean "bug or bad input" — retrying them is
# wasted cycles. The pipeline's ``raise ValueError("Job has neither address
# nor company")`` and similar hard-stops live here.
_TERMINAL_TYPES: tuple[type[BaseException], ...] = (
    ValueError,
    TypeError,
    KeyError,
    AssertionError,
    # Named rather than left to the default: this is the branch that keeps the
    # comment in _TRANSIENT_TYPES honest, and a reader checking it should find
    # the entry rather than infer it from a fall-through.
    StorageContentAbsent,
)


def classify(exc: BaseException) -> Kind:
    """Decide whether *exc* warrants a retry.

    Order matters: ``HTTPError`` is checked first because the verdict depends
    on the response status code, not just the type. Transient set is checked
    before terminal set so the (rare) overlap (a project-defined subclass of
    both) classifies as transient.
    """
    if isinstance(exc, requests.exceptions.HTTPError):
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None) if response is not None else None
        if isinstance(status, int) and status in _TRANSIENT_HTTP:
            return "transient"
        return "terminal"
    if isinstance(exc, _TRANSIENT_TYPES):
        return "transient"
    if isinstance(exc, _TERMINAL_TYPES):
        return "terminal"
    return "terminal"


def compute_next_attempt(retry_count: int, *, now: datetime | None = None) -> datetime:
    """Wall-clock time for the next retry of a job.

    Backoff: ``base * 2 ** retry_count`` seconds with ±25% jitter, capped at
    ``_RETRY_CAP_S``. ``retry_count`` is the count of *prior* attempts (0
    when computing the first retry's delay).

    ``secrets.SystemRandom`` is used so a stray ``random.seed()`` somewhere
    else in the codebase can't accidentally synchronize a fleet's retry
    storms by giving every worker the same jitter draw.
    """
    base = retry_base_s()
    safe_count = max(0, retry_count)
    delay = min(base * (2**safe_count), float(_RETRY_CAP_S))
    jitter = secrets.SystemRandom().uniform(0.75, 1.25)
    delay = min(delay * jitter, float(_RETRY_CAP_S))
    moment = now or datetime.now(timezone.utc)
    return moment + timedelta(seconds=delay)


__all__ = [
    "Kind",
    "classify",
    "compute_next_attempt",
    "max_retries",
    "retry_base_s",
]
