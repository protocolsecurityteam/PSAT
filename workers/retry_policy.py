"""Classify pipeline exceptions as transient (requeue with backoff) or terminal.

Type-only: never string-match messages. New transient cases go in the type tuples or the ``HTTPError`` status branch.
"""

from __future__ import annotations

import os
import secrets
import socket
from datetime import datetime, timedelta, timezone
from typing import Literal

import requests
import urllib3.exceptions
from sqlalchemy.exc import DBAPIError

from db.storage import (
    StorageContentAbsent,
    StorageContentNotDetermined,
    StorageKeyAbsent,
    StorageUnavailable,
)
from services.clients.rpc_limits import RpcBackpressure
from services.discovery.classifier import ClassificationIncompleteError
from services.effects.exceptions import AnvilSpawnError, ForkRpcTimeoutError

# Neon idle disconnects surface as OperationalError; don't terminally fail the job for them.
try:
    import psycopg2

    _PSYCOPG2_OPERATIONAL: tuple[type[BaseException], ...] = (psycopg2.OperationalError,)
except Exception:  # pragma: no cover — psycopg2 is a hard dep in production
    _PSYCOPG2_OPERATIONAL = ()


Kind = Literal["transient", "terminal"]

_DEFAULT_MAX_RETRIES = 5
_DEFAULT_RETRY_BASE_S = 30.0
# Matters only when ``PSAT_JOB_MAX_RETRIES`` is raised; the default sequence hits it by attempt five.
_RETRY_CAP_S = 30 * 60


def max_retries() -> int:
    raw = os.getenv("PSAT_JOB_MAX_RETRIES")
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return _DEFAULT_MAX_RETRIES


def retry_base_s() -> float:
    raw = os.getenv("PSAT_JOB_RETRY_BASE_S")
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
    return _DEFAULT_RETRY_BASE_S


_TRANSIENT_HTTP: frozenset[int] = frozenset({408, 425, 429, 500, 502, 503, 504, 522, 524})

# ``HTTPError`` is excluded: its status code drives the verdict.
_TRANSIENT_TYPES: tuple[type[BaseException], ...] = (
    RpcBackpressure,
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
    socket.timeout,
    urllib3.exceptions.ReadTimeoutError,
    urllib3.exceptions.NewConnectionError,
    urllib3.exceptions.ProtocolError,
    # Fail-closed proxy-slot read self-heals once RPC recovers; a terminal kill would erase the implementation's
    # surface.
    ClassificationIncompleteError,
    # Infra blips; the effects stage degrades-and-advances on exhaustion regardless.
    AnvilSpawnError,
    ForkRpcTimeoutError,
    # "We did not find out": only a re-run can turn that into a fact. ``StorageKeyAbsent`` is written by the inline path
    # when the backend is unconfigured.
    #
    # ``StorageKeyMissing`` / ``StorageContentAbsent`` are deliberately absent: the bucket answered, so retrying just
    # burns budget before the same verdict.
    StorageContentNotDetermined,
    StorageKeyAbsent,
    StorageUnavailable,
    *_PSYCOPG2_OPERATIONAL,
)

# Deterministic failures (bug or bad input); retrying wastes cycles.
_TERMINAL_TYPES: tuple[type[BaseException], ...] = (
    ValueError,
    TypeError,
    KeyError,
    AssertionError,
    # Named explicitly so a reader checking the transient-set comment finds it.
    StorageContentAbsent,
)


def classify(exc: BaseException) -> Kind:
    """Decide whether *exc* warrants a retry.

    ``HTTPError`` is checked first (status decides); transient beats terminal on overlap.
    """
    if isinstance(exc, DBAPIError):
        # SQLAlchemy wraps the driver exception; checking only psycopg2's bare
        # OperationalError incorrectly made connection loss terminal.
        if exc.connection_invalidated or isinstance(exc.orig, _PSYCOPG2_OPERATIONAL):
            return "transient"
        if getattr(exc.orig, "pgcode", None) in {"40001", "40P01", "55P03"}:
            return "transient"  # serialization failure, deadlock, lock timeout
        return "terminal"
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
    """``base * 2 ** retry_count`` seconds, ±25% jitter, capped at ``_RETRY_CAP_S``.

    ``retry_count`` counts prior attempts.

    ``SystemRandom`` so a stray ``random.seed()`` can't synchronize a fleet's retry storms.
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
