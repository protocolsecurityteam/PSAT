"""Unit tests for ``workers/retry_policy.py`` (no DB).

The classifier decides on type alone (not message); backoff respects base + jitter +
cap; env overrides are read each call so monkeypatch isn't cached behind a singleton.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests
import urllib3.exceptions

from workers.retry_policy import (
    classify,
    compute_next_attempt,
    max_retries,
    retry_base_s,
)

# ---------------------------------------------------------------------------
# classify() — type tuples
# ---------------------------------------------------------------------------


_TRANSIENT_STATUSES = [408, 425, 429, 500, 502, 503, 504, 522, 524]
_TERMINAL_STATUSES = [400, 401, 403, 404, 405, 410, 422]


def _http_error(status: int | None) -> requests.exceptions.HTTPError:
    # ``classify`` uses ``getattr(response, "status_code", None)`` so a
    # SimpleNamespace stand-in is enough — avoids constructing a real
    # ``Response`` object just to set one attribute.
    response = SimpleNamespace(status_code=status) if status is not None else None
    return requests.exceptions.HTTPError(f"{status}", response=response)  # pyright: ignore[reportArgumentType]


def _psycopg2_operational() -> Exception:
    psycopg2 = pytest.importorskip("psycopg2")
    return psycopg2.OperationalError("connection closed")


# Network errors must retry; bug-class exceptions must not (CRITICAL: a terminal error that
# retries loops forever). Exceptions are built lazily so importorskip only skips its own case.
@pytest.mark.parametrize(
    "make_exc, expected",
    [
        pytest.param(lambda: requests.exceptions.ConnectionError("connection reset"), "transient", id="conn-error"),
        pytest.param(lambda: requests.exceptions.Timeout("read timeout"), "transient", id="timeout"),
        pytest.param(lambda: requests.exceptions.ChunkedEncodingError("chunked"), "transient", id="chunked"),
        pytest.param(lambda: socket.timeout("blip"), "transient", id="socket-timeout"),
        pytest.param(
            lambda: urllib3.exceptions.ReadTimeoutError(MagicMock(), "/u", "timeout"), "transient", id="urllib3-read"
        ),
        pytest.param(
            lambda: urllib3.exceptions.NewConnectionError(MagicMock(), "refused"), "transient", id="urllib3-newconn"
        ),
        pytest.param(lambda: urllib3.exceptions.ProtocolError("partial"), "transient", id="urllib3-protocol"),
        pytest.param(_psycopg2_operational, "transient", id="psycopg2-operational"),
        pytest.param(lambda: ValueError("bad"), "terminal", id="value-error"),
        pytest.param(lambda: TypeError("bad"), "terminal", id="type-error"),
        pytest.param(lambda: KeyError("missing"), "terminal", id="key-error"),
        pytest.param(lambda: AssertionError("nope"), "terminal", id="assertion-error"),
        pytest.param(lambda: RuntimeError("generic"), "terminal", id="runtime-error"),
        *[pytest.param(lambda s=s: _http_error(s), "transient", id=f"http-{s}") for s in _TRANSIENT_STATUSES],
        *[pytest.param(lambda s=s: _http_error(s), "terminal", id=f"http-{s}") for s in _TERMINAL_STATUSES],
        # HTTPError raised without a response is a deterministic shape problem.
        pytest.param(lambda: _http_error(None), "terminal", id="http-no-response"),
    ],
)
def test_classify(make_exc, expected):
    assert classify(make_exc()) == expected


# ---------------------------------------------------------------------------
# compute_next_attempt() — backoff math
# ---------------------------------------------------------------------------


_NOW = datetime(2026, 5, 2, 12, 0, 0, tzinfo=timezone.utc)


def _delay_seconds(result: datetime) -> float:
    return (result - _NOW).total_seconds()


@pytest.mark.parametrize(
    "retry_count, expected_base",
    [
        (0, 30),  # first retry: base * 1, jitter +-25% -> [22.5, 37.5]
        (1, 60),
        (2, 120),
        (3, 240),
        (4, 480),
    ],
)
def test_compute_next_attempt_doubles_each_retry(monkeypatch, retry_count, expected_base):
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "30")
    for _ in range(50):
        delay = _delay_seconds(compute_next_attempt(retry_count, now=_NOW))
        assert expected_base * 0.75 <= delay <= expected_base * 1.25 + 1e-6


def test_compute_next_attempt_caps_at_30min(monkeypatch):
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "30")
    # retry_count=10 → 30 * 1024 = 30720s, well past the 30min cap of 1800s.
    cap = 30 * 60
    for _ in range(20):
        delay = _delay_seconds(compute_next_attempt(10, now=_NOW))
        # Jitter only shrinks the cap (post-cap multiply ≤ 1.25 then re-cap).
        assert delay <= cap


# ---------------------------------------------------------------------------
# Env-tunable knobs honour overrides
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn, var, value, expected",
    [
        pytest.param(max_retries, "PSAT_JOB_MAX_RETRIES", None, 5, id="max_retries-default"),
        pytest.param(max_retries, "PSAT_JOB_MAX_RETRIES", "9", 9, id="max_retries-override"),
        pytest.param(max_retries, "PSAT_JOB_MAX_RETRIES", "not-an-int", 5, id="max_retries-garbage-falls-back"),
        pytest.param(retry_base_s, "PSAT_JOB_RETRY_BASE_S", None, 30.0, id="retry_base_s-default"),
        pytest.param(retry_base_s, "PSAT_JOB_RETRY_BASE_S", "12.5", 12.5, id="retry_base_s-override"),
    ],
)
def test_env_knobs(monkeypatch, fn, var, value, expected):
    if value is None:
        monkeypatch.delenv(var, raising=False)
    else:
        monkeypatch.setenv(var, value)
    assert fn() == expected
