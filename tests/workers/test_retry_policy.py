"""Unit tests for ``workers/retry_policy.py``.

No DB needed — this is pure exception-type bookkeeping plus a small math
helper. Verifies the classifier decides on type alone (not message), that
the backoff respects base + jitter + cap, and that env overrides are read
each call (so monkeypatch in a test doesn't get cached behind a singleton).
"""

from __future__ import annotations

import socket
from datetime import datetime, timedelta, timezone
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


@pytest.mark.parametrize(
    "exc",
    [
        requests.exceptions.ConnectionError("connection reset"),
        requests.exceptions.Timeout("read timeout"),
        requests.exceptions.ChunkedEncodingError("chunked"),
        socket.timeout("blip"),
        urllib3.exceptions.ReadTimeoutError(MagicMock(), "/u", "timeout"),
        urllib3.exceptions.NewConnectionError(MagicMock(), "refused"),
        urllib3.exceptions.ProtocolError("partial"),
    ],
)
def test_classify_transient_for_network_blips(exc):
    assert classify(exc) == "transient"


@pytest.mark.parametrize(
    "exc",
    [
        ValueError("bad"),
        TypeError("bad"),
        KeyError("missing"),
        AssertionError("nope"),
        RuntimeError("generic"),
    ],
)
def test_classify_terminal_for_bug_or_bad_input(exc):
    assert classify(exc) == "terminal"


def test_classify_psycopg2_operational_is_transient():
    """``psycopg2.OperationalError`` (Neon idle disconnect, etc.) is transient."""
    psycopg2 = pytest.importorskip("psycopg2")
    assert classify(psycopg2.OperationalError("connection closed")) == "transient"


# ---------------------------------------------------------------------------
# classify() — HTTPError status-code branch
# ---------------------------------------------------------------------------


def _http_error(status: int | None) -> requests.exceptions.HTTPError:
    # ``classify`` uses ``getattr(response, "status_code", None)`` so a
    # SimpleNamespace stand-in is enough — avoids constructing a real
    # ``Response`` object just to set one attribute.
    response = SimpleNamespace(status_code=status) if status is not None else None
    return requests.exceptions.HTTPError(f"{status}", response=response)  # pyright: ignore[reportArgumentType]


@pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504, 522, 524])
def test_classify_http_transient_statuses(status):
    assert classify(_http_error(status)) == "transient"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 410, 422])
def test_classify_http_terminal_statuses(status):
    assert classify(_http_error(status)) == "terminal"


def test_classify_http_no_response_is_terminal():
    """HTTPError raised without a response is treated as a deterministic shape problem."""
    exc = requests.exceptions.HTTPError("no response attached")
    exc.response = None
    assert classify(exc) == "terminal"


# ---------------------------------------------------------------------------
# compute_next_attempt() — backoff math
# ---------------------------------------------------------------------------


_NOW = datetime(2026, 5, 2, 12, 0, 0, tzinfo=timezone.utc)


def _delay_seconds(result: datetime) -> float:
    return (result - _NOW).total_seconds()


def test_compute_next_attempt_first_retry_in_jitter_window(monkeypatch):
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "30")
    for _ in range(50):
        delay = _delay_seconds(compute_next_attempt(0, now=_NOW))
        # base=30, retry_count=0 → 30s; jitter ±25% → [22.5, 37.5]
        assert 30 * 0.75 <= delay <= 30 * 1.25 + 1e-6


@pytest.mark.parametrize(
    "retry_count, expected_base",
    [
        (1, 60),
        (2, 120),
        (3, 240),
        (4, 480),
    ],
)
def test_compute_next_attempt_doubles_each_retry(monkeypatch, retry_count, expected_base):
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "30")
    for _ in range(20):
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


def test_compute_next_attempt_uses_provided_now():
    pinned = datetime(2030, 1, 1, tzinfo=timezone.utc)
    result = compute_next_attempt(0, now=pinned)
    assert result > pinned
    assert result - pinned <= timedelta(seconds=30 * 1.25 + 1)


# ---------------------------------------------------------------------------
# Env-tunable knobs honour overrides
# ---------------------------------------------------------------------------


def test_max_retries_default(monkeypatch):
    monkeypatch.delenv("PSAT_JOB_MAX_RETRIES", raising=False)
    assert max_retries() == 5


def test_max_retries_env_override(monkeypatch):
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "9")
    assert max_retries() == 9


def test_max_retries_env_garbage_falls_back(monkeypatch):
    monkeypatch.setenv("PSAT_JOB_MAX_RETRIES", "not-an-int")
    assert max_retries() == 5


def test_retry_base_s_default(monkeypatch):
    monkeypatch.delenv("PSAT_JOB_RETRY_BASE_S", raising=False)
    assert retry_base_s() == 30.0


def test_retry_base_s_env_override(monkeypatch):
    monkeypatch.setenv("PSAT_JOB_RETRY_BASE_S", "12.5")
    assert retry_base_s() == 12.5
