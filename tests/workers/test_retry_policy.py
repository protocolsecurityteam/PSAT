"""The classifier decides on type alone; env overrides are read each call so monkeypatch isn't cached."""

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
)

_TRANSIENT_STATUSES = [408, 425, 429, 500, 502, 503, 504, 522, 524]
_TERMINAL_STATUSES = [400, 401, 403, 404, 405, 410, 422]


def _http_error(status: int | None) -> requests.exceptions.HTTPError:
    response = SimpleNamespace(status_code=status) if status is not None else None
    return requests.exceptions.HTTPError(f"{status}", response=response)  # pyright: ignore[reportArgumentType]


def _psycopg2_operational() -> Exception:
    psycopg2 = pytest.importorskip("psycopg2")
    return psycopg2.OperationalError("connection closed")


# A terminal error that retries loops forever. Exceptions are built lazily so importorskip only skips its own case.
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
        pytest.param(lambda: _http_error(None), "terminal", id="http-no-response"),
    ],
)
def test_classify(make_exc, expected):
    assert classify(make_exc()) == expected


def test_sqlalchemy_wrapped_disconnect_remains_transient():
    from sqlalchemy.exc import IntegrityError, OperationalError

    assert classify(OperationalError("SELECT 1", {}, _psycopg2_operational())) == "transient"
    assert classify(IntegrityError("INSERT", {}, ValueError("duplicate"))) == "terminal"


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
