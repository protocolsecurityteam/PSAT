from __future__ import annotations

from unittest.mock import Mock

import pytest
import requests
from requests.adapters import HTTPAdapter

from tests.live import conftest as live


def response(status: int, body: bytes) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = body
    return result


@pytest.fixture
def clock(monkeypatch):
    elapsed = [0.0]

    def sleep(seconds):
        elapsed[0] += seconds

    monkeypatch.setattr(live.time, "monotonic", lambda: elapsed[0])
    monkeypatch.setattr(live.time, "sleep", sleep)
    return elapsed


def test_company_client_waits_for_preparation_without_changing_auth(monkeypatch, clock):
    client = live.LiveClient("http://preview.local", "test-admin-key")
    get = Mock(side_effect=[response(503, b'{"code":"company_preparing"}'), response(200, b'{"contracts":[]}')])
    monkeypatch.setattr(client._company_session, "get", get)
    assert client.company_overview("example") == {"contracts": []}
    assert get.call_count == 2
    assert clock[0] == 2
    assert client._company_session.headers["X-PSAT-Admin-Key"] == "test-admin-key"
    public = live.LiveClient("http://preview.local", "")
    assert "X-PSAT-Admin-Key" not in public._company_session.headers
    adapter = client._company_session.get_adapter(client.base_url)
    assert isinstance(adapter, HTTPAdapter)
    assert adapter.max_retries.total == 0


def test_company_client_fails_if_builder_never_finishes(monkeypatch, clock):
    client = live.LiveClient("http://preview.local", "")
    get = Mock(return_value=response(503, b'{"code":"company_preparing"}'))
    monkeypatch.setattr(client._company_session, "get", get)
    with pytest.raises(AssertionError, match="not prepared within 5s"):
        client.company_response("example", "summary", wait_seconds=5)
    assert clock[0] == 5
    assert get.call_count == 3
    get.assert_called_with("http://preview.local/api/company/example/summary", timeout=1)


@pytest.mark.parametrize(
    ("status", "body"),
    [(503, b'{"code":"unavailable"}'), (503, b"unavailable"), (503, b"[]"), (500, b"{}"), (404, b"{}")],
)
def test_company_client_does_not_retry_unrelated_errors(monkeypatch, clock, status, body):
    client = live.LiveClient("http://preview.local", "")
    get = Mock(return_value=response(status, body))
    monkeypatch.setattr(client._company_session, "get", get)
    with pytest.raises(requests.HTTPError):
        client.company_response("example")
    assert get.call_count == 1
    assert clock[0] == 0
