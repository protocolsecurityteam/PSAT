from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from services.clients.tavily import (
    TavilyError,
    _cache_key,
    error_from_exception,
    normalize_error,
    search,
)


class TestNormalizeError:
    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            pytest.param({}, {"provider": "tavily", "error": "fail"}, id="message_only"),
            pytest.param({"status_code": 500}, {"status_code": 500}, id="with_status_code"),
            pytest.param({"retryable": True}, {"retryable": True}, id="with_retryable"),
            pytest.param({"retryable": False}, {"retryable": False}, id="with_retryable_false"),
            pytest.param({"detail": "extra info"}, {"detail": "extra info"}, id="with_detail"),
            pytest.param({"detail": ""}, {}, id="detail_empty_string_omitted"),
            pytest.param(
                {"status_code": 429, "retryable": True, "detail": "rate"},
                {"status_code": 429, "retryable": True, "detail": "rate"},
                id="all_fields",
            ),
        ],
    )
    def test_fields(self, kwargs, expected):
        # Unset/empty fields must be omitted from the dict, not present as None.
        err = normalize_error("fail", **kwargs)
        assert err == {"provider": "tavily", "error": "fail", **expected}


class TestTavilyError:
    def test_missing_error_key_default_message(self):
        exc = TavilyError({"provider": "tavily"})
        assert str(exc) == "Tavily request failed"


class TestErrorFromException:
    def test_tavily_error_returns_copy(self):
        original = {"provider": "tavily", "error": "bad", "retryable": True}
        exc = TavilyError(original)
        result = error_from_exception(exc)
        assert result == original
        assert result is not original  # must be a copy

    def test_generic_exception(self):
        exc = ValueError("something broke")
        result = error_from_exception(exc)
        assert result["error"] == "something broke"
        assert result["provider"] == "tavily"
        assert result["retryable"] is False


def _mock_response(status_code=200, json_data=None, text="", raise_on_json=False):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    if raise_on_json:
        resp.json.side_effect = ValueError("No JSON")
    else:
        resp.json.return_value = json_data or {}
    return resp


class TestSearch:
    @pytest.mark.parametrize(
        ("post_kwargs", "match", "sleeps"),
        [
            pytest.param(
                {"return_value": _mock_response(500, text="Internal Server Error")}, "HTTP 500", 2, id="http_500"
            ),
            pytest.param(
                {"return_value": _mock_response(400, text="Bad Request")}, "HTTP 400", 0, id="http_400_no_retry"
            ),
            pytest.param({"return_value": _mock_response(429, text="Too Many Requests")}, "HTTP 429", 2, id="http_429"),
            pytest.param({"side_effect": requests.Timeout("timed out")}, "timed out", 2, id="timeout"),
            pytest.param(
                {"side_effect": requests.ConnectionError("connection refused")},
                "request failed",
                2,
                id="request_exception",
            ),
        ],
    )
    @patch("services.clients.tavily.load_dotenv")
    @patch("services.clients.tavily.time.sleep")
    def test_retry_policy(self, mock_sleep, _mock_dotenv, monkeypatch, post_kwargs, match, sleeps):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")

        with patch("services.clients.tavily.requests.post", **post_kwargs):
            with pytest.raises(TavilyError, match=match):
                search("query", max_results=3)

        assert mock_sleep.call_count == sleeps

    @patch("services.clients.tavily.load_dotenv")
    @patch("services.clients.tavily.time.sleep")
    def test_invalid_json_raises_no_retry(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(status_code=200, raise_on_json=True)

        with patch("services.clients.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError, match="Invalid JSON"):
                search("query", max_results=3)

        mock_sleep.assert_not_called()

    @patch("services.clients.tavily.load_dotenv")
    @patch("services.clients.tavily.time.sleep")
    def test_results_not_list_raises(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(json_data={"results": "not a list"})

        with patch("services.clients.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError, match="did not include a list"):
                search("query", max_results=3)

        mock_sleep.assert_not_called()


class TestCacheKey:
    def _key_for(self, **overrides):
        base = {
            "api_key": "secret",
            "query": "etherfi",
            "max_results": 10,
            "topic": "general",
            "search_depth": "advanced",
            "include_raw_content": False,
            "include_usage": True,
        }
        base.update(overrides)
        return _cache_key(base)

    def test_stable_across_dict_ordering(self):
        k1 = _cache_key({"a": 1, "b": 2, "api_key": "x"})
        k2 = _cache_key({"b": 2, "a": 1, "api_key": "y"})
        assert k1 == k2


class TestCacheBehavior:
    @patch("services.clients.tavily.load_dotenv")
    def test_hit_skips_network(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        envelope = json.dumps(
            {
                "schema_version": 1,
                "cached_at": time.time(),
                "results": [{"title": "from-cache", "url": "https://x"}],
            }
        ).encode("utf-8")

        storage_client = MagicMock()
        storage_client.get.return_value = envelope

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post") as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "from-cache", "url": "https://x"}]
        mock_post.assert_not_called()
        storage_client.put.assert_not_called()

    @patch("services.clients.tavily.load_dotenv")
    def test_expired_envelope_refetches(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        stale = json.dumps(
            {
                "schema_version": 1,
                "cached_at": time.time() - (40 * 24 * 60 * 60),  # 40 days old
                "results": [{"title": "stale"}],
            }
        ).encode("utf-8")

        storage_client = MagicMock()
        storage_client.get.return_value = stale
        resp = _mock_response(json_data={"results": [{"title": "fresh"}]})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "fresh"}]
        mock_post.assert_called_once()
        storage_client.put.assert_called_once()
