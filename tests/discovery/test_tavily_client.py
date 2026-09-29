"""Tests for services/clients/tavily.py – Tavily search client."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from services.clients.tavily import (
    TavilyError,
    _build_payload,
    _cache_key,
    error_from_exception,
    normalize_error,
    search,
)

# ---------------------------------------------------------------------------
# 1. normalize_error
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 2. TavilyError
# ---------------------------------------------------------------------------


class TestTavilyError:
    def test_message_from_error_key(self):
        exc = TavilyError({"error": "some message"})
        assert str(exc) == "some message"

    def test_missing_error_key_default_message(self):
        exc = TavilyError({"provider": "tavily"})
        assert str(exc) == "Tavily request failed"


# ---------------------------------------------------------------------------
# 3. error_from_exception
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 4. _build_payload
# ---------------------------------------------------------------------------


class TestBuildPayload:
    @patch("services.clients.tavily.load_dotenv")
    def test_success(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        payload = _build_payload(
            "my query",
            max_results=5,
            topic="general",
            search_depth="advanced",
            include_raw_content=True,
        )
        assert payload["api_key"] == "test-key"
        assert payload["query"] == "my query"
        assert payload["max_results"] == 5
        assert payload["topic"] == "general"
        assert payload["search_depth"] == "advanced"
        assert payload["include_raw_content"] is True

    @pytest.mark.parametrize("key", [None, "   "], ids=["missing", "blank"])
    @patch("services.clients.tavily.load_dotenv")
    def test_missing_api_key_raises(self, _mock_dotenv, monkeypatch, key):
        if key is None:
            monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        else:
            monkeypatch.setenv("TAVILY_API_KEY", key)
        with pytest.raises(TavilyError, match="Missing TAVILY_API_KEY"):
            _build_payload("q", 5, "general", "advanced", True)


# ---------------------------------------------------------------------------
# 5-11. search()
# ---------------------------------------------------------------------------


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
        ("query", "max_results", "match"),
        [
            pytest.param("", 5, "query must not be empty", id="empty_query"),
            pytest.param("   ", 5, "query must not be empty", id="whitespace_query"),
            pytest.param("hello", 0, "max_results must be >= 1", id="max_results_zero"),
            pytest.param("hello", -1, "max_results must be >= 1", id="max_results_negative"),
        ],
    )
    def test_invalid_input_raises_value_error(self, monkeypatch, query, max_results, match):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        with pytest.raises(ValueError, match=match):
            search(query, max_results=max_results)

    @patch("services.clients.tavily.load_dotenv")
    def test_success_returns_filtered_list(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        results_data = [
            {"title": "A", "url": "https://a.com"},
            {"title": "B", "url": "https://b.com"},
        ]
        resp = _mock_response(json_data={"results": results_data})

        with patch("services.clients.tavily.requests.post", return_value=resp) as mock_post:
            result = search("test query", max_results=5)
            assert result == results_data
            mock_post.assert_called_once()

    @patch("services.clients.tavily.load_dotenv")
    def test_success_filters_non_dict_items(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        results_data = [
            {"title": "A"},
            "not a dict",
            42,
            {"title": "B"},
        ]
        resp = _mock_response(json_data={"results": results_data})

        with patch("services.clients.tavily.requests.post", return_value=resp):
            result = search("query", max_results=5)
            assert result == [{"title": "A"}, {"title": "B"}]

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

    @patch("services.clients.tavily.load_dotenv")
    def test_missing_results_key_returns_empty(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(json_data={"answer": "something"})

        with patch("services.clients.tavily.requests.post", return_value=resp):
            result = search("query", max_results=3)
            assert result == []

    @patch("services.clients.tavily.load_dotenv")
    def test_query_whitespace_stripped(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        with patch("services.clients.tavily.requests.post", return_value=resp) as mock_post:
            search("  hello world  ", max_results=3)
            posted_payload = mock_post.call_args[1]["json"]
            assert posted_payload["query"] == "hello world"


# ---------------------------------------------------------------------------
# 12. cache layer (PSAT_TAVILY_CACHE)
# ---------------------------------------------------------------------------


class TestCacheKey:
    """The cache key must drop api_key and react to every other request field."""

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

    def test_api_key_excluded(self):
        assert self._key_for(api_key="A") == self._key_for(api_key="B")

    def test_query_drives_key(self):
        assert self._key_for(query="x") != self._key_for(query="y")

    def test_max_results_drives_key(self):
        assert self._key_for(max_results=5) != self._key_for(max_results=10)

    def test_search_depth_drives_key(self):
        assert self._key_for(search_depth="basic") != self._key_for(search_depth="advanced")

    def test_include_raw_content_drives_key(self):
        assert self._key_for(include_raw_content=True) != self._key_for(include_raw_content=False)

    def test_stable_across_dict_ordering(self):
        # sort_keys=True in _cache_key guards against insertion-order drift.
        k1 = _cache_key({"a": 1, "b": 2, "api_key": "x"})
        k2 = _cache_key({"b": 2, "a": 1, "api_key": "y"})
        assert k1 == k2


class TestCacheBehavior:
    """search() consults the cache only when PSAT_TAVILY_CACHE is set."""

    @patch("services.clients.tavily.load_dotenv")
    def test_disabled_skips_storage(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.delenv("PSAT_TAVILY_CACHE", raising=False)
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        storage_client = MagicMock()
        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]
        mock_post.assert_called_once()
        storage_client.get.assert_not_called()
        storage_client.put.assert_not_called()

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
    def test_miss_writes_envelope(self, _mock_dotenv, monkeypatch):
        from db.storage import StorageKeyMissing

        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        resp = _mock_response(json_data={"results": [{"title": "fresh"}]})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post", return_value=resp),
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "fresh"}]
        storage_client.put.assert_called_once()
        put_call = storage_client.put.call_args
        key, body = put_call.args[0], put_call.args[1]
        assert key.startswith("tavily-cache/") and key.endswith(".json")
        envelope = json.loads(body)
        assert envelope["schema_version"] == 1
        assert envelope["results"] == [{"title": "fresh"}]
        assert isinstance(envelope["cached_at"], (int, float))

    @patch("services.clients.tavily.load_dotenv")
    def test_empty_results_not_cached(self, _mock_dotenv, monkeypatch):
        from db.storage import StorageKeyMissing

        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        resp = _mock_response(json_data={"results": []})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post", return_value=resp),
        ):
            result = search("q", max_results=3)

        assert result == []
        # A flaky empty response would poison the cache for 30 days; the write
        # path bails before that happens.
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

    @patch("services.clients.tavily.load_dotenv")
    def test_schema_mismatch_refetches(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        wrong = json.dumps(
            {
                "schema_version": 99,
                "cached_at": time.time(),
                "results": [{"title": "v99"}],
            }
        ).encode("utf-8")

        storage_client = MagicMock()
        storage_client.get.return_value = wrong
        resp = _mock_response(json_data={"results": [{"title": "fresh"}]})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "fresh"}]
        mock_post.assert_called_once()

    @patch("services.clients.tavily.load_dotenv")
    def test_no_storage_client_falls_through(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        with (
            patch("db.storage.get_storage_client", return_value=None),
            patch("services.clients.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]
        mock_post.assert_called_once()

    @patch("services.clients.tavily.load_dotenv")
    def test_cache_write_failure_does_not_break_search(self, _mock_dotenv, monkeypatch):
        from db.storage import StorageKeyMissing, StorageUnavailable

        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        storage_client.put.side_effect = StorageUnavailable("bucket down")
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post", return_value=resp),
        ):
            # Bucket flake on write must not surface to the caller.
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]

    @patch("services.clients.tavily.load_dotenv")
    def test_cache_read_failure_falls_through(self, _mock_dotenv, monkeypatch):
        from db.storage import StorageUnavailable

        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageUnavailable("read flake")
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("services.clients.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]
        mock_post.assert_called_once()
