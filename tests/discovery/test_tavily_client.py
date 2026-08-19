"""Tests for utils/tavily.py – Tavily search client."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.tavily import (
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
    def test_message_only(self):
        err = normalize_error("boom")
        assert err == {"provider": "tavily", "error": "boom"}

    def test_with_status_code(self):
        err = normalize_error("fail", status_code=500)
        assert err["status_code"] == 500

    def test_with_retryable(self):
        err = normalize_error("fail", retryable=True)
        assert err["retryable"] is True

    def test_with_retryable_false(self):
        err = normalize_error("fail", retryable=False)
        assert err["retryable"] is False

    def test_with_detail(self):
        err = normalize_error("fail", detail="extra info")
        assert err["detail"] == "extra info"

    def test_detail_empty_string_omitted(self):
        err = normalize_error("fail", detail="")
        assert "detail" not in err

    def test_all_fields(self):
        err = normalize_error("fail", status_code=429, retryable=True, detail="rate")
        assert err == {
            "provider": "tavily",
            "error": "fail",
            "status_code": 429,
            "retryable": True,
            "detail": "rate",
        }

    def test_none_defaults_omitted(self):
        err = normalize_error("x")
        assert "status_code" not in err
        assert "retryable" not in err
        assert "detail" not in err


# ---------------------------------------------------------------------------
# 2. TavilyError
# ---------------------------------------------------------------------------


class TestTavilyError:
    def test_stores_error_dict(self):
        d = {"provider": "tavily", "error": "oops"}
        exc = TavilyError(d)
        assert exc.error is d

    def test_message_from_error_key(self):
        exc = TavilyError({"error": "some message"})
        assert str(exc) == "some message"

    def test_missing_error_key_default_message(self):
        exc = TavilyError({"provider": "tavily"})
        assert str(exc) == "Tavily request failed"

    def test_is_runtime_error(self):
        assert issubclass(TavilyError, RuntimeError)


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
    @patch("utils.tavily.load_dotenv")
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

    @patch("utils.tavily.load_dotenv")
    def test_missing_api_key_raises(self, _mock_dotenv, monkeypatch):
        monkeypatch.delenv("TAVILY_API_KEY", raising=False)
        with pytest.raises(TavilyError, match="Missing TAVILY_API_KEY"):
            _build_payload("q", 5, "general", "advanced", True)

    @patch("utils.tavily.load_dotenv")
    def test_blank_api_key_raises(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "   ")
        with pytest.raises(TavilyError, match="Missing TAVILY_API_KEY"):
            _build_payload("q", 5, "general", "advanced", True)


# ---------------------------------------------------------------------------
# 5-11. search()
# ---------------------------------------------------------------------------


# Helper to create a mock response object
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
    """Tests for the search() function."""

    # 5a. empty query
    def test_empty_query_raises_value_error(self, monkeypatch):
        with pytest.raises(ValueError, match="query must not be empty"):
            search("", max_results=5)

    def test_whitespace_only_query_raises_value_error(self, monkeypatch):
        with pytest.raises(ValueError, match="query must not be empty"):
            search("   ", max_results=5)

    # 5b. max_results < 1
    def test_max_results_zero_raises_value_error(self, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        with pytest.raises(ValueError, match="max_results must be >= 1"):
            search("hello", max_results=0)

    def test_max_results_negative_raises_value_error(self, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        with pytest.raises(ValueError, match="max_results must be >= 1"):
            search("hello", max_results=-1)

    # 6. successful response
    @patch("utils.tavily.load_dotenv")
    def test_success_returns_filtered_list(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        results_data = [
            {"title": "A", "url": "https://a.com"},
            {"title": "B", "url": "https://b.com"},
        ]
        resp = _mock_response(json_data={"results": results_data})

        with patch("utils.tavily.requests.post", return_value=resp) as mock_post:
            result = search("test query", max_results=5)
            assert result == results_data
            mock_post.assert_called_once()

    @patch("utils.tavily.load_dotenv")
    def test_success_filters_non_dict_items(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        results_data = [
            {"title": "A"},
            "not a dict",
            42,
            {"title": "B"},
        ]
        resp = _mock_response(json_data={"results": results_data})

        with patch("utils.tavily.requests.post", return_value=resp):
            result = search("query", max_results=5)
            assert result == [{"title": "A"}, {"title": "B"}]

    # 7. HTTP 500 retries then raises
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_http_500_retries_then_raises(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(status_code=500, text="Internal Server Error")

        with patch("utils.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError, match="HTTP 500"):
                search("query", max_results=3)

        # Should have retried MAX_RETRIES times (2 sleeps for 3 total attempts)
        assert mock_sleep.call_count == 2

    # 8. HTTP 400 does NOT retry
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_http_400_no_retry(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(status_code=400, text="Bad Request")

        with patch("utils.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError, match="HTTP 400"):
                search("query", max_results=3)

        # Should NOT have slept (no retries for 4xx except 429)
        mock_sleep.assert_not_called()

    # 8b. HTTP 429 DOES retry
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_http_429_retries(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(status_code=429, text="Too Many Requests")

        with patch("utils.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError, match="HTTP 429"):
                search("query", max_results=3)

        assert mock_sleep.call_count == 2

    # 9. timeout retries
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_timeout_retries_then_raises(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")

        with patch(
            "utils.tavily.requests.post",
            side_effect=requests.Timeout("timed out"),
        ):
            with pytest.raises(TavilyError, match="timed out"):
                search("query", max_results=3)

        assert mock_sleep.call_count == 2

    # 9b. generic RequestException retries
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_request_exception_retries_then_raises(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")

        with patch(
            "utils.tavily.requests.post",
            side_effect=requests.ConnectionError("connection refused"),
        ):
            with pytest.raises(TavilyError, match="request failed"):
                search("query", max_results=3)

        assert mock_sleep.call_count == 2

    # 10. invalid JSON raises TavilyError (non-retryable)
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_invalid_json_raises_no_retry(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(status_code=200, raise_on_json=True)

        with patch("utils.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError, match="Invalid JSON"):
                search("query", max_results=3)

        # Not retryable, so no sleep
        mock_sleep.assert_not_called()

    # 11. results not a list raises TavilyError
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_results_not_list_raises(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(json_data={"results": "not a list"})

        with patch("utils.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError, match="did not include a list"):
                search("query", max_results=3)

        mock_sleep.assert_not_called()

    # Edge: missing "results" key returns empty list
    @patch("utils.tavily.load_dotenv")
    def test_missing_results_key_returns_empty(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(json_data={"answer": "something"})

        with patch("utils.tavily.requests.post", return_value=resp):
            result = search("query", max_results=3)
            assert result == []

    # Edge: HTTP 500 with empty body -> detail should be None
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_http_500_empty_body_detail_none(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(status_code=500, text="")

        with patch("utils.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError) as exc_info:
                search("query", max_results=3)

        assert "detail" not in exc_info.value.error

    # Edge: verify exponential backoff sleep values
    @patch("utils.tavily.load_dotenv")
    @patch("utils.tavily.time.sleep")
    def test_backoff_timing(self, mock_sleep, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(status_code=500, text="err")

        with patch("utils.tavily.requests.post", return_value=resp):
            with pytest.raises(TavilyError):
                search("query", max_results=3)

        # BACKOFF_BASE_SECONDS=0.75, sleep(0.75*2^0)=0.75, sleep(0.75*2^1)=1.5
        assert mock_sleep.call_args_list[0][0][0] == pytest.approx(0.75)
        assert mock_sleep.call_args_list[1][0][0] == pytest.approx(1.5)

    # Edge: search strips whitespace from query
    @patch("utils.tavily.load_dotenv")
    def test_query_whitespace_stripped(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        with patch("utils.tavily.requests.post", return_value=resp) as mock_post:
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

    @patch("utils.tavily.load_dotenv")
    def test_disabled_skips_storage(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.delenv("PSAT_TAVILY_CACHE", raising=False)
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        storage_client = MagicMock()
        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("utils.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]
        mock_post.assert_called_once()
        # No env var → cache helpers must not touch storage at all.
        storage_client.get.assert_not_called()
        storage_client.put.assert_not_called()

    @patch("utils.tavily.load_dotenv")
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
            patch("utils.tavily.requests.post") as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "from-cache", "url": "https://x"}]
        # Cache hit → no HTTP, no cache write.
        mock_post.assert_not_called()
        storage_client.put.assert_not_called()

    @patch("utils.tavily.load_dotenv")
    def test_miss_writes_envelope(self, _mock_dotenv, monkeypatch):
        from db.storage import StorageKeyMissing

        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        resp = _mock_response(json_data={"results": [{"title": "fresh"}]})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("utils.tavily.requests.post", return_value=resp),
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

    @patch("utils.tavily.load_dotenv")
    def test_empty_results_not_cached(self, _mock_dotenv, monkeypatch):
        from db.storage import StorageKeyMissing

        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        resp = _mock_response(json_data={"results": []})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("utils.tavily.requests.post", return_value=resp),
        ):
            result = search("q", max_results=3)

        assert result == []
        # A flaky empty response would poison the cache for 30 days; the write
        # path bails before that happens.
        storage_client.put.assert_not_called()

    @patch("utils.tavily.load_dotenv")
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
            patch("utils.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "fresh"}]
        mock_post.assert_called_once()
        storage_client.put.assert_called_once()

    @patch("utils.tavily.load_dotenv")
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
            patch("utils.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "fresh"}]
        mock_post.assert_called_once()

    @patch("utils.tavily.load_dotenv")
    def test_no_storage_client_falls_through(self, _mock_dotenv, monkeypatch):
        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        with (
            patch("db.storage.get_storage_client", return_value=None),
            patch("utils.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]
        mock_post.assert_called_once()

    @patch("utils.tavily.load_dotenv")
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
            patch("utils.tavily.requests.post", return_value=resp),
        ):
            # Bucket flake on write must not surface to the caller.
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]

    @patch("utils.tavily.load_dotenv")
    def test_cache_read_failure_falls_through(self, _mock_dotenv, monkeypatch):
        from db.storage import StorageUnavailable

        monkeypatch.setenv("TAVILY_API_KEY", "test-key")
        monkeypatch.setenv("PSAT_TAVILY_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageUnavailable("read flake")
        resp = _mock_response(json_data={"results": [{"title": "A"}]})

        with (
            patch("db.storage.get_storage_client", return_value=storage_client),
            patch("utils.tavily.requests.post", return_value=resp) as mock_post,
        ):
            result = search("q", max_results=3)

        assert result == [{"title": "A"}]
        mock_post.assert_called_once()
