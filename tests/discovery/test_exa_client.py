from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import pytest
import requests

from db.storage import StorageKeyMissing, StorageUnavailable
from services.clients import exa
from services.clients.exa import _cache_key


class _FakeResp:
    def __init__(self, *, status_code: int = 200, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


def test_normalize_error_full():
    err = exa.normalize_error("boom", status_code=429, retryable=True, detail="rate limited")
    assert err["provider"] == "exa"
    assert err["status_code"] == 429
    assert err["retryable"] is True
    assert err["detail"] == "rate limited"


def test_error_from_exception_exa_error():
    original = exa.normalize_error("oops", retryable=False)
    out = exa.error_from_exception(exa.ExaError(original))
    assert out == original


def test_error_from_exception_generic():
    out = exa.error_from_exception(KeyError("missing"))
    assert out["provider"] == "exa"
    assert out["retryable"] is False


def test_get_api_key_missing(monkeypatch):
    monkeypatch.delenv("EXA_API_KEY", raising=False)
    monkeypatch.setattr(exa, "load_dotenv", lambda *a, **kw: None)
    with pytest.raises(exa.ExaError) as ei:
        exa._get_api_key()
    assert "EXA_API_KEY" in ei.value.error["error"]


def test_get_api_key_present(monkeypatch):
    monkeypatch.setenv("EXA_API_KEY", "  abc  ")
    monkeypatch.setattr(exa, "load_dotenv", lambda *a, **kw: None)
    assert exa._get_api_key() == "abc"


@pytest.mark.parametrize(
    ("query", "kwargs"),
    [
        pytest.param("   ", {"max_results": 5}, id="empty_query"),
        pytest.param("q", {"max_results": 0}, id="zero_results"),
        pytest.param("q", {"max_results": 5, "mode": "bogus"}, id="unsupported_mode"),
    ],
)
def test_search_rejects_invalid_arguments(query, kwargs):
    with pytest.raises(ValueError):
        exa.search(query, **kwargs)


@pytest.mark.parametrize(
    "alias,resolved", [("regular", "auto"), ("instant", "keyword"), ("auto", "auto"), ("deep-lite", "deep-lite")]
)
def test_search_mode_aliases(monkeypatch, alias, resolved):
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
    captured = {}

    def fake_post(url, json, headers, timeout):
        captured["payload"] = json
        return _FakeResp(payload={"results": []})

    monkeypatch.setattr(exa.requests, "post", fake_post)
    exa.search("ether.fi", max_results=3, mode=alias)
    assert captured["payload"]["type"] == resolved
    assert captured["payload"]["numResults"] == 3
    assert captured["payload"]["query"] == "ether.fi"


def test_search_happy_path_normalizes(monkeypatch):
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")

    payload = {
        "results": [
            {
                "url": "https://a.example.com",
                "title": "  Title A  ",
                "text": "snip-a",
                "score": 0.9,
            },
            {
                "url": "https://b.example.com",
                "title": "B",
                "text": {"text": "from-dict"},
                "score": 0.5,
            },
            {"url": "https://c.example.com", "content": "from-content"},
            {"title": "no url"},
        ]
    }
    monkeypatch.setattr(exa.requests, "post", lambda *a, **kw: _FakeResp(payload=payload))
    out = exa.search("q", max_results=4)
    assert len(out) == 3
    assert out[0]["title"] == "Title A"
    assert out[0]["score"] == 0.9
    assert out[1]["content"] == "from-dict"
    assert out[2]["content"] == "from-content"


def test_search_include_text_false_omits_contents(monkeypatch):
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
    captured = {}

    def fake_post(url, json, headers, timeout):
        captured["payload"] = json
        return _FakeResp(payload={"results": []})

    monkeypatch.setattr(exa.requests, "post", fake_post)
    exa.search("q", max_results=1, include_text=False)
    assert "contents" not in captured["payload"]


def test_search_network_error(monkeypatch):
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")

    def fake_post(*a, **kw):
        raise requests.ConnectionError("dropped")

    monkeypatch.setattr(exa.requests, "post", fake_post)
    with pytest.raises(exa.ExaError) as ei:
        exa.search("q", max_results=1)
    assert ei.value.error["retryable"] is True


@pytest.mark.parametrize("status,retryable", [(429, True), (502, True), (400, False), (401, False)])
def test_search_http_error(monkeypatch, status, retryable):
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
    monkeypatch.setattr(
        exa.requests,
        "post",
        lambda *a, **kw: _FakeResp(status_code=status, text="boom"),
    )
    with pytest.raises(exa.ExaError) as ei:
        exa.search("q", max_results=1)
    assert ei.value.error["retryable"] is retryable
    assert ei.value.error["status_code"] == status


def test_search_truncates_content_to_1000(monkeypatch):
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
    long_text = "y" * 5000
    monkeypatch.setattr(
        exa.requests,
        "post",
        lambda *a, **kw: _FakeResp(payload={"results": [{"url": "https://x.example.com", "text": long_text}]}),
    )
    out = exa.search("q", max_results=1)
    assert len(out[0]["content"]) == 1000


def test_deep_research_happy_path(monkeypatch):
    # time.sleep is imported inside the function.
    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda _s: None)
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")

    create_resp = _FakeResp(payload={"id": "task-123"})
    poll_resp = _FakeResp(
        payload={
            "status": "completed",
            "data": {"auditReports": [{"auditor": "Trail of Bits", "url": "https://example.com/a"}]},
        }
    )
    monkeypatch.setattr(exa.requests, "post", lambda *a, **kw: create_resp)
    monkeypatch.setattr(exa.requests, "get", lambda *a, **kw: poll_resp)

    out = exa.deep_research("find audits", timeout_seconds=60)
    assert out["task_id"] == "task-123"
    assert out["status"] == "completed"
    assert out["data"]["auditReports"][0]["url"] == "https://example.com/a"


@pytest.mark.parametrize(
    ("create_resp", "poll_resp", "status_code", "fragment"),
    [
        pytest.param(_FakeResp(status_code=500, text="server boom"), None, 500, "create", id="create_http_error"),
        pytest.param(
            _FakeResp(payload={"id": "t1"}),
            _FakeResp(status_code=503, text="unavail"),
            503,
            "poll",
            id="poll_http_error",
        ),
    ],
)
def test_deep_research_http_errors_carry_status(monkeypatch, create_resp, poll_resp, status_code, fragment):
    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda _s: None)
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
    monkeypatch.setattr(exa.requests, "post", lambda *a, **kw: create_resp)
    monkeypatch.setattr(exa.requests, "get", lambda *a, **kw: poll_resp)
    with pytest.raises(exa.ExaError) as ei:
        exa.deep_research("inst", timeout_seconds=60)
    assert ei.value.error["status_code"] == status_code
    assert fragment in ei.value.error["error"]


@pytest.mark.parametrize(
    ("create_resp", "poll_resp", "fragment"),
    [
        pytest.param(_FakeResp(payload={"foo": "bar"}), None, "no task id", id="no_task_id"),
        pytest.param(
            _FakeResp(payload={"id": "t1"}),
            _FakeResp(payload={"status": "failed", "error": "model down"}),
            "failed",
            id="failed_status",
        ),
    ],
)
def test_deep_research_task_errors(monkeypatch, create_resp, poll_resp, fragment):
    import time as _time

    monkeypatch.setattr(_time, "sleep", lambda _s: None)
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
    monkeypatch.setattr(exa.requests, "post", lambda *a, **kw: create_resp)
    monkeypatch.setattr(exa.requests, "get", lambda *a, **kw: poll_resp)
    with pytest.raises(exa.ExaError) as ei:
        exa.deep_research("inst", timeout_seconds=60)
    assert fragment in ei.value.error["error"]


def test_deep_research_timeout(monkeypatch):
    import time as _time

    ticks = iter([0.0, 0.0, 100.0, 100.0])
    monkeypatch.setattr(_time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(_time, "sleep", lambda _s: None)
    monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
    monkeypatch.setattr(exa.requests, "post", lambda *a, **kw: _FakeResp(payload={"id": "t1"}))
    monkeypatch.setattr(
        exa.requests,
        "get",
        lambda *a, **kw: _FakeResp(payload={"status": "running"}),
    )
    with pytest.raises(exa.ExaError) as ei:
        exa.deep_research("inst", timeout_seconds=10)
    assert "timed out" in ei.value.error["error"]


class TestCacheKey:
    def _key_for(self, **overrides):
        base = {
            "api_key": "secret",
            "endpoint": "search",
            "query": "etherfi",
            "numResults": 10,
            "type": "auto",
        }
        base.update(overrides)
        return _cache_key(base)

    def test_api_key_excluded(self):
        assert self._key_for(api_key="A") == self._key_for(api_key="B")

    @pytest.mark.parametrize(
        ("a", "b"),
        [
            pytest.param({"query": "x"}, {"query": "y"}, id="query"),
            pytest.param({"numResults": 5}, {"numResults": 10}, id="num_results"),
            pytest.param({"type": "neural"}, {"type": "keyword"}, id="type"),
            pytest.param({"endpoint": "search"}, {"endpoint": "deep_research"}, id="endpoint"),
        ],
    )
    def test_field_drives_key(self, a, b):
        assert self._key_for(**a) != self._key_for(**b)

    def test_stable_across_dict_ordering(self):
        k1 = _cache_key({"a": 1, "b": 2, "api_key": "x"})
        k2 = _cache_key({"b": 2, "a": 1, "api_key": "y"})
        assert k1 == k2


class TestSearchCacheBehavior:
    def test_disabled_skips_storage(self, monkeypatch):
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.delenv("PSAT_EXA_CACHE", raising=False)
        storage_client = MagicMock()
        post_mock = MagicMock(return_value=_FakeResp(payload={"results": [{"url": "https://x", "text": "a"}]}))

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            result = exa.search("q", max_results=3)

        assert result == [{"url": "https://x", "title": "", "content": "a", "score": None}]
        post_mock.assert_called_once()
        storage_client.get.assert_not_called()
        storage_client.put.assert_not_called()

    def test_hit_skips_network(self, monkeypatch):
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        cached_payload = [{"url": "https://cached", "title": "from-cache", "content": "c", "score": 0.9}]
        envelope = json.dumps(
            {
                "schema_version": 1,
                "cached_at": time.time(),
                "payload": cached_payload,
            }
        ).encode("utf-8")

        storage_client = MagicMock()
        storage_client.get.return_value = envelope
        post_mock = MagicMock()

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            result = exa.search("q", max_results=3)

        assert result == cached_payload
        post_mock.assert_not_called()
        storage_client.put.assert_not_called()

    def test_miss_writes_envelope(self, monkeypatch):
        from db.storage import StorageKeyMissing

        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        post_mock = MagicMock(return_value=_FakeResp(payload={"results": [{"url": "https://fresh", "text": "f"}]}))

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            result = exa.search("q", max_results=3)

        assert result == [{"url": "https://fresh", "title": "", "content": "f", "score": None}]
        storage_client.put.assert_called_once()
        key, body = storage_client.put.call_args.args[0], storage_client.put.call_args.args[1]
        assert key.startswith("exa-cache/") and key.endswith(".json")
        envelope = json.loads(body)
        assert envelope["schema_version"] == 1
        assert envelope["payload"][0]["url"] == "https://fresh"

    def test_empty_results_not_cached(self, monkeypatch):
        from db.storage import StorageKeyMissing

        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        post_mock = MagicMock(return_value=_FakeResp(payload={"results": []}))

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            result = exa.search("q", max_results=3)

        assert result == []
        # An empty response would poison the cache for 30 days.
        storage_client.put.assert_not_called()

    def test_expired_envelope_refetches(self, monkeypatch):
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        stale = json.dumps(
            {
                "schema_version": 1,
                "cached_at": time.time() - (40 * 24 * 60 * 60),  # 40 days old
                "payload": [{"url": "https://stale"}],
            }
        ).encode("utf-8")

        storage_client = MagicMock()
        storage_client.get.return_value = stale
        post_mock = MagicMock(return_value=_FakeResp(payload={"results": [{"url": "https://fresh"}]}))

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            result = exa.search("q", max_results=3)

        assert result[0]["url"] == "https://fresh"
        post_mock.assert_called_once()
        storage_client.put.assert_called_once()

    def test_schema_mismatch_refetches(self, monkeypatch):
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        wrong = json.dumps(
            {
                "schema_version": 99,
                "cached_at": time.time(),
                "payload": [{"url": "https://v99"}],
            }
        ).encode("utf-8")

        storage_client = MagicMock()
        storage_client.get.return_value = wrong
        post_mock = MagicMock(return_value=_FakeResp(payload={"results": [{"url": "https://fresh"}]}))

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            result = exa.search("q", max_results=3)

        assert result[0]["url"] == "https://fresh"
        post_mock.assert_called_once()

    @pytest.mark.parametrize(
        ("has_client", "get_exc", "put_exc"),
        [
            pytest.param(False, None, None, id="no_storage_client"),
            pytest.param(True, StorageKeyMissing("k"), StorageUnavailable("bucket down"), id="cache_write_failure"),
            pytest.param(True, StorageUnavailable("read flake"), None, id="cache_read_failure"),
        ],
    )
    def test_storage_trouble_falls_through_to_network(self, monkeypatch, has_client, get_exc, put_exc):
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = get_exc
        storage_client.put.side_effect = put_exc
        post_mock = MagicMock(return_value=_FakeResp(payload={"results": [{"url": "https://x"}]}))

        with patch("db.storage.get_storage_client", return_value=storage_client if has_client else None):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            result = exa.search("q", max_results=3)

        assert result[0]["url"] == "https://x"
        post_mock.assert_called_once()


class TestDeepResearchCacheBehavior:
    def test_hit_skips_task_creation(self, monkeypatch):
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        cached = {
            "data": {"auditReports": [{"auditor": "ToB", "url": "https://x"}]},
            "task_id": "old",
            "status": "completed",
        }
        envelope = json.dumps({"schema_version": 1, "cached_at": time.time(), "payload": cached}).encode("utf-8")

        storage_client = MagicMock()
        storage_client.get.return_value = envelope
        post_mock = MagicMock()
        get_mock = MagicMock()

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            monkeypatch.setattr(exa.requests, "get", get_mock)
            out = exa.deep_research("inst", timeout_seconds=60)

        assert out == cached
        post_mock.assert_not_called()
        get_mock.assert_not_called()
        storage_client.put.assert_not_called()

    def test_miss_writes_completed_envelope(self, monkeypatch):
        import time as _time

        from db.storage import StorageKeyMissing

        monkeypatch.setattr(_time, "sleep", lambda _s: None)
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        post_mock = MagicMock(return_value=_FakeResp(payload={"id": "task-77"}))
        get_mock = MagicMock(
            return_value=_FakeResp(payload={"status": "completed", "data": {"auditReports": [{"a": 1}]}})
        )

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            monkeypatch.setattr(exa.requests, "get", get_mock)
            out = exa.deep_research("inst", timeout_seconds=60)

        assert out["status"] == "completed"
        assert out["task_id"] == "task-77"
        storage_client.put.assert_called_once()
        key, body = storage_client.put.call_args.args[0], storage_client.put.call_args.args[1]
        assert key.startswith("exa-cache/")
        envelope = json.loads(body)
        assert envelope["payload"]["task_id"] == "task-77"
        assert envelope["payload"]["data"]["auditReports"] == [{"a": 1}]

    def test_empty_data_not_cached(self, monkeypatch):
        import time as _time

        from db.storage import StorageKeyMissing

        monkeypatch.setattr(_time, "sleep", lambda _s: None)
        monkeypatch.setattr(exa, "_get_api_key", lambda: "k")
        monkeypatch.setenv("PSAT_EXA_CACHE", "1")

        storage_client = MagicMock()
        storage_client.get.side_effect = StorageKeyMissing("k")
        post_mock = MagicMock(return_value=_FakeResp(payload={"id": "task-empty"}))
        get_mock = MagicMock(return_value=_FakeResp(payload={"status": "completed", "data": {}}))

        with patch("db.storage.get_storage_client", return_value=storage_client):
            monkeypatch.setattr(exa.requests, "post", post_mock)
            monkeypatch.setattr(exa.requests, "get", get_mock)
            out = exa.deep_research("inst", timeout_seconds=60)

        assert out["data"] == {}
        storage_client.put.assert_not_called()
