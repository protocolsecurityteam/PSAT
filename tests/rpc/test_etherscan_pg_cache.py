from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from services.clients import etherscan


@pytest.fixture(autouse=True)
def _isolated_inmem_cache():
    etherscan.clear_etherscan_cache()
    yield
    etherscan.clear_etherscan_cache()


def _stable_etherscan_response_mock(payload: dict):
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload
    return resp


@pytest.mark.parametrize(
    ("params_a", "params_b", "equal"),
    [
        pytest.param(
            {"address": "0xabc", "extra": "x"}, {"extra": "x", "address": "0xabc"}, True, id="stable_across_key_order"
        ),
        pytest.param({"address": "0xa"}, {"address": "0xb"}, False, id="changes_with_params"),
    ],
)
def test_params_hash(params_a, params_b, equal):
    h1 = etherscan._params_hash("contract", "getsourcecode", 1, params_a)
    h2 = etherscan._params_hash("contract", "getsourcecode", 1, params_b)
    assert (h1 == h2) is equal
    assert len(h1) == 64  # sha256 hex


def test_pg_cache_get_hit_promotes_whitelisted_to_in_memory(monkeypatch):
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    cached_response = {"status": "1", "result": "from-pg"}
    monkeypatch.setattr(etherscan, "_pg_cache_get", lambda *a, **kw: cached_response)
    monkeypatch.setattr(etherscan, "_pg_cache_put", lambda *a, **kw: None)

    monkeypatch.setattr(
        etherscan, "requests", MagicMock(get=MagicMock(side_effect=AssertionError("must not call Etherscan")))
    )
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake")

    result = etherscan.get("contract", "getabi", 1, address="0xabc")
    assert result == cached_response

    def _no_pg(*_a, **_kw):
        raise AssertionError("PG hit must promote to in-memory; second call must short-circuit")

    monkeypatch.setattr(etherscan, "_pg_cache_get", _no_pg)
    second = etherscan.get("contract", "getabi", 1, address="0xabc")
    assert second == cached_response


def test_getsourcecode_served_from_bounded_source_cache_not_metadata_cache(monkeypatch):
    """Multi-MB source blobs in the 256-entry metadata ``_cache`` were the OOM; the separate bounded
    ``_source_cache`` still avoids re-reading PG.
    """
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    cached_response = {"status": "1", "result": [{"SourceCode": "contract Foo {}"}]}

    pg_calls = {"n": 0}

    def _pg(*_a, **_kw):
        pg_calls["n"] += 1
        return cached_response

    monkeypatch.setattr(etherscan, "_pg_cache_get", _pg)
    monkeypatch.setattr(etherscan, "_pg_cache_put", lambda *a, **kw: None)
    monkeypatch.setattr(
        etherscan, "requests", MagicMock(get=MagicMock(side_effect=AssertionError("must not call Etherscan")))
    )
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake")

    etherscan.get("contract", "getsourcecode", 1, address="0xabc")
    etherscan.get("contract", "getsourcecode", 1, address="0xabc")
    assert pg_calls["n"] == 1, "second getsourcecode read must be served from the bounded source cache, not re-hit PG"
    assert etherscan._cache == {}, "source must never enter the small-entry metadata cache"
    assert len(etherscan._source_cache) == 1, "source must be held in the bounded source cache"


def test_pg_cache_miss_calls_etherscan_then_writes_back(monkeypatch):
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_pg_cache_get", lambda *a, **kw: None)

    pg_writes: list[dict] = []

    def _track_put(_m, _a, _c, _p, response):
        pg_writes.append(response)

    monkeypatch.setattr(etherscan, "_pg_cache_put", _track_put)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake-key")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)

    etherscan_response = {"status": "1", "result": "from-etherscan"}
    fake_resp = _stable_etherscan_response_mock(etherscan_response)
    monkeypatch.setattr(etherscan, "requests", MagicMock(get=MagicMock(return_value=fake_resp)))

    result = etherscan.get("contract", "getsourcecode", 1, address="0xdef")
    assert result == etherscan_response
    assert len(pg_writes) == 1, "successful Etherscan response must be written to PG cache"
    assert pg_writes[0] == etherscan_response


def test_pg_cache_whitelisted_actions_pass_through(monkeypatch):
    assert etherscan._pg_cache_eligible("contract", "getsourcecode") is True
    assert etherscan._pg_cache_eligible("contract", "getabi") is True
    assert etherscan._pg_cache_eligible("contract", "getcontractcreation") is True


class _FakePgStore:
    def __init__(self):
        self.store: dict[str, dict] = {}

    def get(self, module, action, chain_id, params):
        if not etherscan._PG_CACHE_ENABLED or not etherscan._pg_cache_eligible(module, action, params):
            return None
        return self.store.get(etherscan._params_hash(module, action, chain_id, dict(params)))

    def put(self, module, action, chain_id, params, response):
        if not etherscan._PG_CACHE_ENABLED or not etherscan._pg_cache_eligible(module, action, params):
            return
        self.store[etherscan._params_hash(module, action, chain_id, dict(params))] = response


def _wire_empty(payload: dict, monkeypatch, pg: _FakePgStore):
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_pg_cache_get", pg.get)
    monkeypatch.setattr(etherscan, "_pg_cache_put", pg.put)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    fake_resp = _stable_etherscan_response_mock(payload)
    wire = MagicMock(get=MagicMock(return_value=fake_resp))
    monkeypatch.setattr(etherscan, "requests", wire)
    return wire


def test_empty_txhash_txlistinternal_cached_in_pg_for_mature_tx(monkeypatch):
    empty = {"status": "0", "message": "No transactions found", "result": []}
    pg = _FakePgStore()
    wire = _wire_empty(empty, monkeypatch, pg)

    first = etherscan.get(
        "account", "txlistinternal", 1, empty_result_ok=True, cache_empty=True, txhash="0x" + "11" * 32
    )
    second = etherscan.get(
        "account", "txlistinternal", 1, empty_result_ok=True, cache_empty=True, txhash="0x" + "11" * 32
    )
    assert first == empty
    assert second == empty
    assert wire.get.call_count == 1, "second empty per-txhash call must be served from the PG cache"


def test_is_persistable_other_actions_pass_through():
    assert etherscan._is_persistable("contract", "getabi", {"status": "1", "result": "[]"}) is True
    assert etherscan._is_persistable("contract", "getcontractcreation", {"status": "1", "result": []}) is True


# In-memory cache: narrow whitelist + bounded LRU


def _wire_status1(payload: dict, monkeypatch):
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_pg_cache_get", lambda *a, **kw: None)
    monkeypatch.setattr(etherscan, "_pg_cache_put", lambda *a, **kw: None)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    fake_resp = _stable_etherscan_response_mock(payload)
    monkeypatch.setattr(etherscan, "requests", MagicMock(get=MagicMock(return_value=fake_resp)))


def test_inmem_cache_bound_evicts(monkeypatch):
    monkeypatch.setattr(etherscan, "_CACHE_MAX", 8)
    _wire_status1({"status": "1", "result": "[]"}, monkeypatch)
    for i in range(20):
        etherscan.get("contract", "getabi", 1, address=f"0x{i:040x}")
    assert len(etherscan._cache) <= etherscan._CACHE_MAX


def test_clear_etherscan_cache_resets_pressure_state(monkeypatch):
    from utils import memory

    monkeypatch.setattr(etherscan, "_CACHE_MAX", 8)
    with etherscan._cache_lock:
        for i in range(5):  # 5/8 = 62% → crosses the 50% threshold
            key = ("contract", "getabi", 1, (("address", f"0x{i:040x}"),))
            etherscan._cache[key] = ({"status": "1"}, float(i))
        etherscan._log_cache_pressure()
    assert memory._CACHE_PRESSURE_STATE.get("etherscan", 0) >= 50

    etherscan.clear_etherscan_cache()
    assert len(etherscan._cache) == 0
    assert "etherscan" not in memory._CACHE_PRESSURE_STATE


def test_source_cache_wire_fetch_populates_then_serves(monkeypatch):
    payload = {"status": "1", "result": [{"SourceCode": "contract Bar {}"}]}
    _wire_status1(payload, monkeypatch)
    etherscan.get("contract", "getsourcecode", 1, address="0xfeed")
    assert len(etherscan._source_cache) == 1
    assert etherscan._cache == {}, "source must not enter the metadata cache"
    setattr(etherscan.requests.get, "side_effect", AssertionError("second call must hit the source cache"))
    result = etherscan.get("contract", "getsourcecode", 1, address="0xfeed")
    assert result == payload


def test_source_cache_bound_evicts(monkeypatch):
    """The cap, not a TTL, is the OOM guard."""
    monkeypatch.setattr(etherscan, "_SOURCE_CACHE_MAX", 8)
    _wire_status1({"status": "1", "result": [{"SourceCode": "contract X {}"}]}, monkeypatch)
    for i in range(20):
        etherscan.get("contract", "getsourcecode", 1, address=f"0x{i:040x}")
    assert len(etherscan._source_cache) <= etherscan._SOURCE_CACHE_MAX


def test_clear_etherscan_cache_clears_source_cache_and_pressure(monkeypatch):
    from utils import memory

    monkeypatch.setattr(etherscan, "_SOURCE_CACHE_MAX", 8)
    with etherscan._source_cache_lock:
        for i in range(5):  # 5/8 = 62% → crosses the 50% threshold
            key = ("contract", "getsourcecode", 1, (("address", f"0x{i:040x}"),))
            etherscan._source_cache[key] = ({"status": "1"}, float(i))
        etherscan._log_source_cache_pressure()
    assert memory._CACHE_PRESSURE_STATE.get("etherscan_source", 0) >= 50

    etherscan.clear_etherscan_cache()
    assert len(etherscan._source_cache) == 0
    assert "etherscan_source" not in memory._CACHE_PRESSURE_STATE
