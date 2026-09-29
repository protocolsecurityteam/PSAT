"""Regression tests for the Postgres-backed Etherscan cache layer in ``services.clients.etherscan``.

Phase B Step 5: a PG layer (``etherscan_cache``) lets workers share hits across the fleet on
top of the per-process ``_cache``. Pinned: params-hash equivalence with the in-memory key;
disabled flag and DB outages degrade gracefully; a PG hit skips Etherscan and is promoted
in-memory; a miss populates both layers. Mocks at the module boundary (db.models.SessionLocal,
requests.get): no real DB or network.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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
        # Key order must not change the hash.
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


def test_pg_cache_disabled_skips_db(monkeypatch):
    """ETHERSCAN_PG_CACHE=0 must not import db.models / open a session (DB-less CLI tooling must keep working)."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", False)
    result = etherscan._pg_cache_get("contract", "getsourcecode", 1, {"address": "0xa"})
    assert result is None


def test_pg_cache_get_returns_none_on_db_unavailable(monkeypatch):
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)

    def _raise_session(*_a, **_kw):
        raise RuntimeError("DB connection refused")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_raise_session)}):
        result = etherscan._pg_cache_get("contract", "getsourcecode", 1, {"address": "0xa"})
    assert result is None


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
    """getsourcecode never enters the small-entry metadata ``_cache`` (256 multi-MB blobs would be the OOM).
    It IS held in the SEPARATE, tightly bounded ``_source_cache`` so a run doesn't re-deserialize
    it from Postgres on every read: first read hits PG, second is served in-process."""
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


def test_pg_cache_put_swallows_db_errors(monkeypatch):
    """Best-effort write: DB errors in _pg_cache_put must NOT propagate; a flaky cache write must never fail a
    successful Etherscan call."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)

    def _raise_session(*_a, **_kw):
        raise RuntimeError("DB write timeout")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_raise_session)}):
        etherscan._pg_cache_put("contract", "getsourcecode", 1, {"address": "0xa"}, {"status": "1"})


# Codex iter-4 P1: PG cache whitelist gates non-immutable actions


def test_pg_cache_skips_non_whitelisted_actions(monkeypatch):
    """Codex iter-4 P1: dynamic actions (account/balance, stats/ethprice) MUST NOT be persisted, or
    every worker would see the first balance lookup's stale value forever."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)
    assert etherscan._pg_cache_eligible("account", "balance") is False
    assert etherscan._pg_cache_eligible("stats", "ethprice") is False

    def _no_db(*_a, **_kw):
        raise AssertionError("non-whitelisted action must not touch DB")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_no_db)}):
        result = etherscan._pg_cache_get("account", "balance", 1, {"address": "0xa"})
    assert result is None

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_no_db)}):
        etherscan._pg_cache_put("account", "balance", 1, {"address": "0xa"}, {"status": "1"})


def test_pg_cache_whitelisted_actions_pass_through(monkeypatch):
    """Whitelisted actions DO go to the DB (else the PG layer is dead code)."""
    assert etherscan._pg_cache_eligible("contract", "getsourcecode") is True
    assert etherscan._pg_cache_eligible("contract", "getabi") is True
    assert etherscan._pg_cache_eligible("contract", "getcontractcreation") is True


def test_pg_cache_txlistinternal_by_txhash_only(monkeypatch):
    assert etherscan._pg_cache_eligible("account", "txlistinternal", {"txhash": "0x" + "11" * 32}) is True
    assert etherscan._pg_cache_eligible("account", "txlistinternal", {"address": "0xa"}) is False
    assert etherscan._pg_cache_eligible("account", "txlistinternal") is False
    assert etherscan._pg_cache_eligible("account", "txlist", {"address": "0xa"}) is False


# ---------------------------------------------------------------------------
# Empty-result caching: immutable per-txhash empties persist; dynamic empties stay uncached
# ---------------------------------------------------------------------------


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
    """A MATURE mined tx with no internal frames is a permanent fact: with the caller's
    ``cache_empty=True`` attestation the empty answer persists (exactly one wire call)."""
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


def test_empty_txhash_txlistinternal_not_cached_for_immature_tx(monkeypatch):
    """Etherscan's trace indexing lags the head: an empty answer without the ``cache_empty``
    maturity attestation may be a transient false-empty, so it is never persisted."""
    empty = {"status": "0", "message": "No transactions found", "result": []}
    pg = _FakePgStore()
    wire = _wire_empty(empty, monkeypatch, pg)

    etherscan.get("account", "txlistinternal", 1, empty_result_ok=True, txhash="0x" + "22" * 32)
    etherscan.get("account", "txlistinternal", 1, empty_result_ok=True, txhash="0x" + "22" * 32)
    assert wire.get.call_count == 2, "an unattested empty must not be served from the PG cache"
    assert pg.store == {}, "immature empty must never persist"


@pytest.mark.parametrize(
    ("action", "message", "reason"),
    [
        pytest.param("txlist", "No transactions found", "by-address empty must never persist", id="txlist_by_address"),
        pytest.param(
            "addresstokenbalance", "No token found", "dynamic empty must never persist", id="addresstokenbalance"
        ),
    ],
)
def test_dynamic_empty_not_cached(monkeypatch, action, message, reason):
    empty = {"status": "0", "message": message, "result": []}
    pg = _FakePgStore()
    wire = _wire_empty(empty, monkeypatch, pg)

    etherscan.get("account", action, 1, empty_result_ok=True, address="0xabc")
    etherscan.get("account", action, 1, empty_result_ok=True, address="0xabc")
    assert wire.get.call_count == 2
    assert pg.store == {}, reason


# Codex iter-5 P2: skip caching empty-source / unverified responses


def test_is_persistable_skips_empty_getsourcecode():
    """Etherscan returns status="1" with empty SourceCode for not-yet-verified contracts; persisting it would poison
    the cache after verification."""
    response = {
        "status": "1",
        "result": [
            {
                "SourceCode": "",
                "ABI": "",
                "ContractName": "",
            }
        ],
    }
    assert etherscan._is_persistable("contract", "getsourcecode", response) is False


def test_is_persistable_accepts_real_source():
    response = {
        "status": "1",
        "result": [
            {"SourceCode": "contract Foo {}", "ContractName": "Foo"},
        ],
    }
    assert etherscan._is_persistable("contract", "getsourcecode", response) is True


def test_is_persistable_other_actions_pass_through():
    assert etherscan._is_persistable("contract", "getabi", {"status": "1", "result": "[]"}) is True
    assert etherscan._is_persistable("contract", "getcontractcreation", {"status": "1", "result": []}) is True


def test_pg_cache_put_skips_unverified_source(monkeypatch):
    """An empty-source response must not reach the DB at all (skips before SessionLocal is imported)."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)

    def _no_db(*_a, **_kw):
        raise AssertionError("must not touch DB on empty-source response")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_no_db)}):
        etherscan._pg_cache_put(
            "contract",
            "getsourcecode",
            1,
            {"address": "0xunverified"},
            {"status": "1", "result": [{"SourceCode": "", "ContractName": ""}]},
        )


# In-memory cache: narrow whitelist (P0.1) + bounded LRU (P0.2)


def test_inmem_cache_eligible_whitelist():
    """Only small, immutable contract metadata is held in process memory; source is psql-only and volatile data is
    never in-mem-cached."""
    assert etherscan._inmem_cache_eligible("contract", "getabi") is True
    assert etherscan._inmem_cache_eligible("contract", "getcontractcreation") is True
    assert etherscan._inmem_cache_eligible("contract", "getsourcecode") is False
    assert etherscan._inmem_cache_eligible("account", "balance") is False
    assert etherscan._inmem_cache_eligible("stats", "ethprice") is False
    assert etherscan._inmem_cache_eligible("account", "txlist") is False
    assert etherscan._inmem_cache_eligible("account", "addresstokenbalance") is False
    assert etherscan._inmem_cache_eligible("logs", "getLogs") is False


def _wire_status1(payload: dict, monkeypatch):
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_pg_cache_get", lambda *a, **kw: None)
    monkeypatch.setattr(etherscan, "_pg_cache_put", lambda *a, **kw: None)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    fake_resp = _stable_etherscan_response_mock(payload)
    monkeypatch.setattr(etherscan, "requests", MagicMock(get=MagicMock(return_value=fake_resp)))


def test_volatile_actions_never_inmem_cached(monkeypatch):
    _wire_status1({"status": "1", "result": "123"}, monkeypatch)
    etherscan.get("account", "balance", 1, address="0xabc", tag="latest")
    etherscan.get("stats", "ethprice", 1)
    etherscan.get("account", "txlist", 1, address="0xabc")
    assert etherscan._cache == {}, "volatile actions must never enter the in-mem cache"


def test_whitelisted_action_is_inmem_cached(monkeypatch):
    _wire_status1({"status": "1", "result": "[]"}, monkeypatch)
    etherscan.get("contract", "getabi", 1, address="0xfeed")
    assert len(etherscan._cache) == 1
    setattr(etherscan.requests.get, "side_effect", AssertionError("second call must hit in-mem cache"))
    etherscan.get("contract", "getabi", 1, address="0xfeed")


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


# ---------------------------------------------------------------------------
# Bounded in-process source cache (getsourcecode only): cuts redundant multi-MB Postgres
# deserializes WITHOUT reintroducing the OOM (separate tightly bounded LRU).
# ---------------------------------------------------------------------------


def test_source_cache_eligible():
    assert etherscan._source_cache_eligible("contract", "getsourcecode") is True
    assert etherscan._source_cache_eligible("contract", "getabi") is False
    assert etherscan._source_cache_eligible("contract", "getcontractcreation") is False
    assert etherscan._source_cache_eligible("account", "balance") is False


def test_source_cache_wire_fetch_populates_then_serves(monkeypatch):
    payload = {"status": "1", "result": [{"SourceCode": "contract Bar {}"}]}
    _wire_status1(payload, monkeypatch)
    etherscan.get("contract", "getsourcecode", 1, address="0xfeed")
    assert len(etherscan._source_cache) == 1
    assert etherscan._cache == {}, "source must not enter the metadata cache"
    setattr(etherscan.requests.get, "side_effect", AssertionError("second call must hit the source cache"))
    result = etherscan.get("contract", "getsourcecode", 1, address="0xfeed")
    assert result == payload


def test_source_cache_skips_empty_source(monkeypatch):
    """An empty-source response must NOT be pinned in the source cache (mirrors the PG gate), so a later verification
    isn't masked."""
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    key = ("contract", "getsourcecode", 1, (("address", "0xunverified"),))
    etherscan._source_cache_put(key, "contract", "getsourcecode", {"status": "1", "result": [{"SourceCode": ""}]})
    assert etherscan._source_cache == {}, "empty/unverified source must not be cached"
    etherscan._source_cache_put(key, "contract", "getsourcecode", {"status": "1", "result": [{"SourceCode": "x"}]})
    assert len(etherscan._source_cache) == 1


def test_source_cache_bound_evicts(monkeypatch):
    """The source cache cannot grow past _SOURCE_CACHE_MAX: the OOM guard for multi-MB blobs (the cap, not a TTL, is
    the bound)."""
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
