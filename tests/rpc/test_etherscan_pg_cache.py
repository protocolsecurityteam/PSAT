"""Regression tests for the Postgres-backed Etherscan cache layer in
``utils.etherscan``.

Phase B Step 5. The in-memory cache (``_cache``) was per-process; this
adds a Postgres-backed layer (``etherscan_cache`` table) so worker
processes share hits across the fleet — a cold cascade on worker A
that fetched WETH source code populates the cache for worker B's
sibling cascade later.

What we pin:
1. params hashing: same equivalence class as in-memory _cache_key
2. PG-cache disabled (env flag off) → no DB calls attempted
3. PG-cache enabled, DB unavailable → graceful degradation (no crash,
   no exception bubbling)
4. PG-cache hit → returned without calling Etherscan AND populated
   into the in-memory layer (so the second call in same process is
   free again)
5. PG-cache miss → Etherscan called, response cached in BOTH layers

Mocks at the module-level boundary (db.models.SessionLocal,
requests.get for Etherscan) so no real DB or network access.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from utils import etherscan


@pytest.fixture(autouse=True)
def _isolated_inmem_cache():
    etherscan.clear_etherscan_cache()
    yield
    etherscan.clear_etherscan_cache()


def _stable_etherscan_response_mock(payload: dict):
    """Build a mock for `requests.get` returning a successful Etherscan envelope."""
    resp = MagicMock()
    resp.status_code = 200
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload
    return resp


def test_params_hash_is_stable_for_same_inputs():
    """Hash must be deterministic — same module/action/chain_id/params
    in any param order yields the same hash."""
    h1 = etherscan._params_hash("contract", "getsourcecode", 1, {"address": "0xabc", "extra": "x"})
    h2 = etherscan._params_hash("contract", "getsourcecode", 1, {"extra": "x", "address": "0xabc"})
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_params_hash_changes_with_params():
    """Different params must yield different hashes (collision rejection)."""
    h1 = etherscan._params_hash("contract", "getsourcecode", 1, {"address": "0xa"})
    h2 = etherscan._params_hash("contract", "getsourcecode", 1, {"address": "0xb"})
    assert h1 != h2


def test_pg_cache_disabled_skips_db(monkeypatch):
    """ETHERSCAN_PG_CACHE=0 → _pg_cache_get must NOT attempt to import
    db.models / open a session. CLI tooling that doesn't have a DB
    must keep working."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", False)
    # If a DB call were attempted this would fail; instead we expect None.
    result = etherscan._pg_cache_get("contract", "getsourcecode", 1, {"address": "0xa"})
    assert result is None


def test_pg_cache_get_returns_none_on_db_unavailable(monkeypatch):
    """Graceful degradation: importing/using db.models can fail (DB not
    configured, connection refused). Must not crash; just return None."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)

    def _raise_session(*_a, **_kw):
        raise RuntimeError("DB connection refused")

    # Patch the lazy-imported SessionLocal to blow up on use.
    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_raise_session)}):
        result = etherscan._pg_cache_get("contract", "getsourcecode", 1, {"address": "0xa"})
    assert result is None


def test_pg_cache_get_hit_promotes_whitelisted_to_in_memory(monkeypatch):
    """A PG-cache hit on an in-mem-whitelisted action (getabi) must
    populate the in-memory cache too — second call in the same process
    should be free (never reaches PG)."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    cached_response = {"status": "1", "result": "from-pg"}
    monkeypatch.setattr(etherscan, "_pg_cache_get", lambda *a, **kw: cached_response)
    monkeypatch.setattr(etherscan, "_pg_cache_put", lambda *a, **kw: None)

    # If we hit Etherscan, fail loudly.
    monkeypatch.setattr(
        etherscan, "requests", MagicMock(get=MagicMock(side_effect=AssertionError("must not call Etherscan")))
    )
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake")

    result = etherscan.get("contract", "getabi", 1, address="0xabc")
    assert result == cached_response

    # In-memory cache now populated — second call doesn't even hit PG.
    def _no_pg(*_a, **_kw):
        raise AssertionError("PG hit must promote to in-memory; second call must short-circuit")

    monkeypatch.setattr(etherscan, "_pg_cache_get", _no_pg)
    second = etherscan.get("contract", "getabi", 1, address="0xabc")
    assert second == cached_response


def test_getsourcecode_served_from_bounded_source_cache_not_metadata_cache(monkeypatch):
    """getsourcecode never enters the small-entry metadata ``_cache`` (256 multi-MB
    source blobs would be the OOM). It IS held in the SEPARATE, tightly bounded
    ``_source_cache`` so a contract's source isn't re-deserialized from Postgres on
    every read within a run: the first read hits PG, the second is served in-process."""
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
    """PG-cache miss → Etherscan is hit → response is written to BOTH
    in-memory and PG. Verify the write-back fires."""
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
    """Best-effort write: DB errors during _pg_cache_put must NOT
    propagate (the in-memory cache + caller's retry loop are the safety
    net). A flaky cache write should never fail an otherwise-successful
    Etherscan call."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)

    def _raise_session(*_a, **_kw):
        raise RuntimeError("DB write timeout")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_raise_session)}):
        # Should not raise.
        etherscan._pg_cache_put("contract", "getsourcecode", 1, {"address": "0xa"}, {"status": "1"})


# ---------------------------------------------------------------------------
# Codex iter-4 P1: PG cache whitelist gates non-immutable actions
# ---------------------------------------------------------------------------


def test_pg_cache_skips_non_whitelisted_actions(monkeypatch):
    """Codex iter-4 P1: with PG cache enabled, dynamic Etherscan actions
    (account/balance, stats/ethprice, etc.) MUST NOT be persisted —
    after the first balance lookup, every worker would see that stale
    value forever. Whitelist gates which actions get the PG layer."""
    monkeypatch.setattr(etherscan, "_PG_CACHE_ENABLED", True)
    # account/balance is intentionally NOT in _PG_CACHE_WHITELIST.
    assert etherscan._pg_cache_eligible("account", "balance") is False
    assert etherscan._pg_cache_eligible("stats", "ethprice") is False

    # _pg_cache_get must short-circuit (return None) for non-whitelisted
    # without ever reaching the DB.
    def _no_db(*_a, **_kw):
        raise AssertionError("non-whitelisted action must not touch DB")

    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_no_db)}):
        result = etherscan._pg_cache_get("account", "balance", 1, {"address": "0xa"})
    assert result is None

    # Same for puts.
    with patch.dict("sys.modules", {"db.models": MagicMock(SessionLocal=_no_db)}):
        etherscan._pg_cache_put("account", "balance", 1, {"address": "0xa"}, {"status": "1"})


def test_pg_cache_whitelisted_actions_pass_through(monkeypatch):
    """Whitelisted actions (contract/getsourcecode + adjacent immutable
    contract metadata) DO go to the DB. Without this the entire PG
    layer is dead code."""
    assert etherscan._pg_cache_eligible("contract", "getsourcecode") is True
    assert etherscan._pg_cache_eligible("contract", "getabi") is True
    assert etherscan._pg_cache_eligible("contract", "getcontractcreation") is True


# ---------------------------------------------------------------------------
# Codex iter-5 P2: skip caching empty-source / unverified responses
# ---------------------------------------------------------------------------


def test_is_persistable_skips_empty_getsourcecode():
    """Etherscan returns status="1" for not-yet-verified contracts but
    with an empty SourceCode field. Persisting that would poison the
    cache after the contract gets verified."""
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
    """Successful getsourcecode WITH source content must be persistable."""
    response = {
        "status": "1",
        "result": [
            {"SourceCode": "contract Foo {}", "ContractName": "Foo"},
        ],
    }
    assert etherscan._is_persistable("contract", "getsourcecode", response) is True


def test_is_persistable_other_actions_pass_through():
    """Non-getsourcecode whitelisted actions don't have the empty-success
    pattern; they always persist."""
    assert etherscan._is_persistable("contract", "getabi", {"status": "1", "result": "[]"}) is True
    assert etherscan._is_persistable("contract", "getcontractcreation", {"status": "1", "result": []}) is True


def test_pg_cache_put_skips_unverified_source(monkeypatch):
    """The full _pg_cache_put path: empty-source response must not
    reach the DB at all (skips before SessionLocal is even imported)."""
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


# ---------------------------------------------------------------------------
# In-memory cache: narrow whitelist (P0.1) + bounded LRU (P0.2)
# ---------------------------------------------------------------------------


def test_inmem_cache_eligible_whitelist():
    """Only the small, immutable contract metadata actions are held in
    process memory. Source is psql-only; volatile data (balances, prices,
    tx history, logs) is never in-mem-cached."""
    assert etherscan._inmem_cache_eligible("contract", "getabi") is True
    assert etherscan._inmem_cache_eligible("contract", "getcontractcreation") is True
    assert etherscan._inmem_cache_eligible("contract", "getsourcecode") is False
    assert etherscan._inmem_cache_eligible("account", "balance") is False
    assert etherscan._inmem_cache_eligible("stats", "ethprice") is False
    assert etherscan._inmem_cache_eligible("account", "txlist") is False
    assert etherscan._inmem_cache_eligible("account", "addresstokenbalance") is False
    assert etherscan._inmem_cache_eligible("logs", "getLogs") is False


def _wire_status1(payload: dict, monkeypatch):
    """Wire every Etherscan call to a successful envelope; skip PG + rate limit."""
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    monkeypatch.setattr(etherscan, "_pg_cache_get", lambda *a, **kw: None)
    monkeypatch.setattr(etherscan, "_pg_cache_put", lambda *a, **kw: None)
    monkeypatch.setattr(etherscan, "_get_api_key", lambda: "fake")
    monkeypatch.setattr(etherscan, "_wait_rate_limit", lambda: None)
    fake_resp = _stable_etherscan_response_mock(payload)
    monkeypatch.setattr(etherscan, "requests", MagicMock(get=MagicMock(return_value=fake_resp)))


def test_volatile_actions_never_inmem_cached(monkeypatch):
    """A successful wire fetch of balances/prices/tx history must leave the
    in-mem cache empty — these are gated out by the whitelist."""
    _wire_status1({"status": "1", "result": "123"}, monkeypatch)
    etherscan.get("account", "balance", 1, address="0xabc", tag="latest")
    etherscan.get("stats", "ethprice", 1)
    etherscan.get("account", "txlist", 1, address="0xabc")
    assert etherscan._cache == {}, "volatile actions must never enter the in-mem cache"


def test_whitelisted_action_is_inmem_cached(monkeypatch):
    """getabi (whitelisted) IS held in-mem: the second call serves from the
    cache and never re-hits the wire."""
    _wire_status1({"status": "1", "result": "[]"}, monkeypatch)
    etherscan.get("contract", "getabi", 1, address="0xfeed")
    assert len(etherscan._cache) == 1
    # Second call hits in-mem; wire must not be called again.
    setattr(etherscan.requests.get, "side_effect", AssertionError("second call must hit in-mem cache"))
    etherscan.get("contract", "getabi", 1, address="0xfeed")


def test_inmem_cache_bound_evicts(monkeypatch):
    """The in-mem cache cannot grow past _CACHE_MAX — the oldest quartile is
    evicted at the cap (the cap, not a TTL, is the memory bound)."""
    monkeypatch.setattr(etherscan, "_CACHE_MAX", 8)
    _wire_status1({"status": "1", "result": "[]"}, monkeypatch)
    for i in range(20):
        etherscan.get("contract", "getabi", 1, address=f"0x{i:040x}")
    assert len(etherscan._cache) <= etherscan._CACHE_MAX


def test_clear_etherscan_cache_resets_pressure_state(monkeypatch):
    """clear_etherscan_cache empties the dict AND resets the cache-pressure
    threshold so a later genuine pressure event still logs."""
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
# Bounded in-process source cache (getsourcecode only): cut redundant in-run
# multi-MB Postgres deserializes WITHOUT reintroducing the OOM — a SEPARATE,
# tightly bounded LRU, never the 256-entry metadata cache.
# ---------------------------------------------------------------------------


def test_source_cache_eligible():
    """Only getsourcecode uses the separate bounded source cache; the in-mem-whitelisted
    metadata actions and volatile actions do not."""
    assert etherscan._source_cache_eligible("contract", "getsourcecode") is True
    assert etherscan._source_cache_eligible("contract", "getabi") is False
    assert etherscan._source_cache_eligible("contract", "getcontractcreation") is False
    assert etherscan._source_cache_eligible("account", "balance") is False


def test_source_cache_wire_fetch_populates_then_serves(monkeypatch):
    """A getsourcecode PG miss → wire fetch must populate the bounded source cache (and
    never the metadata cache); the next read is served in-process without re-hitting the wire."""
    payload = {"status": "1", "result": [{"SourceCode": "contract Bar {}"}]}
    _wire_status1(payload, monkeypatch)
    etherscan.get("contract", "getsourcecode", 1, address="0xfeed")
    assert len(etherscan._source_cache) == 1
    assert etherscan._cache == {}, "source must not enter the metadata cache"
    # Second call hits the source cache; wire must not be called again.
    setattr(etherscan.requests.get, "side_effect", AssertionError("second call must hit the source cache"))
    result = etherscan.get("contract", "getsourcecode", 1, address="0xfeed")
    assert result == payload


def test_source_cache_skips_empty_source(monkeypatch):
    """An unverified-contract empty-source response must NOT be pinned in the source cache
    (mirrors the PG persistability gate), so a later verification isn't masked by a stale empty."""
    monkeypatch.setattr(etherscan, "_CACHE_ENABLED", True)
    key = ("contract", "getsourcecode", 1, (("address", "0xunverified"),))
    etherscan._source_cache_put(key, "contract", "getsourcecode", {"status": "1", "result": [{"SourceCode": ""}]})
    assert etherscan._source_cache == {}, "empty/unverified source must not be cached"
    # Real source IS cached.
    etherscan._source_cache_put(key, "contract", "getsourcecode", {"status": "1", "result": [{"SourceCode": "x"}]})
    assert len(etherscan._source_cache) == 1


def test_source_cache_bound_evicts(monkeypatch):
    """The source cache cannot grow past _SOURCE_CACHE_MAX — the oldest quartile is evicted
    at the cap (the cap, not a TTL, is the memory bound). This is the OOM guard for multi-MB blobs."""
    monkeypatch.setattr(etherscan, "_SOURCE_CACHE_MAX", 8)
    _wire_status1({"status": "1", "result": [{"SourceCode": "contract X {}"}]}, monkeypatch)
    for i in range(20):
        etherscan.get("contract", "getsourcecode", 1, address=f"0x{i:040x}")
    assert len(etherscan._source_cache) <= etherscan._SOURCE_CACHE_MAX


def test_clear_etherscan_cache_clears_source_cache_and_pressure(monkeypatch):
    """clear_etherscan_cache empties BOTH the metadata and source caches and resets both
    pressure thresholds so a later genuine pressure event still logs."""
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
