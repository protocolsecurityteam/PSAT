"""Etherscan API client.

All Etherscan calls are routed through :func:`get`, which enforces a
global rate limit (``ETHERSCAN_RATE_LIMIT`` calls/sec).  Callers do
**not** need to add their own sleeps or per-module limiters.
"""

import json as _json
import logging
import os
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path

import requests
from dotenv import load_dotenv
from eth_utils.crypto import keccak

from utils.logging import record_degraded

logger = logging.getLogger(__name__)

ETHERSCAN_API = "https://api.etherscan.io/v2/api"
_RATE_LIMIT_RETRIES = 5
_RATE_LIMIT_BACKOFF = 1.0  # seconds, doubles each retry

# Global Etherscan rate limit — applies to every call through get().
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
ETHERSCAN_RATE_LIMIT = int(os.getenv("ETHERSCAN_RATE_LIMIT", "5"))

_min_interval = 1.0 / ETHERSCAN_RATE_LIMIT
_rate_lock = threading.Lock()
_last_call = 0.0


def _wait_rate_limit() -> None:
    """Block until the minimum interval since the last call has elapsed."""
    global _last_call
    with _rate_lock:
        now = time.monotonic()
        elapsed = now - _last_call
        if elapsed < _min_interval:
            time.sleep(_min_interval - elapsed)
        _last_call = time.monotonic()


def _get_api_key() -> str:
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    key = os.getenv("ETHERSCAN_API_KEY")
    if not key:
        raise RuntimeError("ETHERSCAN_API_KEY not set in .env")
    return key


# Two-layer cache: per-process in-memory dict + Postgres-backed cross-process; both default on.
_CACHE_ENABLED = os.getenv("ETHERSCAN_CACHE", "1").lower() in ("1", "true", "yes")
_PG_CACHE_ENABLED = os.getenv("ETHERSCAN_PG_CACHE", "1").lower() in ("1", "true", "yes")

# Whitelist of effectively-immutable (module, action) pairs eligible for the Postgres layer; dynamic data (balances,
# prices, tx history) is excluded so workers don't serve stale state.
_PG_CACHE_WHITELIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("contract", "getsourcecode"),
        ("contract", "getabi"),
        ("contract", "getcontractcreation"),
    }
)


def _pg_cache_eligible(module: str, action: str) -> bool:
    return (module, action) in _PG_CACHE_WHITELIST


# Narrower whitelist for the in-memory layer: only the small, immutable contract
# metadata responses (ABI, creation record) live in process memory. Source is
# psql-only (multi-MB blobs served by the PG layer); volatile data (balances,
# prices, tx history, logs) is never held in-process.
_INMEM_CACHE_WHITELIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("contract", "getabi"),
        ("contract", "getcontractcreation"),
    }
)


def _inmem_cache_eligible(module: str, action: str) -> bool:
    return (module, action) in _INMEM_CACHE_WHITELIST


def _source_cache_eligible(module: str, action: str) -> bool:
    """``getsourcecode`` only — held in the separate bounded source LRU below, never the
    small-entry metadata ``_cache`` (256 multi-MB source blobs would be the OOM this avoids)."""
    return (module, action) == ("contract", "getsourcecode")


# Bounded LRU over the whitelisted in-memory responses. Each value carries a
# monotonic insert time so the oldest quartile is evicted at the cap — the cap
# is the memory bound. No TTL: the cached actions are immutable, and the cap is
# kept small because that's the whole point.
_CACHE_MAX = 256
_cache: dict[tuple, tuple[dict, float]] = {}
_cache_lock = threading.Lock()


def _cache_key(module: str, action: str, chain_id: int, params: dict) -> tuple:
    return (module, action, chain_id, tuple(sorted(params.items())))


def _evict_cache_if_needed() -> None:
    """Drop the oldest 25% of _cache entries when the bound is reached (caller holds _cache_lock)."""
    if len(_cache) < _CACHE_MAX:
        return
    cutoff = sorted(_cache.values(), key=lambda v: v[1])[len(_cache) // 4][1]
    for k in [k for k, v in _cache.items() if v[1] <= cutoff]:
        _cache.pop(k, None)


def _log_cache_pressure() -> None:
    """Log when _cache crosses 50/75/95% of its bound (caller holds _cache_lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("etherscan", len(_cache), _CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


# Separate bounded LRU for getsourcecode. Its responses are multi-MB, so they are kept
# OUT of the 256-entry metadata _cache (256 source blobs would reintroduce the OOM this
# module avoids) and were psql-only — but a single analysis run re-reads the same
# contract's source many times, each a multi-MB Postgres deserialize. This holds them in
# process so the same source isn't re-fetched within a run; the SMALL cap is the memory
# bound (worst case cap × blob, a handful of contracts). No TTL — verified source is
# immutable. Each value carries a monotonic insert time so the oldest quartile evicts.
_SOURCE_CACHE_MAX = int(os.getenv("ETHERSCAN_SOURCE_CACHE_MAX", "16"))
_source_cache: dict[tuple, tuple[dict, float]] = {}
_source_cache_lock = threading.Lock()


def _evict_source_cache_if_needed() -> None:
    """Drop the oldest 25% of _source_cache entries when the bound is reached (caller holds _source_cache_lock)."""
    if len(_source_cache) < _SOURCE_CACHE_MAX:
        return
    cutoff = sorted(_source_cache.values(), key=lambda v: v[1])[len(_source_cache) // 4][1]
    for k in [k for k, v in _source_cache.items() if v[1] <= cutoff]:
        _source_cache.pop(k, None)


def _log_source_cache_pressure() -> None:
    """Log when _source_cache crosses 50/75/95% of its bound (caller holds _source_cache_lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("etherscan_source", len(_source_cache), _SOURCE_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _source_cache_put(key: tuple, module: str, action: str, response: dict) -> None:
    """Cache a getsourcecode response in the bounded source LRU, skipping empty/unverified
    sources (the same ``_is_persistable`` gate the PG layer uses) so a not-yet-verified
    contract's empty response is never pinned in process."""
    if not _is_persistable(module, action, response):
        return
    with _source_cache_lock:
        _evict_source_cache_if_needed()
        _source_cache[key] = (response, time.monotonic())
        _log_source_cache_pressure()


def clear_etherscan_cache() -> None:
    """Clear the process-wide in-memory Etherscan caches (metadata + source). For tests + manual reset."""
    from utils.memory import reset_cache_pressure_state

    with _cache_lock:
        _cache.clear()
    with _source_cache_lock:
        _source_cache.clear()
    reset_cache_pressure_state("etherscan")
    reset_cache_pressure_state("etherscan_source")


def _params_hash(module: str, action: str, chain_id: int, params: dict) -> str:
    """SHA-256 of canonical JSON form of (module, action, chain_id, sorted params); fits the VARCHAR(64) PK column."""
    import hashlib

    canonical = _json.dumps(
        {"module": module, "action": action, "chain_id": chain_id, "params": dict(sorted(params.items()))},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _pg_cache_get(module: str, action: str, chain_id: int, params: dict) -> dict | None:
    """Postgres read-through; returns None on miss or DB unavailability so CLI usage without a DB still works."""
    if not _PG_CACHE_ENABLED or not _pg_cache_eligible(module, action):
        return None
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception:
        return None
    h = _params_hash(module, action, chain_id, params)
    try:
        with SessionLocal() as session:
            row = session.execute(
                text(
                    "SELECT response FROM etherscan_cache "
                    "WHERE module = :m AND action = :a AND chain_id = :c "
                    "  AND params_hash = :h "
                    "  AND (ttl_expires_at IS NULL OR ttl_expires_at > NOW()) "
                    "LIMIT 1"
                ),
                {"m": module, "a": action, "c": chain_id, "h": h},
            ).scalar_one_or_none()
        if row is not None:
            return dict(row) if not isinstance(row, dict) else row
    except Exception as exc:
        logger.debug("Etherscan PG cache lookup failed (%s) — falling through", exc)
    return None


def _is_persistable(module: str, action: str, response: dict) -> bool:
    """Skip persisting empty-source ``getsourcecode`` responses (unverified contracts return status=1 with empty
    SourceCode)."""
    if action != "getsourcecode":
        return True
    result = response.get("result")
    if not isinstance(result, list) or not result:
        return False
    first = result[0]
    if not isinstance(first, dict):
        return False
    source = first.get("SourceCode")
    return bool(source)


def _pg_cache_put(module: str, action: str, chain_id: int, params: dict, response: dict) -> None:
    """Best-effort upsert into etherscan_cache; whitelist-gated and empty-source responses are skipped."""
    if not _PG_CACHE_ENABLED or not _pg_cache_eligible(module, action):
        return
    if not _is_persistable(module, action, response):
        logger.debug(
            "Etherscan PG cache: skipping persist of empty %s/%s response (likely unverified contract)",
            module,
            action,
        )
        return
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception:
        return
    h = _params_hash(module, action, chain_id, params)
    try:
        with SessionLocal() as session:
            session.execute(
                text(
                    "INSERT INTO etherscan_cache (module, action, chain_id, params_hash, response) "
                    "VALUES (:m, :a, :c, :h, CAST(:r AS JSONB)) "
                    "ON CONFLICT (module, action, chain_id, params_hash) DO UPDATE "
                    "  SET response = EXCLUDED.response, cached_at = NOW()"
                ),
                {"m": module, "a": action, "c": chain_id, "h": h, "r": _json.dumps(response)},
            )
            session.commit()
    except Exception as exc:
        logger.debug("Etherscan PG cache write failed (%s) — keeping in-memory only", exc)


def get(module: str, action: str, chain_id: int, **params) -> dict:
    """Etherscan API call with rate-limit retry; reads through in-memory then Postgres cache before the wire.

    *chain_id* is required (invariant 6): the v2 endpoint is chain-scoped via the
    ``chainid`` query param, so a call with no chain can no longer silently hit
    mainnet. Callers thread the job/contract chain explicitly.
    """
    inmem = _CACHE_ENABLED and _inmem_cache_eligible(module, action)
    source_cached = _CACHE_ENABLED and _source_cache_eligible(module, action)
    key = _cache_key(module, action, chain_id, params)
    if inmem:
        with _cache_lock:
            cached = _cache.get(key)
            if cached is not None:
                logger.debug("Etherscan in-memory cache hit: %s/%s %s", module, action, params.get("address", ""))
                return cached[0]
    if source_cached:
        with _source_cache_lock:
            cached = _source_cache.get(key)
            if cached is not None:
                logger.debug("Etherscan source cache hit: %s", params.get("address", ""))
                return cached[0]

    pg_hit = _pg_cache_get(module, action, chain_id, params)
    if pg_hit is not None:
        logger.debug("Etherscan PG cache hit: %s/%s %s", module, action, params.get("address", ""))
        if inmem:
            with _cache_lock:
                _evict_cache_if_needed()
                _cache[key] = (pg_hit, time.monotonic())
                _log_cache_pressure()
        if source_cached:
            _source_cache_put(key, module, action, pg_hit)
        return pg_hit

    api_key = _get_api_key()
    backoff = _RATE_LIMIT_BACKOFF

    for attempt in range(_RATE_LIMIT_RETRIES + 1):
        _wait_rate_limit()
        resp = requests.get(
            ETHERSCAN_API,
            params={
                "chainid": str(chain_id),
                "module": module,
                "action": action,
                "apikey": api_key,
                **params,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "1":
            if inmem:
                with _cache_lock:
                    _evict_cache_if_needed()
                    _cache[key] = (data, time.monotonic())
                    _log_cache_pressure()
            if source_cached:
                _source_cache_put(key, module, action, data)
            _pg_cache_put(module, action, chain_id, params, data)
            return data

        result_str = str(data.get("result", ""))
        if "rate limit" in result_str.lower() and attempt < _RATE_LIMIT_RETRIES:
            # Per-retry line is per-iteration detail → DEBUG (one summary
            # WARNING is emitted once on exhaustion below, not per attempt).
            logger.debug(
                "Etherscan rate limit hit, retrying",
                extra={
                    "module": module,
                    "action": action,
                    "backoff_s": backoff,
                    "attempt": attempt + 1,
                    "max_retries": _RATE_LIMIT_RETRIES,
                },
            )
            time.sleep(backoff)
            backoff *= 2
            continue

        raise RuntimeError(f"Etherscan error: {data.get('message', 'unknown')} - {result_str}")

    # Single WARNING on retry exhaustion — the one degraded summary for a
    # sustained rate-limit, replacing the per-attempt noise above.
    exhausted = RuntimeError("Etherscan rate limit: max retries exceeded")
    logger.warning(
        "Etherscan rate limit: max retries exceeded",
        extra={"module": module, "action": action, "max_retries": _RATE_LIMIT_RETRIES},
    )
    record_degraded(phase="etherscan_rate_limit", exc=exhausted, context={"module": module, "action": action})
    raise exhausted


def get_contract_creation_block(address: str, *, chain_id: int = 1, rpc_url: str | None = None) -> int | None:
    """Block in which *address* was deployed, or ``None`` if it can't be
    determined.

    Used to seed event-log cursors at the contract's birth instead of block 0,
    so the indexer never scans the empty pre-deployment range. ``getcontractcreation``
    is PG-cached (immutable), so this is a one-time cost per address. Prefers the
    ``blockNumber`` Etherscan v2 returns directly; falls back to resolving the
    creation ``txHash`` via RPC (through eRPC) when an older response omits it.
    Best-effort: any failure returns ``None`` and the caller defers enrollment.
    """
    if not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        return None
    try:
        data = get("contract", "getcontractcreation", chain_id=chain_id, contractaddresses=address)
    except Exception:
        return None
    result = data.get("result") if isinstance(data, dict) else None
    if not isinstance(result, list) or not result or not isinstance(result[0], dict):
        return None
    item = result[0]

    raw_block = item.get("blockNumber")
    if isinstance(raw_block, int):
        return raw_block if raw_block >= 0 else None
    if isinstance(raw_block, str) and raw_block.strip():
        try:
            return int(raw_block, 16) if raw_block.startswith("0x") else int(raw_block)
        except ValueError:
            pass

    tx_hash = item.get("txHash")
    if isinstance(tx_hash, str) and tx_hash.startswith("0x"):
        try:
            from utils.rpc import default_rpc_url, rpc_request

            url = rpc_url or default_rpc_url(chain_id=chain_id)
            tx = rpc_request(url, "eth_getTransactionByHash", [tx_hash]) if url else None
            block = tx.get("blockNumber") if isinstance(tx, dict) else None
            if isinstance(block, str) and block.startswith("0x"):
                return int(block, 16)
        except Exception:
            return None
    return None


def _canonical_abi_type(inp: dict) -> str:
    """Expand an ABI input type to its canonical form, recursing into tuple components."""
    if inp.get("type") == "tuple":
        components = inp.get("components", [])
        inner = ",".join(_canonical_abi_type(c) for c in components)
        return f"({inner})"
    if inp.get("type", "").startswith("tuple["):
        # tuple[] or tuple[N] — expand the base tuple and keep the array suffix
        suffix = inp["type"][5:]  # e.g. "[]" or "[3]"
        components = inp.get("components", [])
        inner = ",".join(_canonical_abi_type(c) for c in components)
        return f"({inner}){suffix}"
    return inp.get("type", "")


def _build_selector_map(abi_json: str) -> dict[str, str]:
    """Parse an ABI JSON string into a selector → function name mapping."""
    try:
        abi = _json.loads(abi_json)
    except (ValueError, TypeError):
        return {}
    selector_map: dict[str, str] = {}
    for entry in abi:
        if entry.get("type") != "function":
            continue
        name = entry.get("name", "")
        inputs = entry.get("inputs", [])
        sig = f"{name}({','.join(_canonical_abi_type(inp) for inp in inputs)})"
        selector = "0x" + keccak(text=sig).hex()[:8]
        selector_map[selector] = name
    return selector_map


def parallel_get(
    calls: Mapping[str, Callable[[], object]],
    *,
    heartbeat: Callable[[], None] | None = None,
) -> dict[str, object | BaseException]:
    """Submit Etherscan callables concurrently and return ``{call_id: result_or_exception}``.

    Each callable is expected to be a thunk over an existing helper (typically
    ``functools.partial(etherscan.get_contract_name, addr)`` or a lambda over
    :func:`get`). Submission goes through the shared ``RpcExecutor`` so threads
    stack request RTTs across siblings, but every wire call still routes
    through :func:`_wait_rate_limit` — the rate limit is preserved, only the
    serial dead time between calls is removed.

    Failures are returned in-place rather than raised so the caller can
    decide which IDs to skip (mirrors :func:`utils.concurrency.parallel_map`).
    """
    from utils.concurrency import parallel_map

    if not calls:
        return {}

    items = list(calls.items())

    def _run(item: tuple[str, Callable[[], object]]) -> tuple[str, object]:
        call_id, fn = item
        return call_id, fn()

    results: dict[str, object | BaseException] = {}
    for (call_id, _fn), outcome in parallel_map(_run, items, max_workers=len(items), heartbeat=heartbeat):
        if isinstance(outcome, BaseException):
            results[call_id] = outcome
            continue
        result_call_id, value = outcome
        results[result_call_id] = value
    return results


def get_contract_info(address: str, *, chain_id: int) -> tuple[str | None, dict[str, str]]:
    """Fetch contract name and selector map in a single Etherscan call.

    Returns (name_or_None, {selector: function_name}).
    """
    try:
        data = get("contract", "getsourcecode", address=address, chain_id=chain_id)
        result = data["result"][0]
    except Exception as exc:
        # Errored fetch (network/rate-limit/shape) — distinct from a verified
        # contract that simply has no name. WARNING so an upstream outage is a
        # visible breadcrumb instead of silently collapsing to an empty result.
        logger.warning(
            "Etherscan getsourcecode failed",
            extra={"address": address, "exc_type": type(exc).__name__},
        )
        record_degraded(phase="etherscan_getsourcecode", exc=exc, context={"address": address})
        return None, {}
    name = (result.get("ContractName") or "").strip() or None
    if name is None:
        # Not an error: an unverified contract returns status=1 with empty
        # source/name. DEBUG keeps it off the WARNING channel the errored
        # fetch above owns.
        logger.debug("Etherscan: contract unverified (empty name)", extra={"address": address})
    selector_map = _build_selector_map(result.get("ABI", ""))
    return name, selector_map


def get_contract_name(address: str, *, chain_id: int) -> str | None:
    """Return the verified contract name for *address*, or None if unavailable."""
    name, _ = get_contract_info(address, chain_id=chain_id)
    return name


def get_source(address: str, *, chain_id: int) -> dict:
    """Fetch verified source code for a contract address. Returns the first result."""
    data = get("contract", "getsourcecode", address=address, chain_id=chain_id)
    result = data["result"][0]

    if not result.get("SourceCode"):
        raise RuntimeError(f"No verified source code for {address}")

    return result


# ---------------------------------------------------------------------------
# Token balance queries
# ---------------------------------------------------------------------------


def get_eth_balance(address: str, chain_id: int) -> int:
    """Return the ETH balance of *address* in wei."""
    data = get("account", "balance", chain_id=chain_id, address=address, tag="latest")
    return int(data["result"])


def get_eth_price(chain_id: int) -> float:
    """Return the current ETH price in USD via Etherscan's ethprice endpoint."""
    data = get("stats", "ethprice", chain_id=chain_id)
    return float(data["result"]["ethusd"])


_token_balance_lock = threading.Lock()
_token_balance_last_call = 0.0


def get_token_balances(address: str, chain_id: int) -> list[dict]:
    """Return all ERC-20 token balances for *address* in a single call.

    Uses Etherscan's ``addresstokenbalance`` endpoint. Hardcoded to 1 req/s
    independent of the global rate limit since this endpoint is heavier.

    Returns a list of dicts with ``token_address``, ``token_name``,
    ``token_symbol``, ``decimals``, and ``balance``.
    """
    global _token_balance_last_call
    # Hardcoded 1 req/s rate limit for this endpoint
    with _token_balance_lock:
        now = time.monotonic()
        elapsed = now - _token_balance_last_call
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
        _token_balance_last_call = time.monotonic()

    try:
        data = get(
            "account",
            "addresstokenbalance",
            chain_id=chain_id,
            address=address,
            page="1",
            offset="100",
        )
    except RuntimeError:
        return []

    results = []
    for entry in data.get("result", []):
        raw_balance = int(entry.get("TokenQuantity", "0") or "0")
        if raw_balance > 0:
            decimals = int(entry.get("TokenDivisor", "18") or "18")
            price_usd = float(entry.get("TokenPriceUSD", "0") or "0")
            human_balance = raw_balance / (10**decimals)
            usd_value = human_balance * price_usd if price_usd > 0 else None
            results.append(
                {
                    "token_address": (entry.get("TokenAddress") or "").lower(),
                    "token_name": entry.get("TokenName", ""),
                    "token_symbol": entry.get("TokenSymbol", ""),
                    "decimals": decimals,
                    "balance": raw_balance,
                    "price_usd": price_usd,
                    "usd_value": usd_value,
                }
            )

    return sorted(results, key=lambda t: t.get("usd_value") or 0, reverse=True)
