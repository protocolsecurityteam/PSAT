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


_cache: dict[tuple, dict] = {}
_cache_lock = threading.Lock()


def _cache_key(module: str, action: str, chain_id: int, params: dict) -> tuple:
    return (module, action, chain_id, tuple(sorted(params.items())))


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


def get(module: str, action: str, chain_id: int = 1, **params) -> dict:
    """Etherscan API call with rate-limit retry; reads through in-memory then Postgres cache before the wire."""
    if _CACHE_ENABLED:
        key = _cache_key(module, action, chain_id, params)
        with _cache_lock:
            if key in _cache:
                logger.debug("Etherscan in-memory cache hit: %s/%s %s", module, action, params.get("address", ""))
                return _cache[key]

    pg_hit = _pg_cache_get(module, action, chain_id, params)
    if pg_hit is not None:
        logger.debug("Etherscan PG cache hit: %s/%s %s", module, action, params.get("address", ""))
        if _CACHE_ENABLED:
            with _cache_lock:
                _cache[_cache_key(module, action, chain_id, params)] = pg_hit
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
            if _CACHE_ENABLED:
                with _cache_lock:
                    _cache[_cache_key(module, action, chain_id, params)] = data
            _pg_cache_put(module, action, chain_id, params, data)
            return data

        result_str = str(data.get("result", ""))
        if "rate limit" in result_str.lower() and attempt < _RATE_LIMIT_RETRIES:
            logger.warning(
                "Etherscan rate limit hit, retrying in %.1fs (attempt %d/%d)",
                backoff,
                attempt + 1,
                _RATE_LIMIT_RETRIES,
            )
            time.sleep(backoff)
            backoff *= 2
            continue

        raise RuntimeError(f"Etherscan error: {data.get('message', 'unknown')} - {result_str}")

    raise RuntimeError("Etherscan rate limit: max retries exceeded")


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
            from utils.rpc import PUBLIC_ETH_RPC_URL, default_rpc_url, rpc_request

            url = rpc_url or default_rpc_url(chain_id=chain_id) or PUBLIC_ETH_RPC_URL
            tx = rpc_request(url, "eth_getTransactionByHash", [tx_hash])
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


def get_contract_info(address: str) -> tuple[str | None, dict[str, str]]:
    """Fetch contract name and selector map in a single Etherscan call.

    Returns (name_or_None, {selector: function_name}).
    """
    try:
        data = get("contract", "getsourcecode", address=address)
        result = data["result"][0]
    except Exception:
        return None, {}
    name = (result.get("ContractName") or "").strip() or None
    selector_map = _build_selector_map(result.get("ABI", ""))
    return name, selector_map


def get_contract_name(address: str) -> str | None:
    """Return the verified contract name for *address*, or None if unavailable."""
    name, _ = get_contract_info(address)
    return name


def get_source(address: str) -> dict:
    """Fetch verified source code for a contract address. Returns the first result."""
    data = get("contract", "getsourcecode", address=address)
    result = data["result"][0]

    if not result.get("SourceCode"):
        raise RuntimeError(f"No verified source code for {address}")

    return result


# ---------------------------------------------------------------------------
# Token balance queries
# ---------------------------------------------------------------------------


def get_eth_balance(address: str, chain_id: int = 1) -> int:
    """Return the ETH balance of *address* in wei."""
    data = get("account", "balance", chain_id=chain_id, address=address, tag="latest")
    return int(data["result"])


def get_eth_price(chain_id: int = 1) -> float:
    """Return the current ETH price in USD via Etherscan's ethprice endpoint."""
    data = get("stats", "ethprice", chain_id=chain_id)
    return float(data["result"]["ethusd"])


_token_balance_lock = threading.Lock()
_token_balance_last_call = 0.0


def get_token_balances(address: str, chain_id: int = 1) -> list[dict]:
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
