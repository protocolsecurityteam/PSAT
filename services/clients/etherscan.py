"""Etherscan client.

Every call goes through :func:`get`, which enforces the global ``ETHERSCAN_RATE_LIMIT``; callers add no sleeps of their
own.
"""

import json as _json
import logging
import math
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

import requests
from dotenv import load_dotenv
from eth_utils.crypto import keccak

from utils.balance_status import (
    ASSET_SET_STATUS_AT_PAGE_CAP,
    ASSET_SET_STATUS_FETCH_FAILED,
    ASSET_SET_STATUS_RETURNED_ASSETS,
    ASSET_SET_STATUS_RETURNED_EMPTY,
)
from utils.chains import chain_by_id
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

ETHERSCAN_API = "https://api.etherscan.io/v2/api"
_RATE_LIMIT_RETRIES = 5
_RATE_LIMIT_BACKOFF = 1.0  # seconds, doubles each retry

load_dotenv(Path(__file__).resolve().parents[2] / ".env")
ETHERSCAN_RATE_LIMIT = int(os.getenv("ETHERSCAN_RATE_LIMIT", "5"))

_min_interval = 1.0 / ETHERSCAN_RATE_LIMIT
_rate_lock = threading.Lock()
_last_call = 0.0


def _wait_rate_limit() -> None:
    global _last_call
    with _rate_lock:
        now = time.monotonic()
        elapsed = now - _last_call
        if elapsed < _min_interval:
            time.sleep(_min_interval - elapsed)
        _last_call = time.monotonic()


def _get_api_key() -> str:
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    key = os.getenv("ETHERSCAN_API_KEY")
    if not key:
        raise RuntimeError("ETHERSCAN_API_KEY not set in .env")
    return key


# Per-process dict + cross-process Postgres, both on by default.
_CACHE_ENABLED = os.getenv("ETHERSCAN_CACHE", "1").lower() in ("1", "true", "yes")
_PG_CACHE_ENABLED = os.getenv("ETHERSCAN_PG_CACHE", "1").lower() in ("1", "true", "yes")

# Only effectively-immutable (module, action) pairs; dynamic data would serve stale state.
_PG_CACHE_WHITELIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("contract", "getsourcecode"),
        ("contract", "getabi"),
        ("contract", "getcontractcreation"),
    }
)


def _pg_cache_eligible(module: str, action: str, params: Mapping | None = None) -> bool:
    if (module, action) in _PG_CACHE_WHITELIST:
        return True
    # A mined tx's internal frames are immutable; the by-address form is living history.
    return (module, action) == ("account", "txlistinternal") and bool(params) and "txhash" in params


# Only small immutable metadata (ABI, creation record) in process; multi-MB source lives in PG and the source LRU.
_INMEM_CACHE_WHITELIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("contract", "getabi"),
        ("contract", "getcontractcreation"),
    }
)


def _inmem_cache_eligible(module: str, action: str) -> bool:
    return (module, action) in _INMEM_CACHE_WHITELIST


def _source_cache_eligible(module: str, action: str) -> bool:
    """Separate from the metadata ``_cache``: 256 multi-MB source blobs would OOM."""
    return (module, action) == ("contract", "getsourcecode")


# The cap is the memory bound; no TTL since cached actions are immutable.
_CACHE_MAX = 256
_cache: dict[tuple, tuple[dict, float]] = {}
_cache_lock = threading.Lock()


def _cache_key(module: str, action: str, chain_id: int, params: dict) -> tuple:
    return (module, action, chain_id, tuple(sorted(params.items())))


def _evict_cache_if_needed() -> None:
    if len(_cache) < _CACHE_MAX:
        return
    cutoff = sorted(_cache.values(), key=lambda v: v[1])[len(_cache) // 4][1]
    for k in [k for k, v in _cache.items() if v[1] <= cutoff]:
        _cache.pop(k, None)


def _log_cache_pressure() -> None:
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("etherscan", len(_cache), _CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


# One run re-reads the same source many times (each a multi-MB PG deserialize); the small cap bounds memory. No TTL:
# verified source is immutable.
_SOURCE_CACHE_MAX = int(os.getenv("ETHERSCAN_SOURCE_CACHE_MAX", "16"))
_source_cache: dict[tuple, tuple[dict, float]] = {}
_source_cache_lock = threading.Lock()


def _evict_source_cache_if_needed() -> None:
    if len(_source_cache) < _SOURCE_CACHE_MAX:
        return
    cutoff = sorted(_source_cache.values(), key=lambda v: v[1])[len(_source_cache) // 4][1]
    for k in [k for k, v in _source_cache.items() if v[1] <= cutoff]:
        _source_cache.pop(k, None)


def _log_source_cache_pressure() -> None:
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("etherscan_source", len(_source_cache), _SOURCE_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _source_cache_put(key: tuple, module: str, action: str, response: dict) -> None:
    """Skips empty/unverified sources (same ``_is_persistable`` gate as PG)."""
    if not _is_persistable(module, action, response):
        return
    with _source_cache_lock:
        _evict_source_cache_if_needed()
        _source_cache[key] = (response, time.monotonic())
        _log_source_cache_pressure()


def clear_etherscan_cache() -> None:
    from utils.memory import reset_cache_pressure_state

    with _cache_lock:
        _cache.clear()
    with _source_cache_lock:
        _source_cache.clear()
    reset_cache_pressure_state("etherscan")
    reset_cache_pressure_state("etherscan_source")


def _params_hash(module: str, action: str, chain_id: int, params: dict) -> str:
    """Fits the VARCHAR(64) PK."""
    import hashlib

    canonical = _json.dumps(
        {"module": module, "action": action, "chain_id": chain_id, "params": dict(sorted(params.items()))},
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _pg_cache_get(module: str, action: str, chain_id: int, params: dict) -> dict | None:
    """None on miss or no DB, so CLI use without a DB works."""
    if not _PG_CACHE_ENABLED or not _pg_cache_eligible(module, action, params):
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
    """Unverified contracts return status=1 with empty SourceCode."""
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
    if not _PG_CACHE_ENABLED or not _pg_cache_eligible(module, action, params):
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


# ``status=0`` shapes that are answers (empty token/tx/log lists): exact status + known message + empty list. Opt-in per
# call site via ``empty_result_ok`` so no other error can reach a caller as data.
_EMPTY_RESULT_MESSAGES = frozenset({"No token found", "No transactions found", "No records found"})


def _is_empty_result(data: dict) -> bool:
    result = data.get("result")
    return (
        str(data.get("status")).strip() == "0"
        and str(data.get("message", "")).strip() in _EMPTY_RESULT_MESSAGES
        and isinstance(result, list)
        and not result
    )


def get(
    module: str, action: str, chain_id: int, empty_result_ok: bool = False, cache_empty: bool = False, **params
) -> dict:
    """Etherscan call with rate-limit retry, reading through in-memory then Postgres cache.

    *chain_id* is required (v2 is chain-scoped).

    ``empty_result_ok`` returns the empty-list triple instead of raising, so "holds no tokens" is distinguishable from
    transport failure. An empty answer is cached only when PG-eligible AND ``cache_empty=True``: even per-txhash
    ``txlistinternal`` can be falsely empty while Etherscan's trace indexing lags, and only the caller knows the tx's
    age.
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
        from services.clients.request_budget import charge_attempt

        _wait_rate_limit()
        charge_attempt("etherscan")
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

        if empty_result_ok and _is_empty_result(data):
            # A lag-empty frozen for a fresh tx would permanently delete its CREATE frames.
            if cache_empty:
                _pg_cache_put(module, action, chain_id, params, data)
            return data

        result_str = str(data.get("result", ""))
        if "rate limit" in result_str.lower() and attempt < _RATE_LIMIT_RETRIES:
            # Per-attempt detail; one WARNING on exhaustion.
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

    exhausted = RuntimeError("Etherscan rate limit: max retries exceeded")
    logger.warning(
        "Etherscan rate limit: max retries exceeded",
        extra={"module": module, "action": action, "max_retries": _RATE_LIMIT_RETRIES},
    )
    record_degraded(phase="etherscan_rate_limit", exc=exhausted, context={"module": module, "action": action})
    raise exhausted


def get_contract_creation_block(address: str, *, chain_id: int, rpc_url: str | None = None) -> int | None:
    """Deployment block for *address*, or ``None``, to seed event cursors at birth.

    PG-cached. Falls back to resolving ``txHash`` via RPC when older responses omit ``blockNumber``.
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
            from services.clients.rpc import default_rpc_url, rpc_request

            url = rpc_url or default_rpc_url(chain_id=chain_id)
            tx = rpc_request(url, "eth_getTransactionByHash", [tx_hash], chain_id=chain_id) if url else None
            block = tx.get("blockNumber") if isinstance(tx, dict) else None
            if isinstance(block, str) and block.startswith("0x"):
                return int(block, 16)
        except Exception:
            return None
    return None


def _canonical_abi_type(inp: dict) -> str:
    if inp.get("type") == "tuple":
        components = inp.get("components", [])
        inner = ",".join(_canonical_abi_type(c) for c in components)
        return f"({inner})"
    if inp.get("type", "").startswith("tuple["):
        suffix = inp["type"][5:]  # e.g. "[]" or "[3]"
        components = inp.get("components", [])
        inner = ",".join(_canonical_abi_type(c) for c in components)
        return f"({inner}){suffix}"
    return inp.get("type", "")


def _build_selector_map(abi_json: str) -> dict[str, str]:
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
    """Run Etherscan thunks concurrently, returning ``{call_id: result_or_exception}``.

    Every wire call still passes :func:`_wait_rate_limit`; only serial dead time is removed.
    """
    from services.concurrency import parallel_map

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
    """``(name_or_None, {selector: function_name})`` from one call."""
    try:
        data = get("contract", "getsourcecode", address=address, chain_id=chain_id)
        result = data["result"][0]
    except Exception as exc:
        # Errored fetch, distinct from a verified contract with no name.
        logger.warning(
            "Etherscan getsourcecode failed",
            extra={"address": address, "exc_type": type(exc).__name__},
        )
        record_degraded(phase="etherscan_getsourcecode", exc=exc, context={"address": address})
        return None, {}
    name = (result.get("ContractName") or "").strip() or None
    if name is None:
        # Unverified returns status=1 with an empty name; not an error.
        logger.debug("Etherscan: contract unverified (empty name)", extra={"address": address})
    selector_map = _build_selector_map(result.get("ABI", ""))
    return name, selector_map


def get_contract_name(address: str, *, chain_id: int) -> str | None:
    name, _ = get_contract_info(address, chain_id=chain_id)
    return name


def get_source(address: str, *, chain_id: int) -> dict:
    data = get("contract", "getsourcecode", address=address, chain_id=chain_id)
    result = data["result"][0]

    if not result.get("SourceCode"):
        raise RuntimeError(f"No verified source code for {address}")

    return result


def get_eth_balance(address: str, chain_id: int) -> int:
    data = get("account", "balance", chain_id=chain_id, address=address, tag="latest")
    return int(data["result"])


def get_native_price(chain_id: int) -> float:
    """USD price of *chain_id*'s native coin.

    Only the action varies (``ChainInfo.native_price_action``). The response key doesn't name the asset (POL and BNB
    both come back as ``ethusd``), so read any ``*usd`` field; the asset is the registry's ``native_asset``.
    """
    info = chain_by_id(chain_id)
    data = get("stats", info.native_price_action, chain_id=chain_id)
    result = data["result"]
    for field, value in result.items():
        if field.lower().endswith("usd"):
            return float(value)
    raise RuntimeError(
        f"Etherscan {info.native_price_action} (chain {chain_id}) returned no USD price field: {result!r}"
    )


def get_eth_price(chain_id: int) -> float:
    """Pre-multichain wrapper; on ETH-native chains it's the ETH/USD quote."""
    return get_native_price(chain_id)


_token_balance_lock = threading.Lock()
_token_balance_last_call = 0.0


# One page per request. At the cap locally: 15 contracts, 7 inside a scored perimeter;
# ``ValuePlane.asset_set_truncated`` / ``ceiling_for`` handle that, and ``selection._holdings_completeness`` on the
# effects side.
TOKEN_BALANCE_PAGE_SIZE = 100


@dataclass(frozen=True)
class TokenBalancePage:
    """An ``addresstokenbalance`` read with what the endpoint said.

    ``rows`` are the ``raw_balance > 0`` holdings. ``page_length`` counts raw entries across every page read (so it can
    exceed the page size); ``None`` = fetch failed. Only ``status`` says whether the list was cut off: ``rows == []``
    alone is failed, empty or truncated. ``basis`` states whether the list is complete or a prefix.
    """

    rows: list[dict]
    page_length: int | None
    status: str
    pages_read: int = 0
    basis: str = ""


def token_balance_page_budget() -> int:
    """Raises on a bad value: 0 would mark every single-page list incomplete."""
    raw = os.getenv("PSAT_TOKEN_BALANCE_MAX_PAGES", "20")
    try:
        budget = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"PSAT_TOKEN_BALANCE_MAX_PAGES must be an integer >= 1, got {raw!r}") from exc
    if budget < 1:
        raise ValueError(f"PSAT_TOKEN_BALANCE_MAX_PAGES must be >= 1, got {budget}")
    return budget


def _throttle_token_balance_call() -> None:
    global _token_balance_last_call
    with _token_balance_lock:
        now = time.monotonic()
        elapsed = now - _token_balance_last_call
        if elapsed < 1.0:
            time.sleep(1.0 - elapsed)
        _token_balance_last_call = time.monotonic()


def get_token_balances_page(address: str, *, chain_id: int) -> TokenBalancePage:
    """ERC-20 balances plus list status.

    Pages until a short page, the only witness the list ended (usually page one). Stopping for any other reason keeps
    ``at_page_cap``: the list is a lower bound. The empty answer arrives as data via ``empty_result_ok``.
    """
    budget = token_balance_page_budget()
    raw_entries: list[dict] = []
    seen_tokens: set[str] = set()
    pages_read = 0
    incomplete_because: str | None = None

    while pages_read < budget:
        _throttle_token_balance_call()
        try:
            data = get(
                "account",
                "addresstokenbalance",
                chain_id=chain_id,
                empty_result_ok=True,
                address=address,
                page=str(pages_read + 1),
                offset=str(TOKEN_BALANCE_PAGE_SIZE),
            )
        except (RuntimeError, requests.RequestException) as exc:
            from services.clients.request_budget import RequestBudgetExceeded

            if isinstance(exc, RequestBudgetExceeded) and pages_read == 0:
                raise
            # Downstream an empty set is indistinguishable from holding no tokens.
            record_degraded(
                phase="token_balance_fetch",
                exc=exc,
                context={"address": address, "chain_id": chain_id, "page": pages_read + 1},
            )
            logger.warning(
                "token balance fetch failed for %s on chain %s (page %d): %s",
                address,
                chain_id,
                pages_read + 1,
                type(exc).__name__,
            )
            if pages_read == 0:
                # None, not 0: 0 would read as a proven-empty list.
                return TokenBalancePage(
                    rows=[],
                    page_length=None,
                    status=ASSET_SET_STATUS_FETCH_FAILED,
                    pages_read=0,
                    basis="etherscan addresstokenbalance: page 1 failed, nothing observed",
                )
            # Pages in hand stay, as a prefix.
            incomplete_because = f"page {pages_read + 1} failed"
            break

        page = data.get("result")
        if not isinstance(page, list):
            logger.warning(
                "token balance fetch for %s on chain %s returned a non-list page %d", address, chain_id, pages_read + 1
            )
            if pages_read == 0:
                return TokenBalancePage(
                    rows=[],
                    page_length=None,
                    status=ASSET_SET_STATUS_FETCH_FAILED,
                    pages_read=0,
                    basis="etherscan addresstokenbalance: page 1 was not a list, nothing observed",
                )
            incomplete_because = f"page {pages_read + 1} was not a list"
            break

        pages_read += 1
        fresh = 0
        for entry in page:
            if not isinstance(entry, dict):
                incomplete_because = "malformed entry in provider response"
                continue
            token = str(entry.get("TokenAddress") or "").lower()
            if token and token in seen_tokens:
                continue
            if token:
                seen_tokens.add(token)
            raw_entries.append(entry)
            fresh += 1

        if len(page) < TOKEN_BALANCE_PAGE_SIZE:
            # The endpoint had fewer entries left than asked for.
            break
        if fresh == 0:
            # Endpoint ignores ``page``; paging would loop and the list can't be shown whole.
            incomplete_because = f"page {pages_read} repeated entries already seen; paging not honoured"
            break
    else:
        incomplete_because = f"page budget of {budget} exhausted with a full page in hand"

    results = []
    for entry in raw_entries:
        try:
            raw_balance = int(entry["TokenQuantity"])
            token = str(entry.get("TokenAddress") or "").lower()
            if not (len(token) == 42 and token.startswith("0x")):
                raise ValueError("invalid token address")
            int(token[2:], 16)
            if raw_balance < 0 or raw_balance >= 2**256:
                raise ValueError("invalid token quantity")
        except (KeyError, TypeError, ValueError):
            incomplete_because = "malformed token quantity/address in provider response"
            continue
        # Zero entries are dropped as a witness rule: ``tag=latest`` names no height, and a stored zero reads as an
        # earned negative (``planes._is_proven_zero_quantity``). Proven zeros come only from reads at a named height.
        if raw_balance > 0:
            raw_divisor = entry.get("TokenDivisor")
            try:
                decimals = int(raw_divisor) if raw_divisor not in (None, "") else None
            except (TypeError, ValueError):
                decimals = None
            if decimals is not None and not 0 <= decimals <= 255:
                decimals = None
            try:
                price_usd = float(entry.get("TokenPriceUSD", "0") or "0")
                if not math.isfinite(price_usd) or price_usd <= 0 or price_usd >= 1e20:
                    price_usd = 0.0
            except (TypeError, ValueError):
                price_usd = 0.0
            # No divisor means the USD figure would be off by 10^n. The column stores 18 by convention; the value fields
            # say unknown.
            if decimals is None or price_usd <= 0:
                usd_value = None
            else:
                usd_value = (raw_balance / (10**decimals)) * price_usd
                if not math.isfinite(usd_value) or usd_value >= 1e20:
                    usd_value = None
            results.append(
                {
                    "token_address": (entry.get("TokenAddress") or "").lower(),
                    "token_name": str(entry.get("TokenName", ""))[:255],
                    "token_symbol": str(entry.get("TokenSymbol", ""))[:50],
                    "decimals": 18 if decimals is None else decimals,
                    "decimals_reported": decimals is not None,
                    "balance": raw_balance,
                    "price_usd": price_usd if decimals is not None and price_usd > 0 else None,
                    "usd_value": usd_value,
                }
            )
    # Ask of raw entries: dropping zero-balance entries makes a full page look short.
    returned = len(raw_entries)
    if incomplete_because is not None:
        logger.warning(
            "token balance list for %s on chain %s is a PREFIX (%d entries over %d page(s), %d with a balance): %s — "
            "any total derived from it is a lower bound",
            address,
            chain_id,
            returned,
            pages_read,
            len(results),
            incomplete_because,
        )
        status = ASSET_SET_STATUS_AT_PAGE_CAP
        basis = (
            f"etherscan addresstokenbalance, {pages_read} page(s) of {TOKEN_BALANCE_PAGE_SIZE}; "
            f"INCOMPLETE: {incomplete_because}"
        )
    elif returned:
        status = ASSET_SET_STATUS_RETURNED_ASSETS
        basis = (
            f"etherscan addresstokenbalance, {pages_read} page(s) of {TOKEN_BALANCE_PAGE_SIZE}, ended on a short page"
        )
    else:
        # An empty list per one third-party index, not proof nothing is held.
        status = ASSET_SET_STATUS_RETURNED_EMPTY
        basis = f"etherscan addresstokenbalance, {pages_read} page(s), empty list"
    return TokenBalancePage(
        rows=sorted(results, key=lambda t: t.get("usd_value") or 0, reverse=True),
        page_length=returned,
        status=status,
        pages_read=pages_read,
        basis=basis,
    )
