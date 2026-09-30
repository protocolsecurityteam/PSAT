from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Mapping, NamedTuple, Sequence
from urllib.parse import urlparse

import requests
from eth_utils.crypto import keccak
from requests.adapters import HTTPAdapter

from utils.chains import chain_by_id, chain_name_to_id_map
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

JSON_RPC_TIMEOUT_SECONDS = 10

MAX_BATCH_SIZE = 500

RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504}

ERPC_SECRET_HEADER = "X-ERPC-Secret-Token"
# Derived from the registry.
COMMON_CHAIN_IDS = chain_name_to_id_map()

# Keyed by (chain_id, address) so URL aliases share a slot; RPC errors aren't cached.
_GETCODE_CACHE: dict[tuple, tuple[str, str, float]] = {}
_GETCODE_CACHE_LOCK = threading.Lock()
_GETCODE_CACHE_MAX = 8192
_GETCODE_CACHE_TTL_S = float(os.getenv("PSAT_GETCODE_CACHE_TTL_S", "1800"))


def _getcode_cache_key(rpc_url: str, chain_id_eff: int | None, addr: str) -> tuple:
    return (chain_id_eff, addr) if chain_id_eff is not None else (rpc_url, addr)


# Bytecode is immutable, so no TTL in PG. Disable for CLI use without a DB.
_PG_BYTECODE_CACHE_ENABLED = os.getenv("PSAT_BYTECODE_PG_CACHE", "1").lower() in ("1", "true", "yes")
# Capped with FIFO eviction in case a caller mints per-request URLs.
_chain_id_cache: dict[str, int] = {}
_chain_id_cache_lock = threading.Lock()
_CHAIN_ID_CACHE_MAX = 256


def _remember_chain_id(rpc_url: str, chain_id: int) -> None:
    with _chain_id_cache_lock:
        if rpc_url not in _chain_id_cache and len(_chain_id_cache) >= _CHAIN_ID_CACHE_MAX:
            _chain_id_cache.pop(next(iter(_chain_id_cache)), None)
        _chain_id_cache[rpc_url] = chain_id


def clear_getcode_cache() -> None:
    from utils.memory import reset_cache_pressure_state

    with _GETCODE_CACHE_LOCK:
        _GETCODE_CACHE.clear()
    reset_cache_pressure_state("getcode")
    with _chain_id_cache_lock:
        _chain_id_cache.clear()


def _resolve_chain_id(rpc_url: str, chain_hint: int | None = None) -> int | None:
    """Chain id for *rpc_url* (a hint wins), memoized per URL. None on failure so the PG layer is skipped cleanly."""
    if chain_hint is not None:
        _remember_chain_id(rpc_url, chain_hint)
        return chain_hint
    with _chain_id_cache_lock:
        cached = _chain_id_cache.get(rpc_url)
    if cached is not None:
        return cached
    try:
        # Chain-discovery exemption: this call discovers the chain id.
        raw = rpc_request(rpc_url, "eth_chainId", [], retries=0)
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    try:
        chain_id = int(raw, 16)
    except ValueError:
        return None
    _remember_chain_id(rpc_url, chain_id)
    return chain_id


def _pg_bytecode_get(chain_id: int, address: str) -> tuple[str, str] | None:
    if not _PG_BYTECODE_CACHE_ENABLED:
        return None
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception:
        return None
    try:
        with SessionLocal() as session:
            row = session.execute(
                text(
                    "SELECT bytecode, code_keccak FROM bytecode_cache "
                    "WHERE chain_id = :c AND address = :a "
                    "  AND selfdestructed_at IS NULL "
                    "LIMIT 1"
                ),
                {"c": chain_id, "a": address.lower()},
            ).first()
        if row is None:
            return None
        return str(row[0]), str(row[1])
    except Exception as exc:
        logger.debug("Bytecode PG cache lookup failed (%s) — falling through", exc)
        return None


def _pg_bytecode_put(chain_id: int, address: str, bytecode: str, code_keccak: str) -> None:
    """DB errors swallowed; the in-memory cache is the safety net."""
    if not _PG_BYTECODE_CACHE_ENABLED:
        return
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception:
        return
    try:
        with SessionLocal() as session:
            session.execute(
                text(
                    "INSERT INTO bytecode_cache (chain_id, address, bytecode, code_keccak) "
                    "VALUES (:c, :a, :b, :k) "
                    "ON CONFLICT (chain_id, address) DO UPDATE "
                    "  SET bytecode = EXCLUDED.bytecode, "
                    "      code_keccak = EXCLUDED.code_keccak, "
                    "      cached_at = NOW(), "
                    "      selfdestructed_at = NULL"
                ),
                {"c": chain_id, "a": address.lower(), "b": bytecode, "k": code_keccak},
            )
            session.commit()
    except Exception as exc:
        logger.debug("Bytecode PG cache write failed (%s) — keeping in-memory only", exc)


def _pg_bytecode_get_many(chain_id: int, addresses: list[str]) -> dict[str, tuple[str, str]]:
    if not _PG_BYTECODE_CACHE_ENABLED or not addresses:
        return {}
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception:
        return {}
    try:
        with SessionLocal() as session:
            rows = session.execute(
                text(
                    "SELECT address, bytecode, code_keccak FROM bytecode_cache "
                    "WHERE chain_id = :c AND address = ANY(:addrs) "
                    "  AND selfdestructed_at IS NULL"
                ),
                {"c": chain_id, "addrs": [a.lower() for a in addresses]},
            ).all()
        return {str(addr).lower(): (str(code), str(kek)) for addr, code, kek in rows}
    except Exception as exc:
        logger.debug("Bytecode PG cache batch lookup failed (%s) — falling through", exc)
        return {}


def _pg_bytecode_put_many(chain_id: int, rows: list[tuple[str, str, str]]) -> None:
    if not _PG_BYTECODE_CACHE_ENABLED or not rows:
        return
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception:
        return
    try:
        payload = [
            {"c": chain_id, "a": addr.lower(), "b": bytecode, "k": code_keccak} for addr, bytecode, code_keccak in rows
        ]
        with SessionLocal() as session:
            session.execute(
                text(
                    "INSERT INTO bytecode_cache (chain_id, address, bytecode, code_keccak) "
                    "VALUES (:c, :a, :b, :k) "
                    "ON CONFLICT (chain_id, address) DO UPDATE "
                    "  SET bytecode = EXCLUDED.bytecode, "
                    "      code_keccak = EXCLUDED.code_keccak, "
                    "      cached_at = NOW(), "
                    "      selfdestructed_at = NULL"
                ),
                payload,
            )
            session.commit()
    except Exception as exc:
        logger.debug("Bytecode PG cache batch write failed (%s) — keeping in-memory only", exc)


def _log_getcode_pressure() -> None:
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("getcode", len(_GETCODE_CACHE), _GETCODE_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _normalized_addr(address: str) -> str:
    return address.lower() if address.startswith("0x") else "0x" + address.lower()


# Session isn't thread-safe.
_session_local = threading.local()


def _get_session() -> requests.Session:
    s = getattr(_session_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        _session_local.session = s
    return s


def erpc_url_for_chain_id(
    chain_id: int | str | None,
    *,
    base_url: str | None = None,
) -> str | None:
    if chain_id is None:
        return None
    try:
        chain_id_int = int(chain_id)
    except (TypeError, ValueError):
        return None
    if chain_id_int <= 0:
        return None

    base = (base_url if base_url is not None else os.getenv("ERPC_BASE_URL")) or ""
    if not base.strip():
        return None
    return f"{base.rstrip('/')}/main/evm/{chain_id_int}"


def rpc_url_for_chain_id(chain_id: int | str | None, explicit_rpc_url: str | None = None) -> str | None:
    if isinstance(explicit_rpc_url, str) and explicit_rpc_url.strip():
        return explicit_rpc_url
    return erpc_url_for_chain_id(chain_id)


def chain_id_for_chain_name(chain: str | None) -> int | None:
    if not isinstance(chain, str) or not chain.strip():
        return None
    return COMMON_CHAIN_IDS.get(chain.lower().strip())


_LOCAL_RPC_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def is_local_rpc_url(url: str | None) -> bool:
    """Only local URLs may shadow eRPC: a pinned hosted URL let a direct-provider 429 storm through."""
    if not isinstance(url, str) or not url.strip():
        return False
    try:
        host = urlparse(url.strip()).hostname or ""
    except ValueError:
        return False
    return host in _LOCAL_RPC_HOSTS or host.endswith(".local")


def default_rpc_url(
    *,
    explicit_rpc_url: str | None = None,
    chain_id: int | str | None = None,
    chain: str | None = None,
) -> str | None:
    """eRPC URL for a chain; eRPC is the single front door for rate-limiting, caching and failover.

    An explicit URL wins only if local (Anvil/fork). Returns None for unresolvable chains or unset ``ERPC_BASE_URL`` so
    callers fail loud via :func:`require_rpc_url`. No mainnet or public-node fallback: a chainless call is a plumbing
    bug.
    """
    if is_local_rpc_url(explicit_rpc_url):
        return explicit_rpc_url

    effective_chain_id = None
    if chain_id is not None:
        try:
            parsed = int(chain_id)
            if parsed > 0:
                effective_chain_id = parsed
        except (TypeError, ValueError):
            effective_chain_id = None
    if effective_chain_id is None:
        effective_chain_id = chain_id_for_chain_name(chain)

    return erpc_url_for_chain_id(effective_chain_id)


def require_rpc_url(
    *,
    explicit_rpc_url: str | None = None,
    chain_id: int | str | None = None,
    chain: str | None = None,
    context: str = "RPC URL resolution",
) -> str:
    """:func:`default_rpc_url` that raises: ``UnsupportedChainError`` for a missing/unknown chain, ``RuntimeError``
    when ``ERPC_BASE_URL`` is unset, so the two aren't confused. A local explicit URL still wins without a chain.
    """
    if explicit_rpc_url and is_local_rpc_url(explicit_rpc_url):
        return explicit_rpc_url

    from utils.chains import require_chain

    info = require_chain(chain_id, chain=chain, context=context)
    url = erpc_url_for_chain_id(info.chain_id)
    if not url:
        raise RuntimeError(
            f"{context}: chain_id={info.chain_id} resolved but no eRPC route — set "
            "ERPC_BASE_URL (and ERPC_SECRET) to the eRPC proxy, or pass an explicit "
            "local rpc_url for Anvil/tests. PSAT routes all hosted reads through eRPC; "
            "ETH_RPC is no longer consulted."
        )
    return url


@dataclass(frozen=True)
class ChainContext:
    """A chain id bound to its RPC URL, so a caller can't pair one chain's id with another's URL.

    Build via :func:`chain_context`.
    """

    chain_id: int
    rpc_url: str


def chain_context(chain_id: int, *, explicit_rpc_url: str | None = None) -> ChainContext:
    """Registry-backed; the URL comes from :func:`require_rpc_url`."""
    info = chain_by_id(chain_id)
    url = require_rpc_url(explicit_rpc_url=explicit_rpc_url, chain_id=info.chain_id)
    return ChainContext(chain_id=info.chain_id, rpc_url=url)


def _is_configured_erpc_url(rpc_url: str) -> bool:
    base = os.getenv("ERPC_BASE_URL")
    if not base:
        return False
    normalized_url = rpc_url.rstrip("/")
    normalized_base = base.rstrip("/")
    return normalized_url == normalized_base or normalized_url.startswith(f"{normalized_base}/")


def _erpc_chain_id_from_url(rpc_url: str) -> int | None:
    """Chain id in an eRPC path (``{ERPC_BASE_URL}/main/evm/{id}``), or None for non-eRPC URLs (the guard is then a
    no-op).
    """
    if not isinstance(rpc_url, str):
        return None
    base = os.getenv("ERPC_BASE_URL")
    if not base:
        return None
    normalized_url = rpc_url.rstrip("/")
    prefix = f"{base.rstrip('/')}/main/evm/"
    if not normalized_url.startswith(prefix):
        return None
    suffix = normalized_url[len(prefix) :]
    if not suffix or "/" in suffix:
        return None
    try:
        chain_id = int(suffix)
    except ValueError:
        return None
    # Reject non-canonical spellings ("01").
    return chain_id if str(chain_id) == suffix else None


def _assert_url_chain_id(rpc_url: str, chain_id: int | None) -> None:
    """URL/chain guard: a declared *chain_id* must match the id in an eRPC URL path. No-op for non-eRPC URLs."""
    if chain_id is None:
        return
    url_chain_id = _erpc_chain_id_from_url(rpc_url)
    if url_chain_id is None or url_chain_id == chain_id:
        return
    from utils.secrets import sanitize_url

    raise RuntimeError(
        f"eRPC URL/chain_id mismatch: caller declared chain_id={chain_id} but the RPC "
        f"URL routes chain_id={url_chain_id} ({sanitize_url(rpc_url)})"
    )


# ``PSAT_PIN_BLOCKS=1:20850000,8453:...`` pins eRPC reads to a finalized height so eRPC's forever-cache serves repeat
# runs and results stop drifting. Local URLs are never rewritten.
PIN_BLOCKS_ENV = "PSAT_PIN_BLOCKS"
# eRPC labels metrics by User-Agent and collapses "python"/"go/"/"rust" to generic names.
PINNED_USER_AGENT = "psat-pinned/1"
_MOVING_BLOCK_TAGS = frozenset({"latest", "pending", "safe", "finalized"})
_BLOCK_PARAM_INDEX = {
    "eth_call": 1,
    "eth_estimateGas": 1,
    "eth_createAccessList": 1,
    "eth_simulateV1": 1,
    "debug_traceCall": 1,
    "eth_getBalance": 1,
    "eth_getCode": 1,
    "eth_getTransactionCount": 1,
    "eth_getStorageAt": 2,
    "eth_getProof": 2,
    "eth_getBlockByNumber": 0,
}


def pinned_block(rpc_url: str) -> int | None:
    raw = os.getenv(PIN_BLOCKS_ENV, "").strip()
    if not raw:
        return None
    chain_id = _erpc_chain_id_from_url(rpc_url)
    if chain_id is None:
        return None
    for entry in raw.split(","):
        key, _, value = entry.partition(":")
        if key.strip() == str(chain_id):
            return int(value.strip())
    return None


def _is_moving_tag(value: Any) -> bool:
    return isinstance(value, str) and value in _MOVING_BLOCK_TAGS


def pin_params(method: str, params: list[Any], block: int) -> list[Any]:
    tag = hex(block)
    if method == "eth_getLogs":
        if not params or not isinstance(params[0], Mapping) or "blockHash" in params[0]:
            return params
        flt = dict(params[0])
        for key in ("fromBlock", "toBlock"):
            value = flt.get(key)
            if value is None or _is_moving_tag(value):
                flt[key] = tag
            elif isinstance(value, str) and value.startswith("0x") and int(value, 16) > block:
                flt[key] = tag
        return [flt, *params[1:]]
    index = _BLOCK_PARAM_INDEX.get(method)
    if index is None:
        return params
    if len(params) == index:
        return [*params, tag]
    if len(params) > index and _is_moving_tag(params[index]):
        return [*params[:index], tag, *params[index + 1 :]]
    return params


def _pin_calls(rpc_url: str, calls: list[tuple[str, list[Any]]]) -> list[tuple[str, list[Any]]]:
    block = pinned_block(rpc_url)
    if block is None:
        return calls
    return [(method, pin_params(method, params, block)) for method, params in calls]


def rpc_headers(rpc_url: str, extra_headers: Mapping[str, str] | None = None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if _is_configured_erpc_url(rpc_url):
        secret = os.getenv("ERPC_SECRET")
        if secret:
            headers[ERPC_SECRET_HEADER] = secret
    if extra_headers:
        headers.update({str(key): str(value) for key, value in extra_headers.items()})
    if os.getenv(PIN_BLOCKS_ENV) and _is_configured_erpc_url(rpc_url):
        headers["User-Agent"] = PINNED_USER_AGENT
    return headers


def normalize_address(address: str) -> str:
    return "0x" + address.lower().replace("0x", "", 1)


class RpcClientTimeout(RuntimeError):
    """This process stopped waiting; the upstream answered neither way.

    A reject says narrow the query; a timeout says nothing about it. Subclasses ``RuntimeError`` so existing handlers
    still catch it.
    """


def rpc_request(
    rpc_url: str,
    method: str,
    params: list[Any],
    retries: int = 1,
    headers: Mapping[str, str] | None = None,
    *,
    chain_id: int | None = None,
    timeout: float | None = None,
    before_retry: Callable[[], None] | None = None,
) -> Any:
    """One JSON-RPC call.

    ``timeout`` lets legitimately slow queries (wide ``eth_getLogs``) exceed the hot-path default. Transport failures
    raise ``RuntimeError``; timeouts raise :class:`RpcClientTimeout`. ``before_retry`` lets budgeted callers charge
    retries; raising cancels the next attempt.
    """
    _assert_url_chain_id(rpc_url, chain_id)
    block = pinned_block(rpc_url)
    if block is not None:
        if method == "eth_blockNumber":
            return hex(block)
        params = pin_params(method, params, block)
    session = _get_session()
    effective_timeout = JSON_RPC_TIMEOUT_SECONDS if timeout is None else timeout
    for attempt in range(retries + 1):
        from services.clients.request_budget import charge_attempt

        if attempt and before_retry is not None:
            before_retry()
        charge_attempt("rpc")
        try:
            response = session.post(
                rpc_url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=effective_timeout,
                headers=rpc_headers(rpc_url, headers),
            )
            if response.status_code in RETRYABLE_HTTP_CODES and attempt < retries:
                time.sleep(0.3 * (2**attempt))
                continue
            try:
                response.raise_for_status()
            except requests.HTTPError:
                from utils.secrets import sanitize_url

                raise RuntimeError(f"RPC HTTP {response.status_code} for {sanitize_url(rpc_url)}") from None
            payload = response.json()
            if payload.get("error"):
                raise RuntimeError(str(payload["error"]))
            # Hot path: never above DEBUG.
            logger.debug("rpc call", extra={"method": method, "attempt": attempt})
            return payload.get("result")
        except (requests.ConnectionError, requests.Timeout, OSError) as exc:
            if attempt < retries:
                time.sleep(0.3 * (2**attempt))
                continue
            from utils.secrets import sanitize_string, sanitize_url

            detail = f"RPC request failed for {sanitize_url(rpc_url)}: {sanitize_string(str(exc))}"
            # Connect and read timeouts are our ceiling, not the upstream's verdict.
            if isinstance(exc, requests.Timeout):
                raise RpcClientTimeout(detail) from exc
            raise RuntimeError(detail) from exc
    from utils.secrets import sanitize_url

    raise RuntimeError(f"RPC request failed for {sanitize_url(rpc_url)}: all {retries + 1} attempts exhausted")


def get_code(rpc_url: str, address: str, *, chain_id: int | None = None) -> str:
    """eth_getCode, cached (TTL ``PSAT_GETCODE_CACHE_TTL_S``).

    Errors aren't cached. Pass *chain_id* to skip ``eth_chainId`` discovery.
    """
    code, _keccak = get_code_with_keccak(rpc_url, address, chain_id=chain_id)
    return code


def get_code_with_keccak(rpc_url: str, address: str, *, chain_id: int | None = None) -> tuple[str, str]:
    """``(bytecode_hex, keccak_hex)``: in-memory (TTL) -> Postgres (no TTL) -> wire."""
    addr = _normalized_addr(address)
    now = time.monotonic()
    chain_id_eff = _resolve_chain_id(rpc_url, chain_id) if _PG_BYTECODE_CACHE_ENABLED else None
    key = _getcode_cache_key(rpc_url, chain_id_eff, addr)
    with _GETCODE_CACHE_LOCK:
        cached = _GETCODE_CACHE.get(key)
        if cached is not None:
            code, keccak_hex, inserted_at = cached
            if now - inserted_at < _GETCODE_CACHE_TTL_S:
                return code, keccak_hex
            del _GETCODE_CACHE[key]

    if chain_id_eff is not None:
        pg_hit = _pg_bytecode_get(chain_id_eff, addr)
        if pg_hit is not None:
            code, keccak_hex = pg_hit
            with _GETCODE_CACHE_LOCK:
                _evict_getcode_if_needed()
                _GETCODE_CACHE[key] = (code, keccak_hex, now)
                _log_getcode_pressure()
            return code, keccak_hex

    # Outside the lock so misses don't serialize. Declare the caller's chain_id, never the URL-derived one, or the
    # URL/chain guard is a tautology.
    raw = rpc_request(rpc_url, "eth_getCode", [address, "latest"], chain_id=chain_id)
    code = raw if isinstance(raw, str) and raw.startswith("0x") else "0x"
    # ``bytes.fromhex`` raises on odd-length hex.
    if code in {"0x", "0x0"}:
        code = "0x"
    code_bytes = bytes.fromhex(code[2:]) if len(code) > 2 else b""
    keccak_hex = "0x" + keccak(code_bytes).hex()

    with _GETCODE_CACHE_LOCK:
        _evict_getcode_if_needed()
        _GETCODE_CACHE[key] = (code, keccak_hex, now)
        _log_getcode_pressure()
    if chain_id_eff is not None:
        _pg_bytecode_put(chain_id_eff, addr, code, keccak_hex)
    return code, keccak_hex


def _evict_getcode_if_needed() -> None:
    if len(_GETCODE_CACHE) < _GETCODE_CACHE_MAX:
        return
    cutoff = sorted(_GETCODE_CACHE.values(), key=lambda v: v[2])[len(_GETCODE_CACHE) // 4][2]
    for k in [k for k, v in _GETCODE_CACHE.items() if v[2] <= cutoff]:
        _GETCODE_CACHE.pop(k, None)


def get_code_batch(rpc_url: str, addresses: list[str], *, chain_id: int | None = None) -> dict[str, str]:
    """Cache-aware batched eth_getCode; errored slots are omitted. Same layering as :func:`get_code_with_keccak`."""
    if not addresses:
        return {}

    normalized = [_normalized_addr(a) for a in addresses]
    now = time.monotonic()
    out: dict[str, str] = {}

    chain_id_eff = _resolve_chain_id(rpc_url, chain_id) if _PG_BYTECODE_CACHE_ENABLED else None

    to_fetch: list[str] = []
    with _GETCODE_CACHE_LOCK:
        for addr in normalized:
            cached = _GETCODE_CACHE.get(_getcode_cache_key(rpc_url, chain_id_eff, addr))
            if cached is not None:
                code, _keccak, inserted_at = cached
                if now - inserted_at < _GETCODE_CACHE_TTL_S:
                    out[addr] = code
                    continue
            to_fetch.append(addr)

    if not to_fetch:
        return out

    # Promote PG hits into memory.
    if chain_id_eff is not None and to_fetch:
        pg_hits = _pg_bytecode_get_many(chain_id_eff, to_fetch)
        if pg_hits:
            with _GETCODE_CACHE_LOCK:
                for addr in list(to_fetch):
                    payload = pg_hits.get(addr)
                    if payload is None:
                        continue
                    code, keccak_hex = payload
                    _evict_getcode_if_needed()
                    _GETCODE_CACHE[_getcode_cache_key(rpc_url, chain_id_eff, addr)] = (code, keccak_hex, now)
                    _log_getcode_pressure()
                    out[addr] = code
            to_fetch = [addr for addr in to_fetch if addr not in pg_hits]

    if not to_fetch:
        return out

    calls: list[tuple[str, list[Any]]] = [("eth_getCode", [addr, "latest"]) for addr in to_fetch]
    # The caller's chain_id, not the URL-derived one.
    raw_results = rpc_batch_request_with_status(rpc_url, calls, chain_id=chain_id)
    pg_writes: list[tuple[str, str, str]] = []
    with _GETCODE_CACHE_LOCK:
        for addr, (raw, had_error) in zip(to_fetch, raw_results):
            if had_error:
                continue  # caller treats absence as missing/error
            code = raw if isinstance(raw, str) and raw.startswith("0x") else "0x"
            # ``bytes.fromhex`` raises on odd-length hex; some providers return "0x0" for EOAs.
            if code in {"0x", "0x0"}:
                code = "0x"
            code_bytes = bytes.fromhex(code[2:]) if len(code) > 2 else b""
            keccak_hex = "0x" + keccak(code_bytes).hex()
            # The batch path used to bypass eviction.
            _evict_getcode_if_needed()
            _GETCODE_CACHE[_getcode_cache_key(rpc_url, chain_id_eff, addr)] = (code, keccak_hex, now)
            _log_getcode_pressure()
            out[addr] = code
            pg_writes.append((addr, code, keccak_hex))
    if chain_id_eff is not None and pg_writes:
        _pg_bytecode_put_many(chain_id_eff, pg_writes)
    return out


def rpc_batch_request(
    rpc_url: str,
    calls: list[tuple[str, list[Any]]],
    headers: Mapping[str, str] | None = None,
    *,
    chain_id: int | None = None,
) -> list[Any]:
    if not calls:
        return []

    _assert_url_chain_id(rpc_url, chain_id)
    calls = _pin_calls(rpc_url, calls)

    results: list[Any] = [None] * len(calls)

    for chunk_start in range(0, len(calls), MAX_BATCH_SIZE):
        chunk = calls[chunk_start : chunk_start + MAX_BATCH_SIZE]
        batch = [
            {"jsonrpc": "2.0", "id": chunk_start + i, "method": method, "params": params}
            for i, (method, params) in enumerate(chunk)
        ]

        try:
            response = _get_session().post(
                rpc_url,
                json=batch,
                timeout=max(JSON_RPC_TIMEOUT_SECONDS, len(chunk) * 0.1),
                headers=rpc_headers(rpc_url, headers),
            )
            response.raise_for_status()
        except (requests.HTTPError, requests.ConnectionError, requests.Timeout, OSError) as exc:
            from utils.secrets import sanitize_string, sanitize_url

            status = getattr(getattr(exc, "response", None), "status_code", None)
            detail = f"HTTP {status}" if status is not None else sanitize_string(str(exc))
            raise RuntimeError(f"RPC batch failed for {sanitize_url(rpc_url)}: {detail}") from None

        payload = response.json()
        if isinstance(payload, dict):
            payload = [payload]

        for item in payload:
            idx = item.get("id")
            if idx is not None and not item.get("error"):
                results[idx] = item.get("result")

    return results


def rpc_batch_request_classified(
    rpc_url: str,
    calls: list[tuple[str, list[Any]]],
    headers: Mapping[str, str] | None = None,
    *,
    chain_id: int | None = None,
) -> list[tuple[Any, str]]:
    """Batch JSON-RPC with a ``(result, status)`` per call:

      * ``"ok"`` — answered with a result.
      * ``"error"`` — per-call JSON-RPC error (e.g. revert): an observed negative.
      * ``"transport"`` — no usable answer for this slot; outcome unobserved.

    Never raises for wire failures.
    """
    if not calls:
        return []

    _assert_url_chain_id(rpc_url, chain_id)
    calls = _pin_calls(rpc_url, calls)

    # Unanswered slots stay unobserved rather than looking like an earned error.
    results: list[tuple[Any, str]] = [(None, "transport")] * len(calls)

    for chunk_start in range(0, len(calls), MAX_BATCH_SIZE):
        chunk = calls[chunk_start : chunk_start + MAX_BATCH_SIZE]
        batch = [
            {"jsonrpc": "2.0", "id": chunk_start + i, "method": method, "params": params}
            for i, (method, params) in enumerate(chunk)
        ]

        try:
            response = _get_session().post(
                rpc_url,
                json=batch,
                timeout=max(JSON_RPC_TIMEOUT_SECONDS, len(chunk) * 0.1),
                headers=rpc_headers(rpc_url, headers),
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            logger.warning(
                "rpc batch chunk failed wholesale — slots flagged transient",
                extra={"chunk_start": chunk_start, "chunk_size": len(chunk), "exc_type": type(exc).__name__},
            )
            record_degraded(phase="rpc_batch_chunk", exc=exc, context={"chunk_start": chunk_start})
            continue

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            # Some providers refuse batches with a non-list error; nothing per-call was observed.
            continue

        for item in payload:
            if not isinstance(item, dict):
                continue
            idx = item.get("id")
            if not isinstance(idx, int) or idx < 0 or idx >= len(calls):
                continue
            if item.get("error"):
                results[idx] = (None, "error")
            else:
                results[idx] = (item.get("result"), "ok")

    return results


def rpc_batch_request_with_status(
    rpc_url: str,
    calls: list[tuple[str, list[Any]]],
    headers: Mapping[str, str] | None = None,
    *,
    chain_id: int | None = None,
) -> list[tuple[Any, bool]]:
    """``(result, had_error)``, collapsing error and transport.

    Anything publishing a negative must use the classified form.
    """
    return [
        (result, status != "ok")
        for result, status in rpc_batch_request_classified(rpc_url, calls, headers, chain_id=chain_id)
    ]


class EthCallResult(NamedTuple):
    """One ``eth_call`` outcome, preserving revert data:

    * success            → ``(True,  return_hex, None, None)``
    * revert WITH data   → ``(False, "0x", revert_hex, message)`` — attributes which gate fired
    * revert/err NO data → ``(False, "0x", None, message)`` — indeterminate
    """

    success: bool
    return_data: str
    revert_data: str | None
    error_message: str | None


def _extract_revert_data(data: Any) -> str | None:
    """Revert hex from an error ``data`` field (bare, prefixed or nested by node).

    ``"0x"`` for a bare revert (a real gate); None when nothing decodable (indeterminate).
    """
    if isinstance(data, str):
        s = data.strip()
        if s.startswith("0x"):
            return s.lower()
        idx = s.find("0x")
        if idx != -1:
            return s[idx:].split()[0].lower()
        return None
    if isinstance(data, Mapping):
        inner = data.get("data")
        if isinstance(inner, str):
            return _extract_revert_data(inner)
    return None


def _eth_call_result_from_rpc_item(item: Mapping[str, Any]) -> EthCallResult:
    error = item.get("error")
    if error:
        if isinstance(error, Mapping):
            raw_msg = error.get("message")
            message = str(raw_msg) if raw_msg is not None else "error"
            return EthCallResult(False, "0x", _extract_revert_data(error.get("data")), message)
        return EthCallResult(False, "0x", None, str(error))
    result = item.get("result")
    if isinstance(result, str) and result.startswith("0x"):
        return EthCallResult(True, result, None, None)
    return EthCallResult(True, "0x", None, None)


def eth_call_batch(
    rpc_url: str,
    calls: Sequence[Mapping[str, str]],
    block_tag: str = "latest",
    *,
    headers: Mapping[str, str] | None = None,
    chain_id: int | None = None,
) -> list[EthCallResult]:
    """Batch ``eth_call``s with per-call ``from`` at one ``block_tag``, preserving revert data.

    Not Multicall3: ``aggregate3`` makes Multicall3 the ``msg.sender``, erasing the ``from`` a differential probe needs.
    A chunk transport failure flags every slot unsuccessful with no data.
    """
    if not calls:
        return []

    _assert_url_chain_id(rpc_url, chain_id)
    block = pinned_block(rpc_url)
    if block is not None and _is_moving_tag(block_tag):
        block_tag = hex(block)
    results: list[EthCallResult] = [EthCallResult(False, "0x", None, "no_response")] * len(calls)
    for chunk_start in range(0, len(calls), MAX_BATCH_SIZE):
        chunk = calls[chunk_start : chunk_start + MAX_BATCH_SIZE]
        batch = [
            {"jsonrpc": "2.0", "id": chunk_start + i, "method": "eth_call", "params": [dict(call), block_tag]}
            for i, call in enumerate(chunk)
        ]
        try:
            response = _get_session().post(
                rpc_url,
                json=batch,
                timeout=max(JSON_RPC_TIMEOUT_SECONDS, len(chunk) * 0.1),
                headers=rpc_headers(rpc_url, headers),
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            from utils.secrets import sanitize_string

            msg = f"transport: {sanitize_string(str(exc))}"
            logger.warning(
                "eth_call batch chunk failed wholesale — slots flagged transient",
                extra={"chunk_start": chunk_start, "chunk_size": len(chunk), "exc_type": type(exc).__name__},
            )
            record_degraded(phase="eth_call_batch_chunk", exc=exc, context={"chunk_start": chunk_start})
            for i in range(len(chunk)):
                results[chunk_start + i] = EthCallResult(False, "0x", None, msg)
            continue

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            continue
        for item in payload:
            if not isinstance(item, dict):
                continue
            idx = item.get("id")
            if not isinstance(idx, int) or idx < 0 or idx >= len(calls):
                continue
            results[idx] = _eth_call_result_from_rpc_item(item)

    return results


MULTICALL3_ADDRESS = "0xcA11bde05977b3631167028862bE2a173976CA11"
# Each aggregate3 is one billable call; the cap only keeps gas under node ceilings.
_MULTICALL3_CHUNK = int(os.getenv("PSAT_MULTICALL3_CHUNK", "100"))


def multicall3_aggregate3(
    rpc_url: str,
    calls: list[tuple[str, str]],
    block_tag: str = "latest",
    *,
    chunk_size: int | None = None,
    headers: Mapping[str, str] | None = None,
    chain_id: int | None = None,
) -> list[tuple[bool, str]]:
    """N read-only ``eth_call``s as one billable call per chunk via ``aggregate3``.

    Returns ``[(success, return_data_hex)]``, byte-identical to direct calls. Raises on transport or malformed responses
    so callers fall back to per-call reads.

    Only for caller-independent reads: Multicall3 becomes ``msg.sender``.
    """
    if not calls:
        return []
    from eth_abi.abi import decode as _abi_decode
    from eth_abi.abi import encode as _abi_encode

    # Derived so a typo can't mint wrong calldata.
    agg3_selector = selector("aggregate3((address,bool,bytes)[])")
    size = chunk_size or _MULTICALL3_CHUNK
    results: list[tuple[bool, str]] = []
    for start in range(0, len(calls), size):
        chunk = calls[start : start + size]
        encoded_calls = [
            (target, True, bytes.fromhex((calldata[2:] if calldata.startswith("0x") else calldata)))
            for target, calldata in chunk
        ]
        data = agg3_selector + _abi_encode(["(address,bool,bytes)[]"], [encoded_calls]).hex()
        raw = rpc_request(
            rpc_url,
            "eth_call",
            [{"to": MULTICALL3_ADDRESS, "data": data}, block_tag],
            headers=headers,
            chain_id=chain_id,
        )
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise RuntimeError(f"multicall3 aggregate3: non-hex result {raw!r}")
        decoded = _abi_decode(["(bool,bytes)[]"], bytes.fromhex(raw[2:]))[0]
        if len(decoded) != len(chunk):
            raise RuntimeError(f"multicall3 aggregate3: got {len(decoded)} results, expected {len(chunk)}")
        results.extend((bool(success), "0x" + return_data.hex()) for success, return_data in decoded)
    return results


def parse_address_result(raw: Any) -> str | None:
    """Address from an ``eth_getStorageAt`` / ``eth_call`` result, or None for empty, zero, short (<66 chars) or
    revert-like responses.
    """
    if not raw or not isinstance(raw, str) or len(raw) < 66:
        return None
    if raw == "0x" + "0" * 64:
        return None
    addr = "0x" + raw[-40:]
    if addr == "0x" + "0" * 40:
        return None
    return normalize_hex(addr)


def selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def encode_address_word(address: str) -> str:
    """One 32-byte word, no ``0x``; shared so encodings can't drift."""
    return address.lower().removeprefix("0x").rjust(64, "0")


def decode_bool_word(raw: Any) -> bool:
    """Too short or unparseable is False: a revert isn't truthy."""
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return False
    try:
        return int(raw[-64:], 16) != 0
    except ValueError:
        return False


def normalize_hex(value: str | None) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        return "0x"
    return value.lower()
