"""Shared low-level helpers for JSON-RPC and EVM encoding."""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Mapping, NamedTuple, Sequence
from urllib.parse import urlparse

import requests
from eth_utils.crypto import keccak
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

JSON_RPC_TIMEOUT_SECONDS = 10

# Maximum calls per JSON-RPC batch (stay under provider limits)
MAX_BATCH_SIZE = 500

RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504}

ERPC_SECRET_HEADER = "X-ERPC-Secret-Token"
COMMON_CHAIN_IDS = {
    "ethereum": 1,
    "mainnet": 1,
    "arbitrum": 42161,
    "optimism": 10,
    "polygon": 137,
    "base": 8453,
    "avalanche": 43114,
    "bsc": 56,
    "linea": 59144,
    "scroll": 534352,
    "zksync": 324,
    "blast": 81457,
    "mode": 34443,
    "bera": 80094,
    "berachain": 80094,
}

# Process-wide cache for eth_getCode (bytecode + its keccak); skips caching on RPC error and applies a TTL for safety.
_GETCODE_CACHE: dict[tuple[str, str], tuple[str, str, float]] = {}
_GETCODE_CACHE_LOCK = threading.Lock()
_GETCODE_CACHE_MAX = 8192
_GETCODE_CACHE_TTL_S = float(os.getenv("PSAT_GETCODE_CACHE_TTL_S", "1800"))

# Cross-process bytecode cache: layered in-memory → Postgres → wire. Bytecode at
# a deployed address is effectively immutable, so the PG layer skips the TTL
# the in-memory layer carries. Disabled flag makes the CLI usable without a DB.
_PG_BYTECODE_CACHE_ENABLED = os.getenv("PSAT_BYTECODE_PG_CACHE", "1").lower() in ("1", "true", "yes")
_chain_id_cache: dict[str, int] = {}
_chain_id_cache_lock = threading.Lock()


def clear_getcode_cache() -> None:
    """Clear the process-wide eth_getCode cache. For tests + manual reset."""
    from utils.memory import reset_cache_pressure_state

    with _GETCODE_CACHE_LOCK:
        _GETCODE_CACHE.clear()
    reset_cache_pressure_state("getcode")
    with _chain_id_cache_lock:
        _chain_id_cache.clear()


def _resolve_chain_id(rpc_url: str, chain_hint: int | None = None) -> int | None:
    """Return the EIP-155 chain id for *rpc_url*, or None if discovery fails.

    When *chain_hint* is supplied, it wins and is cached for future calls
    against the same URL. Otherwise we issue one ``eth_chainId`` per URL per
    process and memoise the result. Any RPC failure returns None so the caller
    skips the PG layer cleanly — the in-memory dict + wire fetch keep working.
    """
    if chain_hint is not None:
        with _chain_id_cache_lock:
            _chain_id_cache[rpc_url] = chain_hint
        return chain_hint
    with _chain_id_cache_lock:
        cached = _chain_id_cache.get(rpc_url)
    if cached is not None:
        return cached
    try:
        raw = rpc_request(rpc_url, "eth_chainId", [], retries=0)
    except Exception:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    try:
        chain_id = int(raw, 16)
    except ValueError:
        return None
    with _chain_id_cache_lock:
        _chain_id_cache[rpc_url] = chain_id
    return chain_id


def _pg_bytecode_get(chain_id: int, address: str) -> tuple[str, str] | None:
    """Postgres read-through; returns ``(bytecode, code_keccak)`` or None on miss/DB-unavailable."""
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
    """Best-effort upsert into bytecode_cache. DB errors swallowed (in-memory cache is the safety net)."""
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
    """Batch read for bytecode_cache; returns ``{address_lower: (bytecode, keccak)}``. Empty dict on disable/failure."""
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
    """Batch upsert; *rows* is ``[(address, bytecode, code_keccak), ...]``."""
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
    """Log when _GETCODE_CACHE crosses 50/75/95% of its bound (caller holds the lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("getcode", len(_GETCODE_CACHE), _GETCODE_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _normalized_addr(address: str) -> str:
    return address.lower() if address.startswith("0x") else "0x" + address.lower()


# Per-thread requests.Session for TCP/TLS reuse on RPC calls (Session is not thread-safe across calls, hence
# threading.local()).
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
    """Build the configured eRPC URL for an EVM chain id."""
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
    """Return an explicit RPC URL when provided, otherwise the configured eRPC URL."""
    if isinstance(explicit_rpc_url, str) and explicit_rpc_url.strip():
        return explicit_rpc_url
    return erpc_url_for_chain_id(chain_id)


def chain_id_for_chain_name(chain: str | None) -> int | None:
    if not isinstance(chain, str) or not chain.strip():
        return None
    return COMMON_CHAIN_IDS.get(chain.lower().strip())


_LOCAL_RPC_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def is_local_rpc_url(url: str | None) -> bool:
    """True for a localhost/Anvil RPC URL.

    A local URL is the only explicit override allowed to shadow eRPC (local
    fork tests). A hosted URL never wins over eRPC — a pinned mainnet provider
    URL doing exactly that is what let a direct-provider 429 storm through.
    """
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
    default_chain_id: int | None = 1,
) -> str | None:
    """Resolve the RPC URL PSAT should use for a chain — eRPC only.

    eRPC is the single front door for every hosted read, so rate-limiting,
    caching, and multi-upstream failover live in one place. Resolution:

    1. An explicit URL wins ONLY when it targets a local node (Anvil / test
       fork). A hosted explicit URL is ignored in favor of eRPC.
    2. Otherwise build the eRPC route for the resolved chain id. Unknown
       explicit chain names are not silently mapped to mainnet.

    Returns None when no eRPC route can be built (``ERPC_BASE_URL`` unset, or an
    unrecognized chain) so callers fail loud via :func:`require_rpc_url` instead
    of silently hitting a direct provider. There is intentionally no ``ETH_RPC``
    or public-node fallback.
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
    # Empty/None or discovery's ``"unknown"`` sentinel falls back to the default
    # chain (mainnet); a genuinely-named but unsupported chain (e.g. "fantom")
    # stays unresolved so the caller fails loud instead of guessing mainnet.
    chain_is_named = isinstance(chain, str) and bool(chain.strip()) and chain.strip().lower() != "unknown"
    if effective_chain_id is None and not chain_is_named:
        effective_chain_id = default_chain_id

    return erpc_url_for_chain_id(effective_chain_id)


def require_rpc_url(
    *,
    explicit_rpc_url: str | None = None,
    chain_id: int | str | None = None,
    chain: str | None = None,
    default_chain_id: int | None = 1,
) -> str:
    """:func:`default_rpc_url` that raises instead of returning None.

    Use on pipeline paths where a missing RPC route is a hard configuration
    error, not something to paper over with a direct-provider fallback.
    """
    url = default_rpc_url(
        explicit_rpc_url=explicit_rpc_url,
        chain_id=chain_id,
        chain=chain,
        default_chain_id=default_chain_id,
    )
    if not url:
        raise RuntimeError(
            "No eRPC route available: set ERPC_BASE_URL (and ERPC_SECRET) to the eRPC "
            "proxy, or pass an explicit local rpc_url for Anvil/tests. PSAT routes all "
            "hosted reads through eRPC; ETH_RPC is no longer consulted."
        )
    return url


def _is_configured_erpc_url(rpc_url: str) -> bool:
    base = os.getenv("ERPC_BASE_URL")
    if not base:
        return False
    normalized_url = rpc_url.rstrip("/")
    normalized_base = base.rstrip("/")
    return normalized_url == normalized_base or normalized_url.startswith(f"{normalized_base}/")


def rpc_headers(rpc_url: str, extra_headers: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return JSON-RPC headers, adding eRPC auth only for configured eRPC URLs."""
    headers = {"Content-Type": "application/json"}
    if _is_configured_erpc_url(rpc_url):
        secret = os.getenv("ERPC_SECRET")
        if secret:
            headers[ERPC_SECRET_HEADER] = secret
    if extra_headers:
        headers.update({str(key): str(value) for key, value in extra_headers.items()})
    return headers


def erpc_healthcheck_url(chain_id: int | str | None = None, *, eval_chain_id: bool = False) -> str | None:
    """Build an eRPC healthcheck URL for deployment smoke checks."""
    base = (os.getenv("ERPC_BASE_URL") or "").rstrip("/")
    if not base:
        return None
    if chain_id is None:
        return f"{base}/healthcheck"
    rpc_url = erpc_url_for_chain_id(chain_id)
    if rpc_url is None:
        return None
    healthcheck = f"{rpc_url}/healthcheck"
    return f"{healthcheck}?eval=all:evm:eth_chainId" if eval_chain_id else healthcheck


def normalize_address(address: str) -> str:
    """Normalize an Ethereum address to lowercase with a single 0x prefix."""
    return "0x" + address.lower().replace("0x", "", 1)


def rpc_request(
    rpc_url: str,
    method: str,
    params: list[Any],
    retries: int = 1,
    headers: Mapping[str, str] | None = None,
) -> Any:
    session = _get_session()
    for attempt in range(retries + 1):
        try:
            response = session.post(
                rpc_url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                timeout=JSON_RPC_TIMEOUT_SECONDS,
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
            return payload.get("result")
        except (requests.ConnectionError, requests.Timeout, OSError) as exc:
            if attempt < retries:
                time.sleep(0.3 * (2**attempt))
                continue
            from utils.secrets import sanitize_string, sanitize_url

            raise RuntimeError(f"RPC request failed for {sanitize_url(rpc_url)}: {sanitize_string(str(exc))}") from exc
    from utils.secrets import sanitize_url

    raise RuntimeError(f"RPC request failed for {sanitize_url(rpc_url)}: all {retries + 1} attempts exhausted")


def get_code(rpc_url: str, address: str, *, chain_id: int | None = None) -> str:
    """Fetch deployed EVM bytecode at an address via eth_getCode.

    Process-wide cached (TTL ``PSAT_GETCODE_CACHE_TTL_S``, default 30 min)
    so repeated probes of the same address across stages and jobs hit
    the cache instead of the wire. RPC errors are NOT cached — they
    propagate as ``RuntimeError`` so callers can decide retry behavior.
    Pass *chain_id* to skip the one-time ``eth_chainId`` discovery used by
    the cross-process Postgres cache layer.
    """
    code, _keccak = get_code_with_keccak(rpc_url, address, chain_id=chain_id)
    return code


def get_code_with_keccak(rpc_url: str, address: str, *, chain_id: int | None = None) -> tuple[str, str]:
    """Return ``(bytecode_hex, keccak_hex)`` cached together so downstream content-addressed lookups get the keccak for
    free.

    Cache layering: in-memory dict (TTL'd) → Postgres ``bytecode_cache`` (no
    TTL — bytecode is immutable per ``(chain_id, address)``) → wire fetch.
    Pass *chain_id* explicitly to skip the one-time ``eth_chainId`` lookup.
    """
    addr = _normalized_addr(address)
    key = (rpc_url, addr)
    now = time.monotonic()
    with _GETCODE_CACHE_LOCK:
        cached = _GETCODE_CACHE.get(key)
        if cached is not None:
            code, keccak_hex, inserted_at = cached
            if now - inserted_at < _GETCODE_CACHE_TTL_S:
                return code, keccak_hex
            # TTL expired; fall through to re-fetch.
            del _GETCODE_CACHE[key]

    # PG cache: cross-process layer; only consulted when we can resolve a chain id.
    chain_id_eff = _resolve_chain_id(rpc_url, chain_id) if _PG_BYTECODE_CACHE_ENABLED else None
    if chain_id_eff is not None:
        pg_hit = _pg_bytecode_get(chain_id_eff, addr)
        if pg_hit is not None:
            code, keccak_hex = pg_hit
            with _GETCODE_CACHE_LOCK:
                _evict_getcode_if_needed()
                _GETCODE_CACHE[key] = (code, keccak_hex, now)
                _log_getcode_pressure()
            return code, keccak_hex

    # RPC outside the lock so concurrent misses for different addresses don't serialize.
    raw = rpc_request(rpc_url, "eth_getCode", [address, "latest"])
    code = raw if isinstance(raw, str) and raw.startswith("0x") else "0x"
    # Normalize "0x0" → "0x" so bytes.fromhex doesn't raise on odd-length hex.
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
    """Drop the oldest 25% of _GETCODE_CACHE entries when the bound is reached (caller holds _GETCODE_CACHE_LOCK)."""
    if len(_GETCODE_CACHE) < _GETCODE_CACHE_MAX:
        return
    cutoff = sorted(_GETCODE_CACHE.values(), key=lambda v: v[2])[len(_GETCODE_CACHE) // 4][2]
    for k in [k for k, v in _GETCODE_CACHE.items() if v[2] <= cutoff]:
        _GETCODE_CACHE.pop(k, None)


def get_code_batch(rpc_url: str, addresses: list[str], *, chain_id: int | None = None) -> dict[str, str]:
    """Cache-aware batched eth_getCode; errored slots are omitted from the returned ``{address: bytecode}`` map.

    Cache layering matches :func:`get_code_with_keccak`: in-memory → Postgres
    ``bytecode_cache`` (one bulk SELECT for the misses) → wire batch.
    """
    if not addresses:
        return {}

    normalized = [_normalized_addr(a) for a in addresses]
    now = time.monotonic()
    out: dict[str, str] = {}

    to_fetch: list[str] = []
    with _GETCODE_CACHE_LOCK:
        for addr in normalized:
            cached = _GETCODE_CACHE.get((rpc_url, addr))
            if cached is not None:
                code, _keccak, inserted_at = cached
                if now - inserted_at < _GETCODE_CACHE_TTL_S:
                    out[addr] = code
                    continue
            to_fetch.append(addr)

    if not to_fetch:
        return out

    # PG layer: bulk SELECT for the in-memory misses; promote hits into the
    # in-memory cache so a later same-process call short-circuits.
    chain_id_eff = _resolve_chain_id(rpc_url, chain_id) if _PG_BYTECODE_CACHE_ENABLED else None
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
                    _GETCODE_CACHE[(rpc_url, addr)] = (code, keccak_hex, now)
                    _log_getcode_pressure()
                    out[addr] = code
            to_fetch = [addr for addr in to_fetch if addr not in pg_hits]

    if not to_fetch:
        return out

    calls: list[tuple[str, list[Any]]] = [("eth_getCode", [addr, "latest"]) for addr in to_fetch]
    raw_results = rpc_batch_request_with_status(rpc_url, calls)
    pg_writes: list[tuple[str, str, str]] = []
    with _GETCODE_CACHE_LOCK:
        for addr, (raw, had_error) in zip(to_fetch, raw_results):
            if had_error:
                continue  # caller treats absence as missing/error
            code = raw if isinstance(raw, str) and raw.startswith("0x") else "0x"
            # Normalize "0x0" → "0x" so bytes.fromhex doesn't raise on
            # odd-length hex (some providers return "0x0" for EOAs).
            if code in {"0x", "0x0"}:
                code = "0x"
            code_bytes = bytes.fromhex(code[2:]) if len(code) > 2 else b""
            keccak_hex = "0x" + keccak(code_bytes).hex()
            # Honour the cache bound — codex iter-5 P2: batch path was
            # bypassing eviction, letting long-lived workers exceed
            # _GETCODE_CACHE_MAX with full bytecode payloads.
            _evict_getcode_if_needed()
            _GETCODE_CACHE[(rpc_url, addr)] = (code, keccak_hex, now)
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
) -> list[Any]:
    """Send a JSON-RPC batch and return results in call order; per-call errors yield ``None``."""
    if not calls:
        return []

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


def rpc_batch_request_with_status(
    rpc_url: str,
    calls: list[tuple[str, list[Any]]],
    headers: Mapping[str, str] | None = None,
) -> list[tuple[Any, bool]]:
    """Like ``rpc_batch_request`` but returns ``(result, had_error)`` so callers can distinguish RPC failure from a
    legitimate ``None`` result."""
    if not calls:
        return []

    # Default to (None, True) so any chunk that fails wholesale leaves
    # its slots flagged as errored — matches the sequential path's
    # behavior of raising on any RPC failure.
    results: list[tuple[Any, bool]] = [(None, True)] * len(calls)

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
        except Exception:
            # Whole-chunk failure — leave defaults as (None, True). This
            # is the conservative choice: caller will skip caching and
            # treat results as transient.
            continue

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            # Unexpected shape (some providers refuse batches with a
            # non-list error object) — flag every slot in this chunk.
            continue

        for item in payload:
            if not isinstance(item, dict):
                continue
            idx = item.get("id")
            if not isinstance(idx, int) or idx < 0 or idx >= len(calls):
                continue
            if item.get("error"):
                results[idx] = (None, True)
            else:
                results[idx] = (item.get("result"), False)

    return results


class EthCallResult(NamedTuple):
    """One ``eth_call`` outcome, preserving revert DATA (unlike
    ``rpc_batch_request_with_status``, which collapses any error to a bare
    ``had_error`` flag and discards the bytes).

      * success            → ``(True,  return_hex, None, None)``
      * revert WITH data   → ``(False, "0x", revert_hex, message)`` — the revert
        bytes a differential probe decodes to attribute WHICH gate fired
      * revert/err NO data → ``(False, "0x", None, message)`` — OOG, transport, or
        a node that omits ``error.data``: indeterminate, never attributable
    """

    success: bool
    return_data: str
    revert_data: str | None
    error_message: str | None


def _extract_revert_data(data: Any) -> str | None:
    """Pull raw revert-return hex from a JSON-RPC error ``data`` field. Nodes vary:
    geth/erigon give a bare ``0x..`` hex string; some providers prefix it
    (``"Reverted 0x.."``) or nest it (``{"data": "0x.."}``). Returns the
    ``0x``-prefixed bytes (``"0x"`` for an empty/bare revert — a real, comparable
    gate), or None when the node gave no decodable payload (a plain
    ``"execution reverted"`` with no data, OOG) — which a probe treats as
    indeterminate, never as an attributable gate."""
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
) -> list[EthCallResult]:
    """Batch N read-only ``eth_call``s — each its own ``{from?, to, data}`` — in one
    JSON-RPC array request at a single ``block_tag``, returning a per-call
    :class:`EthCallResult` that PRESERVES revert data (aligned 1:1 with ``calls``).

    Each call varies ``msg.sender`` of the TARGET via its own ``from`` field, which
    is exactly why a differential caller probe CANNOT use Multicall3: ``aggregate3``
    makes every sub-call's ``msg.sender`` the Multicall3 contract, erasing the
    ``from`` the probe must discriminate on. A JSON-RPC array batch keeps per-call
    ``from`` while still giving one round trip at one block — the same-block,
    same-node consistency the probe's cross-checks require, without the msg.sender
    rewrite. On a whole-chunk transport failure every slot in the chunk is flagged
    ``success=False`` with no revert data (transient → caller withholds, never
    upgrades)."""
    if not calls:
        return []

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


# Multicall3 is deployed at the same address on every chain PSAT supports.
MULTICALL3_ADDRESS = "0xcA11bde05977b3631167028862bE2a173976CA11"
# Default sub-calls per aggregate3 eth_call. Each aggregate3 is ONE billable
# eth_call regardless of width; the cap only bounds per-call gas so a huge fan-out
# can't trip a node's eth_call gas ceiling (it would revert the whole batch).
_MULTICALL3_CHUNK = int(os.getenv("PSAT_MULTICALL3_CHUNK", "100"))


def multicall3_aggregate3(
    rpc_url: str,
    calls: list[tuple[str, str]],
    block_tag: str = "latest",
    *,
    chunk_size: int | None = None,
    headers: Mapping[str, str] | None = None,
) -> list[tuple[bool, str]]:
    """Collapse N read-only ``eth_call``s into one billable call (per chunk) via Multicall3 ``aggregate3``.

    ``calls`` is ``[(target_address, calldata_hex), ...]``. Returns ``[(success, return_data_hex), ...]``
    aligned 1:1 with ``calls`` — ``success=False`` (``allowFailure=true``) for a reverting sub-call, so the
    caller maps it exactly as it would a per-call revert. ``return_data_hex`` is the raw return bytes of the
    sub-call, byte-identical to what a direct ``eth_call`` at the same block would yield.

    Raises ``RuntimeError`` on transport failure or a malformed / wrong-length response, so callers can fall
    back to per-call reads with **identical** decode semantics. JSON-RPC array batching does NOT reduce
    upstream call count (each sub-call is billed); aggregate3 does (one eth_call).

    Only valid for caller-independent ``view``/``pure`` reads: Multicall3 becomes ``msg.sender``, so never
    route a call whose result depends on the caller through this.
    """
    if not calls:
        return []
    from eth_abi.abi import decode as _abi_decode
    from eth_abi.abi import encode as _abi_encode

    # Derived (not hard-coded) so a typo can never mint wrong calldata: aggregate3((address,bool,bytes)[]).
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
        )
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise RuntimeError(f"multicall3 aggregate3: non-hex result {raw!r}")
        decoded = _abi_decode(["(bool,bytes)[]"], bytes.fromhex(raw[2:]))[0]
        if len(decoded) != len(chunk):
            raise RuntimeError(f"multicall3 aggregate3: got {len(decoded)} results, expected {len(chunk)}")
        results.extend((bool(success), "0x" + return_data.hex()) for success, return_data in decoded)
    return results


def parse_address_result(raw: Any) -> str | None:
    """Extract a valid address from a raw ``eth_getStorageAt`` / ``eth_call`` result.

    Returns None for empty, zero-address, too-short, or revert-like responses.
    A valid ABI-encoded address is at least 66 chars (``0x`` + 64 hex digits).
    Shorter responses are reverts, error selectors, or empty returns.
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
    """ABI-encode an address as one 32-byte word (64 hex chars, NO ``0x`` prefix),
    for concatenation into ``eth_call`` calldata. Shared by the external-check
    materializer and the differential probe so the encoding can't drift between
    them."""
    return address.lower().removeprefix("0x").rjust(64, "0")


def decode_bool_word(raw: Any) -> bool:
    """Decode an ABI ``bool`` return word: True iff the trailing 32-byte word is
    non-zero. Anything too short / non-hex / unparseable is False (a revert or
    empty return is not a truthy answer). Shared with the external-check
    materializer."""
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


def decode_address(raw_value: str) -> str | None:
    normalized = normalize_hex(raw_value)
    if len(normalized) != 66:
        return None
    return "0x" + normalized[-40:]
