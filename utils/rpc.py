"""Shared low-level helpers for JSON-RPC and EVM encoding."""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Mapping

import requests
from eth_utils.crypto import keccak
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

JSON_RPC_TIMEOUT_SECONDS = 10

# Maximum calls per JSON-RPC batch (stay under provider limits)
MAX_BATCH_SIZE = 500

RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504}

ERPC_SECRET_HEADER = "X-ERPC-Secret-Token"
DEFAULT_SUPPORTED_CHAIN_IDS = frozenset(
    {
        1,
        10,
        56,
        137,
        324,
        999,
        8453,
        34443,
        42161,
        43114,
        59144,
        80094,
        81457,
        534352,
    }
)

# Process-wide cache for eth_getCode (bytecode + its keccak); skips caching on RPC error and applies a TTL for safety.
_GETCODE_CACHE: dict[tuple[str, int, str], tuple[str, str, float]] = {}
_GETCODE_CACHE_LOCK = threading.Lock()
_GETCODE_CACHE_MAX = 8192
_GETCODE_CACHE_TTL_S = float(os.getenv("PSAT_GETCODE_CACHE_TTL_S", "1800"))

# Cross-process bytecode cache: layered in-memory → Postgres → wire. Bytecode at
# a deployed address is effectively immutable, so the PG layer skips the TTL
# the in-memory layer carries. Disabled flag makes the CLI usable without a DB.
_PG_BYTECODE_CACHE_ENABLED = os.getenv("PSAT_BYTECODE_PG_CACHE", "1").lower() in ("1", "true", "yes")


def clear_getcode_cache() -> None:
    """Clear the process-wide eth_getCode cache. For tests + manual reset."""
    from utils.memory import reset_cache_pressure_state

    with _GETCODE_CACHE_LOCK:
        _GETCODE_CACHE.clear()
    reset_cache_pressure_state("getcode")


def _pg_bytecode_get(chain_id: int, address: str) -> tuple[str, str] | None:
    """Postgres read-through; returns ``(bytecode, code_keccak)`` or None on miss."""
    if not _PG_BYTECODE_CACHE_ENABLED:
        return None
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception as exc:
        logger.error("Bytecode PG cache lookup could not import DB dependencies: %s", exc)
        raise RuntimeError("Bytecode PG cache lookup could not import DB dependencies") from exc
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
        logger.error("Bytecode PG cache lookup failed chain_id=%s address=%s: %s", chain_id, address, exc)
        raise RuntimeError(f"Bytecode PG cache lookup failed for chain_id={chain_id} address={address}") from exc


def _pg_bytecode_put(chain_id: int, address: str, bytecode: str, code_keccak: str) -> None:
    """Upsert into bytecode_cache when the PG layer is enabled."""
    if not _PG_BYTECODE_CACHE_ENABLED:
        return
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception as exc:
        logger.error("Bytecode PG cache write could not import DB dependencies: %s", exc)
        raise RuntimeError("Bytecode PG cache write could not import DB dependencies") from exc
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
        logger.error("Bytecode PG cache write failed chain_id=%s address=%s: %s", chain_id, address, exc)
        raise RuntimeError(f"Bytecode PG cache write failed for chain_id={chain_id} address={address}") from exc


def _pg_bytecode_get_many(chain_id: int, addresses: list[str]) -> dict[str, tuple[str, str]]:
    """Batch read for bytecode_cache; returns ``{address_lower: (bytecode, keccak)}``."""
    if not _PG_BYTECODE_CACHE_ENABLED or not addresses:
        return {}
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception as exc:
        logger.error("Bytecode PG cache batch lookup could not import DB dependencies: %s", exc)
        raise RuntimeError("Bytecode PG cache batch lookup could not import DB dependencies") from exc
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
        logger.error(
            "Bytecode PG cache batch lookup failed chain_id=%s addresses=%d: %s",
            chain_id,
            len(addresses),
            exc,
        )
        raise RuntimeError(f"Bytecode PG cache batch lookup failed for chain_id={chain_id}") from exc


def _pg_bytecode_put_many(chain_id: int, rows: list[tuple[str, str, str]]) -> None:
    """Batch upsert; *rows* is ``[(address, bytecode, code_keccak), ...]``."""
    if not _PG_BYTECODE_CACHE_ENABLED or not rows:
        return
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception as exc:
        logger.error("Bytecode PG cache batch write could not import DB dependencies: %s", exc)
        raise RuntimeError("Bytecode PG cache batch write could not import DB dependencies") from exc
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
        logger.error("Bytecode PG cache batch write failed chain_id=%s rows=%d: %s", chain_id, len(rows), exc)
        raise RuntimeError(f"Bytecode PG cache batch write failed for chain_id={chain_id}") from exc


def _log_getcode_pressure() -> None:
    """Log when _GETCODE_CACHE crosses 50/75/95% of its bound (caller holds the lock)."""
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message("getcode", len(_GETCODE_CACHE), _GETCODE_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _normalized_addr(address: str) -> str:
    return address.lower() if address.startswith("0x") else "0x" + address.lower()


def _normalize_bytecode_result(raw: Any, *, chain_id: int, address: str, source: str) -> tuple[str, str]:
    """Validate one eth_getCode-shaped payload and return ``(code, keccak)``."""
    if not isinstance(raw, str) or not raw.startswith("0x"):
        logger.error(
            "%s returned invalid bytecode for chain_id=%s address=%s: %r",
            source,
            chain_id,
            address,
            raw,
        )
        raise RuntimeError(f"{source} returned invalid bytecode for chain_id={chain_id} address={address}")
    code = raw.lower()
    if code in {"0x", "0x0"}:
        code = "0x"
    try:
        code_bytes = bytes.fromhex(code[2:]) if len(code) > 2 else b""
    except ValueError as exc:
        logger.error("%s returned malformed bytecode hex for chain_id=%s address=%s", source, chain_id, address)
        raise RuntimeError(
            f"{source} returned malformed bytecode hex for chain_id={chain_id} address={address}"
        ) from exc
    return code, "0x" + keccak(code_bytes).hex()


def _validate_cached_bytecode(
    code: Any,
    keccak_hex: Any,
    *,
    chain_id: int,
    address: str,
    source: str,
) -> tuple[str, str]:
    normalized_code, expected_keccak = _normalize_bytecode_result(
        code,
        chain_id=chain_id,
        address=address,
        source=source,
    )
    if not isinstance(keccak_hex, str) or not keccak_hex.startswith("0x") or len(keccak_hex) != 66:
        logger.error(
            "%s returned invalid code_keccak for chain_id=%s address=%s: %r",
            source,
            chain_id,
            address,
            keccak_hex,
        )
        raise RuntimeError(f"{source} returned invalid code_keccak for chain_id={chain_id} address={address}")
    try:
        bytes.fromhex(keccak_hex[2:])
    except ValueError as exc:
        logger.error("%s returned malformed code_keccak for chain_id=%s address=%s", source, chain_id, address)
        raise RuntimeError(
            f"{source} returned malformed code_keccak for chain_id={chain_id} address={address}"
        ) from exc
    if keccak_hex.lower() != expected_keccak:
        logger.error(
            "%s returned mismatched code_keccak for chain_id=%s address=%s cached=%s expected=%s",
            source,
            chain_id,
            address,
            keccak_hex.lower(),
            expected_keccak,
        )
        raise RuntimeError(f"{source} returned mismatched code_keccak for chain_id={chain_id} address={address}")
    return normalized_code, expected_keccak


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


def _erpc_url_for_chain_id(
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


def supported_chain_ids() -> frozenset[int]:
    """Return the eRPC chain ids this deployment is allowed to route.

    The default is PSAT's built-in known-chain set. Operators can replace it
    with an explicit comma-separated ``PSAT_SUPPORTED_CHAIN_IDS`` allowlist
    when adding a new eRPC-backed chain.
    """
    raw = os.getenv("PSAT_SUPPORTED_CHAIN_IDS")
    if raw is None or not raw.strip():
        return DEFAULT_SUPPORTED_CHAIN_IDS
    out: set[int] = set()
    for item in raw.split(","):
        text = item.strip()
        if not text:
            continue
        try:
            chain_id = int(text)
        except ValueError as exc:
            raise RuntimeError(f"Invalid PSAT_SUPPORTED_CHAIN_IDS entry: {text!r}") from exc
        if chain_id <= 0:
            raise RuntimeError(f"Invalid non-positive PSAT_SUPPORTED_CHAIN_IDS entry: {text!r}")
        out.add(chain_id)
    if not out:
        raise RuntimeError("PSAT_SUPPORTED_CHAIN_IDS must include at least one chain id when set")
    return frozenset(out)


def require_chain_id(
    *,
    chain_id: int | str | None = None,
    context: str = "operation",
) -> int:
    if chain_id is not None:
        try:
            parsed = int(chain_id)
        except (TypeError, ValueError) as exc:
            logger.error("%s requires a valid chain_id, got %r", context, chain_id)
            raise RuntimeError(f"{context} requires a valid chain_id, got {chain_id!r}") from exc
        if parsed > 0:
            return parsed
        logger.error("%s requires a positive chain_id, got %r", context, chain_id)
        raise RuntimeError(f"{context} requires a positive chain_id, got {chain_id!r}")

    logger.error("%s requires explicit chain_id", context)
    raise RuntimeError(f"{context} requires explicit chain_id")


def require_supported_chain_id(
    *,
    chain_id: int | str | None = None,
    context: str = "operation",
) -> int:
    parsed = require_chain_id(chain_id=chain_id, context=context)
    allowed = supported_chain_ids()
    if parsed in allowed:
        return parsed
    message = f"{context} uses unsupported chain_id={parsed}; supported_chain_ids={sorted(allowed)}"
    logger.error("%s", message)
    raise RuntimeError(message)


def default_rpc_url(
    *,
    chain_id: int | str | None = None,
) -> str:
    """Resolve the eRPC URL PSAT should use for a job.

    Chain id must be explicit. Legacy explicit URLs, fallback URLs, and public
    mainnet fallback are intentionally unsupported.
    """
    try:
        effective_chain_id = require_supported_chain_id(chain_id=chain_id, context="RPC URL resolution")
    except RuntimeError as exc:
        logger.error("%s", exc)
        raise

    erpc_url = _erpc_url_for_chain_id(effective_chain_id)
    if erpc_url:
        return erpc_url
    logger.error("RPC URL resolution requires ERPC_BASE_URL for chain_id=%s", effective_chain_id)
    raise RuntimeError(f"RPC URL resolution requires ERPC_BASE_URL for chain_id={effective_chain_id}")


def _erpc_chain_id_from_url(rpc_url: str) -> int | None:
    if not isinstance(rpc_url, str):
        return None
    base = os.getenv("ERPC_BASE_URL")
    if not base:
        return None
    normalized_url = rpc_url.rstrip("/")
    normalized_base = base.rstrip("/")
    prefix = f"{normalized_base}/main/evm/"
    if not normalized_url.startswith(prefix):
        return None
    suffix = normalized_url[len(prefix) :]
    if not suffix or "/" in suffix:
        return None
    try:
        chain_id = int(suffix)
    except ValueError:
        return None
    if str(chain_id) != suffix:
        return None
    return chain_id


def _is_configured_erpc_url(rpc_url: str) -> bool:
    chain_id = _erpc_chain_id_from_url(rpc_url)
    if chain_id is None:
        return False
    return chain_id in supported_chain_ids()


def require_configured_erpc_url(
    rpc_url: str,
    *,
    context: str = "RPC request",
    chain_id: int | str | None = None,
) -> str:
    """Validate that an on-chain JSON-RPC call is routed through a chain-scoped eRPC URL."""
    url_chain_id_raw = _erpc_chain_id_from_url(rpc_url)
    if url_chain_id_raw is None:
        from utils.secrets import sanitize_url

        logger.error("%s requires chain-scoped configured eRPC URL, got %s", context, sanitize_url(rpc_url))
        raise RuntimeError(f"{context} requires chain-scoped configured eRPC URL")
    url_chain_id = require_supported_chain_id(chain_id=url_chain_id_raw, context=f"{context} eRPC URL")
    if chain_id is not None:
        expected_chain_id = require_supported_chain_id(chain_id=chain_id, context=context)
        if url_chain_id != expected_chain_id:
            from utils.secrets import sanitize_url

            logger.error(
                "%s eRPC URL chain mismatch url_chain_id=%s expected_chain_id=%s url=%s",
                context,
                url_chain_id,
                expected_chain_id,
                sanitize_url(rpc_url),
            )
            raise RuntimeError(
                f"{context} eRPC URL chain mismatch: url_chain_id={url_chain_id} "
                f"expected_chain_id={expected_chain_id}"
            )
    return rpc_url.rstrip("/")


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
    effective_chain_id = require_supported_chain_id(chain_id=chain_id, context="eRPC healthcheck")
    rpc_url = _erpc_url_for_chain_id(effective_chain_id)
    if rpc_url is None:
        logger.error("eRPC healthcheck URL requires ERPC_BASE_URL for chain_id=%s", effective_chain_id)
        raise RuntimeError(f"eRPC healthcheck URL requires ERPC_BASE_URL for chain_id={effective_chain_id}")
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
    *,
    chain_id: int | str | None = None,
) -> Any:
    rpc_url = require_configured_erpc_url(rpc_url, context=f"RPC request {method}", chain_id=chain_id)
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
            try:
                payload = response.json()
            except ValueError as exc:
                from utils.secrets import sanitize_url

                logger.error("RPC request %s returned invalid JSON from %s", method, sanitize_url(rpc_url))
                raise RuntimeError(f"RPC request {method} returned invalid JSON for {sanitize_url(rpc_url)}") from exc
            if not isinstance(payload, dict):
                from utils.secrets import sanitize_url

                logger.error(
                    "RPC request %s returned invalid payload from %s: %r",
                    method,
                    sanitize_url(rpc_url),
                    payload,
                )
                raise RuntimeError(f"RPC request {method} returned invalid payload for {sanitize_url(rpc_url)}")
            if payload.get("error"):
                from utils.secrets import sanitize_url

                logger.error(
                    "RPC request %s returned JSON-RPC error from %s: %r",
                    method,
                    sanitize_url(rpc_url),
                    payload["error"],
                )
                raise RuntimeError(str(payload["error"]))
            if "result" not in payload or payload["result"] is None:
                from utils.secrets import sanitize_url

                logger.error(
                    "RPC request %s omitted result from %s: %r",
                    method,
                    sanitize_url(rpc_url),
                    payload,
                )
                raise RuntimeError(f"RPC request {method} omitted result for {sanitize_url(rpc_url)}")
            return payload["result"]
        except (requests.ConnectionError, requests.Timeout, OSError) as exc:
            if attempt < retries:
                time.sleep(0.3 * (2**attempt))
                continue
            from utils.secrets import sanitize_string, sanitize_url

            sanitized_url = sanitize_url(rpc_url)
            detail = sanitize_string(str(exc))
            logger.error("RPC request %s failed for %s: %s", method, sanitized_url, detail)
            raise RuntimeError(f"RPC request failed for {sanitized_url}: {detail}") from exc
    from utils.secrets import sanitize_url

    sanitized_url = sanitize_url(rpc_url)
    logger.error("RPC request %s failed for %s: all %d attempts exhausted", method, sanitized_url, retries + 1)
    raise RuntimeError(f"RPC request failed for {sanitized_url}: all {retries + 1} attempts exhausted")


def get_code(rpc_url: str, address: str, *, chain_id: int) -> str:
    """Fetch deployed EVM bytecode at an address via eth_getCode.

    Process-wide cached (TTL ``PSAT_GETCODE_CACHE_TTL_S``, default 30 min)
    so repeated probes of the same address across stages and jobs hit
    the cache instead of the wire. RPC errors are NOT cached — they
    propagate as ``RuntimeError`` so callers can decide retry behavior.
    ``chain_id`` is required so both the in-memory and Postgres cache layers
    are keyed by the same explicit deployment identity as the rest of the
    pipeline.
    """
    code, _keccak = get_code_with_keccak(rpc_url, address, chain_id=chain_id)
    return code


def get_code_with_keccak(rpc_url: str, address: str, *, chain_id: int) -> tuple[str, str]:
    """Return ``(bytecode_hex, keccak_hex)`` cached together so downstream content-addressed lookups get the keccak for
    free.

    Cache layering: in-memory dict (TTL'd) → Postgres ``bytecode_cache`` (no
    TTL — bytecode is immutable per ``(chain_id, address)``) → wire fetch.
    ``chain_id`` is required; callers must not infer cache tenancy from an RPC
    URL.
    """
    addr = _normalized_addr(address)
    chain_id_eff = require_supported_chain_id(chain_id=chain_id, context="eth_getCode")
    rpc_url = require_configured_erpc_url(rpc_url, context="eth_getCode", chain_id=chain_id_eff)
    key = (rpc_url, chain_id_eff, addr)
    now = time.monotonic()
    with _GETCODE_CACHE_LOCK:
        cached = _GETCODE_CACHE.get(key)
        if cached is not None:
            code, keccak_hex, inserted_at = cached
            if now - inserted_at < _GETCODE_CACHE_TTL_S:
                code, keccak_hex = _validate_cached_bytecode(
                    code,
                    keccak_hex,
                    chain_id=chain_id_eff,
                    address=addr,
                    source="eth_getCode memory cache",
                )
                return code, keccak_hex
            # TTL expired; fall through to re-fetch.
            del _GETCODE_CACHE[key]

    # PG cache: cross-process layer keyed by explicit chain id.
    if _PG_BYTECODE_CACHE_ENABLED:
        pg_hit = _pg_bytecode_get(chain_id_eff, addr)
        if pg_hit is not None:
            code, keccak_hex = pg_hit
            code, keccak_hex = _validate_cached_bytecode(
                code,
                keccak_hex,
                chain_id=chain_id_eff,
                address=addr,
                source="eth_getCode PG cache",
            )
            with _GETCODE_CACHE_LOCK:
                _evict_getcode_if_needed()
                _GETCODE_CACHE[key] = (code, keccak_hex, now)
                _log_getcode_pressure()
            return code, keccak_hex

    # RPC outside the lock so concurrent misses for different addresses don't serialize.
    raw = rpc_request(rpc_url, "eth_getCode", [address, "latest"], chain_id=chain_id_eff)
    code, keccak_hex = _normalize_bytecode_result(
        raw,
        chain_id=chain_id_eff,
        address=addr,
        source="eth_getCode",
    )

    with _GETCODE_CACHE_LOCK:
        _evict_getcode_if_needed()
        _GETCODE_CACHE[key] = (code, keccak_hex, now)
        _log_getcode_pressure()
    if _PG_BYTECODE_CACHE_ENABLED:
        _pg_bytecode_put(chain_id_eff, addr, code, keccak_hex)
    return code, keccak_hex


def _evict_getcode_if_needed() -> None:
    """Drop the oldest 25% of _GETCODE_CACHE entries when the bound is reached (caller holds _GETCODE_CACHE_LOCK)."""
    if len(_GETCODE_CACHE) < _GETCODE_CACHE_MAX:
        return
    cutoff = sorted(_GETCODE_CACHE.values(), key=lambda v: v[2])[len(_GETCODE_CACHE) // 4][2]
    for k in [k for k, v in _GETCODE_CACHE.items() if v[2] <= cutoff]:
        _GETCODE_CACHE.pop(k, None)


def get_code_batch(rpc_url: str, addresses: list[str], *, chain_id: int) -> dict[str, str]:
    """Cache-aware batched ``eth_getCode`` for explicit ``(chain_id, address)`` identities.

    Cache layering matches :func:`get_code_with_keccak`: in-memory → Postgres
    ``bytecode_cache`` (one bulk SELECT for the misses) → wire batch. Per-call
    RPC errors raise; callers must not silently treat omitted bytecode as an
    empty account on the wrong or unsupported chain.
    """
    chain_id_eff = require_supported_chain_id(chain_id=chain_id, context="eth_getCode batch")
    rpc_url = require_configured_erpc_url(rpc_url, context="eth_getCode batch", chain_id=chain_id_eff)
    if not addresses:
        return {}
    normalized = [_normalized_addr(a) for a in addresses]
    now = time.monotonic()
    out: dict[str, str] = {}

    to_fetch: list[str] = []
    with _GETCODE_CACHE_LOCK:
        for addr in normalized:
            cached = _GETCODE_CACHE.get((rpc_url, chain_id_eff, addr))
            if cached is not None:
                code, keccak_hex, inserted_at = cached
                if now - inserted_at < _GETCODE_CACHE_TTL_S:
                    code, _keccak = _validate_cached_bytecode(
                        code,
                        keccak_hex,
                        chain_id=chain_id_eff,
                        address=addr,
                        source="eth_getCode batch memory cache",
                    )
                    out[addr] = code
                    continue
            to_fetch.append(addr)

    if not to_fetch:
        return out

    # PG layer: bulk SELECT for the in-memory misses; promote hits into the
    # in-memory cache so a later same-process call short-circuits.
    if _PG_BYTECODE_CACHE_ENABLED and to_fetch:
        pg_hits = _pg_bytecode_get_many(chain_id_eff, to_fetch)
        if pg_hits:
            with _GETCODE_CACHE_LOCK:
                for addr in list(to_fetch):
                    payload = pg_hits.get(addr)
                    if payload is None:
                        continue
                    code, keccak_hex = payload
                    code, keccak_hex = _validate_cached_bytecode(
                        code,
                        keccak_hex,
                        chain_id=chain_id_eff,
                        address=addr,
                        source="eth_getCode batch PG cache",
                    )
                    _evict_getcode_if_needed()
                    _GETCODE_CACHE[(rpc_url, chain_id_eff, addr)] = (code, keccak_hex, now)
                    _log_getcode_pressure()
                    out[addr] = code
            to_fetch = [addr for addr in to_fetch if addr not in pg_hits]

    if not to_fetch:
        return out

    calls: list[tuple[str, list[Any]]] = [("eth_getCode", [addr, "latest"]) for addr in to_fetch]
    raw_results = rpc_batch_request_with_status(rpc_url, calls, chain_id=chain_id_eff)
    if len(raw_results) != len(to_fetch):
        logger.error(
            "eth_getCode batch returned %d result(s) for %d address(es) on chain_id=%s",
            len(raw_results),
            len(to_fetch),
            chain_id_eff,
        )
        raise RuntimeError(
            f"eth_getCode batch returned {len(raw_results)} result(s) for {len(to_fetch)} address(es)"
        )
    pg_writes: list[tuple[str, str, str]] = []
    with _GETCODE_CACHE_LOCK:
        for addr, (raw, had_error) in zip(to_fetch, raw_results):
            if had_error:
                logger.error("eth_getCode batch item failed for chain_id=%s address=%s", chain_id_eff, addr)
                raise RuntimeError(f"eth_getCode batch item failed for chain_id={chain_id_eff} address={addr}")
            code, keccak_hex = _normalize_bytecode_result(
                raw,
                chain_id=chain_id_eff,
                address=addr,
                source="eth_getCode batch",
            )
            # Honour the cache bound — codex iter-5 P2: batch path was
            # bypassing eviction, letting long-lived workers exceed
            # _GETCODE_CACHE_MAX with full bytecode payloads.
            _evict_getcode_if_needed()
            _GETCODE_CACHE[(rpc_url, chain_id_eff, addr)] = (code, keccak_hex, now)
            _log_getcode_pressure()
            out[addr] = code
            pg_writes.append((addr, code, keccak_hex))
    if _PG_BYTECODE_CACHE_ENABLED and pg_writes:
        _pg_bytecode_put_many(chain_id_eff, pg_writes)
    return out


def rpc_batch_request(
    rpc_url: str,
    calls: list[tuple[str, list[Any]]],
    headers: Mapping[str, str] | None = None,
    *,
    chain_id: int | str | None = None,
) -> list[Any]:
    """Send a JSON-RPC batch and return results in call order.

    Transport errors, malformed payloads, item-level JSON-RPC errors, and
    omitted results are hard failures. Callers that need per-call status should
    use :func:`rpc_batch_request_with_status`.
    """
    if not calls:
        return []
    rpc_url = require_configured_erpc_url(rpc_url, context="RPC batch request", chain_id=chain_id)

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

            sanitized_url = sanitize_url(rpc_url)
            status = getattr(getattr(exc, "response", None), "status_code", None)
            detail = f"HTTP {status}" if status is not None else sanitize_string(str(exc))
            logger.error("RPC batch failed for %s: %s", sanitized_url, detail)
            raise RuntimeError(f"RPC batch failed for {sanitized_url}: {detail}") from None

        try:
            payload = response.json()
        except ValueError as exc:
            from utils.secrets import sanitize_url

            logger.error("RPC batch returned invalid JSON for %s", sanitize_url(rpc_url))
            raise RuntimeError(f"RPC batch returned invalid JSON for {sanitize_url(rpc_url)}") from exc
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            from utils.secrets import sanitize_url

            logger.error("RPC batch returned invalid payload for %s: %r", sanitize_url(rpc_url), payload)
            raise RuntimeError(f"RPC batch returned invalid payload for {sanitize_url(rpc_url)}")

        for item in payload:
            if not isinstance(item, dict):
                from utils.secrets import sanitize_url

                logger.error("RPC batch returned invalid item for %s: %r", sanitize_url(rpc_url), item)
                raise RuntimeError(f"RPC batch returned invalid item for {sanitize_url(rpc_url)}")
            idx = item.get("id")
            if not isinstance(idx, int) or idx < 0 or idx >= len(calls):
                from utils.secrets import sanitize_url

                logger.error("RPC batch returned invalid id for %s: %r", sanitize_url(rpc_url), idx)
                raise RuntimeError(f"RPC batch returned invalid id for {sanitize_url(rpc_url)}")
            if item.get("error"):
                logger.error("RPC batch item failed for call index %s method=%s: %s", idx, calls[idx][0], item["error"])
                raise RuntimeError(f"RPC batch item failed for method={calls[idx][0]}")
            if "result" not in item or item["result"] is None:
                from utils.secrets import sanitize_url

                logger.error(
                    "RPC batch item omitted result for %s call index %s method=%s: %r",
                    sanitize_url(rpc_url),
                    idx,
                    calls[idx][0],
                    item,
                )
                raise RuntimeError(f"RPC batch item omitted result for method={calls[idx][0]}")
            results[idx] = item.get("result")

    if any(result is None for result in results):
        from utils.secrets import sanitize_url

        logger.error("RPC batch omitted one or more results for %s", sanitize_url(rpc_url))
        raise RuntimeError(f"RPC batch omitted one or more results for {sanitize_url(rpc_url)}")

    return results


def rpc_batch_request_with_item_errors(
    rpc_url: str,
    calls: list[tuple[str, list[Any]]],
    headers: Mapping[str, str] | None = None,
    *,
    chain_id: int | str | None = None,
) -> list[tuple[Any, Any | None]]:
    """Send a JSON-RPC batch and preserve item-level error details.

    Transport errors, malformed payloads, invalid item ids, and omitted
    responses are hard failures. Item-level JSON-RPC errors are returned
    beside their corresponding call so callers can distinguish an expected
    contract-level probe miss from a provider/runtime failure.
    """
    if not calls:
        return []
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context="RPC batch request with item errors",
        chain_id=chain_id,
    )

    results: list[tuple[Any, Any | None]] = [(None, None)] * len(calls)
    seen: list[bool] = [False] * len(calls)

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

            sanitized_url = sanitize_url(rpc_url)
            status = getattr(getattr(exc, "response", None), "status_code", None)
            detail = f"HTTP {status}" if status is not None else sanitize_string(str(exc))
            logger.error("RPC batch with item errors failed for %s: %s", sanitized_url, detail)
            raise RuntimeError(f"RPC batch failed for {sanitized_url}: {detail}") from None

        try:
            payload = response.json()
        except ValueError as exc:
            from utils.secrets import sanitize_url

            logger.error("RPC batch returned invalid JSON for %s", sanitize_url(rpc_url))
            raise RuntimeError(f"RPC batch returned invalid JSON for {sanitize_url(rpc_url)}") from exc

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            from utils.secrets import sanitize_url

            logger.error("RPC batch returned invalid payload for %s: %r", sanitize_url(rpc_url), payload)
            raise RuntimeError(f"RPC batch returned invalid payload for {sanitize_url(rpc_url)}")

        for item in payload:
            if not isinstance(item, dict):
                from utils.secrets import sanitize_url

                logger.error("RPC batch returned invalid item for %s: %r", sanitize_url(rpc_url), item)
                raise RuntimeError(f"RPC batch returned invalid item for {sanitize_url(rpc_url)}")
            idx = item.get("id")
            if not isinstance(idx, int) or idx < 0 or idx >= len(calls):
                from utils.secrets import sanitize_url

                logger.error("RPC batch returned invalid id for %s: %r", sanitize_url(rpc_url), idx)
                raise RuntimeError(f"RPC batch returned invalid id for {sanitize_url(rpc_url)}")
            seen[idx] = True
            if item.get("error"):
                results[idx] = (None, item["error"])
            else:
                if "result" not in item or item["result"] is None:
                    from utils.secrets import sanitize_url

                    logger.error(
                        "RPC batch-with-item-errors item omitted result for %s call index %s method=%s: %r",
                        sanitize_url(rpc_url),
                        idx,
                        calls[idx][0],
                        item,
                    )
                    raise RuntimeError(f"RPC batch item omitted result for method={calls[idx][0]}")
                results[idx] = (item["result"], None)

    if not all(seen):
        from utils.secrets import sanitize_url

        logger.error("RPC batch omitted one or more results for %s", sanitize_url(rpc_url))
        raise RuntimeError(f"RPC batch omitted one or more results for {sanitize_url(rpc_url)}")

    return results


def rpc_batch_request_with_status(
    rpc_url: str,
    calls: list[tuple[str, list[Any]]],
    headers: Mapping[str, str] | None = None,
    *,
    chain_id: int | str | None = None,
) -> list[tuple[Any, bool]]:
    """Like ``rpc_batch_request`` but returns ``(result, had_error)`` so callers can distinguish RPC failure from a
    legitimate ``None`` result."""
    if not calls:
        return []
    rpc_url = require_configured_erpc_url(
        rpc_url,
        context="RPC batch request with status",
        chain_id=chain_id,
    )

    # Item-level JSON-RPC errors are returned as ``had_error=True`` so optional
    # contract probes can distinguish getter misses from valid ``None`` results.
    # Malformed or omitted transport responses are not item-level contract
    # errors; they raise to prevent callers from treating provider corruption as
    # an optional miss.
    results: list[tuple[Any, bool]] = [(None, True)] * len(calls)
    seen: list[bool] = [False] * len(calls)

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
        except Exception as exc:
            from utils.secrets import sanitize_string, sanitize_url

            logger.error(
                "RPC batch-with-status failed for %s: %s",
                sanitize_url(rpc_url),
                sanitize_string(str(exc)),
            )
            raise RuntimeError(f"RPC batch-with-status failed for {sanitize_url(rpc_url)}") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            from utils.secrets import sanitize_url

            logger.error("RPC batch-with-status returned invalid JSON for %s", sanitize_url(rpc_url))
            raise RuntimeError(f"RPC batch-with-status returned invalid JSON for {sanitize_url(rpc_url)}") from exc

        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            from utils.secrets import sanitize_url

            logger.error("RPC batch-with-status returned invalid payload for %s: %r", sanitize_url(rpc_url), payload)
            raise RuntimeError(f"RPC batch-with-status returned invalid payload for {sanitize_url(rpc_url)}")

        for item in payload:
            if not isinstance(item, dict):
                from utils.secrets import sanitize_url

                logger.error("RPC batch-with-status returned invalid item for %s: %r", sanitize_url(rpc_url), item)
                raise RuntimeError(f"RPC batch-with-status returned invalid item for {sanitize_url(rpc_url)}")
            idx = item.get("id")
            if not isinstance(idx, int) or idx < 0 or idx >= len(calls):
                from utils.secrets import sanitize_url

                logger.error("RPC batch-with-status returned invalid id for %s: %r", sanitize_url(rpc_url), idx)
                raise RuntimeError(f"RPC batch-with-status returned invalid id for {sanitize_url(rpc_url)}")
            seen[idx] = True
            if item.get("error"):
                results[idx] = (None, True)
            else:
                if "result" not in item or item["result"] is None:
                    from utils.secrets import sanitize_url

                    logger.error(
                        "RPC batch-with-status item omitted result for %s call index %s method=%s: %r",
                        sanitize_url(rpc_url),
                        idx,
                        calls[idx][0],
                        item,
                    )
                    raise RuntimeError(f"RPC batch item omitted result for method={calls[idx][0]}")
                results[idx] = (item["result"], False)

    if not all(seen):
        from utils.secrets import sanitize_url

        logger.error("RPC batch-with-status omitted one or more results for %s", sanitize_url(rpc_url))
        raise RuntimeError(f"RPC batch-with-status omitted one or more results for {sanitize_url(rpc_url)}")

    return results


def parse_address_result(raw: Any) -> str | None:
    """Extract a valid address from a raw ``eth_getStorageAt`` / ``eth_call`` result.

    Returns None for empty, zero-address, too-short, or revert-like responses.
    A valid ABI-encoded address is at least 66 chars (``0x`` + 64 hex digits).
    Shorter responses are reverts, error selectors, or empty returns.
    """
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ValueError(f"expected hex RPC result, got {raw!r}")
    body = raw[2:]
    if len(body) % 2 != 0:
        raise ValueError(f"expected even-length hex RPC result, got {raw!r}")
    try:
        bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"malformed hex RPC result: {raw!r}") from exc
    if raw in {"0x", "0x0"}:
        return None
    if len(raw) != 66:
        raise ValueError(f"expected 32-byte ABI/address result, got {raw!r}")
    if raw == "0x" + "0" * 64:
        return None
    addr = "0x" + raw[-40:]
    if addr == "0x" + "0" * 40:
        return None
    return normalize_hex(addr)


def selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def normalize_hex(value: str | None) -> str:
    if not isinstance(value, str) or not value.startswith("0x"):
        return "0x"
    return value.lower()


def decode_address(raw_value: str) -> str | None:
    normalized = normalize_hex(raw_value)
    if len(normalized) != 66:
        return None
    return "0x" + normalized[-40:]
