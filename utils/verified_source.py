"""Verified source provider for contract source retrieval.

This module exists for source code only. Runtime chain data must go through
configured eRPC helpers, and unsupported indexed data must fail fast instead
of falling through to explorer APIs.
"""

import json as _json
import logging
import os
import threading
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

VERIFIED_SOURCE_API = "https://api.etherscan.io/v2/api"
_SOURCE_MODULE = "contract"
_SOURCE_ACTION = "getsourcecode"
_RATE_LIMIT_RETRIES = 5
_RATE_LIMIT_BACKOFF = 1.0  # seconds, doubles each retry

# Global source-provider rate limit.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
try:
    ETHERSCAN_RATE_LIMIT = int(os.getenv("ETHERSCAN_RATE_LIMIT", "5"))
except ValueError as exc:
    logger.error("ETHERSCAN_RATE_LIMIT must be a positive integer")
    raise RuntimeError("ETHERSCAN_RATE_LIMIT must be a positive integer") from exc
if ETHERSCAN_RATE_LIMIT <= 0:
    logger.error("ETHERSCAN_RATE_LIMIT must be positive, got %s", ETHERSCAN_RATE_LIMIT)
    raise RuntimeError(f"ETHERSCAN_RATE_LIMIT must be positive, got {ETHERSCAN_RATE_LIMIT}")

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
        logger.error("Verified source retrieval requires ETHERSCAN_API_KEY")
        raise RuntimeError("ETHERSCAN_API_KEY not set in .env")
    return key


def _normalize_source_address(address: str) -> str:
    if not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        logger.error("Verified source retrieval requires 20-byte 0x address, got %r", address)
        raise RuntimeError(f"verified source retrieval requires 20-byte 0x address, got {address!r}")
    try:
        bytes.fromhex(address[2:])
    except ValueError as exc:
        logger.error("Verified source retrieval received malformed address hex: %r", address)
        raise RuntimeError(f"verified source retrieval received malformed address hex: {address!r}") from exc
    return address.lower()


# Two-layer source cache: per-process in-memory dict + Postgres-backed cross-process; both default on.
_CACHE_ENABLED = os.getenv("ETHERSCAN_CACHE", "1").lower() in ("1", "true", "yes")
_PG_CACHE_ENABLED = os.getenv("ETHERSCAN_PG_CACHE", "1").lower() in ("1", "true", "yes")

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
    """Postgres read-through; returns None only on cache miss."""
    if not _PG_CACHE_ENABLED:
        return None
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception as exc:
        logger.error("Verified-source PG cache lookup could not import DB dependencies: %s", exc)
        raise RuntimeError("Verified-source PG cache lookup could not import DB dependencies") from exc
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
        logger.error(
            "Verified-source PG cache lookup failed module=%s action=%s chain_id=%s: %s",
            module,
            action,
            chain_id,
            exc,
        )
        raise RuntimeError(
            f"Verified-source PG cache lookup failed for module={module} action={action} chain_id={chain_id}"
        ) from exc
    return None


def _is_persistable(response: dict) -> bool:
    """Skip persisting empty-source ``getsourcecode`` responses (unverified contracts return status=1 with empty
    SourceCode)."""
    result = response.get("result")
    if not isinstance(result, list) or not result:
        return False
    first = result[0]
    if not isinstance(first, dict):
        return False
    source = first.get("SourceCode")
    return bool(source)


def _pg_cache_put(module: str, action: str, chain_id: int, params: dict, response: dict) -> None:
    """Upsert into etherscan_cache; empty-source responses are skipped."""
    if not _PG_CACHE_ENABLED:
        return
    if not _is_persistable(response):
        logger.debug(
            "Verified-source PG cache: skipping persist of empty %s/%s response (likely unverified contract)",
            module,
            action,
        )
        return
    try:
        from sqlalchemy import text

        from db.models import SessionLocal
    except Exception as exc:
        logger.error("Verified-source PG cache write could not import DB dependencies: %s", exc)
        raise RuntimeError("Verified-source PG cache write could not import DB dependencies") from exc
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
        logger.error(
            "Verified-source PG cache write failed module=%s action=%s chain_id=%s: %s",
            module,
            action,
            chain_id,
            exc,
        )
        raise RuntimeError(
            f"Verified-source PG cache write failed for module={module} action={action} chain_id={chain_id}"
        ) from exc


def _request_verified_source(address: str, *, chain_id: int) -> dict:
    """Fetch the source-provider ``contract/getsourcecode`` response."""
    from utils.rpc import require_supported_chain_id

    address = _normalize_source_address(address)
    chain_id = require_supported_chain_id(chain_id=chain_id, context="verified source retrieval")
    params = {"address": address}
    if _CACHE_ENABLED:
        key = _cache_key(_SOURCE_MODULE, _SOURCE_ACTION, chain_id, params)
        with _cache_lock:
            if key in _cache:
                logger.debug("Verified-source in-memory cache hit: %s", address)
                return _cache[key]

    pg_hit = _pg_cache_get(_SOURCE_MODULE, _SOURCE_ACTION, chain_id, params)
    if pg_hit is not None:
        logger.debug("Verified-source PG cache hit: %s", address)
        if _CACHE_ENABLED:
            with _cache_lock:
                _cache[_cache_key(_SOURCE_MODULE, _SOURCE_ACTION, chain_id, params)] = pg_hit
        return pg_hit

    api_key = _get_api_key()
    backoff = _RATE_LIMIT_BACKOFF

    for attempt in range(_RATE_LIMIT_RETRIES + 1):
        _wait_rate_limit()
        try:
            resp = requests.get(
                VERIFIED_SOURCE_API,
                params={
                    "chainid": str(chain_id),
                    "module": _SOURCE_MODULE,
                    "action": _SOURCE_ACTION,
                    "apikey": api_key,
                    **params,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.error(
                "Verified-source provider request failed address=%s chain_id=%s: %s",
                address,
                chain_id,
                exc,
            )
            raise RuntimeError(f"verified source provider request failed for {address} on chain_id={chain_id}") from exc
        except ValueError as exc:
            logger.error(
                "Verified-source provider returned non-JSON response address=%s chain_id=%s",
                address,
                chain_id,
            )
            raise RuntimeError(
                f"verified source provider returned non-JSON response for {address} on chain_id={chain_id}"
            ) from exc

        if data.get("status") == "1":
            if _CACHE_ENABLED:
                with _cache_lock:
                    _cache[_cache_key(_SOURCE_MODULE, _SOURCE_ACTION, chain_id, params)] = data
            _pg_cache_put(_SOURCE_MODULE, _SOURCE_ACTION, chain_id, params, data)
            return data

        result_str = str(data.get("result", ""))
        if "rate limit" in result_str.lower() and attempt < _RATE_LIMIT_RETRIES:
            logger.warning(
                "Verified-source provider rate limit hit, retrying in %.1fs (attempt %d/%d)",
                backoff,
                attempt + 1,
                _RATE_LIMIT_RETRIES,
            )
            time.sleep(backoff)
            backoff *= 2
            continue

        message = f"verified source provider error: {data.get('message', 'unknown')} - {result_str}"
        logger.error("%s", message)
        raise RuntimeError(message)

    logger.error("Verified source provider rate limit exhausted")
    raise RuntimeError("verified source provider rate limit: max retries exceeded")


def fetch_verified_source(address: str, *, chain_id: int) -> dict:
    """Fetch verified source code for a contract address. Returns the first result."""
    data = _request_verified_source(address, chain_id=chain_id)
    result = data["result"][0]

    if not result.get("SourceCode"):
        logger.error("No verified source code for address=%s chain_id=%s", address, chain_id)
        raise RuntimeError(f"No verified source code for {address} on chain_id={chain_id}")

    return result
