#!/usr/bin/env python3
"""Tavily search client with retries and normalized errors."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

TAVILY_SEARCH_URL = "https://api.tavily.com/search"
REQUEST_TIMEOUT_SECONDS = 20
MAX_RETRIES = 2
BACKOFF_BASE_SECONDS = 0.75

# When ``PSAT_TAVILY_CACHE`` is set, search() looks up the request in the
# artifact-storage bucket before hitting the network. Misses fall through to a
# live call whose response is persisted; subsequent identical requests in any
# environment sharing the bucket skip Tavily entirely. Bump _CACHE_SCHEMA when
# changing the cache envelope or the canonical request shape to bulk-invalidate.
_CACHE_KEY_PREFIX = "tavily-cache"
_CACHE_SCHEMA = 1
_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days


def normalize_error(
    message: str,
    *,
    status_code: int | None = None,
    retryable: bool | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"provider": "tavily", "error": message}
    if status_code is not None:
        error["status_code"] = status_code
    if retryable is not None:
        error["retryable"] = retryable
    if detail:
        error["detail"] = detail
    return error


class TavilyError(RuntimeError):
    """Raised when Tavily cannot return a usable response."""

    def __init__(self, error: dict[str, Any]):
        super().__init__(error.get("error", "Tavily request failed"))
        self.error = error


def error_from_exception(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, TavilyError):
        return dict(exc.error)
    return normalize_error(str(exc), retryable=False)


def _build_payload(
    query: str,
    max_results: int,
    topic: str,
    search_depth: str,
    include_raw_content: bool,
) -> dict[str, Any]:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    api_key = os.environ.get("TAVILY_API_KEY", "").strip()
    if not api_key:
        raise TavilyError(
            normalize_error(
                "Missing TAVILY_API_KEY environment variable",
                retryable=False,
            )
        )

    return {
        "api_key": api_key,
        "query": query,
        "max_results": max_results,
        "topic": topic,
        "search_depth": search_depth,
        "include_raw_content": include_raw_content,
        "include_usage": True,
    }


def _cache_key(payload: dict[str, Any]) -> str:
    """Hash the request shape (api_key excluded) into a stable storage key."""
    canonical = {k: v for k, v in payload.items() if k != "api_key"}
    canonical["__schema__"] = _CACHE_SCHEMA
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cache_read(key: str) -> list[dict[str, Any]] | None:
    """Return cached results if present, fresh, and well-formed; else None.

    Storage failures (missing bucket creds, transport errors, malformed
    envelope, expired TTL) all degrade to None — the caller falls through
    to a live API call.
    """
    try:
        from db.storage import StorageKeyMissing, get_storage_client
    except Exception as exc:
        logger.debug("tavily cache disabled: storage import failed: %s", exc)
        return None
    client = get_storage_client()
    if client is None:
        return None
    storage_key = f"{_CACHE_KEY_PREFIX}/{key}.json"
    try:
        body = client.get(storage_key)
    except StorageKeyMissing:
        return None
    except Exception as exc:
        logger.warning("tavily cache read failed for %s: %s", key[:12], exc)
        return None
    try:
        envelope = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if envelope.get("schema_version") != _CACHE_SCHEMA:
        return None
    cached_at = envelope.get("cached_at")
    if not isinstance(cached_at, (int, float)):
        return None
    if time.time() - cached_at > _CACHE_TTL_SECONDS:
        return None
    results = envelope.get("results")
    if not isinstance(results, list) or not results:
        return None
    return [item for item in results if isinstance(item, dict)]


def _cache_write(key: str, results: list[dict[str, Any]]) -> None:
    """Persist results to the cache. Best-effort: errors are logged, not raised."""
    # Empty responses would poison the cache; let next attempt re-fetch.
    if not results:
        return
    try:
        from db.storage import JSON_CONTENT_TYPE, get_storage_client
    except Exception as exc:
        logger.debug("tavily cache write skipped: storage import failed: %s", exc)
        return
    client = get_storage_client()
    if client is None:
        return
    envelope = {
        "schema_version": _CACHE_SCHEMA,
        "cached_at": time.time(),
        "results": results,
    }
    body = json.dumps(envelope).encode("utf-8")
    storage_key = f"{_CACHE_KEY_PREFIX}/{key}.json"
    try:
        client.put(storage_key, body, content_type=JSON_CONTENT_TYPE)
    except Exception as exc:
        logger.warning("tavily cache write failed for %s: %s", key[:12], exc)


def search(
    query: str,
    max_results: int,
    topic: str = "general",
    search_depth: str = "advanced",
    include_raw_content: bool = True,
) -> list[dict[str, Any]]:
    """Search Tavily and return the normalized list of result objects.

    With ``PSAT_TAVILY_CACHE`` set, identical requests are served from
    artifact storage (keyed by SHA-256 of the request shape) — first miss
    pays the live call, every subsequent hit is free. Unset in prod.
    """
    clean_query = query.strip()
    if not clean_query:
        raise ValueError("query must not be empty")
    if max_results < 1:
        raise ValueError("max_results must be >= 1")

    payload = _build_payload(
        clean_query,
        max_results=max_results,
        topic=topic,
        search_depth=search_depth,
        include_raw_content=include_raw_content,
    )

    cache_key: str | None = None
    if os.environ.get("PSAT_TAVILY_CACHE"):
        cache_key = _cache_key(payload)
        cached = _cache_read(cache_key)
        if cached is not None:
            logger.info(
                "tavily cache hit: key=%s query=%r",
                cache_key[:12],
                clean_query[:80],
            )
            return cached

    last_error: TavilyError | None = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = requests.post(
                TAVILY_SEARCH_URL,
                json=payload,
                headers={"Accept": "application/json", "User-Agent": "PSAT/0.1"},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if response.status_code >= 400:
                retryable = response.status_code >= 500 or response.status_code == 429
                raise TavilyError(
                    normalize_error(
                        f"Tavily API returned HTTP {response.status_code}",
                        status_code=response.status_code,
                        retryable=retryable,
                        detail=response.text[:400].strip() or None,
                    )
                )

            data = response.json()
            usage = data.get("usage")
            if isinstance(usage, dict):
                logger.info(
                    "tavily search billed: credits=%s attempt=%d/%d query=%r",
                    usage.get("credits", "?"),
                    attempt + 1,
                    MAX_RETRIES + 1,
                    clean_query[:80],
                )
            results = data.get("results", [])
            if not isinstance(results, list):
                raise TavilyError(
                    normalize_error(
                        "Tavily response did not include a list for 'results'",
                        retryable=False,
                    )
                )
            filtered = [item for item in results if isinstance(item, dict)]
            if cache_key is not None:
                _cache_write(cache_key, filtered)
            return filtered

        except requests.Timeout as exc:
            last_error = TavilyError(
                normalize_error(
                    "Tavily request timed out",
                    retryable=True,
                    detail=str(exc),
                )
            )
        except requests.RequestException as exc:
            last_error = TavilyError(
                normalize_error(
                    "Tavily request failed",
                    retryable=True,
                    detail=str(exc),
                )
            )
        except ValueError as exc:
            last_error = TavilyError(
                normalize_error(
                    "Invalid JSON returned from Tavily",
                    retryable=False,
                    detail=str(exc),
                )
            )
        except TavilyError as exc:
            last_error = exc

        logger.warning(
            "tavily search attempt %d/%d failed (retryable=%s): %s",
            attempt + 1,
            MAX_RETRIES + 1,
            bool(last_error.error.get("retryable")),
            last_error.error.get("error"),
        )
        if attempt >= MAX_RETRIES or not bool(last_error.error.get("retryable")):
            raise last_error
        time.sleep(BACKOFF_BASE_SECONDS * (2**attempt))

    if last_error:
        raise last_error
    raise TavilyError(normalize_error("Unknown Tavily error", retryable=False))
