#!/usr/bin/env python3
"""Exa search client, shape-compatible with ``services.clients.tavily`` (``{title, url, content, score}``).

Neural search clusters slug variants ("ether fi" / "ether.fi") that Tavily's phrase matching splits.
"""

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

EXA_SEARCH_URL = "https://api.exa.ai/search"
EXA_RESEARCH_CREATE_URL = "https://api.exa.ai/research/v0/tasks"
EXA_RESEARCH_GET_URL = "https://api.exa.ai/research/v0/tasks/{task_id}"
REQUEST_TIMEOUT_SECONDS = 30
DEEP_RESEARCH_POLL_INTERVAL_SECONDS = 5
DEEP_RESEARCH_MAX_POLL_SECONDS = 600

# Cache in the artifact bucket, shared across environments. Bump _CACHE_SCHEMA to bulk-invalidate.
_CACHE_KEY_PREFIX = "exa-cache"
_CACHE_SCHEMA = 1
_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60  # 30 days


def _cache_key(payload: dict[str, Any]) -> str:
    canonical = {k: v for k, v in payload.items() if k != "api_key"}
    canonical["__schema__"] = _CACHE_SCHEMA
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _cache_read(key: str) -> Any | None:
    """Any storage or envelope problem degrades to None (live call)."""
    try:
        from db.storage import StorageKeyMissing, get_storage_client
    except Exception as exc:
        logger.debug("exa cache disabled: storage import failed: %s", exc)
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
        logger.warning("exa cache read failed for %s: %s", key[:12], exc)
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
    return envelope.get("payload")


def _cache_write(key: str, payload: Any) -> None:
    """Empty payloads are skipped so an upstream blip doesn't poison the cache for 30 days."""
    if not payload:
        return
    try:
        from db.storage import JSON_CONTENT_TYPE, get_storage_client
    except Exception as exc:
        logger.debug("exa cache write skipped: storage import failed: %s", exc)
        return
    client = get_storage_client()
    if client is None:
        return
    envelope = {
        "schema_version": _CACHE_SCHEMA,
        "cached_at": time.time(),
        "payload": payload,
    }
    body = json.dumps(envelope).encode("utf-8")
    storage_key = f"{_CACHE_KEY_PREFIX}/{key}.json"
    try:
        client.put(storage_key, body, content_type=JSON_CONTENT_TYPE)
    except Exception as exc:
        logger.warning("exa cache write failed for %s: %s", key[:12], exc)


class ExaError(RuntimeError):
    def __init__(self, error: dict[str, Any]):
        super().__init__(error.get("error", "Exa request failed"))
        self.error = error


def normalize_error(
    message: str,
    *,
    status_code: int | None = None,
    retryable: bool | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"provider": "exa", "error": message}
    if status_code is not None:
        error["status_code"] = status_code
    if retryable is not None:
        error["retryable"] = retryable
    if detail:
        error["detail"] = detail
    return error


def error_from_exception(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, ExaError):
        return dict(exc.error)
    return normalize_error(str(exc), retryable=False)


def _get_api_key() -> str:
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    key = (os.environ.get("EXA_API_KEY") or "").strip()
    if not key:
        raise ExaError(
            normalize_error(
                "Missing EXA_API_KEY environment variable",
                retryable=False,
            )
        )
    return key


def search(
    query: str,
    max_results: int,
    mode: str = "auto",
    include_text: bool = True,
) -> list[dict[str, Any]]:
    """Tavily-compatible results.

    Modes: ``auto``, ``neural``, ``keyword``, ``fast``, ``deep-lite``, ``deep``, ``deep-reasoning``; legacy ``regular``
    -> ``auto``, ``instant`` -> ``keyword``.
    """
    clean_query = query.strip()
    if not clean_query:
        raise ValueError("query must not be empty")
    if max_results < 1:
        raise ValueError("max_results must be >= 1")
    mode_aliases = {"regular": "auto", "instant": "keyword"}
    resolved_mode = mode_aliases.get(mode, mode)
    native_modes = {"auto", "neural", "keyword", "fast", "deep-lite", "deep", "deep-reasoning"}
    if resolved_mode not in native_modes:
        raise ValueError(f"unsupported mode: {mode!r}")

    payload: dict[str, Any] = {
        "query": clean_query,
        "numResults": max_results,
        "type": resolved_mode,
    }
    if include_text:
        # Snippets suffice; full pages are fetched directly.
        payload["contents"] = {"text": {"maxCharacters": 300}}

    cache_key: str | None = None
    if os.environ.get("PSAT_EXA_CACHE"):
        cache_key = _cache_key({"endpoint": "search", **payload})
        cached = _cache_read(cache_key)
        if isinstance(cached, list):
            logger.info(
                "exa cache hit: key=%s query=%r",
                cache_key[:12],
                clean_query[:80],
            )
            return [item for item in cached if isinstance(item, dict)]

    headers = {
        "x-api-key": _get_api_key(),
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(
            EXA_SEARCH_URL,
            json=payload,
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise ExaError(normalize_error(f"Exa network error: {exc}", retryable=True)) from exc

    if resp.status_code >= 400:
        retryable = resp.status_code in (429, 500, 502, 503, 504)
        raise ExaError(
            normalize_error(
                f"Exa HTTP {resp.status_code}",
                status_code=resp.status_code,
                retryable=retryable,
                detail=resp.text[:300],
            )
        )

    data = resp.json()
    results = data.get("results") or []
    normalized: list[dict[str, Any]] = []
    for item in results:
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        text = item.get("text") or item.get("content") or ""
        if isinstance(text, dict):
            text = text.get("text", "") or ""
        normalized.append(
            {
                "url": url,
                "title": (item.get("title") or "").strip(),
                "content": str(text)[:1000],
                "score": item.get("score"),
            }
        )
    if cache_key is not None:
        _cache_write(cache_key, normalized)
    return normalized


_AUDIT_RESEARCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["auditReports"],
    "additionalProperties": False,
    "properties": {
        "auditReports": {
            "type": "array",
            "description": "Audit reports with auditor + URL",
            "items": {
                "type": "object",
                "required": ["auditor", "url"],
                "additionalProperties": False,
                "properties": {
                    "auditor": {"type": "string"},
                    "url": {"type": "string"},
                    "title": {"type": "string"},
                    "date": {"type": "string"},
                },
            },
        }
    },
}


def deep_research(
    instructions: str,
    *,
    model: str = "exa-research",
    schema: dict[str, Any] | None = None,
    timeout_seconds: int = DEEP_RESEARCH_MAX_POLL_SECONDS,
) -> dict[str, Any]:
    """Exa Deep Research. Returns ``{"data", "task_id", "status"}``; ``schema`` defaults to an audit-report schema."""
    api_key = _get_api_key()
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}

    create_payload: dict[str, Any] = {"instructions": instructions, "model": model}
    create_payload["output"] = {"schema": schema or _AUDIT_RESEARCH_SCHEMA}

    cache_key: str | None = None
    if os.environ.get("PSAT_EXA_CACHE"):
        cache_key = _cache_key({"endpoint": "deep_research", **create_payload})
        cached = _cache_read(cache_key)
        if isinstance(cached, dict) and cached.get("data") is not None:
            logger.info(
                "exa cache hit: key=%s instructions=%r",
                cache_key[:12],
                instructions[:80],
            )
            return cached

    resp = requests.post(
        EXA_RESEARCH_CREATE_URL,
        json=create_payload,
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if resp.status_code >= 400:
        raise ExaError(
            normalize_error(
                f"Exa /research create HTTP {resp.status_code}",
                status_code=resp.status_code,
                detail=resp.text[:400],
            )
        )
    task = resp.json()
    task_id = str(task.get("id") or task.get("task_id") or "")
    if not task_id:
        raise ExaError(normalize_error("Exa /research returned no task id", detail=str(task)[:300]))

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        time.sleep(DEEP_RESEARCH_POLL_INTERVAL_SECONDS)
        poll = requests.get(
            EXA_RESEARCH_GET_URL.format(task_id=task_id),
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        if poll.status_code >= 400:
            raise ExaError(
                normalize_error(
                    f"Exa /research poll HTTP {poll.status_code}",
                    status_code=poll.status_code,
                    detail=poll.text[:400],
                )
            )
        resp_data = poll.json()
        status = str(resp_data.get("status") or "").lower()
        if status in ("completed", "done", "success"):
            result = {"data": resp_data.get("data") or {}, "task_id": task_id, "status": status}
            if cache_key is not None and result["data"]:
                _cache_write(cache_key, result)
            return result
        if status in ("failed", "error", "cancelled"):
            raise ExaError(
                normalize_error(
                    f"Exa /research task {task_id} status={status}",
                    detail=str(resp_data.get("error") or resp_data)[:400],
                )
            )
    raise ExaError(normalize_error(f"Exa /research task {task_id} timed out after {timeout_seconds}s"))
