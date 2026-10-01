"""Materialize enumerable external authorization checks: for an external bool call with one symbolic caller argument,
enumerate candidates from the checker's events and probe each.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import IndexedEventLog
from services.clients.rpc import (
    decode_bool_word,
    encode_address_word,
    multicall3_aggregate3,
    rpc_batch_request_with_status,
)
from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.resolution.capabilities import CapabilityExpr
from services.resolution.repos.event_logs_pg import _word_to_address

logger = logging.getLogger(__name__)


_MAX_CANDIDATES = int(os.getenv("PSAT_EXTERNAL_CHECK_MATERIALIZE_MAX_CANDIDATES", "512"))

# Keyed (chain_id, checker_address); _MAX_CANDIDATES bounds each list, _CANDIDATE_CACHE_MAX the entry count (oldest 25%
# evicted).
_CANDIDATE_CACHE: dict[tuple[int, str], list[str]] = {}
_CANDIDATE_CACHE_LOCK = threading.Lock()
_CANDIDATE_CACHE_MAX = 1024
_CANDIDATE_PRESSURE_NAME = "external_check_candidates"


def _evict_candidates_if_needed() -> None:
    """Drop the oldest 25% at the bound (caller holds _CANDIDATE_CACHE_LOCK)."""
    if len(_CANDIDATE_CACHE) < _CANDIDATE_CACHE_MAX:
        return
    for k in list(_CANDIDATE_CACHE.keys())[: _CANDIDATE_CACHE_MAX // 4]:
        _CANDIDATE_CACHE.pop(k, None)


def _log_candidate_pressure() -> None:
    from utils.memory import cache_pressure_message

    msg = cache_pressure_message(_CANDIDATE_PRESSURE_NAME, len(_CANDIDATE_CACHE), _CANDIDATE_CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def clear_candidate_cache() -> None:
    from utils.memory import reset_cache_pressure_state

    with _CANDIDATE_CACHE_LOCK:
        _CANDIDATE_CACHE.clear()
    reset_cache_pressure_state(_CANDIDATE_PRESSURE_NAME)


# Batch the per-candidate checker probes into one Multicall3 call. The candidate is an argument, so sender rewriting is
# harmless. Falls back to the JSON-RPC batch on failure. PSAT_EXTERNAL_CHECK_MULTICALL=0 disables; tests/conftest.py
# forces it off.
_EXTERNAL_CHECK_MULTICALL_ENABLED = os.getenv("PSAT_EXTERNAL_CHECK_MULTICALL", "1").lower() in ("1", "true", "yes")


def _eval_candidate_calls(
    rpc_url: str,
    mc_calls: list[tuple[str, str]],
    batch_calls: list[tuple[str, list[Any]]],
    block_tag: str,
) -> list[tuple[Any, bool]]:
    """Probe every candidate's checker call via Multicall3, else the JSON-RPC batch.

    Both return ``[(raw, had_error)]``; reverts are skipped.
    """
    if _EXTERNAL_CHECK_MULTICALL_ENABLED:
        try:
            mc = multicall3_aggregate3(rpc_url, mc_calls, block_tag)
            return [(raw if success else None, not success) for success, raw in mc]
        except Exception:
            pass
    return rpc_batch_request_with_status(rpc_url, batch_calls)


# Small integers in event words (roles, bools, lengths) decode to phantom addresses like 0x..01, and a public capability
# would pass them. Real addresses essentially never fit in 32 bits.
_ADDRESS_PLAUSIBILITY_FLOOR = 2**32


def _is_plausible_candidate_address(addr: str) -> bool:
    try:
        return int(addr, 16) >= _ADDRESS_PLAUSIBILITY_FLOOR
    except (TypeError, ValueError):
        return False


def materialize_external_check_from_events(
    *,
    session: Session,
    rpc_url: str | None,
    chain_id: int,
    checker_address: str,
    checker_selector: str | None,
    call_args: list[dict[str, Any]],
    block: int | None = None,
) -> CapabilityExpr | None:
    """A caller set for ``checker(args...)`` when enumerable: exactly one symbolic caller argument, concrete other
    arguments, candidates from the checker's events.
    """
    if not rpc_url or not checker_selector:
        return None
    caller_index = _caller_arg_index(call_args)
    if caller_index is None:
        return None
    encoded_static_args = [_encode_static_arg(arg) for arg in call_args]
    if any(arg is None for idx, arg in enumerate(encoded_static_args) if idx != caller_index):
        return None

    cache_key = (chain_id, checker_address.lower())
    with _CANDIDATE_CACHE_LOCK:
        candidates = _CANDIDATE_CACHE.get(cache_key)
    if candidates is None:
        # Outside the lock so misses for different checkers don't serialize.
        candidates = _candidate_addresses_from_events(
            session=session,
            chain_id=chain_id,
            checker_address=checker_address,
            limit=_MAX_CANDIDATES,
        )
        if not candidates:
            candidates = _candidate_addresses_from_hypersync(
                checker_address=checker_address, limit=_MAX_CANDIDATES, chain_id=chain_id
            )
        candidates = list(candidates)
        with _CANDIDATE_CACHE_LOCK:
            _evict_candidates_if_needed()
            _CANDIDATE_CACHE[cache_key] = candidates
            _log_candidate_pressure()
    if not candidates:
        return None

    calls: list[tuple[str, list[Any]]] = []
    mc_calls: list[tuple[str, str]] = []
    ordered_candidates: list[str] = []
    block_tag = hex(block) if isinstance(block, int) else "latest"
    for candidate in candidates:
        encoded_args = list(encoded_static_args)
        encoded_args[caller_index] = encode_address_word(candidate)
        data = checker_selector + "".join(arg or "" for arg in encoded_args)
        call: dict[str, str] = {"to": checker_address, "data": data}
        calls.append(("eth_call", [call, block_tag]))
        mc_calls.append((checker_address, data))
        ordered_candidates.append(candidate)

    results = _eval_candidate_calls(rpc_url, mc_calls, calls, block_tag)
    allowed: list[str] = []
    for candidate, (raw, had_error) in zip(ordered_candidates, results, strict=False):
        if had_error:
            continue
        if decode_bool_word(raw):
            allowed.append(candidate)
    if not allowed:
        logger.debug(
            "external_check materialize decision",
            extra={
                "adapter": "external_check_materializer",
                "address": checker_address.lower(),
                "decision": "none",
                "reason": "no_candidate_allowed",
                "candidate_count": len(candidates),
            },
        )
        return None
    logger.debug(
        "external_check materialize decision",
        extra={
            "adapter": "external_check_materializer",
            "address": checker_address.lower(),
            "decision": "finite_set",
            "reason": "candidates_eth_call",
            "candidate_count": len(candidates),
            "allowed_count": len(allowed),
        },
    )
    return CapabilityExpr.finite_set(
        allowed,
        quality="lower_bound",
        confidence="partial",
        trace=[
            {
                "step": "external_check_materialized",
                "checker_address": checker_address.lower(),
                "checker_selector": checker_selector,
                "candidate_count": len(candidates),
                "allowed_count": len(allowed),
                "source": "event_candidates_eth_call",
            }
        ],
    )


def _caller_arg_index(call_args: list[dict[str, Any]]) -> int | None:
    indexes = [idx for idx, arg in enumerate(call_args) if arg.get("source") in _CALLER_SOURCES]
    return indexes[0] if len(indexes) == 1 else None


def _encode_static_arg(arg: dict[str, Any]) -> str | None:
    if arg.get("source") in _CALLER_SOURCES:
        return None
    raw = arg.get("constant_value")
    if not isinstance(raw, str):
        return None
    value = raw.lower()
    if value.startswith("0x") and len(value) == 42:
        return encode_address_word(value)
    if value.startswith("0x") and len(value) == 10:
        return value[2:].ljust(64, "0")
    if value.startswith("0x") and len(value) == 66:
        return value[2:]
    return None


def _candidate_addresses_from_events(
    *,
    session: Session,
    chain_id: int,
    checker_address: str,
    limit: int,
) -> list[str]:
    stmt = (
        select(IndexedEventLog.topics, IndexedEventLog.data_words)
        .where(IndexedEventLog.chain_id == chain_id)
        .where(func.lower(IndexedEventLog.event_address) == checker_address.lower())
        .order_by(
            IndexedEventLog.block_number.asc(),
            IndexedEventLog.transaction_index.asc(),
            IndexedEventLog.log_index.asc(),
        )
    )
    seen: set[str] = set()
    out: list[str] = []
    for topics, data_words in session.execute(stmt):
        for word in list(topics or [])[1:] + list(data_words or []):
            addr = _word_to_address(word)
            if addr is None or not _is_plausible_candidate_address(addr):
                continue
            if addr in seen:
                continue
            seen.add(addr)
            out.append(addr)
            if len(out) >= limit:
                return out
    return out


def _candidate_addresses_from_hypersync(*, checker_address: str, limit: int, chain_id: int) -> list[str]:
    token = os.getenv("ENVIO_API_TOKEN")
    if not token:
        return []
    try:
        return asyncio.run(
            _candidate_addresses_from_hypersync_async(checker_address=checker_address, limit=limit, chain_id=chain_id)
        )
    except Exception:
        return []


async def _candidate_addresses_from_hypersync_async(*, checker_address: str, limit: int, chain_id: int) -> list[str]:
    try:
        import hypersync
    except Exception:
        return []

    from services.resolution.hypersync_bound import hypersync_url_for_chain

    # Per-chain endpoint; no coverage means no candidates. ``PSAT_HYPERSYNC_URL`` is a single-chain dev
    # override only.
    url = os.getenv("PSAT_HYPERSYNC_URL") or hypersync_url_for_chain(chain_id)
    if not url:
        return []
    timeout_s = float(os.getenv("PSAT_EXTERNAL_CHECK_CANDIDATE_TIMEOUT_S", "20"))
    max_pages = int(os.getenv("PSAT_EXTERNAL_CHECK_CANDIDATE_MAX_PAGES", "20"))
    from services.resolution.hypersync_bound import build_hypersync_client, hypersync_slot

    envio_token = os.getenv("ENVIO_API_TOKEN")
    client = build_hypersync_client(hypersync, url=url, bearer_token=envio_token)
    from services.resolution.creation_block_floor import resolve_scan_floor

    # No floor: defer rather than scan from genesis.
    floor = resolve_scan_floor(checker_address, chain_id)
    if floor is None:
        return []
    current_from = floor
    page_count = 0
    started = time.monotonic()
    seen: set[str] = set()
    out: list[str] = []
    while len(out) < limit:
        if time.monotonic() - started > timeout_s or page_count >= max_pages:
            break
        query = hypersync.Query(
            from_block=current_from,
            logs=[hypersync.LogSelection(address=[checker_address.lower()])],
            field_selection=hypersync.FieldSelection(log=[field.value for field in hypersync.LogField]),
        )
        with hypersync_slot(envio_token):
            response = await client.get(query)
        page_count += 1
        for log in _logs_from_hypersync_response(response):
            for word in _topics_from_hypersync_log(log)[1:] + _data_words_from_hypersync_log(log):
                addr = _word_to_address(word)
                if addr is None or not _is_plausible_candidate_address(addr) or addr in seen:
                    continue
                seen.add(addr)
                out.append(addr)
                if len(out) >= limit:
                    return out
        next_block = getattr(response, "next_block", None)
        if next_block is None or next_block <= current_from:
            break
        current_from = next_block
    return out


def _logs_from_hypersync_response(response: Any) -> list[Any]:
    data = getattr(response, "data", None)
    if data is not None:
        logs = getattr(data, "logs", None)
        if isinstance(logs, list):
            return logs
    logs = getattr(response, "logs", None)
    return logs if isinstance(logs, list) else []


def _topics_from_hypersync_log(log: Any) -> list[str]:
    topics = getattr(log, "topics", None)
    if isinstance(topics, list):
        return [t for t in topics if isinstance(t, str)]
    out: list[str] = []
    for key in ("topic0", "topic1", "topic2", "topic3"):
        value = getattr(log, key, None)
        if isinstance(value, str) and value.startswith("0x"):
            out.append(value)
    return out


def _data_words_from_hypersync_log(log: Any) -> list[str]:
    data = getattr(log, "data", None)
    if not isinstance(data, str) or not data.startswith("0x"):
        return []
    body = data[2:]
    return ["0x" + body[idx : idx + 64] for idx in range(0, len(body), 64) if len(body[idx : idx + 64]) == 64]
