"""Materialize enumerable external authorization checks.

This is intentionally generic: given a resolved external bool call with
one symbolic caller argument and concrete non-caller arguments, enumerate
candidate addresses from the checker contract's observed events and probe
the checker for each candidate.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import IndexedEventLog
from services.resolution.capabilities import CapabilityExpr, Confidence, MembershipQuality
from services.resolution.repos.event_logs_pg import _word_to_address
from utils.rpc import rpc_batch_request_with_status

_CALLER_SOURCES = {"msg_sender", "tx_origin", "signature_recovery", "root_caller"}
_MAX_CANDIDATES = int(os.getenv("PSAT_EXTERNAL_CHECK_MATERIALIZE_MAX_CANDIDATES", "512"))
_CANDIDATE_CACHE: dict[tuple[int, str], list[str]] = {}

# Event words are 32 bytes; ``_word_to_address`` takes the low 20. A non-address
# field carrying a small integer (a uint8 role, a bool, an array length, a small
# uint) coerces to a phantom address like 0x00..01–0x00..ff. A real account/contract
# address — being a 20-byte value — is astronomically unlikely to fit in the low 32
# bits, so reject candidates below this floor. This stops phantom principals being
# probed/minted: on a *public* capability ``canCall(0x..01)`` returns true, so the
# phantom would otherwise survive as a controller.
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
    """Return a caller set for ``checker(args...)`` when enumerable.

    The shape is generic and ABI-level:
      * exactly one argument is the symbolic caller dimension;
      * all other arguments are concrete ABI words;
      * candidates are addresses observed in events from the checker.
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
    candidates = _CANDIDATE_CACHE.get(cache_key)
    if candidates is None:
        candidates = _candidate_addresses_from_events(
            session=session,
            chain_id=chain_id,
            checker_address=checker_address,
            limit=_MAX_CANDIDATES,
        )
        if not candidates:
            candidates = _candidate_addresses_from_hypersync(checker_address=checker_address, limit=_MAX_CANDIDATES)
        _CANDIDATE_CACHE[cache_key] = list(candidates)
    if not candidates:
        return None

    calls: list[tuple[str, list[Any]]] = []
    ordered_candidates: list[str] = []
    for candidate in candidates:
        encoded_args = list(encoded_static_args)
        encoded_args[caller_index] = _encode_address(candidate)
        data = checker_selector + "".join(arg or "" for arg in encoded_args)
        call: dict[str, str] = {"to": checker_address, "data": data}
        calls.append(("eth_call", [call, hex(block) if isinstance(block, int) else "latest"]))
        ordered_candidates.append(candidate)

    results = rpc_batch_request_with_status(rpc_url, calls)
    allowed: list[str] = []
    for candidate, (raw, had_error) in zip(ordered_candidates, results, strict=False):
        if had_error:
            continue
        if _decode_bool(raw):
            allowed.append(candidate)
    if not allowed:
        return None
    return CapabilityExpr.finite_set(
        allowed,
        quality=MembershipQuality.LOWER_BOUND,
        confidence=Confidence.PARTIAL,
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
        return _encode_address(value)
    if value.startswith("0x") and len(value) == 10:
        return value[2:].ljust(64, "0")
    if value.startswith("0x") and len(value) == 66:
        return value[2:]
    return None


def _encode_address(address: str) -> str:
    return address.lower().removeprefix("0x").rjust(64, "0")


def _decode_bool(raw: Any) -> bool:
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 66:
        return False
    try:
        return int(raw[-64:], 16) != 0
    except ValueError:
        return False


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


def _candidate_addresses_from_hypersync(*, checker_address: str, limit: int) -> list[str]:
    token = os.getenv("ENVIO_API_TOKEN")
    if not token:
        return []
    try:
        return asyncio.run(_candidate_addresses_from_hypersync_async(checker_address=checker_address, limit=limit))
    except Exception:
        return []


async def _candidate_addresses_from_hypersync_async(*, checker_address: str, limit: int) -> list[str]:
    try:
        import hypersync  # type: ignore
    except Exception:
        return []

    url = os.getenv("PSAT_HYPERSYNC_URL", "https://eth.hypersync.xyz")
    timeout_s = float(os.getenv("PSAT_EXTERNAL_CHECK_CANDIDATE_TIMEOUT_S", "20"))
    max_pages = int(os.getenv("PSAT_EXTERNAL_CHECK_CANDIDATE_MAX_PAGES", "20"))
    client = hypersync.HypersyncClient(hypersync.ClientConfig(url=url, bearer_token=os.getenv("ENVIO_API_TOKEN")))
    current_from = 0
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
