"""Replay mapping-writer events into current allowlist principals."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import threading
import time
from typing import Any, TypedDict

from eth_utils.crypto import keccak

from services.clients.rpc import normalize_hex as _normalize_hex
from services.static.contract_analysis_pipeline.mapping_events import WriterEventSpec
from utils.logging import record_degraded

logger = logging.getLogger(__name__)


def _mainnet_hypersync_url() -> str:
    """Mainnet HyperSync endpoint from the registry; the default for the enumerators below."""
    from utils.chains import chain_by_id

    url = chain_by_id(1).hypersync_url
    assert url is not None  # mainnet always has HyperSync coverage
    return url


DEFAULT_HYPERSYNC_URL: str = _mainnet_hypersync_url()

# Pagination bounds: without them an old contract can wedge a worker for over an hour.
_TIMEOUT_S = float(os.getenv("PSAT_MAPPING_ENUMERATION_TIMEOUT_S", "60"))
_MAX_PAGES = int(os.getenv("PSAT_MAPPING_ENUMERATION_MAX_PAGES", "50"))


def _cache_ttl_s() -> float:
    """Read at call time so tests can monkeypatch the TTL."""
    return float(os.getenv("PSAT_MAPPING_ENUMERATION_CACHE_TTL_S", "1800"))


class EnumeratedPrincipal(TypedDict):
    address: str
    mapping_name: str
    direction_history: list[str]
    last_seen_block: int


class EnumerationResult(TypedDict):
    """Principal list plus status, so a truncated scan is distinguishable from a complete one."""

    principals: list[EnumeratedPrincipal]
    # "complete" | "incomplete_timeout" | "incomplete_max_pages" | "error" | "incomplete_ambiguous_writer_event" (a
    # conflicted event was dropped) | "incomplete_no_writer_specs" | "incomplete_no_hypersync_coverage"
    status: str
    pages_fetched: int
    last_block_scanned: int
    error: str | None


class EnumeratedKeyValue(TypedDict):
    """One key's latest observed value (D.2), for filtering by a downstream ``ValuePredicate``."""

    key: str  # 0x-prefixed canonical address (or 0x... hex word for non-address keys)
    mapping_name: str
    value_hex: str  # 0x-prefixed canonical hex of the latest assigned value
    last_block: int
    last_log_index: int


class EnumerationValueResult(TypedDict):
    entries: list[EnumeratedKeyValue]
    status: str
    pages_fetched: int
    last_block_scanned: int
    error: str | None


# Keyed on (chain, address, specs_hash), the same identity as L2 (db.mapping_enumeration_cache). head_block is in the
# value so cascade siblings share a scan. Size-capped (oldest 25% evicted) plus a TTL.
_CACHE: dict[tuple[str, str, str], tuple[EnumerationResult, float]] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 1024
_PRESENT_PRESSURE_NAME = "mapping_enumeration"
_VALUE_PRESSURE_NAME = "mapping_enumeration_value"


def clear_enumeration_cache() -> None:
    from utils.memory import reset_cache_pressure_state

    with _CACHE_LOCK:
        _CACHE.clear()
        _VALUE_CACHE.clear()
    reset_cache_pressure_state(_PRESENT_PRESSURE_NAME)
    reset_cache_pressure_state(_VALUE_PRESSURE_NAME)


def _chain_key(chain: str | None) -> str:
    """Chain part of the L1 key.

    ``chain_cache_token`` folds names ("ethereum") and ids ("1") to one token, matching L2.
    """
    from utils.chains import chain_cache_token

    return chain_cache_token(chain)


def _scan_hypersync_url_for_chain(chain: str | int | None) -> str | None:
    """The HyperSync endpoint for *chain*.

    Chainless calls raise; chains without proven coverage return ``None`` so the scan is reported unavailable.
    """
    from services.resolution.hypersync_bound import hypersync_url_for_chain
    from utils.chains import require_chain

    if isinstance(chain, int) or (isinstance(chain, str) and chain.strip().isdigit()):
        info = require_chain(int(chain), context="mapping enumeration hypersync url")
    else:
        info = require_chain(
            chain=chain if isinstance(chain, str) else None, context="mapping enumeration hypersync url"
        )
    return hypersync_url_for_chain(info.chain_id)


def _l1_specs_hash(specs_as_dicts: list[dict[str, Any]]) -> str:
    """The fingerprint L2 keys on, with a local digest fallback when the DB module isn't importable."""
    try:
        from db.mapping_enumeration_cache import specs_fingerprint

        return specs_fingerprint(specs_as_dicts)
    except Exception:
        canonical = json.dumps(specs_as_dicts, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _evict_enumeration_if_needed(cache: dict) -> None:
    """Drop the oldest 25% at the bound (caller holds _CACHE_LOCK)."""
    if len(cache) < _CACHE_MAX:
        return
    cutoff = sorted(cache.values(), key=lambda v: v[1])[len(cache) // 4][1]
    for k in [k for k, v in cache.items() if v[1] <= cutoff]:
        cache.pop(k, None)


def _store_enumeration(cache: dict, cache_key: tuple[str, str, str], entry: tuple, name: str) -> None:
    from utils.memory import cache_pressure_message

    _evict_enumeration_if_needed(cache)
    cache[cache_key] = entry
    msg = cache_pressure_message(name, len(cache), _CACHE_MAX)
    if msg:
        logger.info("[CACHE_PRESSURE] %s", msg)


def _event_topic0(signature: str) -> str:
    digest = keccak(text=signature).hex()
    return _normalize_hex("0x" + digest)


def _build_query(hypersync_module, contract_address: str, topic0s: list[str], from_block: int, to_block: int | None):
    return hypersync_module.Query(
        from_block=from_block,
        to_block=to_block,
        logs=[
            hypersync_module.LogSelection(
                address=[contract_address.lower()],
                topics=[topic0s],
            )
        ],
        field_selection=hypersync_module.FieldSelection(
            log=[field.value for field in hypersync_module.LogField],
        ),
    )


def _topics_from_log(log: Any) -> list[str]:
    topics = getattr(log, "topics", None)
    if isinstance(topics, (list, tuple)):
        return [_normalize_hex(t) for t in topics if isinstance(t, str) and t.startswith("0x")]
    extracted: list[str] = []
    for attr in ("topic0", "topic1", "topic2", "topic3"):
        value = getattr(log, attr, None)
        if isinstance(value, str) and value.startswith("0x") and value not in {"0x", "0x0"}:
            extracted.append(_normalize_hex(value))
    return extracted


def _decode_address_topic(topic: str) -> str:
    t = _normalize_hex(topic)
    if len(t) != 66:
        return ""
    return _normalize_hex("0x" + t[-40:])


def _decode_address_arg_from_data(data: str, position: int) -> str:
    hex_body = data[2:] if data.startswith("0x") else data
    start = 64 * position
    end = start + 64
    if end > len(hex_body):
        return ""
    slot = hex_body[start:end]
    return _normalize_hex("0x" + slot[-40:])


def _extract_value_word(
    log: Any,
    value_position: int,
    *,
    indexed_positions: list[int] | None = None,
) -> str:
    """The assigned value at ``value_position`` as a 0x-prefixed 32-byte word, whether indexed or in data."""
    topics = _topics_from_log(log)
    indexed_positions = sorted(set(indexed_positions or []))
    if value_position in indexed_positions:
        rank = indexed_positions.index(value_position)
        topic_index = 1 + rank
        if topic_index < len(topics):
            return _normalize_hex(topics[topic_index])
        return ""
    non_indexed_up_to = [p for p in range(value_position + 1) if p not in indexed_positions]
    if not non_indexed_up_to:
        return ""
    data_rank = len(non_indexed_up_to) - 1
    raw = getattr(log, "data", "0x") or "0x"
    body = raw[2:] if raw.startswith("0x") else raw
    start = 64 * data_rank
    end = start + 64
    if end > len(body):
        return ""
    return _normalize_hex("0x" + body[start:end])


_ZERO_WORD = "0x" + "0" * 64
_ADDRESS_MASK = (1 << 160) - 1
_SIGNED_INT_TYPE = re.compile(r"int\d*")
_SHORT_FIXED_BYTES = re.compile(r"bytes([1-9]|[12]\d|3[01])")


def _value_predicate_passes(value_hex: str, predicate: dict[str, Any]) -> bool | None:
    """Apply a ``ValuePredicate`` to a 32-byte hex word.

    Compares as integers: addresses on their low 160 bits, signed ints as two's complement. ``None`` when the word,
    an rhs, the mask, the op or the value type can't be evaluated; callers publish that as not determined, never as
    a non-match.
    """
    if not value_hex.startswith("0x") or len(value_hex) != 66:
        return None
    try:
        actual = int(value_hex, 16)
    except ValueError:
        return None
    op = str(predicate.get("op") or "")
    if op == "any_nonzero":
        return actual != 0

    value_type = str(predicate.get("value_type") or "uint256").strip()
    # A dynamic value's event word is a hash or an offset, not the value; a short ``bytesN`` is left-aligned, so its
    # integer reading isn't the rhs literal's.
    if value_type in ("string", "bytes") or value_type.endswith("]") or _SHORT_FIXED_BYTES.fullmatch(value_type):
        return None
    mask_raw = predicate.get("mask")
    if mask_raw is not None:
        mask = _to_int(mask_raw)
        if mask is None:
            return None
        actual &= mask
    if value_type.startswith("address"):
        actual &= _ADDRESS_MASK
    elif _SIGNED_INT_TYPE.fullmatch(value_type) and actual >> 255:
        actual -= 1 << 256

    rhs = [_to_int(r) for r in predicate.get("rhs_values") or []]
    if not rhs or any(r is None for r in rhs):
        return None
    if op == "in":
        return actual in rhs
    if len(rhs) != 1:
        return None
    rhs_int = rhs[0]
    assert rhs_int is not None
    if op == "eq":
        return actual == rhs_int
    if op == "ne":
        return actual != rhs_int
    if op == "lt":
        return actual < rhs_int
    if op == "lte":
        return actual <= rhs_int
    if op == "gt":
        return actual > rhs_int
    if op == "gte":
        return actual >= rhs_int
    return None


def _to_int(s: Any) -> int | None:
    """A predicate literal as an int: hex, decimal (``"0"`` from ``address(0)``), or a bool (``True``/``False``)."""
    if isinstance(s, bool):
        return int(s)
    if isinstance(s, int):
        return s
    if not isinstance(s, str):
        return None
    text = s.strip().lower()
    if text in ("true", "false"):
        return int(text == "true")
    try:
        return int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _extract_key_address(
    log: Any,
    key_position: int,
    *,
    indexed_positions: list[int] | None = None,
) -> str:
    topics = _topics_from_log(log)
    indexed_positions = sorted(set(indexed_positions or []))
    if key_position in indexed_positions:
        indexed_rank = indexed_positions.index(key_position)
        topic_index = 1 + indexed_rank
        if topic_index < len(topics):
            return _decode_address_topic(topics[topic_index])
        return ""
    non_indexed = [p for p in range(key_position + 1) if p not in indexed_positions]
    if non_indexed:
        data_rank = len(non_indexed) - 1
        return _decode_address_arg_from_data(getattr(log, "data", "0x") or "0x", data_rank)
    return ""


async def enumerate_mapping_allowlist(
    contract_address: str,
    writer_specs: list[WriterEventSpec],
    *,
    from_block: int,
    hypersync_url: str = DEFAULT_HYPERSYNC_URL,
    bearer_token: str | None = None,
    to_block: int | None = None,
    client: Any = None,
    hypersync_module: Any = None,
    timeout_s: float | None = None,
    max_pages: int | None = None,
) -> EnumerationResult:
    """Replay mapping-writer events into a current allowlist; truncation is reported via
    ``EnumerationResult.status``.
    """
    eff_timeout = _TIMEOUT_S if timeout_s is None else timeout_s
    eff_max_pages = _MAX_PAGES if max_pages is None else max_pages

    if not writer_specs:
        # No specs means nothing was observed; "complete" would publish a vacuous scan as exhaustive.
        return EnumerationResult(
            principals=[],
            status="incomplete_no_writer_specs",
            pages_fetched=0,
            last_block_scanned=from_block,
            error=None,
        )

    topic0_to_specs: dict[str, list[WriterEventSpec]] = {}
    for spec in writer_specs:
        topic0 = _event_topic0(spec["event_signature"])
        topic0_to_specs.setdefault(topic0, []).append(spec)
    ambiguous_dropped = False
    for topic0, specs in list(topic0_to_specs.items()):
        directions = {spec["direction"] for spec in specs}
        if len(directions) <= 1:
            continue
        logger.warning(
            "mapping_enumerator: skipping ambiguous writer event",
            extra={
                "topic0": topic0,
                "directions": sorted(directions),
                "specs": [(spec["event_signature"], spec["mapping_name"], spec["direction"]) for spec in specs],
            },
        )
        ambiguous_dropped = True
        del topic0_to_specs[topic0]
    if not topic0_to_specs:
        # Every writer event was ambiguous, so nothing was scanned; "complete" would look like a real empty scan.
        return EnumerationResult(
            principals=[],
            status="incomplete_ambiguous_writer_event",
            pages_fetched=0,
            last_block_scanned=from_block,
            error=None,
        )

    if hypersync_module is None:
        import hypersync as hypersync_module
    if client is None:
        if not bearer_token:
            raise RuntimeError("Hypersync requires an API token; pass bearer_token= or set ENVIO_API_TOKEN.")
        from services.resolution.hypersync_bound import build_hypersync_client

        client = build_hypersync_client(hypersync_module, url=hypersync_url, bearer_token=bearer_token)

    topic0s = sorted(topic0_to_specs.keys())
    logger.info(
        "mapping_enumerator: scan start",
        extra={
            "address": contract_address,
            "from_block": from_block,
            "to_block": to_block,
            "timeout_s": eff_timeout,
            "max_pages": eff_max_pages,
            "topic0s": topic0s,
            "specs": [(s["event_signature"], s["direction"], s.get("key_position")) for s in writer_specs],
        },
    )
    query = _build_query(hypersync_module, contract_address, topic0s, from_block, to_block)

    from services.resolution.hypersync_bound import hypersync_slot

    state: dict[tuple[str, str], dict[str, Any]] = {}
    current_from = from_block
    page_count = 0
    started = time.monotonic()
    # Dropping an ambiguous event makes the fold incomplete regardless of the scan.
    status: str = "incomplete_ambiguous_writer_event" if ambiguous_dropped else "complete"
    error: str | None = None
    while True:
        if time.monotonic() - started > eff_timeout:
            status = "incomplete_timeout"
            logger.warning(
                "mapping_enumerator: scan timeout",
                extra={
                    "address": contract_address,
                    "timeout_s": eff_timeout,
                    "page_count": page_count,
                    "last_block": current_from,
                },
            )
            break
        if page_count >= eff_max_pages:
            status = "incomplete_max_pages"
            logger.warning(
                "mapping_enumerator: max pages hit",
                extra={"address": contract_address, "max_pages": eff_max_pages, "last_block": current_from},
            )
            break

        try:
            with hypersync_slot(bearer_token):
                result = await client.get(query)
        except Exception as exc:
            status = "error"
            error = str(exc)
            record_degraded(
                phase="mapping_enumerator_scan",
                exc=exc,
                context={"address": contract_address, "page_count": page_count},
            )
            logger.warning(
                "mapping_enumerator: RPC error during scan",
                extra={
                    "address": contract_address,
                    "page_count": page_count,
                    "exc_type": type(exc).__name__,
                },
            )
            break

        page_count += 1
        data_obj = getattr(result, "data", None)
        if data_obj is not None and hasattr(data_obj, "logs"):
            logs = list(getattr(data_obj, "logs", None) or [])
        elif isinstance(data_obj, list):
            logs = data_obj
        else:
            logs = list(getattr(result, "logs", None) or [])
        logger.debug(
            "mapping_enumerator: page fetched",
            extra={
                "page": page_count,
                "logs": len(logs),
                "from_block": current_from,
                "next_block": getattr(result, "next_block", None),
            },
        )
        for raw_log in logs:
            topics = _topics_from_log(raw_log)
            if not topics:
                continue
            topic0 = topics[0]
            matching_specs = topic0_to_specs.get(topic0)
            if not matching_specs:
                continue
            for spec in matching_specs:
                key_address = _extract_key_address(
                    raw_log,
                    spec["key_position"],
                    indexed_positions=list(spec.get("indexed_positions") or []),
                )
                if not key_address.startswith("0x") or len(key_address) != 42:
                    continue
                block = int(getattr(raw_log, "block_number", 0) or 0)
                entry = state.setdefault(
                    (spec["mapping_name"], key_address),
                    {"present": False, "history": [], "last_block": 0},
                )
                if spec["direction"] == "add":
                    entry["present"] = True
                else:
                    entry["present"] = False
                entry["history"].append(spec["direction"])
                entry["last_block"] = max(entry["last_block"], block)

        next_from = getattr(result, "next_block", None)
        if next_from is None or next_from <= current_from:
            break
        current_from = next_from
        query = _build_query(hypersync_module, contract_address, topic0s, current_from, to_block)

    out: list[EnumeratedPrincipal] = []
    for (mapping_name, addr), entry in state.items():
        if not entry["present"]:
            continue
        out.append(
            {
                "address": addr,
                "mapping_name": mapping_name,
                "direction_history": list(entry["history"]),
                "last_seen_block": int(entry["last_block"]),
            }
        )
    return EnumerationResult(
        principals=out,
        status=status,
        pages_fetched=page_count,
        last_block_scanned=current_from,
        error=error,
    )


def enumerate_mapping_allowlist_sync(
    contract_address: str,
    writer_specs: list[WriterEventSpec],
    *,
    chain: str | None = None,
    **kwargs: Any,
) -> EnumerationResult:
    """Sync wrapper with a two-tier TTL cache.

    L1 is in-process; L2 is ``db.mapping_enumeration_cache`` so the resolution and policy stages (different processes)
    share the expensive scan. Misses write L2 then L1. Incomplete and error results are cached too; callers read
    ``status``.

    Every status must fit L2's column, or a rejected write would leave an older ``complete`` row standing.
    ``tests/resolution/test_mapping_enumeration_status_vocabulary.py`` round-trips the vocabulary.
    """
    specs_as_dicts = [dict(s) for s in writer_specs]
    cache_key = (_chain_key(chain), contract_address.lower(), _l1_specs_hash(specs_as_dicts))
    now = time.monotonic()

    with _CACHE_LOCK:
        cached = _CACHE.get(cache_key)
        if cached is not None:
            result, inserted_at = cached
            if now - inserted_at < _cache_ttl_s():
                logger.debug(
                    "mapping_enumerator: L1 cache hit",
                    extra={
                        "address": contract_address,
                        "enumeration_status": result["status"],
                        "principals": len(result["principals"]),
                    },
                )
                return result
            del _CACHE[cache_key]

    if _db_cache_enabled():
        try:
            from db import mapping_enumeration_cache as _db_cache

            specs_hash = _db_cache.specs_fingerprint(specs_as_dicts)
            db_hit = _db_cache.find_fresh(
                chain=chain,
                address=contract_address,
                specs_hash=specs_hash,
                ttl_s=_cache_ttl_s(),
            )
        except Exception as exc:
            record_degraded(
                phase="mapping_enumerator_l2_read",
                exc=exc,
                context={"address": contract_address, "chain": chain},
            )
            logger.warning(
                "mapping_enumerator: L2 read failed, falling through to scan",
                extra={"address": contract_address, "exc_type": type(exc).__name__},
            )
            db_hit = None
            specs_hash = None
        else:
            if db_hit is not None:
                logger.debug(
                    "mapping_enumerator: L2 cache hit",
                    extra={
                        "address": contract_address,
                        "enumeration_status": db_hit["status"],
                        "principals": len(db_hit["principals"]),
                    },
                )
                result = EnumerationResult(**db_hit)
                with _CACHE_LOCK:
                    _store_enumeration(_CACHE, cache_key, (result, now), _PRESENT_PRESSURE_NAME)
                return result
    else:
        specs_hash = None

    # Derive the scan URL from ``chain`` unless a URL or client is injected; no-coverage chains return unavailable.
    if not kwargs.get("client") and not kwargs.get("hypersync_url"):
        scan_url = _scan_hypersync_url_for_chain(chain)
        if scan_url is None:
            return EnumerationResult(
                principals=[],
                status="incomplete_no_hypersync_coverage",
                pages_fetched=0,
                last_block_scanned=int(kwargs.get("from_block") or 0),
                error="hypersync_unavailable_for_chain",
            )
        kwargs["hypersync_url"] = scan_url

    result = asyncio.run(enumerate_mapping_allowlist(contract_address, writer_specs, **kwargs))

    if specs_hash is not None:
        try:
            from db import mapping_enumeration_cache as _db_cache

            _db_cache.upsert(
                chain=chain,
                address=contract_address,
                specs_hash=specs_hash,
                result=dict(result),
            )
        except Exception as exc:
            record_degraded(
                phase="mapping_enumerator_l2_write",
                exc=exc,
                context={"address": contract_address, "chain": chain},
            )
            logger.warning(
                "mapping_enumerator: L2 write failed",
                extra={"address": contract_address, "exc_type": type(exc).__name__},
            )

    with _CACHE_LOCK:
        _store_enumeration(_CACHE, cache_key, (result, now), _PRESENT_PRESSURE_NAME)
    return result


def _db_cache_enabled() -> bool:
    """Whether the L2 cache is on (``PSAT_MAPPING_ENUMERATION_DB_CACHE``, default on).

    The DB module is imported lazily.
    """
    return os.getenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "1").lower() in ("1", "true", "yes")


# Value-scan statuses where a write was skipped or never readable before the scan ended: any key's latest value may be
# wrong, so the entries bound nothing.
UNREADABLE_VALUE_SCAN_STATUSES = frozenset(
    {
        "incomplete_undecodable_event",
        "incomplete_unfoldable_writer_event",
        "incomplete_ambiguous_writer_event",
        "incomplete_no_writer_specs",
    }
)


def value_writer_spec_foldable(spec: Any) -> bool:
    """Whether a value fold can replay this writer: its event carries the value, or it writes zero (``remove``)."""
    return spec.get("value_position") is not None or spec.get("direction") == "remove"


async def enumerate_mapping_values(
    contract_address: str,
    writer_specs: list[WriterEventSpec],
    *,
    from_block: int,
    hypersync_url: str = DEFAULT_HYPERSYNC_URL,
    bearer_token: str | None = None,
    to_block: int | None = None,
    client: Any = None,
    hypersync_module: Any = None,
    timeout_s: float | None = None,
    max_pages: int | None = None,
) -> EnumerationValueResult:
    """Replay writer events into a latest-value-per-key map.

    Unlike ``enumerate_mapping_allowlist`` (add/remove present-set), this keeps each key's most recent value: the
    ``value_position`` word, or zero for a ``remove`` (``m[k] = address(0)``, ``delete m[k]``). The EventIndexedAdapter
    then filters by ``ValuePredicate``. A writer whose value can't be read, two readings of one event, or a log the
    specs can't decode leaves the map incomplete rather than silently missing that write.
    """
    eff_timeout = _TIMEOUT_S if timeout_s is None else timeout_s
    eff_max_pages = _MAX_PAGES if max_pages is None else max_pages

    def _unscanned(status: str) -> EnumerationValueResult:
        return EnumerationValueResult(
            entries=[], status=status, pages_fetched=0, last_block_scanned=from_block, error=None
        )

    if not writer_specs:
        return _unscanned("incomplete_no_writer_specs")
    if not all(value_writer_spec_foldable(spec) for spec in writer_specs):
        return _unscanned("incomplete_unfoldable_writer_event")

    topic0_to_specs: dict[str, list[WriterEventSpec]] = {}
    for spec in writer_specs:
        topic0 = _event_topic0(spec["event_signature"])
        topic0_to_specs.setdefault(topic0, []).append(spec)
    for specs in topic0_to_specs.values():
        readings: dict[str, set[tuple[Any, ...]]] = {}
        for spec in specs:
            readings.setdefault(spec["mapping_name"], set()).add((spec.get("value_position"), spec["key_position"]))
        if any(len(r) > 1 for r in readings.values()):
            return _unscanned("incomplete_ambiguous_writer_event")

    if hypersync_module is None:
        import hypersync as hypersync_module
    if client is None:
        if not bearer_token:
            raise RuntimeError("Hypersync requires an API token; pass bearer_token= or set ENVIO_API_TOKEN.")
        from services.resolution.hypersync_bound import build_hypersync_client

        client = build_hypersync_client(hypersync_module, url=hypersync_url, bearer_token=bearer_token)

    from services.resolution.hypersync_bound import hypersync_slot

    topic0s = sorted(topic0_to_specs.keys())
    query = _build_query(hypersync_module, contract_address, topic0s, from_block, to_block)

    # (mapping_name, key) -> (value_hex, last_block, last_log_index)
    state: dict[tuple[str, str], tuple[str, int, int]] = {}
    current_from = from_block
    page_count = 0
    started = time.monotonic()
    status = "complete"
    error: str | None = None
    while True:
        if time.monotonic() - started > eff_timeout:
            status = "incomplete_timeout"
            break
        if page_count >= eff_max_pages:
            status = "incomplete_max_pages"
            break
        try:
            with hypersync_slot(bearer_token):
                result = await client.get(query)
        except Exception as exc:
            status = "error"
            error = str(exc)
            break
        page_count += 1
        data_obj = getattr(result, "data", None)
        if data_obj is not None and hasattr(data_obj, "logs"):
            logs = list(getattr(data_obj, "logs", None) or [])
        elif isinstance(data_obj, list):
            logs = data_obj
        else:
            logs = list(getattr(result, "logs", None) or [])
        for raw_log in logs:
            topics = _topics_from_log(raw_log)
            if not topics:
                continue
            topic0 = topics[0]
            matching_specs = topic0_to_specs.get(topic0)
            if not matching_specs:
                continue
            for spec in matching_specs:
                indexed = list(spec.get("indexed_positions") or [])
                key_str = _extract_key_address(raw_log, spec["key_position"], indexed_positions=indexed)
                value_pos = spec.get("value_position")
                if value_pos is None:
                    value_hex = _ZERO_WORD
                else:
                    value_hex = _extract_value_word(raw_log, int(value_pos), indexed_positions=indexed)
                if not key_str or len(value_hex) != 66:
                    status = "incomplete_undecodable_event"
                    continue
                block = int(getattr(raw_log, "block_number", 0) or 0)
                log_idx = int(getattr(raw_log, "log_index", 0) or 0)
                key_tuple = (spec["mapping_name"], key_str.lower())
                prior = state.get(key_tuple)
                if prior is None or (block, log_idx) > (prior[1], prior[2]):
                    state[key_tuple] = (value_hex, block, log_idx)

        if status != "complete":
            break
        next_from = getattr(result, "next_block", None)
        if next_from is None or next_from <= current_from:
            break
        current_from = next_from
        query = _build_query(hypersync_module, contract_address, topic0s, current_from, to_block)

    entries: list[EnumeratedKeyValue] = [
        {
            "key": key,
            "mapping_name": mapping_name,
            "value_hex": value_hex,
            "last_block": last_block,
            "last_log_index": last_log_index,
        }
        for (mapping_name, key), (value_hex, last_block, last_log_index) in state.items()
    ]
    return EnumerationValueResult(
        entries=entries,
        status=status,
        pages_fetched=page_count,
        last_block_scanned=current_from,
        error=error,
    )


# Separate from the present-set cache.
_VALUE_CACHE: dict[tuple[str, str, str], tuple[EnumerationValueResult, float]] = {}


def enumerate_mapping_values_sync(
    contract_address: str,
    writer_specs: list[WriterEventSpec],
    *,
    chain: str | None = None,
    value_predicate: dict[str, Any] | None = None,
    **kwargs: Any,
) -> EnumerationValueResult:
    """Sync wrapper for ``enumerate_mapping_values``, L1 cache only.

    L2 is shaped for ``EnumerationResult``, so value-path persistence waits on a schema change (D.3). ``chain``,
    ``value_predicate`` and the specs are accepted for when it lands.
    """
    specs_as_dicts = [dict(s) for s in writer_specs]
    # Fold entries are predicate-independent, so the key excludes value_predicate.
    cache_key = (_chain_key(chain), contract_address.lower(), _l1_specs_hash(specs_as_dicts))
    now = time.monotonic()

    with _CACHE_LOCK:
        cached = _VALUE_CACHE.get(cache_key)
        if cached is not None:
            result, inserted_at = cached
            if now - inserted_at < _cache_ttl_s():
                return result
            del _VALUE_CACHE[cache_key]

    if not kwargs.get("client") and not kwargs.get("hypersync_url"):
        scan_url = _scan_hypersync_url_for_chain(chain)
        if scan_url is None:
            return EnumerationValueResult(
                entries=[],
                status="incomplete_no_hypersync_coverage",
                pages_fetched=0,
                last_block_scanned=int(kwargs.get("from_block") or 0),
                error="hypersync_unavailable_for_chain",
            )
        kwargs["hypersync_url"] = scan_url

    result = asyncio.run(enumerate_mapping_values(contract_address, writer_specs, **kwargs))

    with _CACHE_LOCK:
        _store_enumeration(_VALUE_CACHE, cache_key, (result, now), _VALUE_PRESSURE_NAME)
    # L2 for the value path is deferred until the durable indexer (D.3).
    _ = value_predicate
    return result


def filter_value_entries(
    entries: list[EnumeratedKeyValue],
    predicate: dict[str, Any],
) -> list[str] | None:
    """Keys whose latest value satisfies ``predicate``, or ``None`` when that isn't determined.

    The keys are the whole allowed set only because a never-written key holds zero, so a predicate that admits zero
    (``== 0``, ``< 10``) allows every unwritten key and no key list answers it. A predicate or word that can't be
    evaluated is ``None`` too. Empty means no written key satisfies it; callers mark it lower_bound when the scan was
    incomplete.
    """
    if _value_predicate_passes(_ZERO_WORD, predicate) is not False:
        return None
    out: list[str] = []
    for entry in entries:
        passes = _value_predicate_passes(entry["value_hex"], predicate)
        if passes is None:
            return None
        if passes:
            out.append(entry["key"])
    return out
