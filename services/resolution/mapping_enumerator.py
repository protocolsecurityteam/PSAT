"""Replay mapping-writer events into current allowlist principals."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, TypedDict

from eth_utils.crypto import keccak

from services.static.contract_analysis_pipeline.mapping_events import WriterEventSpec
from utils.rpc import normalize_hex as _normalize_hex

logger = logging.getLogger(__name__)


def _mainnet_hypersync_url() -> str:
    """Mainnet HyperSync endpoint from the registry, not a hardcoded
    literal. The signature default for the enumerators below; callers thread the
    per-chain URL for non-mainnet scans."""
    from utils.chains import chain_by_id

    url = chain_by_id(1).hypersync_url
    assert url is not None  # mainnet always has HyperSync coverage
    return url


DEFAULT_HYPERSYNC_URL: str = _mainnet_hypersync_url()

# Pagination bounds (default 60s / 50 pages); without these caps a 2017-deployed contract can wedge a worker for ~80
# min. Read once at import — bounds aren't expected to change at runtime.
_TIMEOUT_S = float(os.getenv("PSAT_MAPPING_ENUMERATION_TIMEOUT_S", "60"))
_MAX_PAGES = int(os.getenv("PSAT_MAPPING_ENUMERATION_MAX_PAGES", "50"))


def _cache_ttl_s() -> float:
    """Read at call time so tests can flip TTL via monkeypatch.setenv
    without re-importing the module. Default matches the original
    in-process cache (30 min)."""
    return float(os.getenv("PSAT_MAPPING_ENUMERATION_CACHE_TTL_S", "1800"))


class EnumeratedPrincipal(TypedDict):
    address: str
    mapping_name: str
    direction_history: list[str]
    last_seen_block: int


class EnumerationResult(TypedDict):
    """Principal list + status; complete vs. truncated scans (silent [] would drop authorized addresses)."""

    principals: list[EnumeratedPrincipal]
    # "complete" | "incomplete_timeout" | "incomplete_max_pages" | "error"
    # | "incomplete_ambiguous_writer_event" (an add/remove-conflicted event was
    #   dropped: the fold is structurally missing that event's members)
    # | "incomplete_no_writer_specs" (nothing was observed at all)
    # | "incomplete_no_hypersync_coverage"
    status: str
    pages_fetched: int
    last_block_scanned: int
    error: str | None


class EnumeratedKeyValue(TypedDict):
    """One key's latest observed value (D.2). Used by the value-aware
    fold which replaces the add/remove ``present`` boolean with the
    raw value of the most recent assignment, so a downstream
    ``ValuePredicate`` can decide which keys belong in the finite
    set.
    """

    key: str  # 0x-prefixed canonical address (or 0x... hex word for non-address keys)
    mapping_name: str
    value_hex: str  # 0x-prefixed canonical hex of the latest assigned value
    last_block: int
    last_log_index: int


class EnumerationValueResult(TypedDict):
    """Latest-value-per-key fold + status (mirrors ``EnumerationResult``)."""

    entries: list[EnumeratedKeyValue]
    status: str
    pages_fetched: int
    last_block_scanned: int
    error: str | None


# Process-wide L1 caches keyed on (chain, address, specs_hash) — the same identity
# db.mapping_enumeration_cache (L2) uses — so the same address on two chains, or with
# two writer-spec sets, never collides. head_block lives in the value, not the key, so
# cascade siblings still share a scan. Both caches are size-capped (oldest 25% evicted
# at the bound); a wall-clock TTL (see _cache_ttl_s) handles staleness on top.
_CACHE: dict[tuple[str, str, str], tuple[EnumerationResult, float]] = {}
_CACHE_LOCK = threading.Lock()
_CACHE_MAX = 1024
_PRESENT_PRESSURE_NAME = "mapping_enumeration"
_VALUE_PRESSURE_NAME = "mapping_enumeration_value"


def clear_enumeration_cache() -> None:
    """Test helper. Drop all cached enumerations (allowlist present-set + value folds)."""
    from utils.memory import reset_cache_pressure_state

    with _CACHE_LOCK:
        _CACHE.clear()
        _VALUE_CACHE.clear()
    reset_cache_pressure_state(_PRESENT_PRESSURE_NAME)
    reset_cache_pressure_state(_VALUE_PRESSURE_NAME)


def _chain_key(chain: str | None) -> str:
    """Chain component of the L1 key: the canonical decimal-string chain-id token
    (invariant 11). Callers reach this with either a chain *name* (``"ethereum"``)
    or ``str(chain_id)`` (``"1"``) for the same contract; ``chain_cache_token``
    folds both onto one token so the two paths share a cache entry. L2
    (``db.mapping_enumeration_cache``) normalizes identically, so the in-process
    and durable layers stay in agreement."""
    from utils.chains import chain_cache_token

    return chain_cache_token(chain)


def _scan_hypersync_url_for_chain(chain: str | int | None) -> str | None:
    """The HyperSync scan endpoint for *chain*.

    ``chain`` is the same name / decimal-id token the cache key uses. A chainless
    call fails loud (``require_chain`` raises) rather than defaulting the scan to
    mainnet; a registered chain with no proven HyperSync coverage returns ``None``
    so the caller reports the scan unavailable instead of scanning the wrong
    chain. Mainnet resolves to its registry URL — byte-identical to the old
    ``DEFAULT_HYPERSYNC_URL`` default, so mainnet scans are unchanged.
    """
    from services.resolution.repos.event_logs_hypersync import _hypersync_url_for_chain
    from utils.chains import require_chain

    if isinstance(chain, int) or (isinstance(chain, str) and chain.strip().isdigit()):
        info = require_chain(int(chain), context="mapping enumeration hypersync url")
    else:
        info = require_chain(
            chain=chain if isinstance(chain, str) else None, context="mapping enumeration hypersync url"
        )
    return _hypersync_url_for_chain(info.chain_id)


def _l1_specs_hash(specs_as_dicts: list[dict[str, Any]]) -> str:
    """The fingerprint L2 (db.mapping_enumeration_cache) keys on, so L1 distinguishes
    the same (chain, address, specs) identity L2 does. Falls back to a local stable
    digest when the DB module isn't importable (CLI/test paths driving L1 alone)."""
    try:
        from db.mapping_enumeration_cache import specs_fingerprint

        return specs_fingerprint(specs_as_dicts)
    except Exception:
        canonical = json.dumps(specs_as_dicts, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _evict_enumeration_if_needed(cache: dict) -> None:
    """Drop the oldest 25% of *cache* by insertion time when the bound is reached
    (caller holds _CACHE_LOCK)."""
    if len(cache) < _CACHE_MAX:
        return
    cutoff = sorted(cache.values(), key=lambda v: v[1])[len(cache) // 4][1]
    for k in [k for k, v in cache.items() if v[1] <= cutoff]:
        cache.pop(k, None)


def _store_enumeration(cache: dict, cache_key: tuple[str, str, str], entry: tuple, name: str) -> None:
    """Bounded insert into an L1 enumeration cache (caller holds _CACHE_LOCK)."""
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
    """Extract the assigned value at ``value_position`` from the log.

    Returns a 0x-prefixed 32-byte hex word (the canonical "uint256
    slot" form), regardless of whether the value is indexed (topic) or
    in data. The downstream ``_value_predicate_passes`` interprets the
    bytes per ``value_type``.
    """
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


def _value_predicate_passes(value_hex: str, predicate: dict[str, Any]) -> bool:
    """Apply a ``ValuePredicate`` to a 32-byte hex word.

    Numeric ops decode as ``int(value_hex, 16)``; address ops compare
    canonicalized lowercase hex. ``any_nonzero`` matches any nonzero
    word and ignores ``rhs_values`` (used as a "is this slot ever
    written" probe).
    """
    if not value_hex.startswith("0x") or len(value_hex) != 66:
        return False
    op = str(predicate.get("op") or "")
    rhs_raw = predicate.get("rhs_values") or []
    value_type = str(predicate.get("value_type") or "uint256")
    mask_hex = predicate.get("mask")

    if op == "any_nonzero":
        body = value_hex[2:]
        return any(c not in "0" for c in body)

    if value_type == "address":
        # Compare lowercased 20-byte tail. RHS may be the full
        # checksummed address; normalize both.
        actual = "0x" + value_hex[-40:]
        for r in rhs_raw:
            r_norm = (r or "").lower()
            if not r_norm.startswith("0x"):
                continue
            if op == "eq" and r_norm[-40:] == actual[2:]:
                return True
            if op == "ne" and r_norm[-40:] != actual[2:]:
                return True
        return False

    # Numeric. Decode value, optionally apply mask, then compare.
    try:
        actual_int = int(value_hex, 16)
    except ValueError:
        return False
    if isinstance(mask_hex, str) and mask_hex.startswith("0x"):
        try:
            actual_int = actual_int & int(mask_hex, 16)
        except ValueError:
            pass
    if op == "in":
        rhs_set = {_to_int(r) for r in rhs_raw}
        rhs_set.discard(None)  # type: ignore[arg-type]
        return actual_int in rhs_set
    if not rhs_raw:
        return False
    rhs_int = _to_int(rhs_raw[0])
    if rhs_int is None:
        return False
    if op == "eq":
        return actual_int == rhs_int
    if op == "ne":
        return actual_int != rhs_int
    if op == "lt":
        return actual_int < rhs_int
    if op == "lte":
        return actual_int <= rhs_int
    if op == "gt":
        return actual_int > rhs_int
    if op == "gte":
        return actual_int >= rhs_int
    return False


def _to_int(s: Any) -> int | None:
    if not isinstance(s, str):
        return None
    try:
        return int(s, 16) if s.startswith("0x") else int(s)
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
    """Replay mapping-writer events into a current-allowlist principal list, surfacing truncation via
    ``EnumerationResult.status``."""
    eff_timeout = _TIMEOUT_S if timeout_s is None else timeout_s
    eff_max_pages = _MAX_PAGES if max_pages is None else max_pages

    if not writer_specs:
        # No writer specs means nothing was observed, not that the mapping
        # provably has no members — "complete" here would publish a vacuous
        # scan as an exhaustive one.
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
        # Every writer event was ambiguous: the fold KNOWS it scanned nothing.
        # Reporting "complete" here published exactly the same value as a real
        # exhaustive empty scan (observed in production with pages_fetched=0
        # below the first real log). The consumers already
        # handle any non-"complete" status as a truncated enumeration.
        return EnumerationResult(
            principals=[],
            status="incomplete_ambiguous_writer_event",
            pages_fetched=0,
            last_block_scanned=from_block,
            error=None,
        )

    if hypersync_module is None:
        import hypersync as hypersync_module  # type: ignore
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
    # A fold that dropped an ambiguous writer event is incomplete BY
    # CONSTRUCTION, whatever the scan does: members written only through the
    # dropped event are invisible. Timeout/page-cap/error below may overwrite
    # with their own (also non-"complete") status.
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
    """Sync wrapper with two-tier TTL cache.

    L1 is the in-process module dict — fast, but only covers same-process
    repeats. L2 is ``db.mapping_enumeration_cache`` — Postgres-backed and
    cross-process, so the resolution stage and the policy stage of the
    same job (which run in different worker processes since 9ce6fa3) hit
    each other's results instead of re-paying the 60s hypersync scan.

    On miss we run the underlying enumeration, then write back to L2
    first so other processes see it, then to L1. ``incomplete_*`` and
    ``error`` results are cached at both tiers — re-running them inside
    the TTL would just hit the same bound; the caller sees the
    ``status`` field and decides whether to act on partial data. A
    status that L2 cannot store would break that: the rejected write
    leaves the prior row standing, so an in-TTL ``complete`` would be
    served in place of the truncated verdict that superseded it. Adding
    a status therefore has a schema obligation —
    ``tests/test_mapping_enumeration_status_vocabulary.py`` scrapes this
    module for the vocabulary and round-trips every member through the
    real column, so an oversized one is a red suite, not a silent
    republish.
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
                result = EnumerationResult(**db_hit)  # type: ignore[typeddict-item]
                with _CACHE_LOCK:
                    _store_enumeration(_CACHE, cache_key, (result, now), _PRESENT_PRESSURE_NAME)
                return result
    else:
        specs_hash = None

    # Per-chain scan URL: derive from ``chain`` unless the caller pinned
    # an explicit URL or injected a client (tests). Mainnet is byte-identical to
    # the old default; an unknown/missing chain fails loud; a no-coverage chain
    # returns unavailable rather than silently scanning mainnet.
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
            logger.warning(
                "mapping_enumerator: L2 write failed",
                extra={"address": contract_address, "exc_type": type(exc).__name__},
            )

    with _CACHE_LOCK:
        _store_enumeration(_CACHE, cache_key, (result, now), _PRESENT_PRESSURE_NAME)
    return result


def _db_cache_enabled() -> bool:
    """Imported lazily so test code that hasn't pulled in the DB module
    can still drive the in-process path. The env var defaults ON; tests
    that want the in-process behaviour set ``PSAT_MAPPING_ENUMERATION_DB_CACHE=0``.
    """
    return os.getenv("PSAT_MAPPING_ENUMERATION_DB_CACHE", "1").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# D.2 — value-aware fold: latest-value-per-key, filterable by ValuePredicate.
# ---------------------------------------------------------------------------


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
    """Replay set-style writer events into a latest-value-per-key map.

    Differs from ``enumerate_mapping_allowlist``: that one uses
    ``direction in {"add","remove"}`` to fold a present-set; this one
    uses ``direction == "set"`` (or any direction with
    ``value_position`` populated) to remember the most recent value
    each key was assigned. Caller (the EventIndexedAdapter D.2 path)
    then filters by ``ValuePredicate``.
    """
    eff_timeout = _TIMEOUT_S if timeout_s is None else timeout_s
    eff_max_pages = _MAX_PAGES if max_pages is None else max_pages

    if not writer_specs:
        return EnumerationValueResult(
            entries=[], status="complete", pages_fetched=0, last_block_scanned=from_block, error=None
        )

    # Only specs with a known value_position participate; without it
    # we have no idea which event arg holds the assigned value.
    eligible = [s for s in writer_specs if s.get("value_position") is not None]
    if not eligible:
        return EnumerationValueResult(
            entries=[], status="complete", pages_fetched=0, last_block_scanned=from_block, error=None
        )

    topic0_to_specs: dict[str, list[WriterEventSpec]] = {}
    for spec in eligible:
        topic0 = _event_topic0(spec["event_signature"])
        topic0_to_specs.setdefault(topic0, []).append(spec)

    if hypersync_module is None:
        import hypersync as hypersync_module  # type: ignore
    if client is None:
        if not bearer_token:
            raise RuntimeError("Hypersync requires an API token; pass bearer_token= or set ENVIO_API_TOKEN.")
        from services.resolution.hypersync_bound import build_hypersync_client

        client = build_hypersync_client(hypersync_module, url=hypersync_url, bearer_token=bearer_token)

    from services.resolution.hypersync_bound import hypersync_slot

    topic0s = sorted(topic0_to_specs.keys())
    query = _build_query(hypersync_module, contract_address, topic0s, from_block, to_block)

    # state: (mapping_name, key) -> (value_hex, last_block, last_log_index)
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
                if not key_str:
                    continue
                value_pos = spec.get("value_position")
                if value_pos is None:
                    continue
                value_hex = _extract_value_word(raw_log, int(value_pos), indexed_positions=indexed)
                if not value_hex:
                    continue
                block = int(getattr(raw_log, "block_number", 0) or 0)
                log_idx = int(getattr(raw_log, "log_index", 0) or 0)
                key_tuple = (spec["mapping_name"], key_str.lower())
                prior = state.get(key_tuple)
                if prior is None or (block, log_idx) > (prior[1], prior[2]):
                    state[key_tuple] = (value_hex, block, log_idx)

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


# Separate L1 cache for the value path so a re-run with a different
# predicate doesn't blow away the present-set cache.
_VALUE_CACHE: dict[tuple[str, str, str], tuple[EnumerationValueResult, float]] = {}


def enumerate_mapping_values_sync(
    contract_address: str,
    writer_specs: list[WriterEventSpec],
    *,
    chain: str | None = None,
    value_predicate: dict[str, Any] | None = None,
    **kwargs: Any,
) -> EnumerationValueResult:
    """Sync wrapper for ``enumerate_mapping_values``.

    L1 (in-process) cache only. L2 / Postgres caching for the value
    path is deferred — ``MappingEnumerationCache`` is shaped for the
    add/remove ``EnumerationResult`` and the value-aware fold
    produces a different shape (``EnumerationValueResult``). Wiring
    L2 here would require either widening the cache schema or
    serializing ``EnumerationValueResult`` into the existing
    columns, so value-aware replay remains an in-process cache path.

    ``chain``, ``value_predicate``, and the dict-converted writer
    specs are accepted for forward-compatibility — the
    ``specs_fingerprint`` extension at
    ``db/mapping_enumeration_cache.py:51`` already accepts a
    ``value_predicate`` kwarg, so once the L2 schema lands here the
    fingerprint will key on it. Until then they're pass-through
    arguments only.
    """
    specs_as_dicts = [dict(s) for s in writer_specs]
    # The fold entries are predicate-independent (filter_value_entries applies the
    # predicate downstream), so the key excludes value_predicate: a re-run with a
    # different predicate HITs the same scan instead of re-paginating.
    cache_key = (_chain_key(chain), contract_address.lower(), _l1_specs_hash(specs_as_dicts))
    now = time.monotonic()

    with _CACHE_LOCK:
        cached = _VALUE_CACHE.get(cache_key)
        if cached is not None:
            result, inserted_at = cached
            if now - inserted_at < _cache_ttl_s():
                return result
            del _VALUE_CACHE[cache_key]

    # Per-chain scan URL: see ``enumerate_mapping_allowlist_sync``.
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
    # L2 / Postgres caching for the value path is intentionally deferred — the L2
    # schema is keyed on EnumerationResult shape, not EnumerationValueResult, so
    # persisting requires a schema change we'll do alongside the durable indexer (D.3).
    _ = value_predicate
    return result


def filter_value_entries(
    entries: list[EnumeratedKeyValue],
    predicate: dict[str, Any],
) -> list[str]:
    """Return the keys whose latest value satisfies ``predicate``.

    Caller-friendly wrapper around ``_value_predicate_passes`` that
    takes the entry list as produced by ``enumerate_mapping_values``
    and emits the matching keys. Empty list means either no events
    seen or no key passed the predicate; the caller surfaces that as
    ``finite_set([])`` with quality lower_bound when the underlying
    scan was incomplete."""
    out: list[str] = []
    for entry in entries:
        if _value_predicate_passes(entry["value_hex"], predicate):
            out.append(entry["key"])
    return out
