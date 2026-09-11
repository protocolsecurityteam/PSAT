"""View-key membership resolution and HyperSync event-key observation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.static_analysis.predicate_types import (
    SetDescriptor,
)

from ..capabilities import (
    CapabilityExpr,
    ExternalCheck,
    union,
)
from .binding import _selector_for_signature
from .telemetry import _bump_resolve_counter

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")


def _resolve_view_key_membership(descriptor: SetDescriptor, ctx: EvaluationContext) -> CapabilityExpr | None:
    if descriptor.get("kind") != "mapping_membership":
        return None
    key_sources = list(descriptor.get("key_sources") or [])
    caller_indices = [idx for idx, source in enumerate(key_sources) if source.get("source") in _CALLER_SOURCES]
    view_indices = [idx for idx, source in enumerate(key_sources) if source.get("source") == "view_call"]
    if len(caller_indices) != 1 or len(view_indices) != 1:
        return None

    outer_ctx = getattr(getattr(ctx, "adapter", None), "_outer_ctx", None)
    session = getattr(outer_ctx, "session", None)
    rpc_url = getattr(outer_ctx, "rpc_url", None)
    if session is None or not isinstance(rpc_url, str) or not rpc_url:
        return None

    view_index = view_indices[0]
    view_source = key_sources[view_index]
    selector = view_source.get("callee_selector")
    if not isinstance(selector, str) or not selector.startswith("0x"):
        signature = view_source.get("callee_signature")
        selector = _selector_for_signature(signature) if isinstance(signature, str) else None
    if not selector:
        return None

    event_hints: list[dict[str, Any]] = [
        dict(hint) for hint in (descriptor.get("enumeration_hint") or []) if isinstance(hint, dict)
    ]
    if not event_hints:
        return None
    role_words = _observed_event_key_words(
        session=session,
        outer_ctx=outer_ctx,
        descriptor=descriptor,
        event_hints=event_hints,
        key_index=view_index,
    )
    if not role_words:
        return None

    contract_address = getattr(outer_ctx, "contract_address", None) or ctx.contract_address
    if not isinstance(contract_address, str) or not contract_address.startswith("0x"):
        return None
    admin_words = _call_unary_bytes32_view(
        rpc_url=rpc_url,
        contract_address=contract_address,
        selector=selector,
        args=role_words,
        block=getattr(outer_ctx, "block", None) or ctx.block,
    )
    if not admin_words:
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=contract_address.lower(),
                target_call_selector=selector,
                extra={"basis": ["view_key_membership_unresolved"]},
            )
        )

    result: CapabilityExpr | None = None
    for admin_word in admin_words:
        patched = dict(descriptor)
        patched_keys = [dict(source) for source in key_sources]
        patched_keys[view_index] = {"source": "constant", "constant_value": admin_word}
        patched["key_sources"] = patched_keys
        child = ctx.adapter.enumerate(cast(SetDescriptor, patched), ctx.contract_address)
        result = child if result is None else union(result, child)
    return result


def _observed_event_key_words(
    *,
    session: Any,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
) -> list[str]:
    from sqlalchemy import func, select

    from db.models import IndexedEventLog
    from services.resolution.adapters.event_indexed import _resolve_event_address
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word

    scan_chain_id = getattr(outer_ctx, "chain_id", None)
    if not isinstance(scan_chain_id, int):
        # ctx.chain_id is required (inv. 6); a chainless durable read can no longer
        # default to mainnet's indexed logs.
        return []

    out: set[str] = set()
    for hint in event_hints:
        topic0 = hint.get("topic0")
        if not isinstance(topic0, str):
            continue
        event_address = _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx)
        if event_address is None:
            continue
        stmt = (
            select(IndexedEventLog)
            .where(IndexedEventLog.chain_id == scan_chain_id)
            .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
            .where(func.lower(IndexedEventLog.topic0) == topic0.lower())
            .order_by(
                IndexedEventLog.block_number.asc(),
                IndexedEventLog.transaction_index.asc(),
                IndexedEventLog.log_index.asc(),
            )
        )
        block = getattr(outer_ctx, "block", None)
        if isinstance(block, int):
            stmt = stmt.where(IndexedEventLog.block_number <= block)
        for row in session.execute(stmt).scalars():
            keys = _event_keys(
                row.topics or [],
                row.data_words or [],
                hint.get("topics_to_keys") or {},
                hint.get("data_to_keys") or {},
            )
            word = _normalize_word(keys.get(key_index))
            if word is not None:
                out.add(word)
    if not out:
        out.update(
            _observed_event_key_words_from_hypersync(
                outer_ctx=outer_ctx,
                descriptor=descriptor,
                event_hints=event_hints,
                key_index=key_index,
            )
        )
    return sorted(out)


def _observed_event_key_words_from_hypersync(
    *,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
) -> list[str]:
    import asyncio
    import os
    import time

    from services.resolution.adapters.event_indexed import _resolve_event_address
    from services.resolution.repos.event_logs_hypersync import (
        _data_words_from_log,
        _logs_from_response,
        _topics_from_log,
    )
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word

    token = os.getenv("ENVIO_API_TOKEN") or getattr(outer_ctx, "meta", {}).get("hypersync_token")
    if not token:
        return []
    _bump_resolve_counter(outer_ctx, "hypersync_fallback_scans")
    address_topics: dict[str, set[str]] = {}
    hints_by_address_topic: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for hint in event_hints:
        topic0 = hint.get("topic0")
        if not isinstance(topic0, str):
            continue
        event_address = _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx)
        if event_address is None:
            continue
        address_topics.setdefault(event_address.lower(), set()).add(topic0.lower())
        hints_by_address_topic.setdefault((event_address.lower(), topic0.lower()), []).append(hint)
    if not address_topics:
        return []

    async def _scan() -> list[str]:
        try:
            import hypersync
        except Exception:
            return []
        from services.resolution.repos.event_logs_hypersync import _hypersync_url_for_chain

        scan_chain_id = getattr(outer_ctx, "chain_id", None)
        if not isinstance(scan_chain_id, int):
            # ctx.chain_id is required (inv. 6); no chain → no scan surface.
            return []
        # Per-chain HyperSync endpoint (inv. 5), driven by the evaluation's chain:
        # meta override, then env override, then the registry URL. A chain with no
        # registry coverage has no scan surface — skip the live scan (no members)
        # rather than silently scanning mainnet.
        # NOTE (F7): PSAT_HYPERSYNC_URL is a single-URL global — it outranks the
        # per-chain registry URL, so it is a SINGLE-CHAIN DEV OVERRIDE only. Never
        # set it in a multichain deployment or every chain's scan is pinned to one
        # endpoint; multichain routing must come from the registry (or per-eval
        # meta.hypersync_url), not this env var.
        registry_url = _hypersync_url_for_chain(scan_chain_id)
        url = getattr(outer_ctx, "meta", {}).get("hypersync_url") or os.getenv("PSAT_HYPERSYNC_URL") or registry_url
        if not url:
            return []
        url = str(url)
        timeout_s = float(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_TIMEOUT_S", "45"))
        max_pages = int(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_MAX_PAGES", "50"))
        from services.resolution.hypersync_bound import build_hypersync_client, hypersync_slot

        client = build_hypersync_client(hypersync, url=url, bearer_token=token)
        from services.resolution.creation_block_floor import resolve_scan_floor

        found: set[str] = set()
        for event_address, topic0s in address_topics.items():
            # No floor → DEFER this address (skip the live scan) rather than scan
            # from genesis; a known floor scans deploy→head.
            floor = resolve_scan_floor(
                event_address,
                scan_chain_id,
                session=getattr(outer_ctx, "session", None),
            )
            if floor is None:
                continue
            current_from = floor
            page_count = 0
            started = time.monotonic()
            while True:
                if time.monotonic() - started > timeout_s or page_count >= max_pages:
                    break
                query = hypersync.Query(
                    from_block=current_from,
                    to_block=getattr(outer_ctx, "block", None),
                    logs=[
                        hypersync.LogSelection(
                            address=[event_address],
                            topics=[sorted(topic0s)],
                        )
                    ],
                    field_selection=hypersync.FieldSelection(log=[field.value for field in hypersync.LogField]),
                )
                try:
                    with hypersync_slot(token):
                        response = await client.get(query)
                except Exception:
                    break
                page_count += 1
                for log in _logs_from_response(response):
                    topics = _topics_from_log(log)
                    if not topics:
                        continue
                    topic0 = topics[0].lower()
                    for hint in hints_by_address_topic.get((event_address, topic0), []):
                        keys = _event_keys(
                            topics,
                            _data_words_from_log(log),
                            hint.get("topics_to_keys") or {},
                            hint.get("data_to_keys") or {},
                        )
                        word = _normalize_word(keys.get(key_index))
                        if word is not None:
                            found.add(word)
                next_block = getattr(response, "next_block", None)
                if next_block is None or next_block <= current_from:
                    break
                block = getattr(outer_ctx, "block", None)
                if isinstance(block, int) and next_block >= block:
                    break
                current_from = next_block
        return sorted(found)

    try:
        return asyncio.run(_scan())
    except Exception:
        return []


def _call_unary_bytes32_view(
    *,
    rpc_url: str,
    contract_address: str,
    selector: str,
    args: list[str],
    block: int | None,
) -> list[str]:
    from services.clients.rpc import rpc_batch_request_with_status
    from services.resolution.repos.event_logs_pg import _normalize_word

    calls: list[tuple[str, list[Any]]] = []
    for arg in args:
        word = _normalize_word(arg)
        if word is None:
            continue
        calls.append(
            (
                "eth_call",
                [
                    {"to": contract_address.lower(), "data": selector + word[2:]},
                    hex(block) if isinstance(block, int) else "latest",
                ],
            )
        )
    if not calls:
        return []
    out: set[str] = set()
    for raw, had_error in rpc_batch_request_with_status(rpc_url, calls):
        if had_error:
            continue
        word = _normalize_word(raw)
        if word is not None:
            out.add(word)
    return sorted(out)
