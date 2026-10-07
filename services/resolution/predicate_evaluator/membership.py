"""View-key membership resolution and HyperSync event-key observation."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.contract_analysis_pipeline.predicate_types import (
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

# Observed event keys are only assumed to be valid view arguments. When they are not (ERC721
# ``isApprovedForAll(ownerOf(tokenId), sender)`` yields owner addresses, not token ids), every call
# reverts: the 2026-10-05 ENS BaseRegistrar run spent ~1M reverting eth_calls this way.
_VIEW_KEY_LIMIT = 256
_VIEW_KEY_PROBE = 16


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
    contract_address = getattr(outer_ctx, "contract_address", None) or ctx.contract_address
    if role_words is None:
        from services.resolution.repos.event_logs_pg import UNDECODABLE_EVENT_DATA

        # A key the index holds but can't decode would be silently missing from the union below.
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=contract_address.lower() if isinstance(contract_address, str) else None,
                target_call_selector=selector,
                extra={"basis": ["view_key_membership_unresolved", UNDECODABLE_EVENT_DATA]},
            )
        )
    if not role_words:
        return None

    if not isinstance(contract_address, str) or not contract_address.startswith("0x"):
        return None
    if len(role_words) > _VIEW_KEY_LIMIT:
        logger.warning(
            "view-key membership skipped: %d observed keys exceed limit %d for %s",
            len(role_words),
            _VIEW_KEY_LIMIT,
            contract_address,
        )
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=contract_address.lower(),
                target_call_selector=selector,
                extra={"basis": ["view_key_membership_unresolved", "view_key_limit_exceeded"]},
            )
        )
    block = getattr(outer_ctx, "block", None) or ctx.block
    admin_words = _call_unary_bytes32_view(
        rpc_url=rpc_url,
        contract_address=contract_address,
        selector=selector,
        args=role_words[:_VIEW_KEY_PROBE],
        block=block,
    )
    # An all-reverting probe means the keys are not this view's domain; the rest would revert too.
    if admin_words and len(role_words) > _VIEW_KEY_PROBE:
        rest = _call_unary_bytes32_view(
            rpc_url=rpc_url,
            contract_address=contract_address,
            selector=selector,
            args=role_words[_VIEW_KEY_PROBE:],
            block=block,
        )
        admin_words = sorted(set(admin_words) | set(rest))
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
) -> list[str] | None:
    """Key words observed in the indexed rows for ``event_hints``; None when a row carries undecodable data."""
    from sqlalchemy import func, select

    from db.models import IndexedEventLog
    from services.resolution.adapters.event_indexed import _resolve_event_address
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word, row_is_undecodable

    scan_chain_id = getattr(outer_ctx, "chain_id", None)
    if not isinstance(scan_chain_id, int):
        # Chainless reads can't default to mainnet.
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
            if row_is_undecodable(row):
                return None
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
    from services.resolution.hypersync_bound import data_words_from_log, logs_from_response, topics_from_log
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
        from services.resolution.hypersync_bound import hypersync_url_for_chain

        scan_chain_id = getattr(outer_ctx, "chain_id", None)
        if not isinstance(scan_chain_id, int):
            return []
        # Per-chain endpoint: meta override, env override, registry. No coverage means no scan.
        # ``PSAT_HYPERSYNC_URL`` overrides every chain, so it's a single-chain dev override only.
        registry_url = hypersync_url_for_chain(scan_chain_id)
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
            # No floor: defer rather than scan from genesis.
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
                for log in logs_from_response(response):
                    topics = topics_from_log(log)
                    if not topics:
                        continue
                    topic0 = topics[0].lower()
                    for hint in hints_by_address_topic.get((event_address, topic0), []):
                        keys = _event_keys(
                            topics,
                            data_words_from_log(log),
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
