"""View-key membership resolution and HyperSync event-key observation."""

from __future__ import annotations

import logging
from collections.abc import Collection
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, NamedTuple, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.static.contract_analysis_pipeline.predicate_types import (
    SetDescriptor,
)
from utils.logging import record_degraded

from ..capabilities import (
    CapabilityExpr,
    ExternalCheck,
    union,
)
from ..pass_memo import canonical, memoized
from .binding import _selector_for_canonical_signature, _stored_dispatch_selector
from .telemetry import _bump_resolve_counter

if TYPE_CHECKING:
    from .core import EvaluationContext

logger = logging.getLogger("services.resolution.predicate_evaluator")

# Some writer log through the block went unread: a cold or ineligible cursor, a failed tail, or a cut-short scan.
UNPROVEN_EVENT_KEYS = "event_keys_unproven"


class ObservedKeyWords(NamedTuple):
    """Key words seen in writer events; ``complete`` only when every writer log through the block was read."""

    words: list[str]
    complete: bool


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
    signature = view_source.get("callee_signature")
    selector = _stored_dispatch_selector(view_source.get("callee_selector"), signature)
    if not isinstance(selector, str) or not selector.startswith("0x"):
        selector = _selector_for_canonical_signature(signature)
    if not selector:
        return None

    event_hints: list[dict[str, Any]] = [
        dict(hint) for hint in (descriptor.get("enumeration_hint") or []) if isinstance(hint, dict)
    ]
    if not event_hints:
        return None
    observed = _observed_event_key_words(
        session=session,
        outer_ctx=outer_ctx,
        descriptor=descriptor,
        event_hints=event_hints,
        key_index=view_index,
    )
    contract_address = getattr(outer_ctx, "contract_address", None) or ctx.contract_address
    if observed is None or not observed.complete:
        from services.resolution.repos.event_logs_pg import UNDECODABLE_EVENT_DATA

        # A key missing from the union below would drop its admins from the published principals.
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=contract_address.lower() if isinstance(contract_address, str) else None,
                target_call_selector=selector,
                extra={
                    "basis": [
                        "view_key_membership_unresolved",
                        UNDECODABLE_EVENT_DATA if observed is None else UNPROVEN_EVENT_KEYS,
                    ]
                },
            )
        )
    role_words = observed.words
    if not role_words:
        return None

    if not isinstance(contract_address, str) or not contract_address.startswith("0x"):
        return None
    view_block = getattr(outer_ctx, "block", None) or ctx.block
    admin_words = memoized(
        outer_ctx,
        ("unary_bytes32_view", rpc_url, contract_address.lower(), selector.lower(), tuple(role_words), view_block),
        lambda: _call_unary_bytes32_view(
            rpc_url=rpc_url,
            contract_address=contract_address,
            selector=selector,
            args=role_words,
            block=view_block,
        ),
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
) -> ObservedKeyWords | None:
    """Key words observed in the writer logs for ``event_hints``; None when a log carries undecodable data."""
    from services.resolution.adapters.event_indexed import _resolve_event_address

    hint_key = tuple(
        (
            _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx),
            str(hint.get("topic0") or "").lower(),
            canonical(hint.get("topics_to_keys") or {}),
            canonical(hint.get("data_to_keys") or {}),
        )
        for hint in event_hints
    )
    return memoized(
        outer_ctx,
        (
            "observed_event_key_words",
            getattr(outer_ctx, "chain_id", None),
            getattr(outer_ctx, "block", None),
            hint_key,
            key_index,
            id(session),
        ),
        lambda: _scan_observed_event_key_words(
            session=session,
            outer_ctx=outer_ctx,
            descriptor=descriptor,
            event_hints=event_hints,
            key_index=key_index,
        ),
        keep_alive=(session,),
    )


def _scan_observed_event_key_words(
    *,
    session: Any,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
) -> ObservedKeyWords | None:
    from services.resolution.event_tail import tail_scanner_for
    from services.resolution.repos.event_logs_pg import PostgresEventLogRepo, UndecodableEventRow, _row_topic0

    scan_chain_id = getattr(outer_ctx, "chain_id", None)
    if not isinstance(scan_chain_id, int):
        # Chainless reads can't default to mainnet.
        return ObservedKeyWords(words=[], complete=False)
    address_topics, hints_by_address_topic, unaddressed = _hints_by_event_address(descriptor, event_hints, outer_ctx)

    repo = PostgresEventLogRepo(session)
    tail = tail_scanner_for(outer_ctx)
    out: set[str] = set()
    unproven: set[str] = set()
    for event_address, topic0s in address_topics.items():
        try:
            read = repo.logs_through_block(
                chain_id=scan_chain_id,
                event_address=event_address,
                topic0s=sorted(topic0s),
                block=getattr(outer_ctx, "block", None),
                tail=tail,
            )
        except UndecodableEventRow:
            return None
        if not read.complete:
            unproven.add(event_address)
            continue
        for log in read.logs:
            words = _log_key_words(log, hints_by_address_topic.get((event_address, _row_topic0(log)), []), key_index)
            if words is None:
                return None
            out.update(words)
    complete = not unaddressed
    if unproven:
        scanned = _observed_event_key_words_from_hypersync(
            outer_ctx=outer_ctx,
            descriptor=descriptor,
            event_hints=event_hints,
            key_index=key_index,
            event_addresses=unproven,
        )
        out.update(scanned.words)
        complete = complete and scanned.complete
    return ObservedKeyWords(words=sorted(out), complete=complete)


def _hints_by_event_address(
    descriptor: SetDescriptor, event_hints: list[dict[str, Any]], outer_ctx: Any
) -> tuple[dict[str, set[str]], dict[tuple[str, str], list[dict[str, Any]]], bool]:
    """Topics per event address and hints per ``(address, topic0)``; the flag is set when a hint names no readable
    event, so no read of the rest can prove the key set.
    """
    from services.resolution.adapters.event_indexed import _resolve_event_address

    address_topics: dict[str, set[str]] = {}
    hints_by_address_topic: dict[tuple[str, str], list[dict[str, Any]]] = {}
    unaddressed = False
    for hint in event_hints:
        topic0 = hint.get("topic0")
        event_address = _resolve_event_address(cast(dict[str, Any], descriptor), hint, outer_ctx)
        if not isinstance(topic0, str) or event_address is None:
            unaddressed = True
            continue
        address_topics.setdefault(event_address.lower(), set()).add(topic0.lower())
        hints_by_address_topic.setdefault((event_address.lower(), topic0.lower()), []).append(hint)
    return address_topics, hints_by_address_topic, unaddressed


def _log_key_words(log: Any, hints: list[dict[str, Any]], key_index: int) -> set[str] | None:
    """The key words ``log`` writes, or None when a hint can't read its key from it: a writer log always carries every
    key, so a missing one is unreadable data, not an empty write.
    """
    from services.resolution.repos.event_logs_pg import _event_keys, _normalize_word

    words: set[str] = set()
    for hint in hints:
        keys = _event_keys(
            list(getattr(log, "topics", None) or []),
            list(getattr(log, "data_words", None) or []),
            hint.get("topics_to_keys") or {},
            hint.get("data_to_keys") or {},
        )
        word = _normalize_word(keys.get(key_index))
        if word is None:
            return None
        words.add(word)
    return words


def _observed_event_key_words_from_hypersync(
    *,
    outer_ctx: Any,
    descriptor: SetDescriptor,
    event_hints: list[dict[str, Any]],
    key_index: int,
    event_addresses: Collection[str] | None = None,
) -> ObservedKeyWords:
    """Key words from a HyperSync replay of ``event_hints`` (only ``event_addresses`` when given) through the pinned
    block; ``complete`` only when every address was scanned from its floor through that block.
    """
    import asyncio
    import os
    import time

    from services.resolution.hypersync_bound import data_words_from_log, logs_from_response, topics_from_log

    incomplete = ObservedKeyWords(words=[], complete=False)
    token = os.getenv("ENVIO_API_TOKEN") or getattr(outer_ctx, "meta", {}).get("hypersync_token")
    block = getattr(outer_ctx, "block", None)
    # Unpinned, the archive tip is the only end a scan could reach, and it proves nothing about the block read later.
    if not token or not isinstance(block, int):
        return incomplete
    address_topics, hints_by_address_topic, unaddressed = _hints_by_event_address(descriptor, event_hints, outer_ctx)
    if event_addresses is not None:
        wanted = {a.lower() for a in event_addresses}
        address_topics = {a: t for a, t in address_topics.items() if a in wanted}
    if not address_topics:
        return incomplete
    _bump_resolve_counter(outer_ctx, "hypersync_fallback_scans")

    async def _scan() -> ObservedKeyWords:
        try:
            import hypersync
        except Exception:
            return incomplete
        from services.resolution.hypersync_bound import hypersync_url_for_chain

        scan_chain_id = getattr(outer_ctx, "chain_id", None)
        if not isinstance(scan_chain_id, int):
            return incomplete
        # Per-chain endpoint: meta override, env override, registry. No coverage means no scan.
        # ``PSAT_HYPERSYNC_URL`` overrides every chain, so it's a single-chain dev override only.
        registry_url = hypersync_url_for_chain(scan_chain_id)
        url = getattr(outer_ctx, "meta", {}).get("hypersync_url") or os.getenv("PSAT_HYPERSYNC_URL") or registry_url
        if not url:
            return incomplete
        url = str(url)
        timeout_s = float(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_TIMEOUT_S", "45"))
        max_pages = int(os.getenv("PSAT_HYPERSYNC_EVENT_FALLBACK_MAX_PAGES", "50"))
        from services.resolution.hypersync_bound import build_hypersync_client, hypersync_slot

        client = build_hypersync_client(hypersync, url=url, bearer_token=token)
        from services.resolution.creation_block_floor import resolve_scan_floor

        found: set[str] = set()
        complete = not unaddressed
        for event_address, topic0s in address_topics.items():
            # No floor: defer rather than scan from genesis.
            floor = resolve_scan_floor(
                event_address,
                scan_chain_id,
                session=getattr(outer_ctx, "session", None),
            )
            if floor is None:
                complete = False
                continue
            current_from = floor
            page_count = 0
            started = time.monotonic()
            reached_end = False
            readable = True
            while time.monotonic() - started <= timeout_s and page_count < max_pages:
                query = hypersync.Query(
                    from_block=current_from,
                    # ``to_block`` is exclusive.
                    to_block=block + 1,
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
                except Exception as exc:
                    record_degraded(
                        phase="observed_event_key_words_scan",
                        exc=exc,
                        context={"event_address": event_address, "page_count": page_count},
                    )
                    break
                page_count += 1
                for log in logs_from_response(response):
                    topics = topics_from_log(log)
                    hints = hints_by_address_topic.get((event_address, topics[0].lower()), []) if topics else []
                    words = _log_key_words(
                        SimpleNamespace(topics=topics, data_words=data_words_from_log(log)), hints, key_index
                    )
                    if not hints or words is None:
                        readable = False
                    else:
                        found.update(words)
                next_block = getattr(response, "next_block", None)
                if not isinstance(next_block, int) or next_block <= current_from:
                    # A stalled or lagging archive stops short of the block.
                    break
                if next_block > block:
                    reached_end = True
                    break
                current_from = next_block
            complete = complete and reached_end and readable
        return ObservedKeyWords(words=sorted(found), complete=complete)

    try:
        return asyncio.run(_scan())
    except Exception as exc:
        record_degraded(
            phase="observed_event_key_words_scan", exc=exc, context={"chain_id": getattr(outer_ctx, "chain_id", None)}
        )
        return incomplete


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
