"""Generic event-indexed adapter.

Covers any storage var whose writes are observable through events.
The static stage's ``mapping_events.py`` detector populates
``set_descriptor.enumeration_hint`` with EventHint records describing
the event address, topic, key positions, and fold direction. This
adapter consumes those records directly with no per-standard adapter.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, cast

from ..capabilities import CapabilityExpr, Confidence, ExternalCheck, MembershipQuality
from . import EnumerationResult, EvaluationContext

logger = logging.getLogger(__name__)


class EventIndexedAdapter:
    """Generic adapter for storage vars with enumeration_hint
    populated. Folds event-add/remove records into a current member
    set."""

    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        hints = descriptor.get("enumeration_hint")
        if not hints:
            return 0
        # Require at least one add/remove event hint with topic0.
        for hint in hints:
            if hint.get("topic0") and hint.get("direction") in ("add", "remove"):
                return 50
        # D.2 — value-predicate dispatch. ``set`` direction + a
        # ``value_predicate`` on the descriptor + a ``value_position``
        # in the hint is the shape ``OwnerSet(addr, val)`` produces.
        if descriptor.get("value_predicate"):
            for hint in hints:
                if hint.get("topic0") and hint.get("direction") == "set" and hint.get("value_position") is not None:
                    return 55
        return 0

    @classmethod
    def supports_external_check_only(cls) -> bool:
        return True

    def enumerate(self, descriptor: dict, ctx: EvaluationContext) -> CapabilityExpr:
        # D.2 — when the descriptor carries a ValuePredicate and at
        # least one ``set``-direction hint, dispatch to the value-aware
        # fold path (latest-value-per-key, filtered by predicate)
        # rather than the add/remove present-set fold.
        value_predicate = descriptor.get("value_predicate")
        hints = descriptor.get("enumeration_hint") or []
        if value_predicate and ctx.contract_address is not None:
            set_hints = [
                h
                for h in hints
                if h.get("direction") == "set" and h.get("value_position") is not None and h.get("topic0")
            ]
            if set_hints:
                return self._enumerate_value_predicate(descriptor, set_hints, value_predicate, ctx)

        repo = ctx.event_log_repo or (ctx.meta.get("event_log_repo") if ctx.meta else None)
        if repo is None or not hints:
            primary = next(
                (h for h in hints if h.get("topic0") and h.get("direction") in ("add", "remove")),
                None,
            )
            if primary is None:
                return CapabilityExpr.unsupported("event_indexed_no_hint")
            return self._external_check(descriptor, primary, ctx, ["no_event_log_repo"])

        grouped_hints: dict[str, list[dict]] = {}
        primary_hint: dict | None = None
        for hint in hints:
            topic0 = hint.get("topic0")
            direction = hint.get("direction")
            if not topic0 or direction not in ("add", "remove"):
                continue
            primary_hint = primary_hint or hint
            event_address = _resolve_event_address(descriptor, hint, ctx)
            if event_address is None:
                return self._external_check(descriptor, hint, ctx, ["event_address_unresolved"])
            grouped_hints.setdefault(event_address, []).append(hint)

        if not grouped_hints or primary_hint is None:
            return CapabilityExpr.unsupported("event_indexed_no_hint")
        if not any(hint.get("direction") == "add" for group in grouped_hints.values() for hint in group):
            return self._external_check(descriptor, primary_hint, ctx, ["event_indexed_no_add_hint"])

        key_sources = _contextual_key_sources(descriptor.get("key_sources") or [], ctx)
        merged: list[str] = []
        worst_confidence = Confidence.ENUMERABLE
        last_block: int | None = None
        for event_address, event_hints in grouped_hints.items():
            first_hint = event_hints[0]
            try:
                result = _fold_event_history(
                    repo=repo,
                    chain_id=ctx.chain_id,
                    event_address=event_address,
                    event_hints=event_hints,
                    key_sources=key_sources,
                    block=ctx.block,
                )
            except Exception as exc:
                logger.error(
                    "Event-indexed history fold failed chain_id=%s event_address=%s: %s",
                    ctx.chain_id,
                    event_address,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                raise RuntimeError(
                    f"event-indexed history fold failed for chain_id={ctx.chain_id} event_address={event_address}"
                ) from exc
            if result.confidence == Confidence.PARTIAL and result.partial_reason in {
                "event_history_fold_unavailable",
                "unresolved_event_key",
            }:
                return self._external_check(descriptor, first_hint, ctx, [result.partial_reason])
            if result.confidence == Confidence.PARTIAL and result.partial_reason == "no_index_cursor":
                return self._external_check(descriptor, first_hint, ctx, [result.partial_reason])
            merged.extend(result.members)
            if result.confidence == Confidence.PARTIAL and worst_confidence == Confidence.ENUMERABLE:
                worst_confidence = Confidence.PARTIAL
            if result.last_indexed_block is not None:
                last_block = (
                    result.last_indexed_block if last_block is None else min(last_block, result.last_indexed_block)
                )

        return CapabilityExpr.finite_set(
            merged,
            quality=MembershipQuality.EXACT
            if worst_confidence == Confidence.ENUMERABLE
            else MembershipQuality.LOWER_BOUND,
            confidence=worst_confidence,
            last_indexed_block=last_block,
        )

    def _external_check(
        self,
        descriptor: dict,
        hint: dict,
        ctx: EvaluationContext,
        basis: list[str],
    ) -> CapabilityExpr:
        extra: dict[str, Any] = {
            "basis": basis,
            "topic0": hint.get("topic0"),
            "direction": hint.get("direction"),
            "callee_function": descriptor.get("callee_function"),
            "callee_signature": descriptor.get("callee_signature"),
        }
        # See solmate_roles._check_only: tag only the index-cold ``no_index_cursor``
        # deferral so the deferred-resolution reconciler retries it once the event
        # address's logs finish indexing. Structural/transient bases
        # (event_address_unresolved, unresolved_event_key, event_log_backend_error)
        # are not waiting on the index and are left unmarked.
        if "no_index_cursor" in basis:
            extra["deferred_pending_index"] = True
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=_resolve_event_address(descriptor, hint, ctx),
                target_call_selector=descriptor.get("callee_selector"),
                extra=extra,
            )
        )

    def _enumerate_value_predicate(
        self,
        descriptor: dict,
        set_hints: list[dict],
        value_predicate: dict,
        ctx: EvaluationContext,
    ) -> CapabilityExpr:
        """D.2 fold: latest-value-per-key, filtered by ``value_predicate``.

        Uses ``services.resolution.mapping_enumerator`` to replay events
        on demand. The result is a ``finite_set`` of keys whose latest
        value satisfies the predicate. ``status != complete`` from the
        underlying scan demotes ``quality`` to ``lower_bound``.
        """
        contract_address = ctx.contract_address or ""
        # Reconstruct WriterEventSpec dicts the enumerator expects from
        # the EventHint payload. The hint already carries ``topic0``,
        # ``event_signature``, ``key_position`` etc. — we just rename
        # to the spec keys.
        writer_specs = []
        for hint in set_hints:
            writer_specs.append(
                {
                    "mapping_name": hint.get("mapping_name") or descriptor.get("storage_var") or "",
                    "event_signature": hint.get("event_signature") or "",
                    "event_name": hint.get("event_name") or "",
                    "key_position": int(hint.get("key_position") or 0),
                    "indexed_positions": list(hint.get("indexed_positions") or []),
                    "direction": "set",
                    "writer_function": hint.get("writer_function") or "",
                    "value_position": int(hint["value_position"]),
                }
            )

        from ..mapping_enumerator import enumerate_mapping_values_sync, filter_value_entries

        try:
            scan = enumerate_mapping_values_sync(
                contract_address,
                writer_specs,  # type: ignore[arg-type]
                chain_id=ctx.chain_id,
                value_predicate=value_predicate,
            )
        except Exception as exc:
            logger.error(
                "Mapping value scan failed chain_id=%s contract=%s: %s",
                ctx.chain_id,
                contract_address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            raise RuntimeError(
                f"mapping value scan failed for chain_id={ctx.chain_id} contract={contract_address}"
            ) from exc

        keys = filter_value_entries(scan["entries"], value_predicate)
        is_complete = scan["status"] == "complete"
        return CapabilityExpr.finite_set(
            keys,
            quality=MembershipQuality.EXACT if is_complete else MembershipQuality.LOWER_BOUND,
            confidence=Confidence.ENUMERABLE if is_complete else Confidence.PARTIAL,
            last_indexed_block=scan["last_block_scanned"] or None,
        )


def _resolve_event_address(descriptor: dict, hint: dict, ctx: EvaluationContext) -> str | None:
    raw = hint.get("event_address")
    if isinstance(raw, str) and raw.startswith("0x") and len(raw) == 42:
        return raw.lower()

    authority = descriptor.get("authority_contract") or {}
    raw = authority.get("address")
    if isinstance(raw, str) and raw.startswith("0x") and len(raw) == 42:
        return raw.lower()

    source = authority.get("address_source") or {}
    if source.get("source") == "state_variable":
        name = source.get("state_variable_name")
        values = ctx.state_var_values or {}
        value = values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return value.lower()

    if ctx.contract_address and ctx.contract_address.startswith("0x") and len(ctx.contract_address) == 42:
        return ctx.contract_address.lower()
    return None


def _contextual_key_sources(key_sources: list[dict], ctx: EvaluationContext) -> list[dict]:
    out: list[dict] = []
    values = ctx.state_var_values or {}
    for source in key_sources:
        if source.get("source") == "self_address" and ctx.contract_address:
            out.append({"source": "constant", "constant_value": ctx.contract_address})
            continue
        resolved = _contextual_constant_value(source, values)
        if resolved is not None:
            patched = dict(source)
            patched["source"] = "constant"
            patched["constant_value"] = resolved
            out.append(patched)
            continue
        out.append(source)
    return out


def _contextual_constant_value(source: dict, values: dict[str, str]) -> str | None:
    if source.get("constant_value") is not None:
        return None
    name = None
    if source.get("source") == "state_variable":
        name = source.get("state_variable_name")
    elif source.get("source") in {"external_call", "view_call"}:
        name = source.get("callee")
    if not isinstance(name, str) or not name:
        return None
    value = values.get(name)
    if isinstance(value, str) and value.startswith("0x") and len(value) in {42, 66}:
        return value.lower()
    return None


def _fold_event_history(
    *,
    repo: object,
    chain_id: int,
    event_address: str,
    event_hints: list[dict],
    key_sources: list[dict],
    block: int | None,
) -> EnumerationResult:
    fold_history = getattr(repo, "fold_event_history", None)
    if callable(fold_history):
        typed_fold_history = cast(Callable[..., EnumerationResult], fold_history)
        return typed_fold_history(
            chain_id=chain_id,
            event_address=event_address,
            event_hints=event_hints,
            key_sources=key_sources,
            block=block,
        )
    if len(event_hints) != 1:
        return EnumerationResult(
            members=[],
            confidence=Confidence.PARTIAL,
            partial_reason="event_history_fold_unavailable",
        )

    hint = event_hints[0]
    fold_writes = getattr(repo, "fold_event_writes", None)
    if not callable(fold_writes):
        return EnumerationResult(
            members=[],
            confidence=Confidence.PARTIAL,
            partial_reason="event_history_fold_unavailable",
        )
    typed_fold_writes = cast(Callable[..., EnumerationResult], fold_writes)
    return typed_fold_writes(
        chain_id=chain_id,
        event_address=event_address,
        topic0=hint.get("topic0"),
        topics_to_keys=hint.get("topics_to_keys") or {},
        data_to_keys=hint.get("data_to_keys") or {},
        key_sources=key_sources,
        direction=hint.get("direction"),
        block=block,
    )
