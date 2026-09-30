"""Generic event-indexed adapter: folds ``set_descriptor.enumeration_hint`` records (from the static
``mapping_events.py`` detector) into member sets, with no per-standard logic.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_KEY_SOURCES

from ..capabilities import CapabilityExpr, ExternalCheck
from ..event_tail import TailScanner, tail_scanner_for
from ..repos.event_logs_pg import BEHIND_PARTIAL_REASONS
from . import EnumerationResult, EvaluationContext

if TYPE_CHECKING:
    from ..repos.event_logs_pg import ValueFoldResult

logger = logging.getLogger(__name__)


_ZERO_ADDRESS = "0x" + "0" * 40

# ok: a resolved finite_set. cold: no backfill_complete cursor; caller defers. behind: warm but unproven past the
# frontier; caller fails closed. absent: structural (no repo, no event address, repo error); caller falls through to
# live replay.
_FoldStatus = Literal["ok", "cold", "behind", "absent"]


def _descriptor_is_caller_keyed(descriptor: dict) -> bool:
    """Whether a key source is the caller, so an unresolved membership keeps the
    ``caller_keyed_membership_allowlist`` tag.
    """
    key_sources = descriptor.get("key_sources") or []
    return any(k.get("source") in _CALLER_KEY_SOURCES for k in key_sources if isinstance(k, dict))


def _implicit_membership_value_predicate(descriptor: dict) -> dict | None:
    """The implicit ``{value != 0}`` predicate for a caller-keyed boolean membership ACL with no explicit
    ``value_predicate``.

    ``allowedForwardedEigenpodCalls[msg.sender][selector]`` authorizes callers whose latest value is nonzero (polarity
    is applied upstream). Only for caller-keyed ``mapping_membership`` descriptors with a ``set`` hint that has a
    ``value_position``; ``None`` otherwise.
    """
    if descriptor.get("kind") != "mapping_membership":
        return None
    if descriptor.get("value_predicate"):
        return None
    key_sources = descriptor.get("key_sources") or []
    if not any(k.get("source") in _CALLER_KEY_SOURCES for k in key_sources if isinstance(k, dict)):
        return None
    hints = descriptor.get("enumeration_hint") or []
    has_value_set_hint = any(
        h.get("topic0") and h.get("direction") == "set" and h.get("value_position") is not None
        for h in hints
        if isinstance(h, dict)
    )
    if not has_value_set_hint:
        return None
    return {"op": "any_nonzero", "rhs_values": [], "value_type": "uint256"}


class EventIndexedAdapter:
    """Generic adapter for storage vars with ``enumeration_hint``: folds add/remove events into a current member set."""

    @classmethod
    def matches(cls, descriptor: dict, ctx: EvaluationContext) -> int:
        hints = descriptor.get("enumeration_hint")
        if not hints:
            return 0
        # Needs at least one add/remove hint with topic0.
        for hint in hints:
            if hint.get("topic0") and hint.get("direction") in ("add", "remove"):
                return 50
        # D.2: ``set`` direction + ``value_predicate`` + ``value_position`` is the ``OwnerSet(addr, val)`` shape.
        if descriptor.get("value_predicate"):
            for hint in hints:
                if hint.get("topic0") and hint.get("direction") == "set" and hint.get("value_position") is not None:
                    return 55
        # Caller-keyed boolean ACLs take the same value fold with an implicit ``{value != 0}``.
        if _implicit_membership_value_predicate(descriptor) is not None:
            return 55
        return 0

    @classmethod
    def supports_external_check_only(cls) -> bool:
        return True

    def enumerate(self, descriptor: dict, ctx: EvaluationContext) -> CapabilityExpr:
        # D.2: a value predicate (explicit or implicit) with a ``set`` hint goes to the latest-value fold instead of the
        # present-set fold.
        explicit_predicate = descriptor.get("value_predicate")
        implicit_predicate = None if explicit_predicate else _implicit_membership_value_predicate(descriptor)
        value_predicate = explicit_predicate or implicit_predicate
        hints = descriptor.get("enumeration_hint") or []
        if value_predicate and ctx.contract_address is not None:
            set_hints = [
                h
                for h in hints
                if h.get("direction") == "set" and h.get("value_position") is not None and h.get("topic0")
            ]
            if set_hints:
                # A caller-keyed ACL must fold on the caller's event-arg position, not the hint's innermost key (e.g.
                # the selector).
                fold_key_position = (
                    _caller_event_arg_position(descriptor, set_hints[0]) if implicit_predicate is not None else None
                )
                return self._enumerate_value_predicate(
                    descriptor, set_hints, value_predicate, ctx, fold_key_position=fold_key_position
                )

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
        tail = tail_scanner_for(ctx)
        merged: list[str] = []
        worst_confidence = "enumerable"
        last_block: int | None = None
        trace: list[dict[str, Any]] = []
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
                    tail=tail,
                )
            except Exception:
                return self._external_check(descriptor, first_hint, ctx, ["event_log_backend_error"])
            if (
                result.confidence == "partial"
                and result.partial_reason in BEHIND_PARTIAL_REASONS
                and any(hint.get("direction") == "remove" for hint in event_hints)
            ):
                # A removal past the frontier could evict a member, so the durable rows bound nothing.
                return CapabilityExpr.unsupported("event_fold_tail_unavailable")
            if result.scan_window is not None:
                trace.append({"step": "event_fold_tail", "event_address": event_address, **result.scan_window})
            if result.confidence == "partial" and result.partial_reason in {
                "event_history_fold_unavailable",
                "unresolved_event_key",
            }:
                return self._external_check(descriptor, first_hint, ctx, [result.partial_reason])
            if result.confidence == "partial" and result.partial_reason == "ambiguous_event_direction":
                # An undecidable add/remove conflict has no member set at all; settle to a gated check (caller-keyed
                # gates keep the caller-gate tag).
                basis = ["ambiguous_event_direction"]
                if _descriptor_is_caller_keyed(descriptor):
                    basis.append("caller_keyed_membership_allowlist")
                return self._external_check(descriptor, first_hint, ctx, basis)
            if result.confidence == "partial" and result.partial_reason == "no_index_cursor":
                # Cold index defers with ``deferred_pending_index`` instead of a genesis-scan replay;
                # ``deferred_reconciler`` re-resolves after backfill. Caller-keyed gates carry
                # ``caller_keyed_membership_allowlist`` to stay gated.
                basis = ["no_index_cursor"]
                if _descriptor_is_caller_keyed(descriptor):
                    basis.append("caller_keyed_membership_allowlist")
                return self._external_check(descriptor, first_hint, ctx, basis)
            merged.extend(result.members)
            if result.confidence == "partial" and worst_confidence == "enumerable":
                worst_confidence = "partial"
            if result.last_indexed_block is not None:
                last_block = (
                    result.last_indexed_block if last_block is None else min(last_block, result.last_indexed_block)
                )

        logger.debug(
            "event_indexed decision",
            extra={
                "adapter": "event_indexed",
                "address": ctx.contract_address,
                "decision": "finite_set",
                "reason": "event_history_folded",
                "members": len(merged),
                "confidence": worst_confidence,
            },
        )
        return CapabilityExpr.finite_set(
            merged,
            quality="exact" if worst_confidence == "enumerable" else "lower_bound",
            confidence=worst_confidence,
            last_indexed_block=last_block,
            trace=trace or None,
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
        # Only ``no_index_cursor`` waits on the index (see solmate_roles._check_only).
        if "no_index_cursor" in basis:
            extra["deferred_pending_index"] = True
        target = _resolve_event_address(descriptor, hint, ctx)
        logger.debug(
            "event_indexed decision",
            extra={
                "adapter": "event_indexed",
                "address": target,
                "decision": "deferred" if "no_index_cursor" in basis else "external_check",
                "reason": ",".join(basis),
            },
        )
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=target,
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
        fold_key_position: int | None = None,
    ) -> CapabilityExpr:
        """D.2 fold: latest value per key, filtered by ``value_predicate``.

        Reads the durable ``indexed_event_logs`` (no live request); an incomplete backfill demotes to ``lower_bound``.
        ``fold_key_position`` overrides the hint's key (caller-keyed ACLs). A cold index defers to
        ``external_check_only`` with ``deferred_pending_index``; structural absence falls back to live replay; any
        failure is ``unsupported``.
        """
        event_address = next(
            (addr for addr in (_resolve_event_address(descriptor, hint, ctx) for hint in set_hints) if addr),
            None,
        )
        key_sources = _contextual_key_sources(descriptor.get("key_sources") or [], ctx)

        status, durable = self._durable_value_fold(
            descriptor, set_hints, value_predicate, ctx, event_address, key_sources, fold_key_position
        )
        if status == "ok" and durable is not None:
            return durable
        if status == "cold":
            return self._deferred_value_check(descriptor, ctx, event_address)
        if status == "behind":
            # The durable rows are warm but unproven past their frontier; a full live re-scan is never the fallback.
            return CapabilityExpr.unsupported("event_fold_tail_unavailable")
        return self._live_value_fold(descriptor, set_hints, value_predicate, ctx, event_address, fold_key_position)

    def _deferred_value_check(
        self,
        descriptor: dict,
        ctx: EvaluationContext,
        event_address: str | None,
    ) -> CapabilityExpr:
        """Defer a cold-index value fold to a gated ``external_check_only`` tagged ``deferred_pending_index`` (keyed
        on ``target_address`` by ``deferred_reconciler``). The ``caller_keyed_membership_allowlist`` basis keeps
        the function gated until the index warms.
        """
        return CapabilityExpr.external_check_only(
            ExternalCheck(
                target_address=event_address,
                target_call_selector=descriptor.get("callee_selector"),
                extra={
                    "basis": ["no_index_cursor", "caller_keyed_membership_allowlist"],
                    "deferred_pending_index": True,
                    "callee_function": descriptor.get("callee_function"),
                    "callee_signature": descriptor.get("callee_signature"),
                },
            )
        )

    def _durable_value_fold(
        self,
        descriptor: dict,
        set_hints: list[dict],
        value_predicate: dict,
        ctx: EvaluationContext,
        event_address: str | None,
        key_sources: list[dict],
        fold_key_position: int | None,
    ) -> tuple[_FoldStatus, CapabilityExpr | None]:
        """Fold the value predicate over the durable index:

        - ``("ok", finite_set)``: exact, the rows proven through the evaluated block (directly or by a complete tail);
        - ``("cold", None)``: backfill incomplete, caller defers;
        - ``("behind", None)``: warm but behind the evaluated block with no complete tail, caller fails closed;
        - ``("absent", None)``: structural (no repo, no nonzero event address, repo error), caller uses live replay.
        """
        repo = ctx.event_log_repo or (ctx.meta.get("event_log_repo") if ctx.meta else None)
        fold_values = getattr(repo, "fold_event_values", None)
        # A zero event address never gets a cursor, so deferring would wait forever.
        if not callable(fold_values) or event_address is None or event_address == _ZERO_ADDRESS:
            return "absent", None

        value_hints = [
            {
                "topic0": hint.get("topic0"),
                "topics_to_keys": hint.get("topics_to_keys") or {},
                "data_to_keys": hint.get("data_to_keys") or {},
                "indexed_positions": list(hint.get("indexed_positions") or []),
                "value_position": int(hint["value_position"]),
            }
            for hint in set_hints
        ]
        typed_fold_values = cast(Callable[..., "ValueFoldResult"], fold_values)
        tail = tail_scanner_for(ctx)
        try:
            result = typed_fold_values(
                chain_id=ctx.chain_id,
                event_address=event_address,
                value_hints=value_hints,
                key_sources=key_sources,
                fold_key_position=fold_key_position,
                block=ctx.block,
                **({"tail": tail} if tail is not None else {}),
            )
        except Exception:
            return "absent", None
        if not result.complete:
            if result.partial_reason == "no_index_cursor":
                return "cold", None
            if result.partial_reason in BEHIND_PARTIAL_REASONS:
                return "behind", None
            # Any other partial reason is structural and falls through to live replay.
            return "absent", None

        from ..mapping_enumerator import filter_value_entries

        keys = filter_value_entries(cast(Any, result.entries), value_predicate)
        if result.scan_window is None:
            return "ok", CapabilityExpr.finite_set(keys, quality="exact", confidence="enumerable")
        return "ok", CapabilityExpr.finite_set(
            keys,
            quality="exact",
            confidence="enumerable",
            last_indexed_block=result.last_indexed_block,
            trace=[{"step": "event_fold_tail", "event_address": event_address, **result.scan_window}],
        )

    def _live_value_fold(
        self,
        descriptor: dict,
        set_hints: list[dict],
        value_predicate: dict,
        ctx: EvaluationContext,
        event_address: str | None,
        fold_key_position: int | None,
    ) -> CapabilityExpr:
        """Live event replay fallback, used only when the durable index can't answer. Failures are fail-closed."""
        contract_address = event_address or ctx.contract_address or ""
        # Rebuild WriterEventSpec dicts from the hint.
        writer_specs = []
        for hint in set_hints:
            key_position = fold_key_position if fold_key_position is not None else int(hint.get("key_position") or 0)
            writer_specs.append(
                {
                    "mapping_name": hint.get("mapping_name") or descriptor.get("storage_var") or "",
                    "event_signature": hint.get("event_signature") or "",
                    "event_name": hint.get("event_name") or "",
                    "key_position": key_position,
                    "indexed_positions": list(hint.get("indexed_positions") or []),
                    "direction": "set",
                    "writer_function": hint.get("writer_function") or "",
                    "value_position": int(hint["value_position"]),
                }
            )

        from ..mapping_enumerator import enumerate_mapping_values_sync, filter_value_entries

        meta = ctx.meta or {}
        kwargs: dict[str, Any] = {"value_predicate": value_predicate}
        token = meta.get("hypersync_token")
        if token:
            kwargs["bearer_token"] = token
        client = meta.get("hypersync_client")
        if client is not None:
            kwargs["client"] = client
        module = meta.get("hypersync_module")
        if module is not None:
            kwargs["hypersync_module"] = module
        hypersync_url = meta.get("hypersync_url")
        if isinstance(hypersync_url, str) and hypersync_url:
            kwargs["hypersync_url"] = hypersync_url
        if isinstance(ctx.block, int):
            kwargs["to_block"] = ctx.block
        # Floor at the deploy block; with no floor, defer rather than scan from genesis.
        from ..creation_block_floor import resolve_scan_floor_with_basis

        floor, floor_basis = resolve_scan_floor_with_basis(contract_address, ctx.chain_id, session=ctx.session)
        if floor is None:
            return self._deferred_value_check(descriptor, ctx, event_address)
        kwargs["from_block"] = floor

        try:
            scan = enumerate_mapping_values_sync(
                contract_address,
                writer_specs,
                chain=str(ctx.chain_id) if isinstance(ctx.chain_id, int) else None,
                **kwargs,
            )
        except Exception:
            return CapabilityExpr.unsupported("mapping_value_scan_failed")

        keys = filter_value_entries(scan["entries"], value_predicate)
        is_complete = scan["status"] == "complete"
        return CapabilityExpr.finite_set(
            keys,
            quality="exact" if is_complete else "lower_bound",
            confidence="enumerable" if is_complete else "partial",
            last_indexed_block=scan["last_block_scanned"] or None,
            trace=[
                {
                    "step": "live_value_fold",
                    "event_address": contract_address.lower(),
                    "scan_from_block": floor,
                    "scan_to_block": ctx.block if isinstance(ctx.block, int) else (scan["last_block_scanned"] or None),
                    "floor_basis": floor_basis,
                }
            ],
        )


def _caller_event_arg_position(descriptor: dict, hint: dict) -> int | None:
    """Event-arg position of the caller key for a caller-keyed membership.

    ``key_sources`` gives the key index; ``topics_to_keys`` / ``data_to_keys`` invert it to an arg position.
    """
    key_sources = descriptor.get("key_sources") or []
    caller_key_index = next(
        (i for i, src in enumerate(key_sources) if isinstance(src, dict) and src.get("source") in _CALLER_KEY_SOURCES),
        None,
    )
    if caller_key_index is None:
        return None
    indexed_positions = sorted({int(p) for p in (hint.get("indexed_positions") or [])})

    for topic_index, key_index in (hint.get("topics_to_keys") or {}).items():
        if int(key_index) != caller_key_index:
            continue
        rank = int(topic_index) - 1  # topic 0 is the event signature
        if 0 <= rank < len(indexed_positions):
            return indexed_positions[rank]

    non_indexed = [pos for pos in range(64) if pos not in indexed_positions]
    for data_index, key_index in (hint.get("data_to_keys") or {}).items():
        if int(key_index) != caller_key_index:
            continue
        rank = int(data_index)
        if 0 <= rank < len(non_indexed):
            return non_indexed[rank]
    return None


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
    tail: TailScanner | None = None,
) -> EnumerationResult:
    # Only repos that can complete a lagging fold are handed a scanner.
    tail_kwargs: dict[str, Any] = {"tail": tail} if tail is not None else {}
    fold_history = getattr(repo, "fold_event_history", None)
    if callable(fold_history):
        typed_fold_history = cast(Callable[..., EnumerationResult], fold_history)
        return typed_fold_history(
            chain_id=chain_id,
            event_address=event_address,
            event_hints=event_hints,
            key_sources=key_sources,
            block=block,
            **tail_kwargs,
        )
    if len(event_hints) != 1:
        return EnumerationResult(members=[], confidence="partial", partial_reason="event_history_fold_unavailable")

    hint = event_hints[0]
    fold_writes = getattr(repo, "fold_event_writes", None)
    if not callable(fold_writes):
        return EnumerationResult(members=[], confidence="partial", partial_reason="event_history_fold_unavailable")
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
        **tail_kwargs,
    )
