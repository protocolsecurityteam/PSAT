"""Generic event-indexed adapter.

Covers any storage var whose writes are observable through events.
The static stage's ``mapping_events.py`` detector populates
``set_descriptor.enumeration_hint`` with EventHint records describing
the event address, topic, key positions, and fold direction. This
adapter consumes those records directly with no per-standard adapter.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

from ..capabilities import CapabilityExpr, ExternalCheck
from . import EnumerationResult, EvaluationContext

if TYPE_CHECKING:
    from ..repos.event_logs_pg import ValueFoldResult

logger = logging.getLogger(__name__)

_CALLER_KEY_SOURCES = {"msg_sender", "tx_origin", "signature_recovery", "root_caller"}

_ZERO_ADDRESS = "0x" + "0" * 40

# Discriminates the durable value fold's three outcomes for the caller:
#   ok     — a resolved finite_set (warm head, or a populated cold lower bound)
#   cold   — the durable index for this event address has no backfill_complete
#            cursor, so the fold is empty-and-incomplete; the caller defers
#   absent — structural: no repo, repo lacks fold_event_values, no event
#            address, or a repo error; the caller falls through to the live replay
_FoldStatus = Literal["ok", "cold", "absent"]


def _descriptor_is_caller_keyed(descriptor: dict) -> bool:
    """True when one of the descriptor's key sources is the caller, so an
    unresolved membership is a caller-discriminating gate (basis tag
    ``caller_keyed_membership_allowlist`` keeps the earned-public projection
    fail-closed)."""
    key_sources = descriptor.get("key_sources") or []
    return any(k.get("source") in _CALLER_KEY_SOURCES for k in key_sources if isinstance(k, dict))


def _implicit_membership_value_predicate(descriptor: dict) -> dict | None:
    """Synthesize the value predicate a caller-keyed boolean membership ACL
    implies when the descriptor carries no explicit ``value_predicate``.

    A leaf like ``allowedForwardedEigenpodCalls[msg.sender][selector]`` read for
    truthiness authorizes exactly the caller keys whose latest stored value is
    nonzero — i.e. an implicit ``{value != 0}``. The membership-truthy keys are
    the same set the writer-side ``set``-direction fold produces; the leaf's
    own truthy/falsy polarity is applied upstream by the predicate evaluator,
    so this always yields the truthy-key set.

    Returns the synthesized ``{op: any_nonzero}`` predicate only for a
    ``mapping_membership`` descriptor that (a) is keyed on the caller and
    (b) carries a ``set``-direction hint with ``value_position is not None``
    (the gate that structurally excludes caller-keyed data-maps with no value
    slot). Returns ``None`` for everything else, leaving unrelated descriptors
    on their existing path.
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
        # A caller-keyed boolean membership ACL carries the same set-direction
        # value hint but no explicit value_predicate: the truthy read implies
        # ``{value != 0}``. Route it through the same value-aware fold.
        if _implicit_membership_value_predicate(descriptor) is not None:
            return 55
        return 0

    @classmethod
    def supports_external_check_only(cls) -> bool:
        return True

    def enumerate(self, descriptor: dict, ctx: EvaluationContext) -> CapabilityExpr:
        # D.2 — when the descriptor carries a ValuePredicate and at
        # least one ``set``-direction hint, dispatch to the value-aware
        # fold path (latest-value-per-key, filtered by predicate)
        # rather than the add/remove present-set fold. A caller-keyed
        # boolean membership ACL supplies an implicit ``{value != 0}``
        # predicate the same way (the truthy read), routing through the
        # identical fold.
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
                # A caller-keyed membership ACL folds latest-value-per-CALLER:
                # the hint's ``key_position`` points at the innermost mapping
                # key (e.g. the selector), so the fold must be re-keyed on the
                # caller's own event-arg position. For an explicit-predicate
                # descriptor ``key_position`` is already the enumerated key.
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
        merged: list[str] = []
        worst_confidence = "enumerable"
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
            except Exception:
                return self._external_check(descriptor, first_hint, ctx, ["event_log_backend_error"])
            if result.confidence == "partial" and result.partial_reason in {
                "event_history_fold_unavailable",
                "unresolved_event_key",
            }:
                return self._external_check(descriptor, first_hint, ctx, [result.partial_reason])
            if result.confidence == "partial" and result.partial_reason == "no_index_cursor":
                # A cold durable index (no backfill_complete cursor) defers to
                # external_check_only tagged ``deferred_pending_index`` rather
                # than a live genesis-scan replay: ``deferred_reconciler`` (live
                # in event_log_indexer) re-resolves once the indexer backfills
                # the event address. Mirrors the value-fold cold path
                # (_deferred_value_check). A caller-keyed gate also carries
                # ``caller_keyed_membership_allowlist`` (a CALLER_GATE_BASIS_TAGS
                # member) so the earned-public projection keeps it gated.
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
            confidence=worst_confidence,  # type: ignore[arg-type]
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
        """D.2 fold: latest-value-per-key, filtered by ``value_predicate``.

        Folds over the durable ``indexed_event_logs`` index (``ctx.event_log_repo``,
        the same data source the add/remove path reads), so it issues no live
        request and is unaffected by upstream rate-limiting or token plumbing.
        The result is a ``finite_set`` of keys whose latest stored value
        satisfies the predicate; a not-yet-complete backfill demotes ``quality``
        to ``lower_bound``. Only when the durable index is unavailable or holds
        none of these events does it fall back to an on-demand event replay
        (forwarding the token + block), and any failure is fail-closed
        (``unsupported``), never raised.

        ``fold_key_position`` overrides the hint's ``key_position`` when the
        enumerated key is not the hint's innermost mapping key (a caller-keyed
        membership ACL folds on the caller's event-arg position).

        When the durable index for the event address is cold (no
        ``backfill_complete`` cursor) the fold defers to ``external_check_only``
        with ``deferred_pending_index`` rather than blocking on a live replay:
        ``deferred_reconciler`` re-resolves this function once the indexer
        backfills the event address. The structural-absent case (no repo / no
        ``fold_event_values`` / no event address) still falls through to the
        live replay so offline and non-indexed deployments keep resolving.
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
        return self._live_value_fold(descriptor, set_hints, value_predicate, ctx, event_address, fold_key_position)

    def _deferred_value_check(
        self,
        descriptor: dict,
        ctx: EvaluationContext,
        event_address: str | None,
    ) -> CapabilityExpr:
        """Defer a cold-index value fold to ``external_check_only`` so the
        deferred-resolution reconciler re-resolves it once the event address's
        logs finish indexing.

        ``external_check_only`` is the gated safe baseline (it can neither
        manufacture authority nor open the function); ``deferred_pending_index``
        tags it for ``deferred_reconciler`` (live in ``event_log_indexer``),
        which keys on ``target_address`` to detect the backfill. Mirrors
        ``_external_check`` (add/remove path) and ``solmate_roles._check_only``.

        The basis carries ``caller_keyed_membership_allowlist`` (a
        ``CALLER_GATE_BASIS_TAGS`` member, asserted in the adapter tests) because
        an unresolved caller-keyed value gate is a caller-discriminating
        authorization: the earned-public projection must treat the deferral as a
        root-authority blocker so the function stays gated until the index warms,
        never opening on a sibling public path.
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
        """Fold the value predicate over the durable index, returning a tagged
        outcome the caller routes on:

        - ``("ok", finite_set)`` — durable rows resolved (warm-head exact, or a
          populated cold lower bound).
        - ``("cold", None)`` — the index for the event address holds none of
          these events because its backfill cursor isn't complete
          (``partial_reason == "no_index_cursor"``). The caller defers.
        - ``("absent", None)`` — structural: no repo / no ``fold_event_values`` /
          no resolvable (nonzero) event address / a repo error. The caller falls
          through to the live replay (offline + non-indexed deployments resolve
          only there; a never-seeded zero-address cursor must never defer).
        """
        repo = ctx.event_log_repo or (ctx.meta.get("event_log_repo") if ctx.meta else None)
        fold_values = getattr(repo, "fold_event_values", None)
        # A zero / renounced event address never gets an indexer cursor, so a
        # cold fold against it would defer forever. Treat it as structural so the
        # live replay (fail-closed) settles it instead — mirrors solmate_roles'
        # nonzero-authority anti-stranding guard.
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
        try:
            result = typed_fold_values(
                chain_id=ctx.chain_id,
                event_address=event_address,
                value_hints=value_hints,
                key_sources=key_sources,
                fold_key_position=fold_key_position,
                block=ctx.block,
            )
        except Exception:
            return "absent", None
        if not result.entries and not result.complete:
            # An empty, not-complete fold splits two ways. A cold index
            # (``no_index_cursor``: no backfill_complete cursor) is waiting on the
            # indexer — defer so the reconciler re-resolves once it warms, rather
            # than blocking on a live replay. Any other partial reason
            # (unresolved key, etc.) is structural — fall through to the live
            # replay, which is the only resolver in that case.
            if result.partial_reason == "no_index_cursor":
                return "cold", None
            return "absent", None

        from ..mapping_enumerator import filter_value_entries

        keys = filter_value_entries(cast(Any, result.entries), value_predicate)
        return "ok", CapabilityExpr.finite_set(
            keys,
            quality="exact" if result.complete else "lower_bound",
            confidence="enumerable" if result.complete else "partial",
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
        """On-demand event replay fallback (used only when the durable index is
        unavailable or holds none of these events). Forwards the bearer token and
        the resolution block; any failure is fail-closed."""
        contract_address = event_address or ctx.contract_address or ""
        # Reconstruct WriterEventSpec dicts the enumerator expects from
        # the EventHint payload. The hint already carries ``topic0``,
        # ``event_signature``, ``key_position`` etc. — we just rename
        # to the spec keys.
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
        # Floor the scan at the event address's deploy block (deploy→head, not
        # genesis→head): a contract emits no events before it exists, so the log
        # set is identical, but the empty pre-deployment range is never fetched.
        # When no floor can be resolved we DEFER (skip the live scan) rather than
        # scan from genesis — fail-closed to the gated external-check baseline.
        from ..creation_block_floor import resolve_scan_floor

        floor = resolve_scan_floor(contract_address, ctx.chain_id, session=ctx.session)
        if floor is None:
            return self._deferred_value_check(descriptor, ctx, event_address)
        kwargs["from_block"] = floor

        try:
            scan = enumerate_mapping_values_sync(
                contract_address,
                writer_specs,  # type: ignore[arg-type]
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
        )


def _caller_event_arg_position(descriptor: dict, hint: dict) -> int | None:
    """Event-arg position holding the CALLER key for a caller-keyed membership.

    The hint's ``key_position`` names the innermost mapping key (e.g. the
    selector in ``mapping[msg.sender][selector]``). The value fold for a
    caller ACL must instead key on the caller. ``key_sources`` gives the caller
    key index; ``topics_to_keys`` / ``data_to_keys`` invert from key index to
    event-arg position (a topic arg is the n-th ``indexed_positions`` entry;
    a data arg is the m-th non-indexed entry).
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
    )
