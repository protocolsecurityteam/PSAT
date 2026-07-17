"""Generic event-log indexer for predicate ``enumeration_hint`` records."""

from __future__ import annotations

import logging
import os
import signal
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Lock, Thread
from typing import Any, Mapping, MutableMapping, Protocol, Sequence, TypeGuard

from eth_utils.crypto import keccak
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    ControllerValue,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStatus,
    SessionLocal,
    derive_job_chain_id,
)
from db.queue import HEARTBEAT_EVENT_INDEXER, get_artifact, record_heartbeat
from services.resolution.deferred_reconciler import reconcile_deferred_resolutions, reconcile_role_set_drift
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from services.resolution.role_store_standards import all_topic0s, detect_standards, resolve_probe_code
from utils.chains import ChainInfo, UnknownChainError, all_chains, chain_by_id, supported_chain_ids
from utils.etherscan import get_contract_creation_block
from utils.logging import configure_logging, log_timed_phase
from utils.rpc import require_rpc_url
from utils.secrets import sanitize_string

logger = logging.getLogger("workers.event_log_indexer")

DEFAULT_INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_INTERVAL_S", "60"))
DEFAULT_CONFIRMATION_DEPTH = int(os.getenv("PSAT_EVENT_INDEXER_FINALITY_DEPTH", "12"))

# Backfill in bounded windows. A cold cursor's gap to head is ~25M blocks; an
# unbounded step accumulates every match into one list and inserts it in a
# single statement. On high-volume authorities (the LayerZero endpoint) that
# one insert dropped the Neon connection ("SSL connection has been closed
# unexpectedly"), wedging the cursor at block 0 forever. So: cap the span
# scanned per step, batch the insert, and let one pass advance across several
# windows. The span is wide because one window is now ONE eth_getLogs (the
# fetcher bisects only when an upstream rejects the range): the getLogs fast
# lane (HyperRPC via eRPC) meters a flat 1000 credits per request — 60/min —
# regardless of range, so small windows exhaust the lane while scanning almost
# nothing. Dense bursts are bounded by the upstream's own result cap (50k logs)
# plus the fetcher's bisect, and the insert stays batched.
DEFAULT_MAX_BLOCK_SPAN = int(os.getenv("PSAT_EVENT_INDEXER_MAX_BLOCK_SPAN", "500000"))
# Two window caps bound how long a single scan pass runs. The per-group cap
# stops one high-volume address from consuming a whole pass; the per-pass cap
# makes scan RETURN promptly even with many cold cursors enrolled, so the fleet
# heartbeat refreshes and the least-recently-run rotation re-prioritizes every
# pass instead of once per multi-group (~tens-of-minutes) backfill. Per-group <
# per-pass so the budget spreads across several addresses each pass; a cold
# address's gap drains over successive passes, with the durable last_run_at
# ordering as the rotation offset (no separate persisted cursor index needed).
DEFAULT_MAX_WINDOWS_PER_CURSOR = int(os.getenv("PSAT_EVENT_INDEXER_MAX_WINDOWS_PER_CURSOR", "50"))
DEFAULT_MAX_WINDOWS_PER_PASS = int(os.getenv("PSAT_EVENT_INDEXER_MAX_WINDOWS_PER_PASS", "100"))
DEFAULT_INSERT_BATCH = int(os.getenv("PSAT_EVENT_INDEXER_INSERT_BATCH", "1000"))
# When a pass stops on its window budget there's more backfill pending, so the
# backfill loop re-runs after this short pause instead of the full poll interval
# — a cold fleet drains at throughput rather than idling 60s between every
# budget-sized pass. Floored (not 0) so a large warm fleet that legitimately
# fills the budget with cheap catch-up windows can't busy-spin.
DEFAULT_BACKFILL_BUSY_INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_BACKFILL_BUSY_INTERVAL_S", "2"))

# Solmate RolesAuthority canCall: the role events to index at the authority so
# SolmateRolesAuthorityAdapter can fold them. Enrolled directly off the canCall
# descriptor so the fix works even on predicate_trees materialized before the
# enumeration-hint pass existed (the bytecode-keyed materialization cache won't
# carry the hints until rebuilt). Topics computed here to avoid a worker→adapter
# import dependency.
_SOLMATE_CANCALL_SIGNATURE = "canCall(address,address,bytes4)"
_SOLMATE_CANCALL_SELECTOR = "0x" + keccak(text=_SOLMATE_CANCALL_SIGNATURE).hex()[:8]
_SOLMATE_ROLE_TOPICS = [
    "0x" + keccak(text=sig).hex()
    for sig in (
        "RoleCapabilityUpdated(uint8,address,bytes4,bool)",
        "PublicCapabilityUpdated(address,bytes4,bool)",
        "UserRoleUpdated(address,uint8,bool)",
    )
]


def _is_solmate_cancall_descriptor(descriptor: dict[str, Any]) -> bool:
    if not isinstance(descriptor, dict) or descriptor.get("kind") != "external_set":
        return False
    signature = descriptor.get("callee_signature")
    selector = descriptor.get("callee_selector")
    return (isinstance(signature, str) and signature.replace(" ", "") == _SOLMATE_CANCALL_SIGNATURE) or (
        isinstance(selector, str) and selector.lower() == _SOLMATE_CANCALL_SELECTOR
    )


# Key sources that resolve to the transaction's caller — a gate keyed on one of
# these discriminates who may call. Mirrors the resolution-side _CALLER_SOURCES
# (predicate_evaluator / event_indexed) so the indexer's trigger agrees with the
# adapter that folds what it enrolls.
_CALLER_SOURCES = {"msg_sender", "tx_origin", "signature_recovery", "root_caller"}


def _is_single_address_param_signature(signature: Any) -> bool:
    """True for ``name(address)`` — exactly one parameter, of type ``address``.
    The shape of a delegated role gate's callee (``onlyOperatingMultisig(address)``
    and siblings), as opposed to Solmate's 3-arg canCall or a multi-arg canCall."""
    if not isinstance(signature, str) or "(" not in signature or not signature.rstrip().endswith(")"):
        return False
    params = signature[signature.index("(") + 1 : signature.rindex(")")]
    return [p.strip() for p in params.split(",") if p.strip()] == ["address"]


def _is_delegated_role_gate_descriptor(descriptor: dict[str, Any]) -> bool:
    """A caller-keyed external bool check against a single-address-param callee on
    a delegated authority — ``roleRegistry.onlyX(msg.sender)`` — that is NOT the
    already-handled Solmate canCall. The registry's own predicate trees compile to
    zero descriptors (assembly sload/mload operands), so this caller-side outer
    descriptor is the only enrollment trigger for its RoleSet cursor."""
    if not isinstance(descriptor, dict) or descriptor.get("kind") != "external_set":
        return False
    if _is_solmate_cancall_descriptor(descriptor):
        return False
    if not _is_single_address_param_signature(descriptor.get("callee_signature")):
        return False
    keys = descriptor.get("key_sources") or []
    return any(isinstance(k, dict) and k.get("source") in _CALLER_SOURCES for k in keys)


_ALL_ROLE_STORE_TOPIC0S = [t.lower() for t in all_topic0s()]


def _authority_has_role_store_cursor(session: Session, chain_id: int, authority: str) -> bool:
    """True iff a role-store grant/revoke cursor is already enrolled for
    ``authority``. When it is, standard detection — an ``eth_getCode`` per gate
    descriptor, ~250/pass at steady state on the paid RPC — can be skipped
    entirely: the cursor exists and ``enroll_event_cursor`` would only no-op."""
    row = session.execute(
        select(IndexedEventCursor.event_address)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == authority.lower())
        .where(IndexedEventCursor.topic0.in_(_ALL_ROLE_STORE_TOPIC0S))
        .limit(1)
    ).first()
    return row is not None


def _role_store_topic0s(
    session: Session, authority: str, chain_id: int, cache: dict[tuple[int, str], list[str]]
) -> list[str]:
    """The grant/revoke topic0s to enroll at ``authority``. Detect the standard
    from the impl bytecode behind the registry proxy; when detection is
    inconclusive, enroll the UNION of all standards' topic0s — over-enrollment is
    a cheap empty scan window, a missed cursor kills the recall path. Memoized per
    ``(chain_id, authority)`` within a pass (mirrors ``seed_cache``) so the ~92
    functions of a single registry family share one ``resolve_probe_code`` (one
    ``eth_getCode``) — keyed by chain since the impl bytecode is per-chain."""
    key = (chain_id, authority.lower())
    if key in cache:
        return cache[key]
    try:
        code = resolve_probe_code(session, authority, chain_id)
    except Exception:
        code = None
    detected = detect_standards(code)
    if detected:
        topics: set[str] = set()
        for standard in detected:
            topics.update(standard.topic0s())
        result = sorted(topics)
    else:
        result = all_topic0s()
    cache[key] = result
    return result


class LogFetcher(Protocol):
    def fetch_logs(
        self,
        *,
        event_address: str | Sequence[str],
        topics: Sequence[str],
        from_block: int,
        to_block: int,
    ) -> list[FetchedEventLog]: ...


class HeadBlockFetcher(Protocol):
    def head_block(self) -> int: ...


class BlockHashFetcher(Protocol):
    def block_hash(self, block_number: int) -> bytes | None: ...


@dataclass(frozen=True)
class GroupStepResult:
    scanned_from: int
    scanned_to: int
    inserted: int
    members_at_target: int  # cursors of this group at/past the confirmed head after the step
    group_complete: bool  # every member caught up — nothing left to scan this pass
    fetched: bool  # False for the no-fetch visit of an all-warm group


@dataclass(frozen=True)
class ScanSummary:
    """What one ``scan_enrolled_events`` pass did, for the fleet heartbeat.

    ``windows_scanned`` (group steps run — one shared getLogs per step, summed
    across all address groups) over ``total_cursors`` reveals the from-0
    backfill signature: many windows scanned with 0 inserted and
    ``caught_up_cursors`` < ``total_cursors`` means a cold address is grinding
    through empty eth_getLogs ranges while the rest sit at head.
    """

    inserted: int = 0
    windows_scanned: int = 0
    caught_up_cursors: int = 0
    total_cursors: int = 0
    # True when the pass stopped on its per-pass window budget (more cursors were
    # likely left unserviced) — the backfill loop uses this to re-run sooner.
    budget_exhausted: bool = False
    # Address groups whose scan raised and was swallowed-and-continued this pass.
    # Surfaced so the heartbeat can degrade on a total outage (every group failed,
    # ``windows_scanned == 0``) instead of leaving a per-group traceback storm as
    # the only evidence.
    failed_groups: int = 0


def _heartbeat_status_for_pass(status: str, summary: ScanSummary) -> str:
    """Degrade a non-error pass whose every attempted group failed.

    ``failed_groups > 0`` with ``windows_scanned == 0`` means no group advanced a
    single window — a total upstream outage — which is degraded-but-continuing.
    A partial failure (some groups scanned, one raised) stays ``running``: that's
    ordinary per-group churn, not a daemon-health signal worth alerting on.
    """
    if status == "running" and summary.failed_groups and summary.windows_scanned == 0:
        return "degraded"
    return status


def enroll_event_cursor(
    session: Session,
    *,
    chain_id: int,
    event_address: str,
    topic0: str,
    start_block: int = 0,
) -> bool:
    stmt = (
        pg_insert(IndexedEventCursor)
        .values(
            chain_id=chain_id,
            event_address=event_address.lower(),
            topic0=topic0.lower(),
            last_indexed_block=start_block,
        )
        .on_conflict_do_nothing(index_elements=["chain_id", "event_address", "topic0"])
    )
    result = session.execute(stmt)
    return bool(getattr(result, "rowcount", 0))


def index_event_group_step(
    session: Session,
    *,
    chain_id: int,
    event_address: str,
    topics: Sequence[str],
    fetcher: LogFetcher,
    target: int,
    block_hash_fetcher: BlockHashFetcher,
    block_hash_memo: MutableMapping[tuple[int, int], bytes | None] | None = None,
    confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
    max_block_span: int = DEFAULT_MAX_BLOCK_SPAN,
    insert_batch_size: int = DEFAULT_INSERT_BATCH,
) -> GroupStepResult:
    """Advance every cursor of one (chain, address) group by one shared window.

    One ``eth_getLogs`` covers all the group's topic0s (an OR list); results
    demux back to per-topic cursors. Members advance in lockstep from the group
    minimum — one that is already ahead of the window keeps its position and
    only sees logs above it (re-inserts would be conflict-ignored anyway). The
    upstream budget meters REQUESTS, not block range, so the group costs one
    request per window instead of one per topic.

    ``target`` is the confirmed head (``head - confirmation_depth``), computed
    once per pass by the caller rather than re-fetched per step.
    """
    memo: MutableMapping[tuple[int, int], bytes | None] = block_hash_memo if block_hash_memo is not None else {}
    topic_list = sorted({str(t).lower() for t in topics})
    cursors = (
        session.execute(
            select(IndexedEventCursor)
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
            .where(func.lower(IndexedEventCursor.topic0).in_(topic_list))
            .with_for_update()
        )
        .scalars()
        .all()
    )
    if not cursors:
        return GroupStepResult(
            scanned_from=0, scanned_to=0, inserted=0, members_at_target=0, group_complete=True, fetched=False
        )

    def _hash_at(block: int) -> bytes | None:
        key = (chain_id, block)
        if key not in memo:
            memo[key] = block_hash_fetcher.block_hash(block)
        return memo[key]

    # Reorg guard. A hash stamp only exists where a cursor previously reached
    # the confirmed target (mid-backfill windows are final and never stamp), so
    # this runs once per warm cursor as it re-enters a scan — not per window —
    # and the memo collapses same-block lookups across the whole pass.
    for cursor in cursors:
        last = int(cursor.last_indexed_block or 0)
        if last <= 0 or cursor.last_indexed_block_hash is None or last >= target:
            continue
        observed_hash = _hash_at(last)
        if observed_hash is not None and observed_hash != cursor.last_indexed_block_hash:
            rewind_to = max(0, last - confirmation_depth)
            # A reorg rewind DELETEs already-indexed logs; without this line the
            # data loss left no trail. WARNING (degraded-but-continuing): the
            # indexer re-fetches the rewound range on the next pass.
            logger.warning(
                "event-log reorg detected; rewinding indexed logs before re-scan",
                extra={
                    "chain_id": chain_id,
                    "event_address": event_address.lower(),
                    "rewind_to": rewind_to,
                    "rewind_from": last,
                    "depth": last - rewind_to,
                },
            )
            # The delete is address-wide (all topics), so every sibling cursor
            # above the rewind point must come back with it — otherwise its
            # already-indexed range would be silently emptied.
            session.execute(
                delete(IndexedEventLog)
                .where(IndexedEventLog.chain_id == chain_id)
                .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
                .where(IndexedEventLog.block_number > rewind_to)
            )
            for member in cursors:
                if int(member.last_indexed_block or 0) > rewind_to:
                    member.last_indexed_block = rewind_to
                    member.last_indexed_block_hash = _hash_at(rewind_to) if rewind_to else None
                    member.backfill_complete = False
            break

    active = [c for c in cursors if int(c.last_indexed_block or 0) < target]
    if not active:
        # Every member is at (or past) the confirmed head — record that so
        # resolvers trust the durable index, and re-stamp last_run_at on this
        # no-fetch visit too: the rotation orders groups least-recently-run
        # first, so a warm group with a stale timestamp would keep sorting
        # ahead of cold groups that need windows.
        for cursor in cursors:
            cursor.backfill_complete = True
            cursor.last_run_at = func.now()
        return GroupStepResult(
            scanned_from=target + 1,
            scanned_to=target,
            inserted=0,
            members_at_target=len(cursors),
            group_complete=True,
            fetched=False,
        )

    start = min(int(c.last_indexed_block or 0) for c in active) + 1
    window_end = min(target, start - 1 + max(1, max_block_span))
    logs = fetcher.fetch_logs(
        event_address=event_address.lower(),
        topics=[c.topic0.lower() for c in active],
        from_block=start,
        to_block=window_end,
    )
    logs_by_topic: dict[str, list[FetchedEventLog]] = {}
    for log in logs:
        if log.topics:
            logs_by_topic.setdefault(log.topics[0].lower(), []).append(log)

    inserted = 0
    members_at_target = 0
    for cursor in cursors:
        last = int(cursor.last_indexed_block or 0)
        if last < target:
            member_logs = [log for log in logs_by_topic.get(cursor.topic0.lower(), []) if log.block_number > last]
            inserted += _bulk_insert_logs(
                session,
                chain_id,
                event_address.lower(),
                cursor.topic0.lower(),
                member_logs,
                batch_size=insert_batch_size,
            )
            if window_end > last:
                cursor.last_indexed_block = window_end
                # The stamp is position-bound; clear it on a mid-backfill
                # advance so a later reorg pre-check can't compare the hash of
                # one block against the position of another.
                cursor.last_indexed_block_hash = None
        if int(cursor.last_indexed_block or 0) >= target:
            members_at_target += 1
            cursor.backfill_complete = True
            if cursor.last_indexed_block_hash is None:
                # The only hash stamp: at the confirmed fringe, where a reorg
                # could still rewrite the block — keyed on the missing stamp
                # (an advance clears it), NOT on the completeness transition,
                # which never re-fires when a warm cursor catches up again.
                # Finalized mid-backfill windows never stamp, keeping
                # per-window eth_getBlockByNumber traffic out of the hot loop.
                cursor.last_indexed_block_hash = _hash_at(int(cursor.last_indexed_block))
        cursor.last_run_at = func.now()
    return GroupStepResult(
        scanned_from=start,
        scanned_to=window_end,
        inserted=inserted,
        members_at_target=members_at_target,
        group_complete=members_at_target == len(cursors),
        fetched=True,
    )


def scan_enrolled_events(
    session: Session,
    *,
    fetchers: Mapping[int, LogFetcher],
    head_fetchers: Mapping[int, HeadBlockFetcher],
    block_hash_fetchers: Mapping[int, BlockHashFetcher],
    confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
    max_block_span: int = DEFAULT_MAX_BLOCK_SPAN,
    max_windows_per_cursor: int = DEFAULT_MAX_WINDOWS_PER_CURSOR,
    max_windows_per_pass: int = DEFAULT_MAX_WINDOWS_PER_PASS,
    insert_batch_size: int = DEFAULT_INSERT_BATCH,
) -> ScanSummary:
    # Cursors group by (chain, address): every topic0 on one address rides the
    # same eth_getLogs (an OR list), so the upstream request budget pays once
    # per window per ADDRESS, not once per topic. Rotation is per group,
    # least-recently-run first (min over members; a never-run member sorts the
    # whole group first) — same fairness contract as before, at group
    # granularity: a single high-volume address can't monopolize successive
    # passes, and a freshly-enrolled deferred authority warms within a rotation
    # rather than behind hours of someone else's backfill.
    all_rows = session.execute(
        select(
            IndexedEventCursor.chain_id,
            IndexedEventCursor.event_address,
            IndexedEventCursor.topic0,
            IndexedEventCursor.last_run_at,
        )
    ).all()
    # Skip zero/invalid-address cursors that predate the enroll-time guard: 0x0 can
    # never emit logs, so scanning it just burns one RPC round-trip every pass.
    rows = [row for row in all_rows if _is_enrollable_event_address(row[1])]
    groups: dict[tuple[int, str], dict[str, Any]] = {}
    for chain_id, event_address, topic0, last_run_at in rows:
        entry = groups.setdefault((chain_id, event_address.lower()), {"topics": set(), "runs": []})
        entry["topics"].add(topic0.lower())
        entry["runs"].append(last_run_at)

    _epoch = datetime.min.replace(tzinfo=timezone.utc)

    def _rotation_key(item: tuple[tuple[int, str], dict[str, Any]]) -> tuple[int, datetime, str]:
        (chain_id, address), entry = item
        runs = entry["runs"]
        if any(run is None for run in runs):
            return (0, _epoch, address)
        return (1, min(runs), address)

    inserted = 0
    windows_scanned = 0
    caught_up_cursors = 0
    failed_groups = 0
    pass_budget = max(1, max_windows_per_pass)
    # One confirmed-head target and one block-hash memo per pass: the head is a
    # per-chain fact, and hash lookups repeat across groups (every cursor
    # reaching the same target stamps the same block), so neither belongs in
    # the per-window hot path.
    targets: dict[int, int] = {}
    block_hash_memo: dict[tuple[int, int], bytes | None] = {}
    # Chains whose cursors were skipped this pass for lack of a fetcher — logged
    # once each (inv. 4/10). The indexer is deliberately disabled for a chain with
    # ``hypersync_url is None``, but a chain that silently accretes cursors and
    # never advances must be visible in the logs, not a black hole.
    skipped_chains: set[int] = set()
    for (chain_id, event_address), entry in sorted(groups.items(), key=lambda item: _rotation_key(item)):
        # Global per-pass budget: stop and return once this pass has scanned
        # pass_budget windows total, even with cold groups still unserviced.
        # They keep their older last_run_at, so the next pass — re-ordered
        # least-recently-run first — picks them up: fine-grained round-robin with
        # no separate persisted offset. Without this, one pass walks every group
        # to completion (~tens of minutes on a cold subset), the heartbeat can't
        # refresh, and groups late in the order wait the whole pass.
        if windows_scanned >= pass_budget:
            break
        fetcher = fetchers.get(chain_id)
        head_fetcher = head_fetchers.get(chain_id)
        block_hash_fetcher = block_hash_fetchers.get(chain_id)
        if fetcher is None or head_fetcher is None or block_hash_fetcher is None:
            if chain_id not in skipped_chains:
                skipped_chains.add(chain_id)
                logger.warning(
                    "event indexer has no fetcher for chain; its enrolled cursors are not being "
                    "advanced this pass (indexer disabled for this chain, or its hypersync_url is unset)",
                    extra={"chain_id": chain_id},
                )
            continue
        # Per-chain finality (inv. 10): L2s reorg at different depths, so the
        # confirmed-head target and every rewind use the registry's depth for THIS
        # chain, not the fleet-wide default. Registry mainnet value == 12, so
        # chain 1 is unchanged; the passed-in ``confirmation_depth`` is the
        # last-resort fallback for a chain absent from the registry.
        try:
            chain_confirmation_depth = chain_by_id(chain_id).confirmation_depth
        except UnknownChainError:
            chain_confirmation_depth = confirmation_depth
        # Walk several windows per group, but cap it (per-group) so one
        # high-volume address can't consume the whole pass budget, and stop at
        # the global budget mid-group. Commit per window: each transaction (and
        # INSERT) stays small, progress is durable, and a mid-backfill failure on
        # one group doesn't roll back the windows it already landed.
        group_members_at_target = 0
        try:
            if chain_id not in targets:
                targets[chain_id] = max(0, head_fetcher.head_block() - chain_confirmation_depth)
            for _ in range(max(1, max_windows_per_cursor)):
                if windows_scanned >= pass_budget:
                    break
                result = index_event_group_step(
                    session,
                    chain_id=chain_id,
                    event_address=event_address,
                    topics=sorted(entry["topics"]),
                    fetcher=fetcher,
                    target=targets[chain_id],
                    block_hash_fetcher=block_hash_fetcher,
                    block_hash_memo=block_hash_memo,
                    confirmation_depth=chain_confirmation_depth,
                    max_block_span=max_block_span,
                    insert_batch_size=insert_batch_size,
                )
                session.commit()
                inserted += result.inserted
                windows_scanned += 1
                group_members_at_target = result.members_at_target
                if result.group_complete:
                    break
        except Exception as exc:
            session.rollback()
            failed_groups += 1
            # Swallowed-and-continued: the next group still runs and the cursor
            # resumes next pass. WARNING + exc_type (not logger.exception) — an
            # outage once emitted 2,172 ERROR tracebacks here; the per-pass
            # heartbeat carries the aggregate via ``failed_groups`` instead.
            logger.warning(
                "event indexer group scan failed; continuing to next group",
                extra={
                    "chain_id": chain_id,
                    "event_address": event_address,
                    "topics": sorted(entry["topics"]),
                    "exc_type": type(exc).__name__,
                    # Bounded, sanitized message so a swallowed error is still
                    # attributable without re-enabling per-window traceback storms.
                    # sanitize_string scrubs any URL the message carries (an eRPC
                    # URL, say); the ~200-char cap keeps one line, not a stack.
                    "exc_msg": sanitize_string(str(exc))[:200],
                },
            )
        caught_up_cursors += group_members_at_target
    return ScanSummary(
        inserted=inserted,
        windows_scanned=windows_scanned,
        caught_up_cursors=caught_up_cursors,
        total_cursors=len(rows),
        budget_exhausted=windows_scanned >= pass_budget,
        failed_groups=failed_groups,
    )


_ZERO_ADDRESS = "0x" + "0" * 40


def _is_enrollable_event_address(address: object) -> TypeGuard[str]:
    """True only for a real, non-zero 0x address. A descriptor whose event
    emitter resolves to None or the zero address (an unset/renounced state var)
    must be skipped: 0x0 has no creation block, so it would seed at genesis and
    backfill the whole chain for an address that can never emit logs."""
    return (
        isinstance(address, str)
        and len(address) == 42
        and address.lower().startswith("0x")
        and address.lower() != _ZERO_ADDRESS
    )


def _seed_block(address: str, cache: dict[tuple[int, str], int | None], *, chain_id: int) -> int | None:
    """The ``last_indexed_block`` a new cursor should start at: one below the
    event address's creation block, so the first scan window begins at the
    deploy block and the ~20M empty pre-deployment blocks are never fetched.

    Returns ``None`` when the creation block can't be determined, so the caller
    defers enrollment to a later pass (retrying once it resolves) instead of
    seeding at genesis: a single transient Etherscan failure must never pin a
    cursor to a full-chain backfill. Cached per pass, keyed by ``(chain_id,
    address)`` — the same address on two chains has independent creation blocks.
    """
    addr = address.lower()
    key = (chain_id, addr)
    if key in cache:
        return cache[key]
    seed: int | None = None
    try:
        created = get_contract_creation_block(addr, chain_id=chain_id)
        if isinstance(created, int) and created > 0:
            seed = created - 1
    except Exception as exc:
        logger.warning(
            "creation-block lookup failed for %s; deferring enrollment to a later pass",
            addr,
            extra={"address": addr, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )
        seed = None
    cache[key] = seed
    return seed


def enroll_from_completed_jobs(session: Session, *, limit: int = 500) -> int:
    jobs = session.execute(
        select(Job)
        .where(Job.status == JobStatus.completed)
        .where(Job.address.isnot(None))
        .order_by(Job.updated_at.desc())
        .limit(limit)
    ).scalars()
    inserted = 0
    # Caches are keyed by ``(chain_id, address)`` — the enrolled cursor's chain is
    # the job's own chain, not a single map-wide value, so the same address on two
    # chains keeps independent creation blocks and role-store standards.
    seed_cache: dict[tuple[int, str], int | None] = {}
    role_store_topic_cache: dict[tuple[int, str], list[str]] = {}
    for job in jobs:
        artifact = get_artifact(session, job.id, "predicate_trees")
        if not isinstance(artifact, dict):
            continue
        # Stamp each cursor with the job's own chain — the first-class
        # ``Job.chain_id`` (backfilled for all address-scoped rows in Phase 0).
        # For a not-yet-migrated NULL, derive from the job's own ``request["chain"]``
        # via the registry rather than a map-wide default (inv. 6), so an address
        # that lives on another chain is never guessed as mainnet.
        job_chain_id = (
            job.chain_id
            if isinstance(job.chain_id, int)
            else derive_job_chain_id(job.request.get("chain") if isinstance(job.request, dict) else None, job.address)
        )
        if job_chain_id is None:
            # Address-scoped by the query filter above, so derivation always
            # yields an id; guard defensively rather than seed a NULL-chain cursor.
            continue
        values = _state_var_values_for_job(session, job)
        for descriptor in _descriptors_from_artifact(artifact):
            for hint in descriptor.get("enumeration_hint") or []:
                topic0 = hint.get("topic0")
                if not isinstance(topic0, str) or not topic0.startswith("0x"):
                    continue
                address = _event_address_for_descriptor(descriptor, hint, job, values)
                if not _is_enrollable_event_address(address):
                    continue
                start_block = _seed_block(address, seed_cache, chain_id=job_chain_id)
                if start_block is None:
                    # Creation block not yet known — enroll on a later pass at the
                    # real deploy block rather than backfilling from genesis.
                    continue
                if enroll_event_cursor(
                    session, chain_id=job_chain_id, event_address=address, topic0=topic0, start_block=start_block
                ):
                    inserted += 1
            if _is_solmate_cancall_descriptor(descriptor):
                # Resolve the authority strictly from authority_contract — never
                # the job.address fallback. The RolesAuthority events are emitted
                # by the authority, not by the protected contract, so enrolling
                # them at job.address would scan an address that can't emit them.
                # If the authority isn't resolved yet, skip; a later pass enrolls
                # it once its ControllerValue is captured.
                authority = _event_address_for_descriptor(descriptor, {}, job, values, allow_job_fallback=False)
                if _is_enrollable_event_address(authority):
                    start_block = _seed_block(authority, seed_cache, chain_id=job_chain_id)
                    if start_block is not None:
                        for topic0 in _SOLMATE_ROLE_TOPICS:
                            if enroll_event_cursor(
                                session,
                                chain_id=job_chain_id,
                                event_address=authority,
                                topic0=topic0,
                                start_block=start_block,
                            ):
                                inserted += 1
            elif _is_delegated_role_gate_descriptor(descriptor):
                # Enroll the role-store's grant/revoke cursor at the authority
                # PROXY — the delegatecall emits RoleSet there, so job.address
                # (the protected contract) would index an address that emits
                # nothing. Skip if the authority isn't resolved yet; a later pass
                # enrolls it once its ControllerValue is captured.
                authority = _event_address_for_descriptor(descriptor, {}, job, values, allow_job_fallback=False)
                if _is_enrollable_event_address(authority) and not _authority_has_role_store_cursor(
                    session, job_chain_id, authority
                ):
                    start_block = _seed_block(authority, seed_cache, chain_id=job_chain_id)
                    if start_block is not None:
                        for topic0 in _role_store_topic0s(session, authority, job_chain_id, role_store_topic_cache):
                            if enroll_event_cursor(
                                session,
                                chain_id=job_chain_id,
                                event_address=authority,
                                topic0=topic0,
                                start_block=start_block,
                            ):
                                inserted += 1
    session.commit()
    return inserted


def _bulk_insert_logs(
    session: Session,
    chain_id: int,
    event_address: str,
    topic0: str,
    logs: list[FetchedEventLog],
    *,
    batch_size: int = DEFAULT_INSERT_BATCH,
) -> int:
    if not logs:
        return 0
    total = 0
    for offset in range(0, len(logs), max(1, batch_size)):
        rows = [
            {
                "chain_id": chain_id,
                "event_address": event_address,
                "topic0": topic0,
                "tx_hash": log.tx_hash,
                "log_index": log.log_index,
                "block_number": log.block_number,
                "block_hash": log.block_hash,
                "transaction_index": log.transaction_index,
                "topics": log.topics,
                "data_words": log.data_words,
            }
            for log in logs[offset : offset + max(1, batch_size)]
        ]
        stmt = (
            pg_insert(IndexedEventLog)
            .values(rows)
            .on_conflict_do_nothing(index_elements=["chain_id", "event_address", "topic0", "tx_hash", "log_index"])
        )
        result = session.execute(stmt)
        total += int(getattr(result, "rowcount", 0) or 0)
    return total


def _descriptors_from_artifact(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for key in ("trees", "check_trees"):
        trees = artifact.get(key)
        if not isinstance(trees, dict):
            continue
        for tree in trees.values():
            out.extend(_walk_descriptors(tree))
    return out


def _walk_descriptors(node: Any) -> list[dict[str, Any]]:
    if not isinstance(node, dict):
        return []
    if node.get("op") == "LEAF":
        leaf = node.get("leaf")
        descriptor = leaf.get("set_descriptor") if isinstance(leaf, dict) else None
        return [descriptor] if isinstance(descriptor, dict) else []
    out: list[dict[str, Any]] = []
    for child in node.get("children") or []:
        out.extend(_walk_descriptors(child))
    return out


def _state_var_values_for_job(session: Session, job: Job) -> dict[str, str]:
    contract = session.execute(select(Contract).where(Contract.job_id == job.id).limit(1)).scalar_one_or_none()
    if contract is None:
        return {}
    rows = session.execute(select(ControllerValue).where(ControllerValue.contract_id == contract.id)).scalars()
    out: dict[str, str] = {}
    for row in rows:
        name = str(row.controller_id or "").partition(":")[2] or str(row.controller_id or "")
        if name and row.value:
            out[name] = row.value
    return out


def _job_runtime_address(job: Job) -> str | None:
    """Address whose events resolution reads for ``job`` — the proxy for a
    proxy-linked impl job, else ``job.address``.

    Tracks ``capability_resolver``'s ``runtime_addr`` (``request['proxy_address']``
    when set, else ``job.address``). An impl behind a proxy emits its self-
    administered role/authority events under the *proxy*; enrolling the cursor at
    ``job.address`` indexes an address that emits nothing, leaving the proxy —
    where the fold reads — cold and forcing a per-function HyperSync fallback.
    """
    request = getattr(job, "request", None)
    if not isinstance(request, dict):
        request = {}
    proxy = request.get("proxy_address")
    if isinstance(proxy, str) and proxy.startswith("0x") and len(proxy) == 42:
        return proxy.lower()
    return job.address.lower() if job.address and len(job.address) == 42 else None


def _event_address_for_descriptor(
    descriptor: dict[str, Any],
    hint: dict[str, Any],
    job: Job,
    state_var_values: dict[str, str],
    *,
    allow_job_fallback: bool = True,
) -> str | None:
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
        value = state_var_values.get(name) if isinstance(name, str) else None
        if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
            return value.lower()
    if not allow_job_fallback:
        return None
    return _job_runtime_address(job)


def _cursor_progress(session: Session) -> tuple[int, int]:
    """``(caught_up, total)`` enrollable cursors, read straight from the table.

    The fleet heartbeat derives its triad from this rather than the backfill
    thread's last published ``ScanSummary``: a cold-start scan pass can run for
    minutes without returning, so the published summary reflects the last
    *completed* pass (e.g. "3 of 3 caught up") while the table holds far more
    pending cursors. Reading the table keeps the fleet view honest about an
    in-progress backfill instead of showing a stale "all caught up".
    """
    caught_up, total = session.execute(
        select(
            func.count().filter(IndexedEventCursor.backfill_complete),
            func.count(),
        ).where(IndexedEventCursor.event_address != _ZERO_ADDRESS)
    ).one()
    return int(caught_up or 0), int(total or 0)


def run_event_log_indexer_loop(
    *,
    fetchers: Mapping[int, LogFetcher],
    head_fetchers: Mapping[int, HeadBlockFetcher],
    block_hash_fetchers: Mapping[int, BlockHashFetcher],
    interval: float = DEFAULT_INTERVAL_S,
    stop_event: Event | None = None,
) -> None:
    """Run the durable event-log indexer.

    The indexer is two decoupled jobs that used to share one serial loop:

    * **Backfill** (``enroll`` + ``scan``) — throughput-oriented. Each pass is
      bounded by a per-pass window budget so it returns within ~a minute even on a
      cold index; a high-volume authority (the LayerZero endpoint) backfills across
      several budgeted passes instead of one multi-hour grind.
    * **Reconcile + heartbeat** — fast, latency-sensitive. The reconcile self-heals
      index-cold capability deferrals the moment their authority's cursor flips
      ``backfill_complete``; the heartbeat keeps the fleet view live.

    Run serially, a long backfill pass starved both: the reconcile never ran, so
    completed jobs whose authorities had *already* warmed (committed mid-scan) sat
    un-reconciled for the whole cold-start window, and the heartbeat went stale.
    So backfill runs on its own thread and this loop runs reconcile + heartbeat
    every ``interval`` — reconcile latency is now ``interval`` regardless of how
    long any scan pass takes. The thread publishes its last scan summary for the
    heartbeat to fold in.
    """
    logger.info("starting event log indexer loop interval=%ss", interval)
    stop_event = stop_event or Event()

    state_lock = Lock()
    published: dict[str, Any] = {"summary": ScanSummary(), "enrolled": 0, "status": "running"}

    def backfill_loop() -> None:
        while not stop_event.is_set():
            enrolled = 0
            summary = ScanSummary()
            status = "running"
            try:
                with SessionLocal() as session:
                    with log_timed_phase(logger, "indexer_enroll", record_metric=False) as ph:
                        enrolled = enroll_from_completed_jobs(session)
                        ph["enrolled"] = enrolled
                    with log_timed_phase(logger, "indexer_scan", record_metric=False) as ph:
                        summary = scan_enrolled_events(
                            session,
                            fetchers=fetchers,
                            head_fetchers=head_fetchers,
                            block_hash_fetchers=block_hash_fetchers,
                        )
                        ph["windows_scanned"] = summary.windows_scanned
                        ph["inserted"] = summary.inserted
            except Exception:
                logger.exception("event log indexer backfill pass failed")
                status = "error"
            # One UNCONDITIONAL per-pass INFO carrying the cursor triad. The old
            # line was gated on ``enrolled or inserted``, so it went silent during
            # exactly the case that needs watching: a cold from-0 backfill grinding
            # empty getLogs windows (0 inserted) while the heartbeat says "caught
            # up". Emitting every pass makes that throughput stall visible.
            status = _heartbeat_status_for_pass(status, summary)
            logger.info(
                "event log indexer pass complete",
                extra={
                    "enrolled": enrolled,
                    "inserted": summary.inserted,
                    "windows_scanned": summary.windows_scanned,
                    "caught_up_cursors": summary.caught_up_cursors,
                    "total_cursors": summary.total_cursors,
                    "pending_cursors": max(0, summary.total_cursors - summary.caught_up_cursors),
                    "budget_exhausted": summary.budget_exhausted,
                    "failed_groups": summary.failed_groups,
                    "status": status,
                },
            )
            with state_lock:
                published["summary"] = summary
                published["enrolled"] = enrolled
                published["status"] = status
            # A budget-capped pass that hit its ceiling has more backfill pending:
            # re-run after a short pause instead of the full interval so a cold
            # fleet drains at throughput. min() so a sub-interval test cadence
            # isn't slowed; the floor keeps a warm fleet from busy-spinning.
            backfill_wait = min(interval, DEFAULT_BACKFILL_BUSY_INTERVAL_S) if summary.budget_exhausted else interval
            stop_event.wait(backfill_wait)

    backfill = Thread(target=backfill_loop, name="event-indexer-backfill", daemon=True)
    backfill.start()

    try:
        while not stop_event.is_set():
            reenqueued = 0
            drift_reenqueued = 0
            try:
                with SessionLocal() as session:
                    with log_timed_phase(logger, "indexer_reconcile", record_metric=False) as ph:
                        # Reconcile once per chain the indexer serves — the
                        # reconcilers filter authorities by chain_id, so the old
                        # single implicit chain_id=1 call left every non-mainnet
                        # chain's index-cold deferrals un-self-healed. The chain set
                        # is the registry allowlist (inv. 10/14): mainnet-only
                        # ({1}) by default, so mainnet behavior is unchanged.
                        for reconcile_chain_id in sorted(supported_chain_ids()):
                            reenqueued += reconcile_deferred_resolutions(session, chain_id=reconcile_chain_id)
                            # Warm-drift arm: re-resolve completed jobs whose
                            # enumerated role-store set has a grant/revoke indexed
                            # past its frontier.
                            drift_reenqueued += reconcile_role_set_drift(session, chain_id=reconcile_chain_id)
                        ph["reenqueued"] = reenqueued
                        ph["drift_reenqueued"] = drift_reenqueued
                if reenqueued or drift_reenqueued:
                    logger.info(
                        "reconcilers re-enqueued %d job(s) (deferred=%d role_drift=%d)",
                        reenqueued + drift_reenqueued,
                        reenqueued,
                        drift_reenqueued,
                    )
            except Exception:
                logger.exception("deferred-resolution reconcile pass failed")
            # Read the cursor triad straight from the table, independent of the
            # backfill thread. A long cold-start scan pass doesn't return for
            # minutes, so the thread's published summary lags reality ("3 of 3
            # caught up" while 10 cursors backfill). Isolated try + own session:
            # a count failure must not blank the rest of the heartbeat.
            caught_up_cursors = 0
            total_cursors = 0
            try:
                with SessionLocal() as session:
                    caught_up_cursors, total_cursors = _cursor_progress(session)
            except Exception:
                logger.exception("event log indexer cursor-progress count failed")
            with state_lock:
                summary = published["summary"]
                enrolled = published["enrolled"]
                status = published["status"]
            # The backfill thread catches its own per-pass exceptions, so a dead
            # thread means a fatal stall — surface it as an indexer error.
            if not backfill.is_alive() and not stop_event.is_set():
                status = "error"
                logger.error("event log indexer backfill thread is not alive; indexing has stalled")
            # The cursor triad comes from the live table (caught_up/total/pending),
            # not the last-completed pass, so the fleet view tracks an in-progress
            # backfill instead of a stale "all caught up". windows_scanned/inserted
            # stay per-pass activity from the published summary.
            record_heartbeat(
                HEARTBEAT_EVENT_INDEXER,
                status=status,
                detail={
                    "enrolled_last_pass": enrolled,
                    "inserted_last_pass": summary.inserted,
                    "windows_scanned": summary.windows_scanned,
                    "caught_up_cursors": caught_up_cursors,
                    "total_cursors": total_cursors,
                    "pending_cursors": max(0, total_cursors - caught_up_cursors),
                    "deferred_reenqueued_last_pass": reenqueued,
                    "role_drift_reenqueued_last_pass": drift_reenqueued,
                },
            )
            stop_event.wait(interval)
    finally:
        backfill.join(timeout=max(1.0, interval))


def _build_indexer_fetchers(
    chains: Sequence[ChainInfo] | None = None,
) -> tuple[dict[int, LogFetcher], dict[int, HeadBlockFetcher], dict[int, BlockHashFetcher]]:
    """Build the per-chain fetcher maps the indexer scan loop dispatches on.

    Indexer chain set = registry chains with proven Envio coverage
    (``hypersync_url is not None``, inv. 10): a chain without it is deliberately
    indexer-disabled and gets no fetcher (its cursors are then skipped-and-logged
    by the scan loop).

    Every fetcher — every chain, mainnet included — POSTs plain JSON-RPC through
    the chain's eRPC route (``require_rpc_url(chain_id=...)``, i.e.
    ``{ERPC_BASE_URL}/main/evm/{chain_id}``). The indexer is just another eRPC
    client; chain 1 is not special. Why eRPC and not a direct provider: routing,
    the per-chain HyperRPC upstreams that make eth_getLogs a $0 read, provider
    failover, and auth (the eRPC secret header, attached by ``rpc_request``) are
    all eRPC-deployment config, deliberately NOT in PSAT. The native
    ``hypersync_url`` (``<chain>.hypersync.xyz``) is the resolution repos' query
    API and rejects JSON-RPC — here it is only the coverage signal, never a
    fetcher URL.
    """
    from services.resolution.repos.event_logs_rpc import RpcBlockHashFetcher, RpcEventLogFetcher, RpcHeadBlockFetcher

    registry_chains = all_chains() if chains is None else chains
    fetchers: dict[int, LogFetcher] = {}
    head_fetchers: dict[int, HeadBlockFetcher] = {}
    block_hash_fetchers: dict[int, BlockHashFetcher] = {}
    for info in registry_chains:
        if info.hypersync_url is None:
            continue
        rpc_url = require_rpc_url(chain_id=info.chain_id)
        fetchers[info.chain_id] = RpcEventLogFetcher(rpc_url)
        head_fetchers[info.chain_id] = RpcHeadBlockFetcher(rpc_url)
        block_hash_fetchers[info.chain_id] = RpcBlockHashFetcher(rpc_url)
    return fetchers, head_fetchers, block_hash_fetchers


def main() -> None:
    # JsonFormatter on the root logger so every line this daemon emits — and
    # every ``extra={}`` field it already attaches (windows_scanned, inserted,
    # exc_type, the cursor triad) — ships as queryable JSON instead of plaintext.
    configure_logging()
    stop_event = Event()

    def handle_signal(signum, _frame):
        logger.info("received signal %s, shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    fetchers, head_fetchers, block_hash_fetchers = _build_indexer_fetchers()
    run_event_log_indexer_loop(
        fetchers=fetchers,
        head_fetchers=head_fetchers,
        block_hash_fetchers=block_hash_fetchers,
        stop_event=stop_event,
    )


if __name__ == "__main__":
    main()
