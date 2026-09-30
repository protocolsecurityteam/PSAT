"""Generic event-log indexer for predicate ``enumeration_hint`` records."""

from __future__ import annotations

import inspect
import logging
import os
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Event, Lock, Thread
from typing import Any, Callable, Iterator, Literal, Mapping, MutableMapping, Protocol, Sequence, TypeGuard, cast

from eth_utils.crypto import keccak
from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.floor_witnesses import (
    WITNESS_FAILED,
    WITNESS_PRIOR_INCARNATION,
    WITNESS_PROVEN,
    WitnessOutcome,
    record_floor_witness,
)
from db.models import (
    CURSOR_BASIS_NOT_DETERMINED,
    ENROLLMENT_BASIS_PREDICATE_HINT,
    ENROLLMENT_BASIS_TRACKED_TOPICS,
    EXACTNESS_ELIGIBLE_ENROLLMENT_BASES,
    FIRST_INDEXED_BASIS_CREATION,
    WINDOW_STATS_CONTINUOUS,
    WINDOW_STATS_NOT_DETERMINED,
    Contract,
    ControllerValue,
    IndexedEventCursor,
    IndexedEventLog,
    Job,
    JobStatus,
    MonitoredContract,
    SessionLocal,
    derive_job_chain_id,
    exactness_eligible_cursor_clause,
)
from db.queue import HEARTBEAT_EVENT_INDEXER, get_artifact, record_heartbeat
from services.clients.etherscan import get_contract_creation_block
from services.clients.rpc import require_rpc_url, rpc_request
from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.resolution.repos.event_logs_rpc import FetchedEventLog, FetchWindowStat
from services.resolution.role_store_standards import all_topic0s, detect_standards, resolve_probe_code
from utils.chains import (
    ChainInfo,
    UnknownChainError,
    all_chains,
    chain_by_id,
    chain_by_name,
    supported_chain_ids,
)
from utils.logging import bind_trace_context, configure_logging, log_timed_phase
from utils.secrets import sanitize_string

logger = logging.getLogger("workers.event_log_indexer")

# Process identity for every line; the indexer isn't a BaseWorker, so it binds its own.
WORKER_ID = f"EventLogIndexer-{os.getpid()}-{uuid.uuid4().hex[:8]}"

DEFAULT_INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_INTERVAL_S", "60"))
DEFAULT_CONFIRMATION_DEPTH = int(os.getenv("PSAT_EVENT_INDEXER_FINALITY_DEPTH", "12"))

# Scan in bounded windows: an unbounded step once built one huge insert that dropped the Neon connection and wedged the
# cursor at 0. Windows are wide because each is one eth_getLogs and HyperRPC bills per request regardless of range;
# dense bursts are bounded by the upstream's 50k cap and the fetcher's bisect.
DEFAULT_MAX_BLOCK_SPAN = int(os.getenv("PSAT_EVENT_INDEXER_MAX_BLOCK_SPAN", "500000"))
# Per-group and per-pass window caps: one busy address can't monopolize a pass, and each pass returns promptly so the
# heartbeat refreshes and least-recently-run rotation reorders. Cold gaps drain over successive passes.
DEFAULT_MAX_WINDOWS_PER_CURSOR = int(os.getenv("PSAT_EVENT_INDEXER_MAX_WINDOWS_PER_CURSOR", "50"))
DEFAULT_MAX_WINDOWS_PER_PASS = int(os.getenv("PSAT_EVENT_INDEXER_MAX_WINDOWS_PER_PASS", "100"))
DEFAULT_INSERT_BATCH = int(os.getenv("PSAT_EVENT_INDEXER_INSERT_BATCH", "1000"))
# Commit in bounded batches, whole blocks at a time; the INSERT trigger's reconciliation row isn't released otherwise.
DEFAULT_WRITE_MAX_ROWS = 5_000
DEFAULT_WRITE_MAX_BYTES = 4 * 1024 * 1024
# Monitored contracts still needing a cursor, worked per pass (each mints a cold backfill). Fully enrolled addresses
# cost one lookup and don't count, so the fleet drains and settles at zero.
DEFAULT_TRACKED_TOPIC_ENROLL_LIMIT = int(os.getenv("PSAT_EVENT_INDEXER_TRACKED_TOPIC_LIMIT", "50"))
# A memory/latency bound on how many contracts a pass looks at, not a work budget; keep it above the fleet size or the
# tail is unreachable.
DEFAULT_TRACKED_TOPIC_SCAN_LIMIT = int(os.getenv("PSAT_EVENT_INDEXER_TRACKED_TOPIC_SCAN_LIMIT", "5000"))
# Only cold history uses the short pause; warm groups use the normal interval.
DEFAULT_BACKFILL_BUSY_INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_BACKFILL_BUSY_INTERVAL_S", "2"))

# Solmate RolesAuthority role events, enrolled directly from the canCall descriptor so it works on trees materialized
# before enumeration hints existed. Topics computed here to avoid importing the adapter.
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


# Basis vocabulary lives in ``db/models/balances.py``. ``FIRST_INDEXED_BASIS_EXPLICIT`` has no writer here (all
# enrolment witness-grades) but stays in the domain so a caller's seed is never read as a witness.
BASIS_NOT_DETERMINED = CURSOR_BASIS_NOT_DETERMINED

# EIP-7702 delegation indicator: 0xef0100 ‖ 20-byte address (23 bytes).
_EIP7702_PREFIX = "ef0100"
_EIP7702_CODE_HEX_LEN = 46


def _is_solmate_cancall_descriptor(descriptor: dict[str, Any]) -> bool:
    if not isinstance(descriptor, dict) or descriptor.get("kind") != "external_set":
        return False
    signature = descriptor.get("callee_signature")
    selector = descriptor.get("callee_selector")
    return (isinstance(signature, str) and signature.replace(" ", "") == _SOLMATE_CANCALL_SIGNATURE) or (
        isinstance(selector, str) and selector.lower() == _SOLMATE_CANCALL_SELECTOR
    )


def _is_single_address_param_signature(signature: Any) -> bool:
    """``name(address)``: the shape of a delegated role gate's callee, as opposed to canCall."""
    if not isinstance(signature, str) or "(" not in signature or not signature.rstrip().endswith(")"):
        return False
    params = signature[signature.index("(") + 1 : signature.rindex(")")]
    return [p.strip() for p in params.split(",") if p.strip()] == ["address"]


def _is_delegated_role_gate_descriptor(descriptor: dict[str, Any]) -> bool:
    """A caller-keyed external bool check on a single-address callee of a delegated authority
    (``roleRegistry.onlyX(msg.sender)``), not Solmate canCall. The registry's own trees compile to no descriptors
    (assembly operands), so this outer descriptor is the only enrollment trigger for its RoleSet cursor.
    """
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
    """Whether an exactness-eligible role-store cursor is already enrolled for ``authority``; if so, the
    per-descriptor ``eth_getCode`` detection can be skipped. Tracking-plan cursors on the same topic don't count,
    or detection would be skipped and the attributed cursor never enrolled.
    """
    row = session.execute(
        select(IndexedEventCursor.event_address)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == authority.lower())
        .where(IndexedEventCursor.topic0.in_(_ALL_ROLE_STORE_TOPIC0S))
        .where(exactness_eligible_cursor_clause())
        .limit(1)
    ).first()
    return row is not None


def _role_store_topic0s(
    session: Session, authority: str, chain_id: int, cache: dict[tuple[int, str], list[str]]
) -> list[str]:
    """Grant/revoke topic0s to enroll at ``authority``, detected from the impl bytecode behind the registry proxy.

    Inconclusive detection enrolls the union (an extra cursor is cheap, a missing one kills recall). Memoized per
    ``(chain_id, authority)`` per pass.
    """
    key = (chain_id, authority.lower())
    if key in cache:
        return cache[key]
    try:
        code = resolve_probe_code(session, authority, chain_id)
    except Exception as exc:
        # No code still enrolls the union, as intended; logged so an RPC outage isn't mistaken for no known standard.
        code = None
        logger.warning(
            "role-store probe code unreadable; enrolling the union of all standards",
            extra={
                "authority": authority,
                "chain_id": chain_id,
                "exc_type": type(exc).__name__,
                "decision": "enroll_all_standards",
            },
        )
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
    # ``window_stats`` is optional so older fetchers still satisfy the protocol; ``_fetch_window`` passes it only where
    # supported.
    def fetch_logs(
        self,
        *,
        event_address: str | Sequence[str],
        topics: Sequence[str],
        from_block: int,
        to_block: int,
    ) -> list[FetchedEventLog]: ...


class StatsAwareLogFetcher(Protocol):
    """A fetcher that reports each accepted page. ``_fetch_window`` checks the signature before using it."""

    def fetch_logs(
        self,
        *,
        event_address: str | Sequence[str],
        topics: Sequence[str],
        from_block: int,
        to_block: int,
        window_stats: list[FetchWindowStat] | None = None,
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
    """What one ``scan_enrolled_events`` pass did, for the heartbeat.

    Many windows with nothing inserted and ``caught_up_cursors`` < ``total_cursors`` is a cold address grinding through
    empty ranges.
    """

    inserted: int = 0
    windows_scanned: int = 0
    caught_up_cursors: int = 0
    total_cursors: int = 0
    # The pass stopped on its window budget; the loop re-runs sooner.
    budget_exhausted: bool = False
    # Groups whose scan raised this pass, so a total outage degrades the heartbeat instead of producing a traceback
    # storm.
    failed_groups: int = 0


def _heartbeat_status_for_pass(status: str, summary: ScanSummary) -> str:
    """Degrade a pass where every attempted group failed and no window advanced (a total outage).

    Partial failures stay ``running``.
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
    first_indexed_block: int | None = None,
    first_indexed_block_basis: str | None = None,
    enrollment_basis: str | None = None,
) -> bool:
    """Insert one cursor, ignoring conflicts.

    The provenance arguments default to "nothing proven"; ``start_block``'s ``= 0`` must never be read as "starts at
    genesis".
    """
    stmt = (
        pg_insert(IndexedEventCursor)
        .values(
            chain_id=chain_id,
            event_address=event_address.lower(),
            topic0=topic0.lower(),
            last_indexed_block=start_block,
            first_indexed_block=first_indexed_block,
            first_indexed_block_basis=first_indexed_block_basis or BASIS_NOT_DETERMINED,
            enrollment_basis=enrollment_basis or BASIS_NOT_DETERMINED,
            window_stats_basis=(
                WINDOW_STATS_CONTINUOUS
                if first_indexed_block_basis == FIRST_INDEXED_BASIS_CREATION
                else WINDOW_STATS_NOT_DETERMINED
            ),
        )
        .on_conflict_do_nothing(index_elements=["chain_id", "event_address", "topic0"])
    )
    result = session.execute(stmt)
    return bool(getattr(result, "rowcount", 0))


def _is_empty_code(code: object) -> bool:
    return isinstance(code, str) and len(code[2:] if code.lower().startswith("0x") else code) == 0


def _is_eip7702_delegation(code: object) -> bool:
    """A 7702 delegation stub has code without being deployed and can be toggled, so code appearing at a block says
    nothing about its first log.
    """
    if not isinstance(code, str):
        return False
    body = (code[2:] if code.lower().startswith("0x") else code).lower()
    return len(body) == _EIP7702_CODE_HEX_LEN and body.startswith(_EIP7702_PREFIX)


def _witness_seed_block(
    address: str,
    seed: int,
    cache: dict[tuple[int, str], tuple[int | None, str]],
    *,
    chain_id: int,
    session: Session | None = None,
) -> tuple[int | None, str]:
    """Grade ``seed`` as a proven lower bound with three pinned reads; returns ``(first_indexed_block, basis)``.

    Empty code at ``seed`` and code at ``seed + 1`` shows a deployment there, but not the first (a SELFDESTRUCTed
    address can be redeployed by CREATE2 with earlier logs still on chain). The witness is a third read: a
    genesis-anchored ``eth_getLogs`` for the address with no topic filter. Zero logs at or below ``seed`` proves nothing
    was emitted there; any log discards the number (how far back is unknown). The request exceeds the range cap; if that
    ever stops being allowed it raises and lands on ``not_determined``.

    Every failure (either code read, the log read, errors, timeouts, non-list responses, a 7702 stub) returns ``(None,
    not_determined)``: the block is dropped with the basis. With a ``session``, the outcome is also upserted into
    ``address_floor_witnesses`` (once per cached address).
    """
    addr = address.lower()
    key = (chain_id, addr)
    if key in cache:
        return cache[key]
    graded: tuple[int | None, str] = (None, BASIS_NOT_DETERMINED)
    outcome: WitnessOutcome = WITNESS_FAILED
    try:
        rpc_url = require_rpc_url(chain_id=chain_id)
        code_before = rpc_request(rpc_url, "eth_getCode", [addr, hex(seed)], chain_id=chain_id)
        code_at = rpc_request(rpc_url, "eth_getCode", [addr, hex(seed + 1)], chain_id=chain_id)
        if _is_empty_code(code_before) and not _is_empty_code(code_at) and not _is_eip7702_delegation(code_at):
            prior_logs = rpc_request(
                rpc_url,
                "eth_getLogs",
                [{"address": addr, "fromBlock": "0x0", "toBlock": hex(seed)}],
                chain_id=chain_id,
            )
            if isinstance(prior_logs, list) and not prior_logs:
                graded = (seed, FIRST_INDEXED_BASIS_CREATION)
                outcome = WITNESS_PROVEN
            elif isinstance(prior_logs, list):
                outcome = WITNESS_PRIOR_INCARNATION
                logger.info(
                    "logs observed below the creation seed; lower bound not determined",
                    extra={
                        "address": addr,
                        "chain_id": chain_id,
                        "seed": seed,
                        "prior_log_count": len(prior_logs),
                    },
                )
    except Exception as exc:
        logger.warning(
            "first-indexed-block witness failed for %s; lower bound not determined",
            addr,
            extra={"address": addr, "chain_id": chain_id, "seed": seed, "exc_type": type(exc).__name__},
        )
    cache[key] = graded
    if session is not None:
        record_floor_witness(session, chain_id=chain_id, address=addr, outcome=outcome, first_indexed_block=graded[0])
    return graded


def _cursor_exists(session: Session, chain_id: int, event_address: str, topic0: str) -> bool:
    """Whether this cursor is already enrolled; skips the three-read witness for addresses that would no-op, so
    steady state costs no RPC.
    """
    return (
        session.execute(
            select(IndexedEventCursor.chain_id)
            .where(IndexedEventCursor.chain_id == chain_id)
            .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
            .where(func.lower(IndexedEventCursor.topic0) == topic0.lower())
        ).first()
        is not None
    )


def _upgrade_to_predicate_hint(session: Session, *, chain_id: int, address: str, topic0: str) -> bool:
    """Upgrade an existing, witnessed cursor whose basis isn't already eligible to ``predicate_tree_hint``; no other
    column changes. A cursor without a ``creation_block_minus_one`` lower bound is never upgraded.
    """
    eligible = [b for b in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES if b is not None]
    result = session.execute(
        update(IndexedEventCursor)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == address.lower())
        .where(func.lower(IndexedEventCursor.topic0) == topic0.lower())
        .where(IndexedEventCursor.first_indexed_block_basis == FIRST_INDEXED_BASIS_CREATION)
        .where(IndexedEventCursor.enrollment_basis.is_not(None))
        .where(IndexedEventCursor.enrollment_basis.not_in(eligible))
        .values(enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT)
        .execution_options(synchronize_session=False)
    )
    upgraded = bool(getattr(result, "rowcount", 0))
    if upgraded:
        logger.info(
            "cursor enrollment basis upgraded to predicate_tree_hint",
            extra={"chain_id": chain_id, "event_address": address.lower(), "topic0": topic0.lower()},
        )
    return upgraded


_FETCHER_ACCEPTS_WINDOW_STATS: dict[type, bool] = {}


def _fetch_window(
    fetcher: LogFetcher,
    *,
    event_address: str,
    topics: list[str],
    from_block: int,
    to_block: int,
    window_stats: list[FetchWindowStat],
) -> list[FetchedEventLog]:
    """Call ``fetch_logs``, passing the stats accumulator only to fetchers that accept it.

    Decided by signature, not by catching ``TypeError`` (which would hide real errors). Without it ``window_stats``
    stays empty, which ``_fold_window_stats`` treats as "advanced without a record".
    """
    key = type(fetcher)
    accepts = _FETCHER_ACCEPTS_WINDOW_STATS.get(key)
    if accepts is None:
        try:
            accepts = "window_stats" in inspect.signature(fetcher.fetch_logs).parameters
        except (TypeError, ValueError):
            accepts = False
        _FETCHER_ACCEPTS_WINDOW_STATS[key] = accepts
    if accepts:
        return cast(StatsAwareLogFetcher, fetcher).fetch_logs(
            event_address=event_address,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
            window_stats=window_stats,
        )
    return fetcher.fetch_logs(event_address=event_address, topics=topics, from_block=from_block, to_block=to_block)


def index_event_group_steps(
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
    write_max_rows: int = DEFAULT_WRITE_MAX_ROWS,
    write_max_bytes: int = DEFAULT_WRITE_MAX_BYTES,
) -> Iterator[GroupStepResult]:
    """Yield atomic write prefixes of one fetched (chain, address) window.

    The caller must commit each prefix before requesting the next (logs, cursor progress and trigger invalidation share
    the transaction), then re-lock and validate cursors; a concurrent advance or rewind discards the remainder.

    One ``eth_getLogs`` covers all the group's topic0s (billing is per request), demuxed to per-topic cursors that
    advance in lockstep from the group minimum. ``target`` is the confirmed head, computed once per pass.
    """
    memo: MutableMapping[tuple[int, int], bytes | None] = block_hash_memo if block_hash_memo is not None else {}
    topic_list = sorted({str(t).lower() for t in topics})
    cursor_query = (
        select(IndexedEventCursor)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
        .where(func.lower(IndexedEventCursor.topic0).in_(topic_list))
        .order_by(IndexedEventCursor.topic0)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    cursors = session.execute(cursor_query).scalars().all()
    if not cursors:
        yield GroupStepResult(
            scanned_from=0, scanned_to=0, inserted=0, members_at_target=0, group_complete=True, fetched=False
        )
        return

    def _hash_at(block: int) -> bytes | None:
        key = (chain_id, block)
        if key not in memo:
            memo[key] = block_hash_fetcher.block_hash(block)
        return memo[key]

    # Reorg guard. Hash stamps exist only where a cursor reached the confirmed target, so this runs once per warm cursor
    # re-entering a scan; the memo dedups lookups.
    rewind_to: int | None = None
    for cursor in cursors:
        last = int(cursor.last_indexed_block or 0)
        if last <= 0 or cursor.last_indexed_block_hash is None or last >= target:
            continue
        observed_hash = _hash_at(last)
        if observed_hash is not None and observed_hash != cursor.last_indexed_block_hash:
            rewind_to = max(0, last - confirmation_depth)
            # A rewind deletes indexed logs; log it. The range is re-fetched next pass.
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
            # The delete is address-wide, so sibling cursors above the rewind point rewind too. The DELETE waits until
            # external reads finish, since its trigger locks the reconciliation row.
            rewind_hash = _hash_at(rewind_to) if rewind_to else None
            for member in cursors:
                if int(member.last_indexed_block or 0) > rewind_to:
                    member.last_indexed_block = rewind_to
                    member.last_indexed_block_hash = rewind_hash
                    member.backfill_complete = False
            break

    active = [c for c in cursors if int(c.last_indexed_block or 0) < target]
    if not active:
        # Mark caught-up cursors and re-stamp last_run_at on this no-fetch visit, or stale warm groups keep sorting
        # ahead of cold ones.
        for cursor in cursors:
            cursor.backfill_complete = True
            cursor.last_run_at = func.now()
        yield GroupStepResult(
            scanned_from=target + 1,
            scanned_to=target,
            inserted=0,
            members_at_target=len(cursors),
            group_complete=True,
            fetched=False,
        )
        return

    start = min(int(c.last_indexed_block or 0) for c in active) + 1
    window_end = min(target, start - 1 + max(1, max_block_span))
    # Per accepted page; an empty record from an older fetcher downgrades the cursor rather than meaning "no logs".
    window_stats: list[FetchWindowStat] = []
    logs = _fetch_window(
        fetcher,
        event_address=event_address.lower(),
        topics=[c.topic0.lower() for c in active],
        from_block=start,
        to_block=window_end,
        window_stats=window_stats,
    )
    # Plan (and fetch all needed hashes) before the first write takes the shared lock.
    for cursor in cursors:
        final_block = max(int(cursor.last_indexed_block or 0), window_end)
        if final_block >= target and (
            cursor.last_indexed_block_hash is None or window_end > int(cursor.last_indexed_block or 0)
        ):
            _hash_at(final_block)
    logs.sort(key=lambda log: log.block_number)
    prefixes = _write_prefixes(logs, window_end, max_rows=write_max_rows, max_bytes=write_max_bytes)
    if rewind_to is not None:
        session.execute(
            delete(IndexedEventLog)
            .where(IndexedEventLog.chain_id == chain_id)
            .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
            .where(IndexedEventLog.block_number > rewind_to)
        )

    expected = None
    prefix_start = start
    for offset, end_offset, prefix_end in prefixes:
        if expected is not None:
            cursors = session.execute(cursor_query).scalars().all()
            if _cursor_positions(cursors) != expected:
                raise RuntimeError("event cursors changed between write prefixes; refetch required")
        logs_by_topic: dict[str, list[FetchedEventLog]] = {}
        for log in logs[offset:end_offset]:
            if log.topics:
                logs_by_topic.setdefault(log.topics[0].lower(), []).append(log)
        inserted = 0
        members_at_target = 0
        for cursor in cursors:
            last = int(cursor.last_indexed_block or 0)
            if prefix_end > last:
                member_logs = [log for log in logs_by_topic.get(cursor.topic0.lower(), []) if log.block_number > last]
                inserted += _bulk_insert_logs(
                    session,
                    chain_id,
                    event_address.lower(),
                    cursor.topic0.lower(),
                    member_logs,
                    batch_size=insert_batch_size,
                )
                cursor.last_indexed_block = prefix_end
                cursor.last_indexed_block_hash = None
                # Keep the RPC page's count and cap even if only a prefix was committed.
                _fold_window_stats(cursor, window_stats)
            cursor.backfill_complete = int(cursor.last_indexed_block or 0) >= target
            if cursor.backfill_complete:
                members_at_target += 1
                if cursor.last_indexed_block_hash is None:
                    cursor.last_indexed_block_hash = memo[(chain_id, int(cursor.last_indexed_block))]
            cursor.last_run_at = func.now()
        expected = _cursor_positions(cursors)
        yield GroupStepResult(
            scanned_from=prefix_start,
            scanned_to=prefix_end,
            inserted=inserted,
            members_at_target=members_at_target,
            group_complete=members_at_target == len(cursors),
            fetched=prefix_start == start,
        )
        prefix_start = prefix_end + 1


def _cursor_positions(cursors: Sequence[IndexedEventCursor]) -> list[tuple[str, int, bytes | None]]:
    return [(c.topic0, int(c.last_indexed_block or 0), c.last_indexed_block_hash) for c in cursors]


def _write_prefixes(
    logs: list[FetchedEventLog], window_end: int, *, max_rows: int, max_bytes: int
) -> list[tuple[int, int, int]]:
    """Write offsets and inclusive frontiers that never split a block.

    An oversized single block is committed alone. Soft budgets; bytes estimate serialized size.
    """
    prefixes: list[tuple[int, int, int]] = []
    offset = 0
    payload_bytes = 0
    block_start = 0
    while block_start < len(logs):
        block_end = block_start
        block_bytes = 0
        block = logs[block_start].block_number
        while block_end < len(logs) and logs[block_end].block_number == block:
            log = logs[block_end]
            block_bytes += 256 + sum(len(word) + 4 for word in (*log.topics, *log.data_words))
            block_end += 1
        if block_start > offset and (
            block_end - offset > max(1, max_rows) or payload_bytes + block_bytes > max(1, max_bytes)
        ):
            prefixes.append((offset, block_start, block - 1))
            offset = block_start
            payload_bytes = 0
        payload_bytes += block_bytes
        block_start = block_end
    prefixes.append((offset, len(logs), window_end))
    return prefixes


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
    write_max_rows: int = DEFAULT_WRITE_MAX_ROWS,
    write_max_bytes: int = DEFAULT_WRITE_MAX_BYTES,
    stop_event: Event | None = None,
    scan_mode: Literal["all", "warm", "cold"] = "all",
) -> ScanSummary:
    # Group cursors by (chain, address) so one eth_getLogs serves every topic on an address. Rotation is
    # least-recently-run per group, so one busy address can't monopolize passes and new cursors warm within a rotation.
    all_rows = session.execute(
        select(
            IndexedEventCursor.chain_id,
            IndexedEventCursor.event_address,
            IndexedEventCursor.topic0,
            IndexedEventCursor.last_run_at,
            IndexedEventCursor.last_indexed_block,
            IndexedEventCursor.backfill_complete,
        )
    ).all()
    # Skip zero/invalid addresses from before the enroll-time guard; 0x0 never emits logs.
    rows = [row for row in all_rows if _is_enrollable_event_address(row[1])]
    groups: dict[tuple[int, str], dict[str, Any]] = {}
    for chain_id, event_address, topic0, last_run_at, last_block, complete in rows:
        entry = groups.setdefault(
            (chain_id, event_address.lower()), {"topics": set(), "runs": [], "last_blocks": [], "complete": True}
        )
        entry["topics"].add(topic0.lower())
        entry["runs"].append(last_run_at)
        entry["last_blocks"].append(int(last_block or 0))
        entry["complete"] &= bool(complete)

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
    # One confirmed-head target and hash memo per pass.
    targets: dict[int, int] = {}
    head_failed_chains: set[int] = set()
    if scan_mode != "all":
        # A backfilled group needing more than one window after an outage counts as cold.
        for chain_id, _address in groups:
            if chain_id in targets or chain_id in head_failed_chains or chain_id not in head_fetchers:
                continue
            try:
                depth = chain_by_id(chain_id).confirmation_depth
            except UnknownChainError:
                depth = confirmation_depth
            try:
                targets[chain_id] = max(0, head_fetchers[chain_id].head_block() - depth)
            except Exception as exc:
                head_failed_chains.add(chain_id)
                logger.warning(
                    "event indexer head read failed; chain skipped this pass",
                    extra={
                        "chain_id": chain_id,
                        "exc_type": type(exc).__name__,
                        "exc_msg": sanitize_string(str(exc))[:200],
                    },
                )
        failed_groups += sum(chain_id in head_failed_chains for chain_id, _address in groups)
        groups = {
            key: entry
            for key, entry in groups.items()
            if key[0] in targets
            and (
                (not entry["complete"] or min(entry["last_blocks"]) + max_block_span < targets[key[0]])
                == (scan_mode == "cold")
            )
        }
        if scan_mode == "warm":
            # At least one window per warm address even when the fleet exceeds the cold budget.
            pass_budget = max(1, len(groups))
            max_windows_per_cursor = 1
    block_hash_memo: dict[tuple[int, int], bytes | None] = {}
    # Chains skipped for lack of a fetcher, logged once each (inv. 4/10) so they aren't silent.
    skipped_chains: set[int] = set()
    for (chain_id, event_address), entry in sorted(groups.items(), key=lambda item: _rotation_key(item)):
        if stop_event is not None and stop_event.is_set():
            break
        # Stop at the per-pass budget; unserviced groups keep their older last_run_at and go first next pass. Without
        # this a cold pass runs for tens of minutes and the heartbeat goes stale.
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
        # Per-chain finality depth (inv. 10); mainnet is 12, and the passed-in depth is the fallback for unregistered
        # chains.
        try:
            chain_confirmation_depth = chain_by_id(chain_id).confirmation_depth
        except UnknownChainError:
            chain_confirmation_depth = confirmation_depth
        # Several windows per group, capped per group and by the global budget; commit complete block prefixes so
        # partial progress survives a later failure.
        group_members_at_target = 0
        try:
            if chain_id not in targets:
                targets[chain_id] = max(0, head_fetcher.head_block() - chain_confirmation_depth)
            for _ in range(max(1, max_windows_per_cursor)):
                if stop_event is not None and stop_event.is_set():
                    break
                if windows_scanned >= pass_budget:
                    break
                group_complete = False
                for result in index_event_group_steps(
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
                    write_max_rows=write_max_rows,
                    write_max_bytes=write_max_bytes,
                ):
                    session.commit()
                    inserted += result.inserted
                    windows_scanned += int(result.fetched)
                    group_members_at_target = result.members_at_target
                    group_complete = result.group_complete
                    if stop_event is not None and stop_event.is_set():
                        break
                if group_complete:
                    break
        except Exception as exc:
            session.rollback()
            failed_groups += 1
            # Swallowed and continued. WARNING with exc_type, not logger.exception (an outage once produced thousands of
            # ERROR tracebacks); ``failed_groups`` carries the aggregate.
            logger.warning(
                "event indexer group scan failed; continuing to next group",
                extra={
                    "chain_id": chain_id,
                    "event_address": event_address,
                    "topics": sorted(entry["topics"]),
                    "exc_type": type(exc).__name__,
                    # Sanitized (URLs scrubbed) and truncated so the error stays attributable.
                    "exc_msg": sanitize_string(str(exc))[:200],
                },
            )
        caught_up_cursors += group_members_at_target
    pending_at_budget = False
    if windows_scanned >= pass_budget:
        for chain_id, target in targets.items():
            addresses = [address for (cid, address) in groups if cid == chain_id]
            query = (
                select(IndexedEventCursor.event_address)
                .where(
                    IndexedEventCursor.chain_id == chain_id,
                    IndexedEventCursor.event_address != _ZERO_ADDRESS,
                    IndexedEventCursor.last_indexed_block < target,
                )
                .limit(1)
            )
            if scan_mode != "all":
                if not addresses:
                    continue
                query = query.where(func.lower(IndexedEventCursor.event_address).in_(addresses))
            if session.execute(query).first() is not None:
                pending_at_budget = True
                break
        # A chain skipped for budget may have work; at most one extra short pass checks.
        pending_at_budget |= scan_mode == "all" and any(
            chain not in targets and chain in fetchers and chain in head_fetchers and chain in block_hash_fetchers
            for chain, _address in groups
        )
    return ScanSummary(
        inserted=inserted,
        windows_scanned=windows_scanned,
        caught_up_cursors=caught_up_cursors,
        total_cursors=len(rows),
        budget_exhausted=pending_at_budget,
        failed_groups=failed_groups,
    )


_ZERO_ADDRESS = "0x" + "0" * 40


def _is_enrollable_event_address(address: object) -> TypeGuard[str]:
    """Only real, non-zero addresses. A zero emitter has no creation block and would backfill the whole chain."""
    return (
        isinstance(address, str)
        and len(address) == 42
        and address.lower().startswith("0x")
        and address.lower() != _ZERO_ADDRESS
    )


def _seed_block(address: str, cache: dict[tuple[int, str], int | None], *, chain_id: int) -> int | None:
    """The starting ``last_indexed_block``: one below the creation block, so the empty pre-deployment range is never
    fetched.

    ``None`` when the creation block is unknown, deferring enrollment rather than seeding at genesis (one Etherscan
    failure must never force a full-chain backfill). Cached per pass by ``(chain_id, address)``.
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


def _enroll_witnessed(
    session: Session,
    *,
    chain_id: int,
    address: str,
    topic0: str,
    seed_cache: dict[tuple[int, str], int | None],
    witness_cache: dict[tuple[int, str], tuple[int | None, str]],
    enrollment_basis: str,
    pending: set[tuple[int, str]] | None = None,
    progress: Callable[[], None] | None = None,
) -> bool:
    """Seed, witness-grade and enrol one cursor; True if inserted. An unresolvable creation block inserts nothing.

    A predicate-hint enrolment that finds the cursor already present upgrades its basis (see
    ``_upgrade_to_predicate_hint``), so the enrolment order never decides eligibility.
    """
    if _cursor_exists(session, chain_id, address, topic0):
        if enrollment_basis == ENROLLMENT_BASIS_PREDICATE_HINT:
            _upgrade_to_predicate_hint(session, chain_id=chain_id, address=address, topic0=topic0)
        return False
    if progress is not None:
        progress()
    seed = _seed_block(address, seed_cache, chain_id=chain_id)
    if seed is None:
        if pending is not None:
            pending.add((chain_id, address.lower()))
        return False
    first_indexed_block, basis = _witness_seed_block(address, seed, witness_cache, chain_id=chain_id, session=session)
    inserted = enroll_event_cursor(
        session,
        chain_id=chain_id,
        event_address=address,
        topic0=topic0,
        start_block=seed,
        first_indexed_block=first_indexed_block,
        first_indexed_block_basis=basis,
        enrollment_basis=enrollment_basis,
    )
    if progress is not None:
        progress()
    return inserted


@dataclass
class EnrollmentCaches:
    """Share lookups, including failures, within one enrollment pass."""

    seeds: dict[tuple[int, str], int | None] = field(default_factory=dict)
    witnesses: dict[tuple[int, str], tuple[int | None, str]] = field(default_factory=dict)
    role_topics: dict[tuple[int, str], list[str]] = field(default_factory=dict)


def enroll_from_completed_jobs(
    session: Session,
    *,
    limit: int = 500,
    job_id: uuid.UUID | None = None,
    pending: set[tuple[int, str]] | None = None,
    progress: Callable[[], None] | None = None,
    commit: bool = True,
    caches: EnrollmentCaches | None = None,
) -> int:
    query = (
        select(Job)
        .where(Job.status == JobStatus.completed)
        .where(Job.request["effects_resume_work_id"].astext.is_(None))
        .where(Job.address.isnot(None))
        .order_by(Job.updated_at.desc())
        .limit(limit)
    )
    if job_id is not None:
        query = query.where(Job.id == job_id)
    jobs = session.execute(query).scalars()
    inserted = 0
    caches = caches if caches is not None else EnrollmentCaches()
    seed_cache = caches.seeds
    witness_cache = caches.witnesses
    role_store_topic_cache = caches.role_topics
    for job in jobs:
        artifact = get_artifact(session, job.id, "predicate_trees")
        if not isinstance(artifact, dict):
            continue
        # Stamp the job's own chain (``Job.chain_id``, else derived from its request), never a default (inv. 6).
        job_chain_id = (
            job.chain_id
            if isinstance(job.chain_id, int)
            else derive_job_chain_id(job.request.get("chain") if isinstance(job.request, dict) else None, job.address)
        )
        if job_chain_id is None:
            # Defensive; the query filter guarantees an id.
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
                # Unknown creation block: enrol on a later pass.
                if _enroll_witnessed(
                    session,
                    chain_id=job_chain_id,
                    address=address,
                    topic0=topic0,
                    seed_cache=seed_cache,
                    witness_cache=witness_cache,
                    enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
                    pending=pending,
                    progress=progress,
                ):
                    inserted += 1
            if _is_solmate_cancall_descriptor(descriptor):
                # The authority from ``authority_contract`` only, never job.address (it doesn't emit these events). Skip
                # until resolved.
                authority = _event_address_for_descriptor(descriptor, {}, job, values, allow_job_fallback=False)
                if _is_enrollable_event_address(authority):
                    for topic0 in _SOLMATE_ROLE_TOPICS:
                        if _enroll_witnessed(
                            session,
                            chain_id=job_chain_id,
                            address=authority,
                            topic0=topic0,
                            seed_cache=seed_cache,
                            witness_cache=witness_cache,
                            enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
                            pending=pending,
                            progress=progress,
                        ):
                            inserted += 1
            elif _is_delegated_role_gate_descriptor(descriptor):
                # Enrol at the authority proxy, where delegatecall emits RoleSet. Skip until resolved.
                authority = _event_address_for_descriptor(descriptor, {}, job, values, allow_job_fallback=False)
                if _is_enrollable_event_address(authority) and not _authority_has_role_store_cursor(
                    session, job_chain_id, authority
                ):
                    # Commit all topics atomically; caches keep external reads before the first insert.
                    if progress is not None:
                        progress()
                    for topic0 in _role_store_topic0s(session, authority, job_chain_id, role_store_topic_cache):
                        if _enroll_witnessed(
                            session,
                            chain_id=job_chain_id,
                            address=authority,
                            topic0=topic0,
                            seed_cache=seed_cache,
                            witness_cache=witness_cache,
                            enrollment_basis=ENROLLMENT_BASIS_PREDICATE_HINT,
                            pending=pending,
                        ):
                            inserted += 1
                    if progress is not None:
                        progress()
    if commit:
        session.commit()
    return inserted


def enroll_from_tracked_topics(
    session: Session,
    *,
    limit: int = 500,
    scan_limit: int = DEFAULT_TRACKED_TOPIC_SCAN_LIMIT,
    monitored_id: uuid.UUID | None = None,
    pending: set[tuple[int, str]] | None = None,
    progress: Callable[[], None] | None = None,
    commit: bool = True,
    caches: EnrollmentCaches | None = None,
) -> int:
    """Enrol cursors for topics a monitoring tracking plan names that nothing else enrolled.

    ``enroll_from_completed_jobs`` reads only ``enumeration_hint``s, which exist only for caller-keyed mappings, so
    parameter-keyed mappings (e.g. a recipient denylist) were never indexed. ``monitoring_config->tracked_topics``
    already lists those topics.

    Only ``topic0`` is read, not ``effect_tags.writes[]`` (a union over emitters that misattributes writes). These
    cursors therefore carry no variable attribution (``enrollment_basis = tracked_topics_asserted``), which the
    resolution gate keys on: they gather evidence but license nothing.
    """
    query = (
        select(MonitoredContract.address, MonitoredContract.chain, MonitoredContract.monitoring_config)
        .where(MonitoredContract.is_active.is_(True))
        .order_by(MonitoredContract.id.asc())
        .limit(scan_limit)
    )
    if monitored_id is not None:
        query = query.where(MonitoredContract.id == monitored_id)
    rows = session.execute(query).all()
    if len(rows) == scan_limit:
        # A truncated scan makes the tail unreachable forever while the counter reads zero; warn loudly.
        logger.warning(
            "tracked-topic enrolment scan hit its row limit; fleet tail unreachable",
            extra={"scan_limit": scan_limit, "scanned": len(rows)},
        )
    inserted = 0
    worked = 0
    caches = caches if caches is not None else EnrollmentCaches()
    seed_cache = caches.seeds
    witness_cache = caches.witnesses
    for address, chain, config in rows:
        # ``limit`` bounds addresses needing work, not rows inspected; bounding rows would re-inspect the same head
        # forever.
        if worked >= limit:
            break
        if not _is_enrollable_event_address(address):
            continue
        try:
            # The row's own chain via the registry, never a default.
            chain_id = chain_by_name(chain).chain_id
        except (UnknownChainError, TypeError):
            continue
        if chain_id not in supported_chain_ids():
            continue
        specs = (config or {}).get("tracked_topics") if isinstance(config, dict) else None
        if not isinstance(specs, list):
            continue
        seen: set[str] = set()
        wanted: list[str] = []
        for spec in specs:
            topic0 = spec.get("topic0") if isinstance(spec, dict) else None
            if not isinstance(topic0, str) or not topic0.lower().startswith("0x") or len(topic0) != 66:
                continue
            if topic0.lower() in seen:
                continue
            seen.add(topic0.lower())
            wanted.append(topic0)
        # Fully enrolled addresses cost no budget or RPC, so passes advance through the fleet.
        pending_topics = [t for t in wanted if not _cursor_exists(session, chain_id, address, t)]
        if not pending_topics:
            continue
        worked += 1
        for topic0 in pending_topics:
            if _enroll_witnessed(
                session,
                chain_id=chain_id,
                address=address,
                topic0=topic0,
                seed_cache=seed_cache,
                witness_cache=witness_cache,
                enrollment_basis=ENROLLMENT_BASIS_TRACKED_TOPICS,
                pending=pending,
                progress=progress,
            ):
                inserted += 1
    if commit:
        session.commit()
    return inserted


def _fold_window_stats(cursor: IndexedEventCursor, stats: list[FetchWindowStat]) -> None:
    """Record what the pages this cursor advanced through returned.

    ``max_window_log_count`` only grows (the question is whether any window hit its cap). The gating cap is stored with
    it, so the verdict doesn't depend on an unrecorded env var; a missing or disagreeing cap collapses to
    ``not_determined``.
    """
    if not stats:
        # Moved without a record, so the window record is no longer continuous.
        cursor.window_stats_basis = WINDOW_STATS_NOT_DETERMINED
        return
    counts = [stat.returned_log_count for stat in stats if stat.returned_log_count is not None]
    if len(counts) != len(stats):
        # A non-list page can't be counted, so the range can't be proven whole (and it isn't zero logs).
        cursor.window_stats_basis = WINDOW_STATS_NOT_DETERMINED
        if not counts:
            return
    observed_caps = {stat.cap for stat in stats}
    observed_cap = observed_caps.pop() if len(observed_caps) == 1 else None
    highest = max(counts)
    prior_max = cursor.max_window_log_count
    cursor.max_window_log_count = highest if prior_max is None else max(int(prior_max), highest)
    if observed_cap is None or (cursor.window_stats_cap is not None and int(cursor.window_stats_cap) != observed_cap):
        cursor.window_stats_cap = None
        cursor.window_stats_basis = WINDOW_STATS_NOT_DETERMINED
        return
    cursor.window_stats_cap = observed_cap


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
    """The address resolution reads events from for ``job``: ``request['proxy_address']`` if set, else
    ``job.address`` (as ``capability_resolver``'s ``runtime_addr``). An impl behind a proxy emits under the proxy.
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
    """``(caught_up, total)`` enrollable cursors read from the table, so the heartbeat reflects an in-progress
    backfill rather than the last completed pass.
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
    """Run the durable event-log indexer as two decoupled jobs.

    * Backfill (enroll + scan) on its own thread, each pass bounded by a window budget so busy authorities backfill
    across passes.
    * Reconcile + heartbeat every ``interval`` on this loop, so deferred capabilities self-heal promptly and the fleet
    view stays live regardless of scan duration.

    The thread publishes its last scan summary for the heartbeat.
    """
    # New threads start with an empty context, so bind here and again in the thread.
    with bind_trace_context(worker_id=WORKER_ID):
        logger.info("starting event log indexer loop interval=%ss", interval)
        stop_event = stop_event or Event()

        state_lock = Lock()
        published: dict[str, Any] = {"summary": ScanSummary(), "enrolled": 0, "status": "running"}

        def backfill_loop() -> None:
            # ``threading.Thread`` doesn't inherit context.
            with bind_trace_context(worker_id=WORKER_ID):
                next_warm_at = 0.0
                cold_pending = True
                while not stop_event.is_set():
                    enrolled = 0
                    summary = ScanSummary()
                    status = "running"
                    try:
                        with SessionLocal() as session:
                            with log_timed_phase(logger, "indexer_enroll", record_metric=False) as ph:
                                from services.resolution.indexer_scheduler import drain_enrollment

                                enrolled = drain_enrollment(
                                    session, tracked_limit=DEFAULT_TRACKED_TOPIC_ENROLL_LIMIT, stop_event=stop_event
                                )
                                ph["enrolled"] = enrolled
                            with log_timed_phase(logger, "indexer_scan", record_metric=False) as ph:
                                warm_due = time.monotonic() >= next_warm_at
                                warm_summary = ScanSummary()
                                if warm_due:
                                    warm_summary = scan_enrolled_events(
                                        session,
                                        fetchers=fetchers,
                                        head_fetchers=head_fetchers,
                                        block_hash_fetchers=block_hash_fetchers,
                                        stop_event=stop_event,
                                        scan_mode="warm",
                                    )
                                    next_warm_at = time.monotonic() + interval
                                cold_summary = ScanSummary()
                                if cold_pending or warm_due or enrolled:
                                    cold_summary = scan_enrolled_events(
                                        session,
                                        fetchers=fetchers,
                                        head_fetchers=head_fetchers,
                                        block_hash_fetchers=block_hash_fetchers,
                                        stop_event=stop_event,
                                        scan_mode="cold",
                                    )
                                    cold_pending = cold_summary.budget_exhausted
                                summary = ScanSummary(
                                    inserted=warm_summary.inserted + cold_summary.inserted,
                                    windows_scanned=warm_summary.windows_scanned + cold_summary.windows_scanned,
                                    caught_up_cursors=warm_summary.caught_up_cursors + cold_summary.caught_up_cursors,
                                    total_cursors=max(warm_summary.total_cursors, cold_summary.total_cursors),
                                    budget_exhausted=cold_pending,
                                    failed_groups=warm_summary.failed_groups + cold_summary.failed_groups,
                                )
                                ph["windows_scanned"] = summary.windows_scanned
                                ph["inserted"] = summary.inserted
                    except Exception:
                        logger.exception("event log indexer backfill pass failed")
                        status = "error"
                    # Unconditional per-pass INFO with the cursor triad, so a cold backfill scanning empty windows is
                    # visible.
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
                    # Only unfinished history uses the short pause.
                    backfill_wait = (
                        min(DEFAULT_BACKFILL_BUSY_INTERVAL_S, max(0.0, next_warm_at - time.monotonic()))
                        if cold_pending
                        else max(0.0, next_warm_at - time.monotonic())
                    )
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
                            from services.resolution.indexer_scheduler import drain_reconciliation

                            reenqueued, drift_reenqueued = drain_reconciliation(session, stop_event=stop_event)
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
                # Read the triad from the table independently of the backfill thread, in its own session so a failure
                # doesn't blank the heartbeat.
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
                # The thread catches per-pass errors, so a dead thread is a fatal stall.
                if not backfill.is_alive() and not stop_event.is_set():
                    status = "error"
                    logger.error("event log indexer backfill thread is not alive; indexing has stalled")
                # Triad from the live table; windows_scanned/inserted from the last summary.
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
            stop_event.set()
            # Don't release the singleton while a scan can commit.
            backfill.join()


def _build_indexer_fetchers(
    chains: Sequence[ChainInfo] | None = None,
) -> tuple[dict[int, LogFetcher], dict[int, HeadBlockFetcher], dict[int, BlockHashFetcher]]:
    """Per-chain fetchers for the scan loop.

    The chain set is registry chains with ``hypersync_url`` (inv. 10); others get no fetcher and their cursors are
    skipped and logged. Every fetcher posts JSON-RPC through the chain's eRPC route (``require_rpc_url(chain_id=...)``);
    routing, the HyperRPC upstreams, failover and auth are eRPC config. ``hypersync_url`` is only the coverage signal
    (it rejects JSON-RPC).
    """
    from services.resolution.repos.event_logs_rpc import (
        RpcBlockHashFetcher,
        RpcEventLogFetcher,
        RpcHeadBlockFetcher,
        default_result_cap,
    )

    registry_chains = all_chains() if chains is None else chains
    # Only the indexer persists per-window counts, so only it applies the result cap.
    result_cap = default_result_cap()
    fetchers: dict[int, LogFetcher] = {}
    head_fetchers: dict[int, HeadBlockFetcher] = {}
    block_hash_fetchers: dict[int, BlockHashFetcher] = {}
    for info in registry_chains:
        if info.hypersync_url is None:
            continue
        rpc_url = require_rpc_url(chain_id=info.chain_id)
        fetchers[info.chain_id] = RpcEventLogFetcher(rpc_url, chain_id=info.chain_id, result_cap=result_cap)
        head_fetchers[info.chain_id] = RpcHeadBlockFetcher(rpc_url, chain_id=info.chain_id)
        block_hash_fetchers[info.chain_id] = RpcBlockHashFetcher(rpc_url, chain_id=info.chain_id)
    return fetchers, head_fetchers, block_hash_fetchers


def main() -> None:
    # JSON logging so every line and extra is queryable.
    configure_logging()
    stop_event = Event()

    def handle_signal(signum, _frame):
        # Every daemon logs this at shutdown; include the identity. The ``worker_id`` extra matches the contextvar name
        # for signals arriving before the bind.
        logger.info(
            "worker %s received signal %s, shutting down",
            WORKER_ID,
            signum,
            extra={"worker_id": WORKER_ID, "pid": os.getpid(), "signal": signum},
        )
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
