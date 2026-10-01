"""Generic event-log indexer for predicate ``enumeration_hint`` records."""

from __future__ import annotations

import dataclasses
import inspect
import logging
import os
import signal
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
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
from services.resolution import indexer_settings as settings
from services.resolution.caller_sources import CALLER_SOURCES as _CALLER_SOURCES
from services.resolution.repos.event_logs_rpc import FetchedEventLog, FetchWindowStat, LogPage
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
from utils.memory import current_rss_bytes
from utils.secrets import sanitize_string

logger = logging.getLogger("workers.event_log_indexer")

# Process identity for every line; the indexer isn't a BaseWorker, so it binds its own.
WORKER_ID = f"EventLogIndexer-{os.getpid()}-{uuid.uuid4().hex[:8]}"

DEFAULT_INTERVAL_S = settings.INTERVAL_S
DEFAULT_CONFIRMATION_DEPTH = settings.CONFIRMATION_DEPTH
DEFAULT_MAX_BLOCK_SPAN = settings.MAX_BLOCK_SPAN
DEFAULT_MAX_WINDOWS_PER_CURSOR = settings.MAX_WINDOWS_PER_CURSOR
DEFAULT_MAX_WINDOWS_PER_PASS = settings.MAX_WINDOWS_PER_PASS
DEFAULT_INSERT_BATCH = settings.INSERT_BATCH
DEFAULT_WRITE_MAX_ROWS = settings.WRITE_MAX_ROWS
DEFAULT_WRITE_MAX_BYTES = settings.WRITE_MAX_BYTES
DEFAULT_TRACKED_TOPIC_ENROLL_LIMIT = settings.TRACKED_TOPIC_ENROLL_LIMIT
DEFAULT_TRACKED_TOPIC_SCAN_LIMIT = settings.TRACKED_TOPIC_SCAN_LIMIT
DEFAULT_BACKFILL_BUSY_INTERVAL_S = settings.BACKFILL_BUSY_INTERVAL_S

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
    page_logs: int = 0  # logs the fetched page returned (first prefix of a page only)
    rejected_pages: int = 0  # requests refused or discarded before the page was accepted


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
    # Per chain, the largest gap between a warm group's frontier and the confirmed target after the sweep.
    warm_max_lag_blocks: Mapping[int, int] = field(default_factory=dict)


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
    event_address: str | Sequence[str],
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


def _legacy_group_steps(
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
    """The legacy engine: yield atomic write prefixes of one fetched (chain, address) window.

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
            # Monotonic: a warm sibling waiting while a new topic backfills stays complete; coverage of the evaluated
            # block is judged by position, and only the reorg rewind above resets the flag.
            if int(cursor.last_indexed_block or 0) >= target:
                cursor.backfill_complete = True
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
            page_logs=len(logs) if prefix_start == start else 0,
        )
        prefix_start = prefix_end + 1


def _cursor_positions(cursors: Sequence[IndexedEventCursor]) -> list[tuple[str, int, bytes | None]]:
    return [(c.topic0, int(c.last_indexed_block or 0), c.last_indexed_block_hash) for c in cursors]


ENGINES = ("legacy", "paged")


class GroupClaims:
    """The (chain, address) groups a scan thread is working, so the other thread skips them.

    Efficiency only: two threads writing one group stay correct through the per-page position check.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._held: set[tuple[int, str]] = set()

    def claim(self, keys: Sequence[tuple[int, str]]) -> bool:
        with self._lock:
            if any(key in self._held for key in keys):
                return False
            self._held.update(keys)
            return True

    def release(self, keys: Sequence[tuple[int, str]]) -> None:
        with self._lock:
            self._held.difference_update(keys)


def _resolve_engine(engine: str | None) -> str:
    chosen = (engine or settings.ENGINE).strip().lower()
    if chosen not in ENGINES:
        raise ValueError(f"unknown event indexer engine {chosen!r}; expected one of {ENGINES}")
    return chosen


class CursorsMoved(RuntimeError):
    """A member's position at write time differs from the plan; the page is discarded and refetched."""


@dataclass(frozen=True)
class _Member:
    event_address: str
    topic0: str
    last: int
    block_hash: bytes | None
    logs_per_block: float | None

    @property
    def key(self) -> tuple[str, str]:
        return (self.event_address, self.topic0)


@dataclass(frozen=True)
class _Rewind:
    to_block: int
    block_hash: bytes | None


@dataclass(frozen=True)
class GroupPlan:
    """Positions read in a short transaction, with any reorg rewind found by the hash check after it."""

    chain_id: int
    addresses: tuple[str, ...]
    members: tuple[_Member, ...]
    rewinds: Mapping[str, _Rewind]


@dataclass(frozen=True)
class PageLimits:
    """How large and how many pages one visit may fetch."""

    max_block_span: int = DEFAULT_MAX_BLOCK_SPAN
    initial_span: int = settings.INITIAL_SPAN
    target_page_logs: int = settings.TARGET_PAGE_LOGS
    max_page_logs: int | None = settings.MAX_PAGE_LOGS
    max_pages: int | None = None
    deadline: float | None = None


_monotonic = time.monotonic


def _end_transaction(session: Session) -> None:
    # Nothing may hold row locks (or the trigger's reconciliation row) while waiting on RPC.
    if session.in_transaction():
        session.commit()


def _cursor_rows_query(chain_id: int, addresses: Sequence[str]):
    return (
        select(IndexedEventCursor)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address).in_(list(addresses)))
        .order_by(func.lower(IndexedEventCursor.event_address), IndexedEventCursor.topic0)
    )


def plan_group(
    session: Session,
    *,
    chain_id: int,
    addresses: Sequence[str],
    target: int,
    hash_at: Callable[[int], bytes | None],
    confirmation_depth: int,
) -> GroupPlan:
    """Read positions, release the transaction, then run the reorg check against the stored fringe stamps."""
    wanted = tuple(sorted({a.lower() for a in addresses}))
    rows = session.execute(
        select(
            IndexedEventCursor.event_address,
            IndexedEventCursor.topic0,
            IndexedEventCursor.last_indexed_block,
            IndexedEventCursor.last_indexed_block_hash,
            IndexedEventCursor.recent_logs_per_block,
        )
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address).in_(list(wanted)))
        .order_by(func.lower(IndexedEventCursor.event_address), IndexedEventCursor.topic0)
    ).all()
    _end_transaction(session)
    members = tuple(
        _Member(
            event_address=str(address).lower(),
            topic0=str(topic0).lower(),
            last=int(last or 0),
            block_hash=block_hash,
            logs_per_block=density,
        )
        for address, topic0, last, block_hash, density in rows
    )
    rewinds: dict[str, _Rewind] = {}
    for member in members:
        if member.event_address in rewinds:
            continue
        if member.last <= 0 or member.block_hash is None or member.last >= target:
            continue
        observed = hash_at(member.last)
        if observed is None or observed == member.block_hash:
            continue
        rewind_to = max(0, member.last - confirmation_depth)
        logger.warning(
            "event-log reorg detected; rewinding indexed logs before re-scan",
            extra={
                "chain_id": chain_id,
                "event_address": member.event_address,
                "rewind_to": rewind_to,
                "rewind_from": member.last,
                "depth": member.last - rewind_to,
            },
        )
        rewinds[member.event_address] = _Rewind(rewind_to, hash_at(rewind_to) if rewind_to else None)
    return GroupPlan(chain_id=chain_id, addresses=wanted, members=members, rewinds=rewinds)


def _member_positions(cursors: Sequence[IndexedEventCursor]) -> list[tuple[str, str, int, bytes | None]]:
    return [
        (c.event_address.lower(), c.topic0.lower(), int(c.last_indexed_block or 0), c.last_indexed_block_hash)
        for c in cursors
    ]


def _lock_members(
    session: Session, plan: GroupPlan, expected: list[tuple[str, str, int, bytes | None]]
) -> list[IndexedEventCursor]:
    """``FOR UPDATE`` every cursor at the plan's addresses in canonical order, and require the positions the plan (or
    this visit's last commit) left. Anything else, including a newly enrolled sibling, discards the page."""
    cursors = list(
        session.execute(
            _cursor_rows_query(plan.chain_id, plan.addresses)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )
    if _member_positions(cursors) != expected:
        raise CursorsMoved("event cursors changed since the page was planned; refetch required")
    return cursors


def _page_density(page: LogPage) -> float | None:
    count = page.returned_log_count
    if count is None:
        return None
    return count / (page.to_block - page.from_block + 1)


def _initial_span(densities: Sequence[float | None], limits: PageLimits) -> int:
    max_span = max(1, limits.max_block_span)
    known = [d for d in densities if d is not None and d > 0]
    if known:
        return max(1, min(max_span, int(limits.target_page_logs / max(known))))
    return max(1, min(limits.initial_span, max_span))


def _next_span(page: LogPage, limits: PageLimits) -> int:
    """Double while pages come back under half the target; otherwise size the next page to the target at this
    page's density."""
    max_span = max(1, limits.max_block_span)
    blocks = page.to_block - page.from_block + 1
    count = page.returned_log_count
    if count is None:
        return max(1, min(max_span, blocks))
    if count < limits.target_page_logs / 2:
        return max(1, min(max_span, blocks * 2))
    return max(1, min(max_span, int(limits.target_page_logs * blocks / count)))


class _PageSource(Protocol):
    def iter_pages(
        self,
        *,
        event_address: str | Sequence[str],
        topics: Sequence[str],
        from_block: int,
        to_block: int,
        max_page_logs: int | None = None,
    ) -> Iterator[LogPage]: ...


def _pages(
    fetcher: LogFetcher,
    *,
    event_address: str | Sequence[str],
    topics: list[str],
    from_block: int,
    to_block: int,
    max_page_logs: int | None,
) -> Iterator[LogPage]:
    """Pages from a streaming fetcher, or the whole range as one page from a fetcher with only ``fetch_logs``."""
    if callable(getattr(fetcher, "iter_pages", None)):
        yield from cast(_PageSource, fetcher).iter_pages(
            event_address=event_address,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
            max_page_logs=max_page_logs,
        )
        return
    stats: list[FetchWindowStat] = []
    logs = _fetch_window(
        fetcher,
        event_address=event_address,
        topics=topics,
        from_block=from_block,
        to_block=to_block,
        window_stats=stats,
    )
    yield LogPage(from_block=from_block, to_block=to_block, logs=logs, stats=tuple(stats))


def index_event_group_steps(
    session: Session,
    *,
    chain_id: int,
    event_address: str,
    fetcher: LogFetcher,
    target: int,
    block_hash_fetcher: BlockHashFetcher,
    block_hash_memo: MutableMapping[tuple[int, int], bytes | None] | None = None,
    confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
    limits: PageLimits | None = None,
    insert_batch_size: int = DEFAULT_INSERT_BATCH,
    write_max_rows: int = DEFAULT_WRITE_MAX_ROWS,
    write_max_bytes: int = DEFAULT_WRITE_MAX_BYTES,
    stop_event: Event | None = None,
) -> Iterator[GroupStepResult]:
    """Stream one (chain, address) group to ``target`` in bounded pages, yielding after each write prefix.

    The caller commits each prefix before resuming. No transaction is open during any RPC: positions are read and
    released first, the reorg check and the target hash read follow, and each page is fetched before its rows are
    locked. Every write re-locks the group and requires the positions it planned (A5); a mismatch raises
    :class:`CursorsMoved` with nothing written.
    """
    memo: MutableMapping[tuple[int, int], bytes | None] = block_hash_memo if block_hash_memo is not None else {}

    def hash_at(block: int) -> bytes | None:
        key = (chain_id, block)
        if key not in memo:
            _end_transaction(session)
            memo[key] = block_hash_fetcher.block_hash(block)
        return memo[key]

    plan = plan_group(
        session,
        chain_id=chain_id,
        addresses=[event_address],
        target=target,
        hash_at=hash_at,
        confirmation_depth=confirmation_depth,
    )
    yield from run_plan(
        session,
        plan,
        fetcher=fetcher,
        target=target,
        hash_at=hash_at,
        memo=memo,
        limits=limits or PageLimits(),
        insert_batch_size=insert_batch_size,
        write_max_rows=write_max_rows,
        write_max_bytes=write_max_bytes,
        stop_event=stop_event,
    )


def run_plan(
    session: Session,
    plan: GroupPlan,
    *,
    fetcher: LogFetcher,
    target: int,
    hash_at: Callable[[int], bytes | None],
    memo: Mapping[tuple[int, int], bytes | None],
    limits: PageLimits,
    insert_batch_size: int,
    write_max_rows: int,
    write_max_bytes: int,
    stop_event: Event | None,
) -> Iterator[GroupStepResult]:
    chain_id = plan.chain_id
    if not plan.members:
        yield GroupStepResult(
            scanned_from=0, scanned_to=0, inserted=0, members_at_target=0, group_complete=True, fetched=False
        )
        return
    expected = [(m.event_address, m.topic0, m.last, m.block_hash) for m in plan.members]
    position: dict[tuple[str, str], int] = {}
    for member in plan.members:
        rewind = plan.rewinds.get(member.event_address)
        position[member.key] = min(member.last, rewind.to_block) if rewind is not None else member.last

    def stamp(block: int) -> bytes | None:
        if (chain_id, block) not in memo:
            raise RuntimeError(f"fringe hash for block {block} was not read before the write")
        return memo[(chain_id, block)]

    if all(pos >= target for pos in position.values()):
        cursors = _lock_members(session, plan, expected)
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

    # Fringe stamps for members already at or past the target, read now so no write waits on RPC.
    for member in plan.members:
        rewind = plan.rewinds.get(member.event_address)
        stamped = member.block_hash if rewind is None or member.last <= rewind.to_block else rewind.block_hash
        if position[member.key] >= target and stamped is None:
            hash_at(position[member.key])
    frontier = min(pos for pos in position.values() if pos < target)
    span = _initial_span([m.logs_per_block for m in plan.members if position[m.key] < target], limits)
    single_address = plan.addresses[0] if len(plan.addresses) == 1 else None
    rewind_pending = bool(plan.rewinds)
    pages = 0
    while frontier < target:
        if stop_event is not None and stop_event.is_set():
            return
        if pages and limits.max_pages is not None and pages >= limits.max_pages:
            return
        if pages and limits.deadline is not None and _monotonic() >= limits.deadline:
            return
        chunk_end = min(target, frontier + span)
        topics = sorted({topic0 for (_address, topic0), pos in position.items() if pos < chunk_end})
        if chunk_end >= target:
            # The fringe hash is read before that block's logs, so a reorg in between is caught by the next check.
            hash_at(target)
        _end_transaction(session)
        page_iter = _pages(
            fetcher,
            event_address=single_address if single_address is not None else list(plan.addresses),
            topics=topics,
            from_block=frontier + 1,
            to_block=chunk_end,
            max_page_logs=limits.max_page_logs,
        )
        while True:
            _end_transaction(session)
            page = next(page_iter, None)
            if page is None:
                break
            logs = sorted(page.logs, key=lambda log: log.block_number)
            density = _page_density(page)
            prefixes = _write_prefixes(logs, page.to_block, max_rows=write_max_rows, max_bytes=write_max_bytes)
            logger.debug(
                "event indexer page",
                extra={
                    "chain_id": chain_id,
                    "event_address": single_address,
                    "addresses": len(plan.addresses),
                    "from_block": page.from_block,
                    "to_block": page.to_block,
                    "topics": len(topics),
                    "returned_log_count": page.returned_log_count,
                    "rejected": page.rejected,
                    "prefixes": len(prefixes),
                },
            )
            for index, (offset, end_offset, prefix_end) in enumerate(prefixes):
                cursors = _lock_members(session, plan, expected)
                if rewind_pending:
                    _apply_rewinds(session, plan, cursors)
                    rewind_pending = False
                buckets: dict[tuple[str, str], list[FetchedEventLog]] = {}
                for log in logs[offset:end_offset]:
                    if log.topics:
                        emitter = single_address if single_address is not None else log.address.lower()
                        if emitter not in plan.addresses:
                            raise RuntimeError("eth_getLogs returned a log from an emitter outside the request")
                        buckets.setdefault((emitter, log.topics[0].lower()), []).append(log)
                inserted = 0
                members_at_target = 0
                for cursor in cursors:
                    address = cursor.event_address.lower()
                    topic0 = cursor.topic0.lower()
                    last = int(cursor.last_indexed_block or 0)
                    if prefix_end > last:
                        if topic0 not in topics:
                            raise RuntimeError("a cursor would advance over a range its topic was not requested for")
                        member_logs = [log for log in buckets.get((address, topic0), []) if log.block_number > last]
                        inserted += _bulk_insert_logs(
                            session, chain_id, address, topic0, member_logs, batch_size=insert_batch_size
                        )
                        cursor.last_indexed_block = prefix_end
                        cursor.last_indexed_block_hash = None
                        _fold_window_stats(cursor, list(page.stats))
                        cursor.last_advanced_at = func.now()
                        if density is not None:
                            cursor.recent_logs_per_block = density
                    # Monotonic: a warm sibling waiting while a new topic backfills stays complete; coverage of the
                    # evaluated block is judged by position, and only a reorg rewind resets the flag.
                    if int(cursor.last_indexed_block or 0) >= target:
                        cursor.backfill_complete = True
                        members_at_target += 1
                        if cursor.last_indexed_block_hash is None:
                            cursor.last_indexed_block_hash = stamp(int(cursor.last_indexed_block))
                    cursor.last_run_at = func.now()
                expected = _member_positions(cursors)
                for address, topic0, last, _hash in expected:
                    position[(address, topic0)] = last
                yield GroupStepResult(
                    scanned_from=page.from_block if index == 0 else prefixes[index - 1][2] + 1,
                    scanned_to=prefix_end,
                    inserted=inserted,
                    members_at_target=members_at_target,
                    group_complete=members_at_target == len(cursors),
                    fetched=index == 0,
                    page_logs=len(logs) if index == 0 else 0,
                    rejected_pages=page.rejected if index == 0 else 0,
                )
            pages += 1
            span = _next_span(page, limits)
            # Release this page before the next request so at most one page is resident.
            page = None
            logs = []
            buckets = {}
            member_logs = []
            if stop_event is not None and stop_event.is_set():
                return
            if limits.max_pages is not None and pages >= limits.max_pages:
                return
            if limits.deadline is not None and _monotonic() >= limits.deadline:
                return
        frontier = min((pos for pos in position.values() if pos < target), default=target)


def _apply_rewinds(session: Session, plan: GroupPlan, cursors: Sequence[IndexedEventCursor]) -> None:
    """Rewind the whole address, then delete its rows above the rewind point, in the page's first transaction.

    The cursor decrease is flushed before the DELETE: the row trigger marks ``reorg`` on the decrease even when the
    DELETE removes nothing.
    """
    for cursor in cursors:
        rewind = plan.rewinds.get(cursor.event_address.lower())
        if rewind is not None and int(cursor.last_indexed_block or 0) > rewind.to_block:
            cursor.last_indexed_block = rewind.to_block
            cursor.last_indexed_block_hash = rewind.block_hash
            cursor.backfill_complete = False
    session.flush()
    for address, rewind in sorted(plan.rewinds.items()):
        session.execute(
            delete(IndexedEventLog)
            .where(IndexedEventLog.chain_id == plan.chain_id)
            .where(func.lower(IndexedEventLog.event_address) == address)
            .where(IndexedEventLog.block_number > rewind.to_block)
        )


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
    on_commit: Callable[[ScanSummary], None] | None = None,
    engine: str | None = None,
    page_limits: PageLimits | None = None,
    group_budget_s: float = settings.GROUP_BUDGET_S,
    pass_budget_s: float = settings.PASS_BUDGET_S,
    claims: GroupClaims | None = None,
) -> ScanSummary:
    engine = _resolve_engine(engine)
    pass_started = _monotonic()
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
            IndexedEventCursor.last_advanced_at,
            IndexedEventCursor.enrollment_basis,
        )
    ).all()
    # Skip zero/invalid addresses from before the enroll-time guard; 0x0 never emits logs.
    rows = [row for row in all_rows if _is_enrollable_event_address(row[1])]
    _end_transaction(session)
    groups: dict[tuple[int, str], dict[str, Any]] = {}
    for chain_id, event_address, topic0, last_run_at, last_block, complete, advanced_at, basis in rows:
        entry = groups.setdefault(
            (chain_id, event_address.lower()),
            {"topics": set(), "runs": [], "last_blocks": [], "complete": True, "never_advanced": False, "hint": False},
        )
        entry["topics"].add(topic0.lower())
        entry["runs"].append(last_run_at)
        entry["last_blocks"].append(int(last_block or 0))
        entry["complete"] &= bool(complete)
        entry["never_advanced"] |= advanced_at is None
        entry["hint"] |= basis in EXACTNESS_ELIGIBLE_ENROLLMENT_BASES

    def _rotation_key(item: tuple[tuple[int, str], dict[str, Any]]) -> tuple[int, int, datetime, str]:
        # Never-advanced groups first (a new hint group isn't stuck behind an old dense backfill), then the bases the
        # resolver can use, then least recently run.
        (_chain_id, address), entry = item
        return (0 if entry["never_advanced"] else 1, 0 if entry["hint"] else 1, min(entry["runs"]), address)

    state = _PassState(total_cursors=len(rows), on_commit=on_commit, stop_event=stop_event)
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
                targets[chain_id] = max(0, head_fetchers[chain_id].head_block() - _depth(chain_id, confirmation_depth))
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
        state.failed_groups += sum(chain_id in head_failed_chains for chain_id, _address in groups)
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
            if engine == "legacy":
                max_windows_per_cursor = 1
    pass_deadline = None if scan_mode == "warm" else pass_started + pass_budget_s
    block_hash_memo: dict[tuple[int, int], bytes | None] = {}
    base_limits = page_limits or PageLimits(max_block_span=max_block_span)
    writes = _WriteSizes(insert_batch_size, write_max_rows, write_max_bytes)

    def visit_group(chain_id: int, event_address: str, topics: list[str]) -> None:
        """One group: the paged engine streams it under the time budgets; the legacy engine fetches whole windows."""
        visit = _GroupVisit(chain_id=chain_id, event_address=event_address)
        claim = [(chain_id, event_address)]
        if claims is not None and not claims.claim(claim):
            state.stopped_short = True
            return
        members_at_target = 0
        try:
            depth = _depth(chain_id, confirmation_depth)
            if chain_id not in targets:
                targets[chain_id] = max(0, head_fetchers[chain_id].head_block() - depth)
            if engine == "paged":
                deadline = _monotonic() + group_budget_s
                if pass_deadline is not None:
                    deadline = min(deadline, pass_deadline)
                limits = dataclasses.replace(
                    base_limits,
                    max_pages=max(1, min(max_windows_per_cursor, pass_budget - state.windows_scanned)),
                    deadline=deadline,
                )
                steps = index_event_group_steps(
                    session,
                    chain_id=chain_id,
                    event_address=event_address,
                    fetcher=fetchers[chain_id],
                    target=targets[chain_id],
                    block_hash_fetcher=block_hash_fetchers[chain_id],
                    block_hash_memo=block_hash_memo,
                    confirmation_depth=depth,
                    limits=limits,
                    insert_batch_size=writes.insert_batch_size,
                    write_max_rows=writes.max_rows,
                    write_max_bytes=writes.max_bytes,
                    stop_event=stop_event,
                )
                group_complete, members_at_target = state.drive(session, steps, visit)
                state.stopped_short |= not group_complete
            else:
                for _ in range(max(1, max_windows_per_cursor)):
                    if state.stopping() or state.windows_scanned >= pass_budget:
                        break
                    steps = _legacy_group_steps(
                        session,
                        chain_id=chain_id,
                        event_address=event_address,
                        topics=topics,
                        fetcher=fetchers[chain_id],
                        target=targets[chain_id],
                        block_hash_fetcher=block_hash_fetchers[chain_id],
                        block_hash_memo=block_hash_memo,
                        confirmation_depth=depth,
                        max_block_span=max_block_span,
                        insert_batch_size=writes.insert_batch_size,
                        write_max_rows=writes.max_rows,
                        write_max_bytes=writes.max_bytes,
                    )
                    group_complete, members_at_target = state.drive(session, steps, visit)
                    if group_complete:
                        break
        except Exception as exc:
            state.discard(session, exc, chain_id=chain_id, addresses=[event_address], topics=topics)
        finally:
            if claims is not None:
                claims.release(claim)
        state.caught_up_cursors += members_at_target
        if visit.pages and scan_mode != "warm":
            visit.log(scan_mode)

    # Chains skipped for lack of a fetcher, logged once each so they aren't silent.
    skipped_chains: set[int] = set()

    def runnable(chain_id: int) -> bool:
        if chain_id in fetchers and chain_id in head_fetchers and chain_id in block_hash_fetchers:
            return True
        if chain_id not in skipped_chains:
            skipped_chains.add(chain_id)
            logger.warning(
                "event indexer has no fetcher for chain; its enrolled cursors are not being "
                "advanced this pass (indexer disabled for this chain, or its hypersync_url is unset)",
                extra={"chain_id": chain_id},
            )
        return False

    sweep_started = _monotonic()
    if scan_mode == "warm" and engine == "paged":
        by_chain: dict[int, list[str]] = {}
        for chain_id, event_address in sorted(groups):
            if runnable(chain_id):
                by_chain.setdefault(chain_id, []).append(event_address)
        for chain_id, addresses in by_chain.items():
            if state.stopping():
                break
            _warm_sweep_chain(
                session,
                state,
                chain_id=chain_id,
                addresses=addresses,
                target=targets[chain_id],
                fetcher=fetchers[chain_id],
                block_hash_fetcher=block_hash_fetchers[chain_id],
                block_hash_memo=block_hash_memo,
                confirmation_depth=_depth(chain_id, confirmation_depth),
                limits=dataclasses.replace(base_limits, deadline=_monotonic() + group_budget_s),
                writes=writes,
                claims=claims,
                visit_single=lambda address, chain_id=chain_id: visit_group(
                    chain_id, address, sorted(groups[(chain_id, address)]["topics"])
                ),
            )
    else:
        for (chain_id, event_address), entry in sorted(groups.items(), key=lambda item: _rotation_key(item)):
            if state.stopping():
                break
            # Stop at the per-pass budget; unserviced groups keep their older last_run_at and go first next pass.
            # Without this a cold pass runs for tens of minutes and the heartbeat goes stale.
            if state.windows_scanned >= pass_budget:
                break
            if engine == "paged" and pass_deadline is not None and _monotonic() >= pass_deadline:
                state.stopped_short = True
                break
            if runnable(chain_id):
                visit_group(chain_id, event_address, sorted(entry["topics"]))
    warm_lag: dict[int, int] = {}
    if scan_mode == "warm":
        warm_lag = _warm_lag(session, groups, targets)
        logger.info(
            "event indexer warm sweep",
            extra={
                "engine": engine,
                "groups": len(groups),
                "pages": state.windows_scanned,
                "inserted": state.inserted,
                "failed_groups": state.failed_groups,
                "max_lag_blocks": {str(chain): lag for chain, lag in sorted(warm_lag.items())},
                "duration_s": round(_monotonic() - sweep_started, 3),
            },
        )
    pending_at_budget = False
    if state.windows_scanned >= pass_budget or (engine == "paged" and state.stopped_short):
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
    _end_transaction(session)
    return ScanSummary(
        inserted=state.inserted,
        windows_scanned=state.windows_scanned,
        caught_up_cursors=state.caught_up_cursors,
        total_cursors=len(rows),
        budget_exhausted=pending_at_budget,
        failed_groups=state.failed_groups,
        warm_max_lag_blocks=warm_lag,
    )


def _depth(chain_id: int, fallback: int) -> int:
    """Per-chain finality depth; mainnet is 12, and the passed-in depth is the fallback for unregistered chains."""
    try:
        return chain_by_id(chain_id).confirmation_depth
    except UnknownChainError:
        return fallback


@dataclass(frozen=True)
class _WriteSizes:
    insert_batch_size: int
    max_rows: int
    max_bytes: int


@dataclass
class _PassState:
    """Running totals for one scan pass, and how each visit's steps are committed and accounted."""

    total_cursors: int
    on_commit: Callable[[ScanSummary], None] | None
    stop_event: Event | None
    inserted: int = 0
    windows_scanned: int = 0
    caught_up_cursors: int = 0
    failed_groups: int = 0
    stopped_short: bool = False

    def stopping(self) -> bool:
        return self.stop_event is not None and self.stop_event.is_set()

    def drive(self, session: Session, steps: Iterator[GroupStepResult], visit: _GroupVisit) -> tuple[bool, int]:
        """Commit each yielded prefix; return whether the group finished and how many members reached the target."""
        group_complete = False
        members_at_target = 0
        for result in steps:
            session.commit()
            self.inserted += result.inserted
            self.windows_scanned += int(result.fetched)
            members_at_target = result.members_at_target
            group_complete = result.group_complete
            visit.record(result)
            if self.on_commit is not None:
                self.on_commit(
                    ScanSummary(
                        inserted=self.inserted,
                        windows_scanned=self.windows_scanned,
                        caught_up_cursors=self.caught_up_cursors + members_at_target,
                        total_cursors=self.total_cursors,
                        failed_groups=self.failed_groups,
                    )
                )
            if self.stopping():
                break
        return group_complete, members_at_target

    def discard(
        self, session: Session, exc: Exception, *, chain_id: int, addresses: Sequence[str], topics: Sequence[str]
    ) -> None:
        session.rollback()
        if isinstance(exc, CursorsMoved):
            # Another writer moved a member between plan and write; nothing was written and the next visit refetches.
            self.stopped_short = True
            logger.info(
                "event indexer page discarded: cursor positions moved since planning",
                extra={"chain_id": chain_id, "event_address": addresses[0] if len(addresses) == 1 else None},
            )
            return
        self.failed_groups += len(addresses)
        # Swallowed and continued. WARNING with exc_type, not logger.exception (an outage once produced thousands of
        # ERROR tracebacks); ``failed_groups`` carries the aggregate.
        logger.warning(
            "event indexer group scan failed; continuing to next group",
            extra={
                "chain_id": chain_id,
                "event_address": addresses[0] if len(addresses) == 1 else None,
                "addresses": len(addresses),
                "topics": list(topics),
                "exc_type": type(exc).__name__,
                # Sanitized (URLs scrubbed) and truncated so the error stays attributable.
                "exc_msg": sanitize_string(str(exc))[:200],
            },
        )


def _hash_reader(
    session: Session,
    chain_id: int,
    block_hash_fetcher: BlockHashFetcher,
    memo: MutableMapping[tuple[int, int], bytes | None],
) -> Callable[[int], bytes | None]:
    def hash_at(block: int) -> bytes | None:
        key = (chain_id, block)
        if key not in memo:
            _end_transaction(session)
            memo[key] = block_hash_fetcher.block_hash(block)
        return memo[key]

    return hash_at


def _warm_sweep_chain(
    session: Session,
    state: _PassState,
    *,
    chain_id: int,
    addresses: Sequence[str],
    target: int,
    fetcher: LogFetcher,
    block_hash_fetcher: BlockHashFetcher,
    block_hash_memo: MutableMapping[tuple[int, int], bytes | None],
    confirmation_depth: int,
    limits: PageLimits,
    writes: _WriteSizes,
    claims: GroupClaims | None,
    visit_single: Callable[[str], None],
    batch_addresses: int | None = None,
    batch_max_lag: int | None = None,
) -> None:
    """Advance one chain's warm groups, up to ``WARM_BATCH_ADDRESSES`` per ``eth_getLogs``.

    A group with a pending rewind, or lagging past ``WARM_BATCH_MAX_LAG``, takes the single-group path first: a batch
    planned across a rewind could advance a cursor over rows just deleted.
    """
    batch_size = max(1, batch_addresses if batch_addresses is not None else settings.WARM_BATCH_ADDRESSES)
    max_lag = batch_max_lag if batch_max_lag is not None else settings.WARM_BATCH_MAX_LAG
    hash_at = _hash_reader(session, chain_id, block_hash_fetcher, block_hash_memo)
    try:
        plan = plan_group(
            session,
            chain_id=chain_id,
            addresses=addresses,
            target=target,
            hash_at=hash_at,
            confirmation_depth=confirmation_depth,
        )
    except Exception as exc:
        state.discard(session, exc, chain_id=chain_id, addresses=addresses, topics=[])
        return
    frontier: dict[str, int] = {}
    for member in plan.members:
        frontier[member.event_address] = min(frontier.get(member.event_address, member.last), member.last)
    singles = [a for a in plan.addresses if a in plan.rewinds or target - frontier.get(a, target) > max_lag]
    for address in singles:
        if state.stopping():
            return
        visit_single(address)
    batchable = [a for a in plan.addresses if a not in singles and a in frontier]
    for offset in range(0, len(batchable), batch_size):
        if state.stopping():
            return
        _sweep_batch(
            session,
            state,
            chain_id=chain_id,
            addresses=batchable[offset : offset + batch_size],
            target=target,
            fetcher=fetcher,
            hash_at=hash_at,
            memo=block_hash_memo,
            confirmation_depth=confirmation_depth,
            limits=limits,
            writes=writes,
            claims=claims,
            visit_single=visit_single,
        )


def _sweep_batch(
    session: Session,
    state: _PassState,
    *,
    chain_id: int,
    addresses: Sequence[str],
    target: int,
    fetcher: LogFetcher,
    hash_at: Callable[[int], bytes | None],
    memo: Mapping[tuple[int, int], bytes | None],
    confirmation_depth: int,
    limits: PageLimits,
    writes: _WriteSizes,
    claims: GroupClaims | None,
    visit_single: Callable[[str], None],
) -> None:
    keys = [(chain_id, a) for a in addresses]
    held = [key for key in keys if claims is None or claims.claim([key])]
    if not held:
        return
    batch = [address for _chain, address in held]
    visit = _GroupVisit(chain_id=chain_id, event_address=f"batch:{len(batch)}")
    split: list[list[str]] = []
    try:
        plan = plan_group(
            session,
            chain_id=chain_id,
            addresses=batch,
            target=target,
            hash_at=hash_at,
            confirmation_depth=confirmation_depth,
        )
        if plan.rewinds:
            rewinding = [(chain_id, address) for address in sorted(plan.rewinds)]
            if claims is not None:
                claims.release(rewinding)
            held = [key for key in held if key not in rewinding]
            for _chain, address in rewinding:
                visit_single(address)
            split = [[a for a in batch if a not in plan.rewinds]]
        else:
            steps = run_plan(
                session,
                plan,
                fetcher=fetcher,
                target=target,
                hash_at=hash_at,
                memo=memo,
                limits=limits,
                insert_batch_size=writes.insert_batch_size,
                write_max_rows=writes.max_rows,
                write_max_bytes=writes.max_bytes,
                stop_event=state.stop_event,
            )
            _complete, members_at_target = state.drive(session, steps, visit)
            state.caught_up_cursors += members_at_target
    except CursorsMoved as exc:
        state.discard(session, exc, chain_id=chain_id, addresses=batch, topics=[])
    except RuntimeError as exc:
        session.rollback()
        if len(batch) == 1:
            state.discard(session, exc, chain_id=chain_id, addresses=batch, topics=[])
        else:
            # The range is already at the bisect floor, so a rejection splits the address set.
            logger.debug(
                "warm batch rejected; splitting the address set",
                extra={"chain_id": chain_id, "addresses": len(batch), "exc_type": type(exc).__name__},
            )
            half = len(batch) // 2
            split = [batch[:half], batch[half:]]
    except Exception as exc:
        state.discard(session, exc, chain_id=chain_id, addresses=batch, topics=[])
    finally:
        if claims is not None:
            claims.release(held)
    for part in split:
        if part and not state.stopping():
            _sweep_batch(
                session,
                state,
                chain_id=chain_id,
                addresses=part,
                target=target,
                fetcher=fetcher,
                hash_at=hash_at,
                memo=memo,
                confirmation_depth=confirmation_depth,
                limits=limits,
                writes=writes,
                claims=claims,
                visit_single=visit_single,
            )


def _warm_lag(session: Session, groups: Mapping[tuple[int, str], Any], targets: Mapping[int, int]) -> dict[int, int]:
    """Per chain, the largest gap between a warm group's lowest cursor and the target, read after the sweep."""
    lag: dict[int, int] = {}
    for chain_id in sorted({chain for chain, _address in groups if chain in targets}):
        addresses = [address for chain, address in groups if chain == chain_id]
        frontier = session.scalar(
            select(func.min(IndexedEventCursor.last_indexed_block)).where(
                IndexedEventCursor.chain_id == chain_id,
                func.lower(IndexedEventCursor.event_address).in_(addresses),
            )
        )
        lag[chain_id] = max(0, targets[chain_id] - int(frontier if frontier is not None else targets[chain_id]))
    _end_transaction(session)
    return lag


@dataclass
class _GroupVisit:
    """What one group visit fetched and wrote, for its INFO line."""

    chain_id: int
    event_address: str
    started: float = field(default_factory=time.monotonic)
    scanned_from: int | None = None
    scanned_to: int | None = None
    pages: int = 0
    rejected_pages: int = 0
    logs: int = 0
    inserted: int = 0

    def record(self, result: GroupStepResult) -> None:
        if result.fetched:
            self.pages += 1
            self.logs += result.page_logs
            self.rejected_pages += result.rejected_pages
            if self.scanned_from is None:
                self.scanned_from = result.scanned_from
        if result.fetched or self.pages:
            self.scanned_to = result.scanned_to
        self.inserted += result.inserted

    def log(self, scan_mode: str) -> None:
        logger.info(
            "event indexer group visit",
            extra={
                "chain_id": self.chain_id,
                "event_address": self.event_address,
                "scan_mode": scan_mode,
                "scanned_from": self.scanned_from,
                "scanned_to": self.scanned_to,
                "pages": self.pages,
                "rejected_pages": self.rejected_pages,
                "logs": self.logs,
                "inserted": self.inserted,
                "duration_s": round(time.monotonic() - self.started, 3),
                "process_rss_bytes": current_rss_bytes(),
            },
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
        # Stamp the job's own chain (``Job.chain_id``, else derived from its request), never a default.
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


_HEARTBEAT_MIN_GAP_S = 5.0


def run_event_log_indexer_loop(
    *,
    fetchers: Mapping[int, LogFetcher],
    head_fetchers: Mapping[int, HeadBlockFetcher],
    block_hash_fetchers: Mapping[int, BlockHashFetcher],
    interval: float = DEFAULT_INTERVAL_S,
    stop_event: Event | None = None,
    engine: str | None = None,
) -> None:
    """Run the durable event-log indexer.

    * With the paged engine, two scan threads: a cold thread (enrolment, then cold groups within a pass budget) and a
    warm thread sweeping every ``interval`` regardless of cold load. Each has its own session; a shared claim set keeps
    them off the same group, and correctness rests on the per-page position check, not on that set.
    * With the legacy engine, one backfill thread runs both, as before.
    * This loop reconciles and beats every ``interval``; scan threads also refresh the heartbeat as pages commit.

    Both scan threads are joined before returning, so the caller's process singleton outlives every commit.
    """
    engine = _resolve_engine(engine)
    # New threads start with an empty context, so bind here and again in each thread.
    with bind_trace_context(worker_id=WORKER_ID):
        logger.info("starting event log indexer loop interval=%ss engine=%s", interval, engine)
        stop_event = stop_event or Event()
        claims = GroupClaims()

        state_lock = Lock()
        published: dict[str, Any] = {
            "cold": ScanSummary(),
            "warm": ScanSummary(),
            "enrolled": 0,
            "status": {"cold": "running", "warm": "running"},
            "warm_max_lag_blocks": {},
            "triad": (0, 0),
            "reconcile": (0, 0),
            "last_beat": 0.0,
        }
        threads: list[Thread] = []

        def beat() -> None:
            with state_lock:
                cold: ScanSummary = published["cold"]
                warm: ScanSummary = published["warm"]
                enrolled = published["enrolled"]
                statuses = dict(published["status"])
                warm_max_lag_blocks = dict(published["warm_max_lag_blocks"])
                caught_up_cursors, total_cursors = published["triad"]
                reenqueued, drift_reenqueued = published["reconcile"]
                published["last_beat"] = time.monotonic()
            status = (
                "error"
                if "error" in statuses.values()
                else "degraded"
                if "degraded" in statuses.values()
                else "running"
            )
            # The threads catch per-pass errors, so a dead one is a fatal stall.
            dead = [t.name for t in threads if not t.is_alive()]
            if dead and not stop_event.is_set():
                status = "error"
                logger.error(
                    "event log indexer scan thread is not alive; indexing has stalled", extra={"threads": dead}
                )
            record_heartbeat(
                HEARTBEAT_EVENT_INDEXER,
                status=status,
                detail={
                    "enrolled_last_pass": enrolled,
                    "inserted_last_pass": cold.inserted + warm.inserted,
                    "windows_scanned": cold.windows_scanned + warm.windows_scanned,
                    "caught_up_cursors": caught_up_cursors,
                    "total_cursors": total_cursors,
                    "pending_cursors": max(0, total_cursors - caught_up_cursors),
                    "deferred_reenqueued_last_pass": reenqueued,
                    "role_drift_reenqueued_last_pass": drift_reenqueued,
                    "warm_max_lag_blocks": {str(chain): lag for chain, lag in sorted(warm_max_lag_blocks.items())},
                },
            )

        def progress(lane: str) -> Callable[[ScanSummary], None]:
            def publish(summary: ScanSummary) -> None:
                with state_lock:
                    published[lane] = summary
                    due = time.monotonic() - published["last_beat"] >= _HEARTBEAT_MIN_GAP_S
                if due:
                    beat()

            return publish

        def publish_pass(lane: str, summary: ScanSummary, status: str, enrolled: int | None = None) -> None:
            with state_lock:
                published[lane] = summary
                published["status"][lane] = status
                if enrolled is not None:
                    published["enrolled"] = enrolled
                if lane == "warm":
                    published["warm_max_lag_blocks"] = dict(summary.warm_max_lag_blocks)

        def enroll(session: Session) -> int:
            with log_timed_phase(logger, "indexer_enroll", record_metric=False) as ph:
                from services.resolution.indexer_scheduler import drain_enrollment

                enrolled = drain_enrollment(
                    session, tracked_limit=DEFAULT_TRACKED_TOPIC_ENROLL_LIMIT, stop_event=stop_event
                )
                ph["enrolled"] = enrolled
            return enrolled

        def scan(session: Session, mode: Literal["warm", "cold"]) -> ScanSummary:
            return scan_enrolled_events(
                session,
                fetchers=fetchers,
                head_fetchers=head_fetchers,
                block_hash_fetchers=block_hash_fetchers,
                stop_event=stop_event,
                scan_mode=mode,
                on_commit=progress(mode),
                engine=engine,
                claims=claims,
            )

        def log_pass(summary: ScanSummary, status: str, enrolled: int, scan_mode: str) -> None:
            # Unconditional per-pass INFO with the cursor triad, so a cold backfill scanning empty windows is visible.
            logger.info(
                "event log indexer pass complete",
                extra={
                    "scan_mode": scan_mode,
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

        def cold_loop() -> None:
            # ``threading.Thread`` doesn't inherit context.
            with bind_trace_context(worker_id=WORKER_ID):
                while not stop_event.is_set():
                    enrolled = 0
                    summary = ScanSummary()
                    status = "running"
                    try:
                        with SessionLocal() as session:
                            enrolled = enroll(session)
                            with log_timed_phase(logger, "indexer_scan", record_metric=False) as ph:
                                summary = scan(session, "cold")
                                ph["windows_scanned"] = summary.windows_scanned
                                ph["inserted"] = summary.inserted
                    except Exception:
                        logger.exception("event log indexer backfill pass failed")
                        status = "error"
                    status = _heartbeat_status_for_pass(status, summary)
                    log_pass(summary, status, enrolled, "cold")
                    publish_pass("cold", summary, status, enrolled)
                    # Only unfinished history uses the short pause.
                    stop_event.wait(DEFAULT_BACKFILL_BUSY_INTERVAL_S if summary.budget_exhausted else interval)

        def warm_loop() -> None:
            with bind_trace_context(worker_id=WORKER_ID):
                while not stop_event.is_set():
                    started = time.monotonic()
                    summary = ScanSummary()
                    status = "running"
                    try:
                        with SessionLocal() as session:
                            summary = scan(session, "warm")
                    except Exception:
                        logger.exception("event log indexer warm sweep failed")
                        status = "error"
                    publish_pass("warm", summary, _heartbeat_status_for_pass(status, summary))
                    stop_event.wait(max(0.0, interval - (time.monotonic() - started)))

        def legacy_loop() -> None:
            with bind_trace_context(worker_id=WORKER_ID):
                next_warm_at = 0.0
                cold_pending = True
                while not stop_event.is_set():
                    enrolled = 0
                    summary = ScanSummary()
                    status = "running"
                    try:
                        with SessionLocal() as session:
                            enrolled = enroll(session)
                            with log_timed_phase(logger, "indexer_scan", record_metric=False) as ph:
                                warm_due = time.monotonic() >= next_warm_at
                                warm_summary = ScanSummary()
                                if warm_due:
                                    warm_summary = scan(session, "warm")
                                    publish_pass("warm", warm_summary, "running")
                                    next_warm_at = time.monotonic() + interval
                                cold_summary = ScanSummary()
                                if cold_pending or warm_due or enrolled:
                                    cold_summary = scan(session, "cold")
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
                    status = _heartbeat_status_for_pass(status, summary)
                    log_pass(summary, status, enrolled, "all")
                    publish_pass("cold", summary, status, enrolled)
                    backfill_wait = (
                        min(DEFAULT_BACKFILL_BUSY_INTERVAL_S, max(0.0, next_warm_at - time.monotonic()))
                        if cold_pending
                        else max(0.0, next_warm_at - time.monotonic())
                    )
                    stop_event.wait(backfill_wait)

        if engine == "paged":
            threads.append(Thread(target=cold_loop, name="event-indexer-backfill", daemon=True))
            threads.append(Thread(target=warm_loop, name="event-indexer-warm", daemon=True))
        else:
            threads.append(Thread(target=legacy_loop, name="event-indexer-backfill", daemon=True))
        for thread in threads:
            thread.start()

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
                # Read the triad from the table independently of the scan threads, in its own session so a failure
                # doesn't blank the heartbeat.
                triad = (0, 0)
                try:
                    with SessionLocal() as session:
                        triad = _cursor_progress(session)
                except Exception:
                    logger.exception("event log indexer cursor-progress count failed")
                with state_lock:
                    published["triad"] = triad
                    published["reconcile"] = (reenqueued, drift_reenqueued)
                beat()
                stop_event.wait(interval)
        finally:
            stop_event.set()
            # Don't release the singleton while a scan can commit.
            for thread in threads:
                thread.join()


def _build_indexer_fetchers(
    chains: Sequence[ChainInfo] | None = None,
    *,
    engine: str | None = None,
) -> tuple[dict[int, LogFetcher], dict[int, HeadBlockFetcher], dict[int, BlockHashFetcher]]:
    """Per-chain fetchers for the scan loop.

    The chain set is registry chains with ``hypersync_url``; others get no fetcher and their cursors are
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
    # The long timeout lets a wide window return whole, so it is only safe with the paged engine's page ceiling.
    timeout = settings.GETLOGS_TIMEOUT_S if _resolve_engine(engine) == "paged" else None
    fetchers: dict[int, LogFetcher] = {}
    head_fetchers: dict[int, HeadBlockFetcher] = {}
    block_hash_fetchers: dict[int, BlockHashFetcher] = {}
    for info in registry_chains:
        if info.hypersync_url is None:
            continue
        rpc_url = require_rpc_url(chain_id=info.chain_id)
        fetchers[info.chain_id] = RpcEventLogFetcher(
            rpc_url, chain_id=info.chain_id, result_cap=result_cap, timeout=timeout, keep_raw=False
        )
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

    engine = _resolve_engine(None)
    fetchers, head_fetchers, block_hash_fetchers = _build_indexer_fetchers(engine=engine)
    run_event_log_indexer_loop(
        engine=engine,
        fetchers=fetchers,
        head_fetchers=head_fetchers,
        block_hash_fetchers=block_hash_fetchers,
        stop_event=stop_event,
    )


if __name__ == "__main__":
    main()
