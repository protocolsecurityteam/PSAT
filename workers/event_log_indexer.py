"""Generic event-log indexer for predicate ``enumeration_hint`` records."""

from __future__ import annotations

import logging
import os
import signal
from dataclasses import dataclass
from threading import Event
from typing import Any, Mapping, Protocol, TypeGuard

from eth_utils.crypto import keccak
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import Contract, ControllerValue, IndexedEventCursor, IndexedEventLog, Job, JobStatus, SessionLocal
from db.queue import HEARTBEAT_EVENT_INDEXER, get_artifact, record_heartbeat
from services.resolution.deferred_reconciler import reconcile_deferred_resolutions
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from utils.etherscan import get_contract_creation_block
from utils.logging import log_timed_phase
from utils.rpc import PUBLIC_ETH_RPC_URL

logger = logging.getLogger("workers.event_log_indexer")

DEFAULT_INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_INTERVAL_S", "60"))
DEFAULT_CONFIRMATION_DEPTH = int(os.getenv("PSAT_EVENT_INDEXER_FINALITY_DEPTH", "12"))

# Backfill in bounded windows. A cold cursor's gap to head is ~25M blocks; the
# fetcher already pages eth_getLogs, but a full-range step accumulates every
# match into one list and inserts it in a single statement. On high-volume
# authorities (the LayerZero endpoint) that one insert dropped the Neon
# connection ("SSL connection has been closed unexpectedly"), wedging the cursor
# at block 0 forever. So: cap the span scanned per step, batch the insert, and
# let one pass advance a cursor across several windows.
DEFAULT_MAX_BLOCK_SPAN = int(os.getenv("PSAT_EVENT_INDEXER_MAX_BLOCK_SPAN", "50000"))
DEFAULT_MAX_WINDOWS_PER_CURSOR = int(os.getenv("PSAT_EVENT_INDEXER_MAX_WINDOWS_PER_CURSOR", "200"))
DEFAULT_INSERT_BATCH = int(os.getenv("PSAT_EVENT_INDEXER_INSERT_BATCH", "1000"))

# HyperSync (Envio) JSON-RPC endpoint for mainnet — the indexer's RPC backend.
# HyperSync serves eth_blockNumber/eth_getBlockByNumber/eth_getLogs at $0; it is
# validated to track head with zero lag and return canonical block hashes at the
# head-confirmation_depth reorg zone (see EVENT_INDEXER_RPC_COST_VERDICT.md).
DEFAULT_HYPERRPC_URL = os.getenv("PSAT_INDEXER_HYPERRPC_URL", "https://eth.rpc.hypersync.xyz")

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


class LogFetcher(Protocol):
    def fetch_logs(
        self,
        *,
        event_address: str,
        topic0: str,
        from_block: int,
        to_block: int,
    ) -> list[FetchedEventLog]: ...


class HeadBlockFetcher(Protocol):
    def head_block(self) -> int: ...


class BlockHashFetcher(Protocol):
    def block_hash(self, block_number: int) -> bytes | None: ...


@dataclass(frozen=True)
class IndexStepResult:
    scanned_from: int
    scanned_to: int
    inserted: int
    caught_up: bool  # True once scanned_to reached the confirmed head (no gap left)


@dataclass(frozen=True)
class ScanSummary:
    """What one ``scan_enrolled_events`` pass did, for the fleet heartbeat.

    ``windows_scanned`` (steps run, summed across all cursors) over
    ``total_cursors`` reveals the from-0 backfill signature: many windows
    scanned with 0 inserted and ``caught_up_cursors`` < ``total_cursors``
    means a cold cursor is grinding through empty eth_getLogs ranges while
    the rest sit at head.
    """

    inserted: int = 0
    windows_scanned: int = 0
    caught_up_cursors: int = 0
    total_cursors: int = 0


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


def index_event_log_step(
    session: Session,
    *,
    chain_id: int,
    event_address: str,
    topic0: str,
    fetcher: LogFetcher,
    head_fetcher: HeadBlockFetcher,
    block_hash_fetcher: BlockHashFetcher,
    confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
    max_block_span: int = DEFAULT_MAX_BLOCK_SPAN,
    insert_batch_size: int = DEFAULT_INSERT_BATCH,
) -> IndexStepResult:
    cursor = session.execute(
        select(IndexedEventCursor)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
        .where(func.lower(IndexedEventCursor.topic0) == topic0.lower())
        .with_for_update()
    ).scalar_one_or_none()
    if cursor is None:
        return IndexStepResult(scanned_from=0, scanned_to=0, inserted=0, caught_up=True)

    head = head_fetcher.head_block()
    target = max(0, head - confirmation_depth)
    last = int(cursor.last_indexed_block or 0)
    if target <= last:
        # Cursor is already at (or past) the confirmed head — the historical
        # backfill is done. Record that so resolvers stop treating a cursor
        # seeded at the deploy block as "still cold" and trust the durable index.
        cursor.backfill_complete = True
        return IndexStepResult(scanned_from=last + 1, scanned_to=target, inserted=0, caught_up=True)

    if last > 0 and cursor.last_indexed_block_hash is not None:
        observed_hash = block_hash_fetcher.block_hash(last)
        if observed_hash is not None and observed_hash != cursor.last_indexed_block_hash:
            rewind_to = max(0, last - confirmation_depth)
            session.execute(
                delete(IndexedEventLog)
                .where(IndexedEventLog.chain_id == chain_id)
                .where(func.lower(IndexedEventLog.event_address) == event_address.lower())
                .where(IndexedEventLog.block_number > rewind_to)
            )
            cursor.last_indexed_block = rewind_to
            cursor.last_indexed_block_hash = block_hash_fetcher.block_hash(rewind_to) if rewind_to else None
            last = rewind_to

    # One bounded window per step — never the whole [last+1, target] gap at once.
    start = last + 1
    window_end = min(target, last + max(1, max_block_span))
    logs = fetcher.fetch_logs(
        event_address=event_address.lower(),
        topic0=topic0.lower(),
        from_block=start,
        to_block=window_end,
    )
    inserted = _bulk_insert_logs(
        session, chain_id, event_address.lower(), topic0.lower(), logs, batch_size=insert_batch_size
    )
    cursor.last_indexed_block = window_end
    cursor.last_indexed_block_hash = block_hash_fetcher.block_hash(window_end)
    cursor.last_run_at = func.now()
    caught_up = window_end >= target
    if caught_up:
        cursor.backfill_complete = True
    return IndexStepResult(scanned_from=start, scanned_to=window_end, inserted=inserted, caught_up=caught_up)


def scan_enrolled_events(
    session: Session,
    *,
    fetchers: Mapping[int, LogFetcher],
    head_fetchers: Mapping[int, HeadBlockFetcher],
    block_hash_fetchers: Mapping[int, BlockHashFetcher],
    confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
    max_block_span: int = DEFAULT_MAX_BLOCK_SPAN,
    max_windows_per_cursor: int = DEFAULT_MAX_WINDOWS_PER_CURSOR,
    insert_batch_size: int = DEFAULT_INSERT_BATCH,
) -> ScanSummary:
    all_rows = session.execute(
        select(IndexedEventCursor.chain_id, IndexedEventCursor.event_address, IndexedEventCursor.topic0)
    ).all()
    # Skip zero/invalid-address cursors that predate the enroll-time guard: 0x0 can
    # never emit logs, so scanning it just burns one RPC round-trip every pass.
    rows = [row for row in all_rows if _is_enrollable_event_address(row[1])]
    inserted = 0
    windows_scanned = 0
    caught_up_cursors = 0
    for chain_id, event_address, topic0 in rows:
        fetcher = fetchers.get(chain_id)
        head_fetcher = head_fetchers.get(chain_id)
        block_hash_fetcher = block_hash_fetchers.get(chain_id)
        if fetcher is None or head_fetcher is None or block_hash_fetcher is None:
            continue
        # Walk several windows per pass so a cold cursor backfills in a handful
        # of passes, but cap it so one high-volume address can't starve the
        # rest. Commit per window: each transaction (and INSERT) stays small,
        # progress is durable, and a mid-backfill failure on one cursor doesn't
        # roll back the windows it already landed.
        try:
            for _ in range(max(1, max_windows_per_cursor)):
                result = index_event_log_step(
                    session,
                    chain_id=chain_id,
                    event_address=event_address,
                    topic0=topic0,
                    fetcher=fetcher,
                    head_fetcher=head_fetcher,
                    block_hash_fetcher=block_hash_fetcher,
                    confirmation_depth=confirmation_depth,
                    max_block_span=max_block_span,
                    insert_batch_size=insert_batch_size,
                )
                session.commit()
                inserted += result.inserted
                windows_scanned += 1
                if result.caught_up:
                    caught_up_cursors += 1
                    break
        except Exception:
            session.rollback()
            logger.exception(
                "event indexer pass failed for chain=%s address=%s topic0=%s",
                chain_id,
                event_address,
                topic0,
            )
    return ScanSummary(
        inserted=inserted,
        windows_scanned=windows_scanned,
        caught_up_cursors=caught_up_cursors,
        total_cursors=len(rows),
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


def _seed_block(address: str, cache: dict[str, int | None], *, chain_id: int = 1) -> int | None:
    """The ``last_indexed_block`` a new cursor should start at: one below the
    event address's creation block, so the first scan window begins at the
    deploy block and the ~20M empty pre-deployment blocks are never fetched.

    Returns ``None`` when the creation block can't be determined, so the caller
    defers enrollment to a later pass (retrying once it resolves) instead of
    seeding at genesis: a single transient Etherscan failure must never pin a
    cursor to a full-chain backfill. Cached per pass (one lookup per address).
    """
    key = address.lower()
    if key in cache:
        return cache[key]
    seed: int | None = None
    try:
        created = get_contract_creation_block(key, chain_id=chain_id)
        if isinstance(created, int) and created > 0:
            seed = created - 1
    except Exception as exc:
        logger.warning(
            "creation-block lookup failed for %s; deferring enrollment to a later pass",
            key,
            extra={"address": key, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )
        seed = None
    cache[key] = seed
    return seed


def enroll_from_completed_jobs(session: Session, *, chain_id: int = 1, limit: int = 500) -> int:
    jobs = session.execute(
        select(Job)
        .where(Job.status == JobStatus.completed)
        .where(Job.address.isnot(None))
        .order_by(Job.updated_at.desc())
        .limit(limit)
    ).scalars()
    inserted = 0
    seed_cache: dict[str, int | None] = {}
    for job in jobs:
        artifact = get_artifact(session, job.id, "predicate_trees")
        if not isinstance(artifact, dict):
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
                start_block = _seed_block(address, seed_cache, chain_id=chain_id)
                if start_block is None:
                    # Creation block not yet known — enroll on a later pass at the
                    # real deploy block rather than backfilling from genesis.
                    continue
                if enroll_event_cursor(
                    session, chain_id=chain_id, event_address=address, topic0=topic0, start_block=start_block
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
                    start_block = _seed_block(authority, seed_cache, chain_id=chain_id)
                    if start_block is not None:
                        for topic0 in _SOLMATE_ROLE_TOPICS:
                            if enroll_event_cursor(
                                session,
                                chain_id=chain_id,
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
    return job.address.lower() if job.address and len(job.address) == 42 else None


def run_event_log_indexer_loop(
    *,
    fetchers: Mapping[int, LogFetcher],
    head_fetchers: Mapping[int, HeadBlockFetcher],
    block_hash_fetchers: Mapping[int, BlockHashFetcher],
    interval: float = DEFAULT_INTERVAL_S,
    stop_event: Event | None = None,
) -> None:
    logger.info("starting event log indexer loop interval=%ss", interval)
    stop_event = stop_event or Event()
    while not stop_event.is_set():
        enrolled = 0
        summary = ScanSummary()
        reenqueued = 0
        status = "running"
        with SessionLocal() as session:
            try:
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
                if enrolled or summary.inserted:
                    logger.info("event log indexer pass: enrolled=%d inserted=%d", enrolled, summary.inserted)
            except Exception:
                session.rollback()
                logger.exception("event log indexer pass failed")
                status = "error"
            # Self-heal index-cold capability deferrals whose authority just
            # finished backfilling (this is the pass that flips backfill_complete,
            # so it's the timely place to re-resolve). Isolated try: a reconcile
            # failure must not mark the indexing pass itself as errored.
            try:
                with log_timed_phase(logger, "indexer_reconcile", record_metric=False) as ph:
                    reenqueued = reconcile_deferred_resolutions(session)
                    ph["reenqueued"] = reenqueued
                if reenqueued:
                    logger.info("deferred-resolution reconciler re-enqueued %d job(s)", reenqueued)
            except Exception:
                session.rollback()
                logger.exception("deferred-resolution reconcile pass failed")
        # windows_scanned + caught_up_cursors/total are the throughput triad
        # for the indexer: "many windows, 0 inserted, caught_up < total" is the
        # from-0 backfill grind; "caught_up == total" means the fleet is at head.
        record_heartbeat(
            HEARTBEAT_EVENT_INDEXER,
            status=status,
            detail={
                "enrolled_last_pass": enrolled,
                "inserted_last_pass": summary.inserted,
                "windows_scanned": summary.windows_scanned,
                "caught_up_cursors": summary.caught_up_cursors,
                "total_cursors": summary.total_cursors,
                "deferred_reenqueued_last_pass": reenqueued,
            },
        )
        stop_event.wait(interval)


def resolve_indexer_rpc() -> tuple[str, dict[str, str] | None]:
    """Resolve the indexer's RPC endpoint and auth headers — HyperSync-only.

    A metered fallback (eRPC/Alchemy) is deliberately NOT in this chain: the
    indexer polls every ``PSAT_EVENT_INDEXER_INTERVAL_S`` against ~N converged
    cursors, and an accidental fall-through to Alchemy is what blew the RPC spend
    cap (see EVENT_INDEXER_RPC_COST_VERDICT.md). Resolution order:

      1. ``PSAT_INDEXER_RPC_URL`` — explicit operator override (any provider).
      2. HyperRPC + ``Authorization: Bearer $ENVIO_API_TOKEN`` — the prod default.
      3. the free public node — only when neither is configured; logged loudly.

    Alchemy/eRPC is never returned here by design.
    """
    explicit = (os.getenv("PSAT_INDEXER_RPC_URL") or "").strip()
    if explicit:
        return explicit, None
    token = (os.getenv("ENVIO_API_TOKEN") or "").strip()
    if token:
        return DEFAULT_HYPERRPC_URL, {"Authorization": f"Bearer {token}"}
    logger.warning(
        "event indexer: no PSAT_INDEXER_RPC_URL and no ENVIO_API_TOKEN — using the free "
        "public node %s. Backfills will be slow and capped; set ENVIO_API_TOKEN to use "
        "HyperSync. Alchemy/eRPC is never used here by design.",
        PUBLIC_ETH_RPC_URL,
    )
    return PUBLIC_ETH_RPC_URL, None


def build_indexer_fetchers(
    rpc_url: str, auth_headers: Mapping[str, str] | None
) -> tuple[dict[int, LogFetcher], dict[int, HeadBlockFetcher], dict[int, BlockHashFetcher]]:
    """Construct the per-chain RPC fetchers, all sharing one endpoint + auth."""
    from services.resolution.repos.event_logs_rpc import RpcBlockHashFetcher, RpcEventLogFetcher, RpcHeadBlockFetcher

    return (
        {1: RpcEventLogFetcher(rpc_url, headers=auth_headers)},
        {1: RpcHeadBlockFetcher(rpc_url, headers=auth_headers)},
        {1: RpcBlockHashFetcher(rpc_url, headers=auth_headers)},
    )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        force=True,
    )
    stop_event = Event()

    def handle_signal(signum, _frame):
        logger.info("received signal %s, shutting down", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    rpc_url, auth_headers = resolve_indexer_rpc()
    logger.info(
        "event indexer RPC backend: %s (auth=%s)",
        "hypersync"
        if rpc_url == DEFAULT_HYPERRPC_URL
        else ("public-node" if rpc_url == PUBLIC_ETH_RPC_URL else "explicit"),
        "bearer" if auth_headers else "none",
    )
    fetchers, head_fetchers, block_hash_fetchers = build_indexer_fetchers(rpc_url, auth_headers)
    run_event_log_indexer_loop(
        fetchers=fetchers,
        head_fetchers=head_fetchers,
        block_hash_fetchers=block_hash_fetchers,
        stop_event=stop_event,
    )


if __name__ == "__main__":
    main()
