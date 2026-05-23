"""Generic event-log indexer for predicate ``enumeration_hint`` records."""

from __future__ import annotations

import logging
import os
import signal
from dataclasses import dataclass
from threading import Event
from typing import Any, Mapping, Protocol

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import Contract, ControllerValue, IndexedEventCursor, IndexedEventLog, Job, JobStatus, SessionLocal
from db.queue import get_artifact
from services.resolution.repos.event_logs_rpc import FetchedEventLog
from utils.rpc import PUBLIC_ETH_RPC_URL, default_rpc_url

logger = logging.getLogger("workers.event_log_indexer")

DEFAULT_INTERVAL_S = float(os.getenv("PSAT_EVENT_INDEXER_INTERVAL_S", "60"))
DEFAULT_CONFIRMATION_DEPTH = int(os.getenv("PSAT_EVENT_INDEXER_FINALITY_DEPTH", "12"))


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
) -> IndexStepResult:
    cursor = session.execute(
        select(IndexedEventCursor)
        .where(IndexedEventCursor.chain_id == chain_id)
        .where(func.lower(IndexedEventCursor.event_address) == event_address.lower())
        .where(func.lower(IndexedEventCursor.topic0) == topic0.lower())
        .with_for_update()
    ).scalar_one_or_none()
    if cursor is None:
        return IndexStepResult(scanned_from=0, scanned_to=0, inserted=0)

    head = head_fetcher.head_block()
    target = max(0, head - confirmation_depth)
    last = int(cursor.last_indexed_block or 0)
    if target <= last:
        return IndexStepResult(scanned_from=last + 1, scanned_to=target, inserted=0)

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

    start = last + 1
    logs = fetcher.fetch_logs(
        event_address=event_address.lower(),
        topic0=topic0.lower(),
        from_block=start,
        to_block=target,
    )
    inserted = _bulk_insert_logs(session, chain_id, event_address.lower(), topic0.lower(), logs)
    cursor.last_indexed_block = target
    cursor.last_indexed_block_hash = block_hash_fetcher.block_hash(target)
    cursor.last_run_at = func.now()
    return IndexStepResult(scanned_from=start, scanned_to=target, inserted=inserted)


def scan_enrolled_events(
    session: Session,
    *,
    fetchers: Mapping[int, LogFetcher],
    head_fetchers: Mapping[int, HeadBlockFetcher],
    block_hash_fetchers: Mapping[int, BlockHashFetcher],
    confirmation_depth: int = DEFAULT_CONFIRMATION_DEPTH,
) -> int:
    rows = session.execute(
        select(IndexedEventCursor.chain_id, IndexedEventCursor.event_address, IndexedEventCursor.topic0)
    ).all()
    inserted = 0
    for chain_id, event_address, topic0 in rows:
        fetcher = fetchers.get(chain_id)
        head_fetcher = head_fetchers.get(chain_id)
        block_hash_fetcher = block_hash_fetchers.get(chain_id)
        if fetcher is None or head_fetcher is None or block_hash_fetcher is None:
            continue
        try:
            result = index_event_log_step(
                session,
                chain_id=chain_id,
                event_address=event_address,
                topic0=topic0,
                fetcher=fetcher,
                head_fetcher=head_fetcher,
                block_hash_fetcher=block_hash_fetcher,
                confirmation_depth=confirmation_depth,
            )
            inserted += result.inserted
            session.commit()
        except Exception:
            session.rollback()
            logger.exception(
                "event indexer pass failed for chain=%s address=%s topic0=%s",
                chain_id,
                event_address,
                topic0,
            )
    return inserted


def enroll_from_completed_jobs(session: Session, *, chain_id: int = 1, limit: int = 500) -> int:
    jobs = session.execute(
        select(Job)
        .where(Job.status == JobStatus.completed)
        .where(Job.address.isnot(None))
        .order_by(Job.updated_at.desc())
        .limit(limit)
    ).scalars()
    inserted = 0
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
                if address is None:
                    continue
                if enroll_event_cursor(session, chain_id=chain_id, event_address=address, topic0=topic0):
                    inserted += 1
    session.commit()
    return inserted


def _bulk_insert_logs(
    session: Session,
    chain_id: int,
    event_address: str,
    topic0: str,
    logs: list[FetchedEventLog],
) -> int:
    if not logs:
        return 0
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
        for log in logs
    ]
    stmt = (
        pg_insert(IndexedEventLog)
        .values(rows)
        .on_conflict_do_nothing(index_elements=["chain_id", "event_address", "topic0", "tx_hash", "log_index"])
    )
    result = session.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)


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
        with SessionLocal() as session:
            try:
                enrolled = enroll_from_completed_jobs(session)
                inserted = scan_enrolled_events(
                    session,
                    fetchers=fetchers,
                    head_fetchers=head_fetchers,
                    block_hash_fetchers=block_hash_fetchers,
                )
                if enrolled or inserted:
                    logger.info("event log indexer pass: enrolled=%d inserted=%d", enrolled, inserted)
            except Exception:
                session.rollback()
                logger.exception("event log indexer pass failed")
        stop_event.wait(interval)


def main() -> None:
    from services.resolution.repos.event_logs_rpc import RpcBlockHashFetcher, RpcEventLogFetcher, RpcHeadBlockFetcher

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

    rpc_url = os.getenv("PSAT_INDEXER_RPC_URL") or default_rpc_url(chain_id=1) or PUBLIC_ETH_RPC_URL
    fetchers = {1: RpcEventLogFetcher(rpc_url)}
    head_fetchers = {1: RpcHeadBlockFetcher(rpc_url)}
    block_hash_fetchers = {1: RpcBlockHashFetcher(rpc_url)}
    run_event_log_indexer_loop(
        fetchers=fetchers,
        head_fetchers=head_fetchers,
        block_hash_fetchers=block_hash_fetchers,
        stop_event=stop_event,
    )


if __name__ == "__main__":
    main()
