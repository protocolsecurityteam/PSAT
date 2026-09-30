"""The restaking plane's periodic step: enroll the fold, read, persist.

Separate from the balance refresh so a restaking failure can't withdraw proven balances. Manager addresses are hardcoded
call targets, not name lookups: ``contracts`` keys them at implementations, which answer nothing. A missing or wrong
target fails closed to ``not_determined``, never zero.
"""

from __future__ import annotations

import logging
import os
import time
from threading import Event

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Protocol, SessionLocal
from db.queue import HEARTBEAT_PROTOCOL_RESTAKING, record_heartbeat
from services.clients.rpc import rpc_url_for_chain_id
from services.monitoring import emit_monitor_cycle
from services.monitoring.restaking_enrollment import (
    DEFAULT_EMITTER_PROBE_SPAN,
    PUBKEY_LINKED_TOPIC0,
    discover_emitters,
    enroll_restaking_fold,
    node_addresses_from_fold,
    protocol_contract_addresses,
)
from services.monitoring.restaking_reads import (
    manager_contract_id_for,
    persist_positions,
    pinned_head,
    read_positions,
)
from services.resolution.repos.event_logs_rpc import RpcEventLogFetcher

logger = logging.getLogger(__name__)

# chain_id -> (EigenPodManager, DelegationManager), at their proxy addresses.
EIGENLAYER_MANAGERS: dict[int, tuple[str, str]] = {
    1: (
        "0x91e677b07f7af907ec9a428aafa9fc14a0d3a338",
        "0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a",
    ),
}

DEFAULT_RESTAKING_INTERVAL = int(os.getenv("PSAT_RESTAKING_INTERVAL", "3600"))


def _log_fetcher(rpc_url: str, *, chain_id: int):
    """Uses the shared bisect-on-reject fetcher so a provider cap can't silently truncate the emitter probe."""
    fetcher = RpcEventLogFetcher(rpc_url, chain_id=chain_id)

    def fetch(addresses, topic0, from_block, to_block):
        return fetcher.fetch_logs(
            event_address=addresses,
            topics=[topic0],
            from_block=from_block,
            to_block=to_block,
        )

    return fetch


def refresh_restaking_plane(
    session: Session,
    *,
    chain_id: int,
    rpc_url: str | None = None,
) -> int:
    """One pass per protocol and proven emitter; returns records written.

    Per emitter so ``manager_contract_id`` names the contract whose log enumerated the node. A failing protocol is
    logged and skipped.
    """
    started = time.monotonic()

    def summarize(*, protocols: int, written: int, failures: int, note: str | None, partial: bool) -> int:
        emit_monitor_cycle(
            HEARTBEAT_PROTOCOL_RESTAKING,
            started=started,
            contracts_scanned=protocols,
            # Two ranges are in play (emitter probe, pinned reads); 0 under-claims.
            blocks_scanned=0,
            events_found=written,
            partial=partial,
            note=note,
            extra_detail={"chain_id": chain_id, "protocols_failed": failures},
        )
        return written

    managers = EIGENLAYER_MANAGERS.get(chain_id)
    if managers is None:
        # No known call target: a configuration absence, not a failed observation.
        return summarize(protocols=0, written=0, failures=0, note="no_manager_pair", partial=False)
    eigen_pod_manager, delegation_manager = managers

    url = rpc_url or rpc_url_for_chain_id(chain_id)
    if not url:
        return summarize(protocols=0, written=0, failures=0, note="no_rpc_route", partial=False)
    pinned = pinned_head(chain_id, url)
    if pinned is None:
        # Degraded: ``pinned_head`` is None only on a failed or inconsistent read.
        return summarize(protocols=0, written=0, failures=0, note="no_pinned_head", partial=True)
    head, _ = pinned
    from_block = max(0, head - DEFAULT_EMITTER_PROBE_SPAN)
    fetch_logs = _log_fetcher(url, chain_id=chain_id)

    # Materialized: the loop commits per protocol.
    protocol_ids = list(session.execute(select(Protocol.id).order_by(Protocol.id)).scalars())
    written = 0
    failures = 0
    for protocol_id in protocol_ids:
        try:
            addresses = protocol_contract_addresses(session, protocol_id=protocol_id)
            if not addresses:
                continue
            emitters = sorted(
                discover_emitters(
                    addresses,
                    from_block=from_block,
                    to_block=head,
                    fetch_logs=fetch_logs,
                )
            )
            if not emitters:
                continue
            enroll_restaking_fold(session, chain_id=chain_id, emitters=emitters)
            session.commit()
            for emitter in emitters:
                nodes = node_addresses_from_fold(session, chain_id=chain_id, event_address=emitter)
                if not nodes:
                    continue
                records = read_positions(
                    nodes,
                    chain_id=chain_id,
                    eigen_pod_manager=eigen_pod_manager,
                    delegation_manager=delegation_manager,
                    rpc_url=url,
                )
                written += persist_positions(
                    session,
                    records,
                    manager_contract_id=manager_contract_id_for(session, emitter=emitter, protocol_id=protocol_id),
                    protocol_id=protocol_id,
                )
                session.commit()
        except Exception as exc:
            failures += 1
            session.rollback()
            logger.warning(
                "restaking cycle: protocol pass failed",
                extra={"protocol_id": protocol_id, "chain_id": chain_id, "exc_type": type(exc).__name__},
            )
    return summarize(
        protocols=len(protocol_ids),
        written=written,
        failures=failures,
        partial=failures > 0,
        note=f"{failures}_failed" if failures else None,
    )


def run_restaking_loop(
    interval: float = DEFAULT_RESTAKING_INTERVAL,
    stop_event: Event | None = None,
    *,
    chain_id: int = 1,
) -> None:
    stop_event = stop_event or Event()
    logger.info("Starting restaking plane tracker (interval=%ss, topic0=%s)", interval, PUBKEY_LINKED_TOPIC0)
    while not stop_event.is_set():
        try:
            with SessionLocal() as session:
                refresh_restaking_plane(session, chain_id=chain_id)
        except Exception as exc:
            logger.warning("restaking position cycle failed: %s", exc, extra={"exc_type": type(exc).__name__})
            record_heartbeat(
                HEARTBEAT_PROTOCOL_RESTAKING,
                status="degraded",
                detail={"partial": True, "note": "cycle_error", "exc_type": type(exc).__name__},
            )
        stop_event.wait(interval)


__all__ = [
    "DEFAULT_RESTAKING_INTERVAL",
    "EIGENLAYER_MANAGERS",
    "refresh_restaking_plane",
    "run_restaking_loop",
]
