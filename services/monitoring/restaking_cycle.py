"""The restaking plane's own periodic step: enroll the fold, read, persist.

Deliberately NOT a phase of the balance refresh. The two planes answer different
questions at different heights from different contracts, and folding this into
``refresh_contract_balances`` would put a restaking read failure inside the
balance cycle's failure domain — a plane that publishes ``not_determined``
everywhere could then withdraw balances that were proven. It runs as its own
supervised loop for the same reason: its worst case is its own degraded
heartbeat.

**The manager addresses are call targets, not published facts.** They are named
per chain below rather than looked up by ``contract_name``, and a chain with no
entry runs no read at all. Both properties matter:

* ``contracts`` keys the EigenLayer managers at their IMPLEMENTATIONS
  (``0xd22dd829…`` for the pod manager), which answer nothing — the same
  implementation-vs-proxy keying defect this plane exists to avoid;
* a wrong or absent target fails CLOSED. ``beaconChainETHStrategy()`` would not
  answer, so no shares read is issued and ``shares_basis`` stays
  ``not_determined``; ``ownerToPod``/``hasPod`` would not corroborate
  ``node.getEigenPod()``, so ``eigenpod_basis`` stays ``not_determined``. No arm
  turns a missing target into a zero.
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

# chain_id -> (EigenPodManager, DelegationManager), both at their RUNTIME (proxy)
# addresses. Reproduced at block 25643300: the pod manager answers
# ``beaconChainETHStrategy()`` = ``0xbeac0eeeeeeeeeeeeeeeeeeeeeeeeeeeeeebeac0``
# (not the ``…eeee`` near-miss the register names as a trap) and ``numPods()`` =
# 34704, and its ``ownerToPod`` agrees with the node's own ``getEigenPod()``.
EIGENLAYER_MANAGERS: dict[int, tuple[str, str]] = {
    1: (
        "0x91e677b07f7af907ec9a428aafa9fc14a0d3a338",
        "0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a",
    ),
}

DEFAULT_RESTAKING_INTERVAL = int(os.getenv("PSAT_RESTAKING_INTERVAL", "3600"))


def _log_fetcher(rpc_url: str, *, chain_id: int):
    """A :data:`LogFetcher` over the shared bisect-on-reject fetcher.

    Reusing it rather than issuing a bare ``eth_getLogs`` is what keeps a
    provider range/result cap from silently truncating the emitter probe: a
    rejected window is halved and retried, not dropped.
    """
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
    """One pass: discover emitters, enroll the fold, read, persist.

    Returns the number of position records written.

    Per protocol and then per PROVEN emitter, so every record's
    ``manager_contract_id`` names the contract whose log enumerated that node.
    A protocol that raises is logged and skipped: one protocol's failure must not
    withhold another's reads, and a withheld read is an absence this plane is not
    allowed to publish as a zero.
    """
    started = time.monotonic()

    def summarize(*, protocols: int, written: int, failures: int, note: str | None, partial: bool) -> int:
        emit_monitor_cycle(
            HEARTBEAT_PROTOCOL_RESTAKING,
            started=started,
            contracts_scanned=protocols,
            # Two different ranges are in play — a fixed-span emitter probe per
            # protocol, and position reads at one pinned height — and no single
            # number describes both. 0 under-claims rather than over-claims.
            blocks_scanned=0,
            events_found=written,
            partial=partial,
            note=note,
            extra_detail={"chain_id": chain_id, "protocols_failed": failures},
        )
        return written

    managers = EIGENLAYER_MANAGERS.get(chain_id)
    if managers is None:
        # No witnessed call target for this chain, so no read is licensed. Row
        # absence reads as not_determined, which is what it is. A configuration
        # absence, not a failed observation — the cycle is healthy.
        return summarize(protocols=0, written=0, failures=0, note="no_manager_pair", partial=False)
    eigen_pod_manager, delegation_manager = managers

    url = rpc_url or rpc_url_for_chain_id(chain_id)
    if not url:
        return summarize(protocols=0, written=0, failures=0, note="no_rpc_route", partial=False)
    pinned = pinned_head(chain_id, url)
    if pinned is None:
        # DEGRADED, not quiet. ``pinned_head`` returns None only when a read
        # failed or answered inconsistently, so this is an unanswered RPC — the
        # partial=True grounds. Reporting it healthy would let a dead route look
        # like a protocol that simply has no nodes, forever.
        return summarize(protocols=0, written=0, failures=0, note="no_pinned_head", partial=True)
    head, _ = pinned
    from_block = max(0, head - DEFAULT_EMITTER_PROBE_SPAN)
    fetch_logs = _log_fetcher(url, chain_id=chain_id)

    # Materialized before the loop commits: the pass commits per protocol, and
    # iterating a live result across those commits couples the two.
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
    """Run the restaking plane loop until *stop_event* is set."""
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
