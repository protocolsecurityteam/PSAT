"""Node enumeration for the restaking plane: one event fold, one cursor.

EtherFiNode instances are BeaconProxies with no ``contracts`` rows, so they are enumerated from ``PubkeyLinked(bytes32
indexed pubkeyHash, address indexed etherFiNode, uint256 indexed legacyId, bytes pubkey)`` (``topics[2]`` is the node).
``EigenPodManager.PodDeployed`` is EigenLayer-wide and BeaconProxy creation emits nothing.

The fold proves a node exists, never that one doesn't, so the node set is a lower bound (``node_set_completeness =
'not_determined'``). Emitters are found by log witness (one ``eth_getLogs`` over the protocol's addresses), not by
contract name.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import Any

from eth_utils.crypto import keccak
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from db.models import ENROLLMENT_BASIS_TRACKED_TOPICS, Contract, IndexedEventLog
from services.clients.etherscan import get_contract_creation_block
from workers.event_log_indexer import enroll_event_cursor

logger = logging.getLogger(__name__)

PUBKEY_LINKED_SIGNATURE = "PubkeyLinked(bytes32,address,uint256,bytes)"
# Derived, not a literal: a mistyped topic would silently fold nothing.
PUBKEY_LINKED_TOPIC0 = "0x" + keccak(text=PUBKEY_LINKED_SIGNATURE).hex()

# Asserted by code, not a descriptor, so it takes the ``tracked_topics`` coverage ceiling: never complete, never
# licensing absence.
RESTAKING_FOLD_ENROLLMENT_BASIS = ENROLLMENT_BASIS_TRACKED_TOPICS

# A shorter window only finds fewer emitters, the safe direction.
DEFAULT_EMITTER_PROBE_SPAN = 200_000

LogFetcher = Callable[[list[str], str, int, int], Sequence[Any]]


def discover_emitters(
    addresses: Sequence[str],
    *,
    from_block: int,
    to_block: int,
    fetch_logs: LogFetcher,
) -> set[str]:
    """The subset of ``addresses`` that emitted the fold's topic, in one request.

    Fetch failures propagate: a silently narrowed emitter set would read as "no nodes".
    """
    if not addresses:
        return set()
    logs = fetch_logs([a.lower() for a in addresses], PUBKEY_LINKED_TOPIC0, from_block, to_block)
    emitters: set[str] = set()
    for log in logs:
        address = log.get("address") if isinstance(log, dict) else getattr(log, "address", None)
        if isinstance(address, str) and len(address) == 42:
            emitters.add(address.lower())
    return emitters


def protocol_contract_addresses(session: Session, *, protocol_id: int) -> list[str]:
    """Every distinct address this protocol owns, lower-cased, proxies and implementations both: the log witness
    decides which emits (the manager's row is keyed at the implementation, its logs at the proxy).
    """
    rows = session.execute(
        select(distinct(func.lower(Contract.address))).where(Contract.protocol_id == protocol_id)
    ).all()
    return [row[0] for row in rows if isinstance(row[0], str)]


def enroll_restaking_fold(
    session: Session,
    *,
    chain_id: int,
    emitters: Sequence[str],
) -> int:
    """Enroll one cursor per proven emitter at ``creation - 1``; returns cursors created.

    An unresolvable creation block skips enrollment for a later retry rather than seeding at genesis.

    Known cost: the EtherFiNodesManager proxy already has two warm cursors, and a cold cursor drags their shared window
    back ~8.5M blocks (about one pass of windows). They don't regress, but stop advancing meanwhile while reporting
    complete. Accepted as bounded.
    """
    created = 0
    for emitter in emitters:
        address = emitter.lower()
        try:
            creation = get_contract_creation_block(address, chain_id=chain_id)
        except Exception as exc:
            logger.warning(
                "restaking fold: creation-block lookup failed; deferring enrollment",
                extra={"address": address, "chain_id": chain_id, "exc_type": type(exc).__name__},
            )
            continue
        if not isinstance(creation, int) or creation <= 0:
            continue
        if enroll_event_cursor(
            session,
            chain_id=chain_id,
            event_address=address,
            topic0=PUBKEY_LINKED_TOPIC0,
            start_block=creation - 1,
            enrollment_basis=RESTAKING_FOLD_ENROLLMENT_BASIS,
        ):
            created += 1
    return created


def node_addresses_from_fold(session: Session, *, chain_id: int, event_address: str | None = None) -> list[str]:
    """Distinct node addresses folded so far, sorted. A lower bound: empty means "none folded yet".

    Pass ``event_address`` when attributing results to an enumerating contract; the chain-wide result mixes every
    emitter's nodes.
    """
    filters = [
        IndexedEventLog.chain_id == chain_id,
        func.lower(IndexedEventLog.topic0) == PUBKEY_LINKED_TOPIC0,
    ]
    if event_address is not None:
        filters.append(func.lower(IndexedEventLog.event_address) == event_address.lower())
    rows = session.execute(select(IndexedEventLog.topics).where(*filters)).all()
    nodes: set[str] = set()
    for (topics,) in rows:
        # A short topic list is skipped; the node can't be read from anywhere else.
        if isinstance(topics, list) and len(topics) >= 3 and isinstance(topics[2], str) and len(topics[2]) == 66:
            nodes.add("0x" + topics[2][-40:].lower())
    return sorted(nodes)


__all__ = [
    "DEFAULT_EMITTER_PROBE_SPAN",
    "PUBKEY_LINKED_SIGNATURE",
    "PUBKEY_LINKED_TOPIC0",
    "RESTAKING_FOLD_ENROLLMENT_BASIS",
    "discover_emitters",
    "enroll_restaking_fold",
    "node_addresses_from_fold",
    "protocol_contract_addresses",
]
