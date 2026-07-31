"""Node enumeration for the restaking plane: one event fold, one cursor.

The live EtherFiNode instances are BeaconProxy deployments and are not
``contracts`` rows — measured: zero rows for the probed node and its pod. They
are enumerated instead from a single event at a single address:

    PubkeyLinked(bytes32 indexed pubkeyHash, address indexed etherFiNode,
                 uint256 indexed legacyId, bytes pubkey)

``topics[2]`` is the node. Measured at block 25643300: 33 logs and **26 distinct
nodes** in the preceding 200,000 blocks alone.

**Why not the obvious sources.** ``EigenPodManager.PodDeployed`` is
EigenLayer-wide (``numPods()`` = 34,704 at that block) and is not scoped to any
protocol; BeaconProxy creation emits no event at all.

**What the fold can and cannot prove.** It proves a node EXISTS. It can never
prove one does not: its cursor is asserted by this code rather than derived from
a descriptor, so it carries the incomplete-coverage ceiling and licenses no
earned negative. The node set is a LOWER BOUND, which is why every record
carries ``node_set_completeness = 'not_determined'``.

**Emitter discovery is a log witness, not a name and not an ABI declaration.**
The schema stores no ABI, and selecting the emitter by ``contract_name`` would
be exactly the name inference this project bans. Instead one ``eth_getLogs``
carries the whole protocol's contract addresses and the topic filter, and the
emitters are the addresses that actually appear in the results — a positive
witness that this address emitted this event, which is strictly stronger than a
declaration that it could.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import Any

from eth_utils.crypto import keccak
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from db.models import Contract, IndexedEventLog
from utils.etherscan import get_contract_creation_block
from workers.event_log_indexer import enroll_event_cursor

logger = logging.getLogger(__name__)

PUBKEY_LINKED_SIGNATURE = "PubkeyLinked(bytes32,address,uint256,bytes)"
# Derived, never written as a literal: a mistyped topic silently folds nothing
# and the absence would look like "this protocol has no nodes".
PUBKEY_LINKED_TOPIC0 = "0x" + keccak(text=PUBKEY_LINKED_SIGNATURE).hex()

# The basis this cursor's enrollment carries. It is asserted by code rather than
# read off a descriptor, so it takes the same coverage ceiling as the
# ``tracked_topics`` surface: enrolled, never complete, never licensing an
# absence claim. Named here so the column added by the event-cursor coverage
# unit can take this value at assembly without a second literal appearing.
RESTAKING_FOLD_ENROLLMENT_BASIS = "tracked_topics_asserted"

# How far back the emitter probe looks. A shorter window can only find FEWER
# emitters, which can only shrink the node set — the safe direction, and already
# covered by ``node_set_completeness``.
DEFAULT_EMITTER_PROBE_SPAN = 200_000

LogFetcher = Callable[[list[str], str, int, int], Sequence[Any]]


def discover_emitters(
    addresses: Sequence[str],
    *,
    from_block: int,
    to_block: int,
    fetch_logs: LogFetcher,
) -> set[str]:
    """The subset of ``addresses`` that actually emitted the fold's topic.

    One request: ``eth_getLogs`` takes an address ARRAY, so the whole protocol is
    one filter rather than one probe per contract.

    A fetch failure surfaces as an exception from ``fetch_logs`` and is left to
    the caller — an emitter set silently narrowed by a transport error would
    enroll nothing and read downstream as "this protocol has no nodes".
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
    """Every distinct address this protocol owns, lower-cased.

    Both proxy and implementation rows are included: which of the two emits is
    exactly what the log witness decides, and pre-filtering to one of them would
    reintroduce the implementation-vs-proxy keying defect — the manager's
    ``contracts`` row is keyed at the implementation while the logs are emitted
    at the proxy.
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
    """Enroll one cursor per proven emitter, seeded one block below creation.

    Returns the number of cursors newly created.

    The seed is ``creation - 1`` so the first window opens at the deploy block.
    Where the creation block cannot be resolved the cursor is NOT enrolled and a
    later pass retries: seeding at genesis on a transient lookup failure would
    pin the cursor to a full-chain backfill.

    **Stated deferral (measured).** The EtherFiNodesManager proxy
    ``0x8b71140ad2e5d1e7018d2a7f8a288bd3cd38916f`` already carries two warm
    cursors at block 25641245 with ``backfill_complete = true``, on
    ``UserAllowedForwardedEigenpodCallsUpdated`` and
    ``UserAllowedForwardedExternalCallsUpdated`` — the forwarded-call allowlist
    topics. ``index_event_group_step`` takes ``start = min(last_indexed_block)``
    over the group's ACTIVE cursors, so adding a cold cursor seeded at 17174452
    (proxy creation 17174453) drags the shared window back over 8,468,848 blocks
    = 17 windows at a 500,000-block span, roughly one pass at the 50-window
    per-cursor budget. The siblings do NOT regress — the advance is guarded by
    ``window_end > last`` — and ``backfill_complete`` is cleared only by a reorg
    rewind. The cost is that those two cursors stop ADVANCING for that period
    while still reporting themselves complete: the stale-warm shape, accepted
    here as a bounded, measured deferral rather than papered over with a later
    seed that no read witnesses.
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
    """Distinct node addresses folded so far, sorted.

    A LOWER BOUND on the node set, never the set. Callers publish
    ``node_set_completeness = 'not_determined'`` beside anything derived from it,
    and an empty result means "none folded yet", never "this protocol has no
    nodes".

    ``event_address`` narrows the fold to one proven emitter. A caller that
    attributes what it publishes to an enumerating contract must pass it: the
    chain-wide result mixes every emitter's nodes, so pinning a single
    ``manager_contract_id`` over it would name a contract that did not enumerate
    the node — provenance by proximity rather than by witness.
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
        # ``topics[2]`` is the indexed node. A log whose topic list is short is
        # skipped rather than guessed at: there is no other position the node
        # could be read from.
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
