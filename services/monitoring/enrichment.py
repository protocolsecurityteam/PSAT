"""Enrichment driver — adds decoded fields to what the taxonomy published.

Ground rules (§3.0, normative):

1. Enrichment adds fields to ``monitored_events.data``. It never changes
   ``event_type``, never changes ``witness_tier``, and never causes or
   suppresses a row insert. The taxonomy decides what may be published;
   enrichment describes what was published.
2. Every derived field is either a **witnessed fact** — decoded from on-chain
   bytes — published bare, or a **labeled heuristic**, published under
   ``data.heuristics.<name>`` with its basis and never promoted to a bare key.
3. A decode that does not complete publishes a reason, not a guess: every
   enrichment block carries a ``status``. An absent block means enrichment did
   not run; it never means "nothing to find".
4. Enrichment failure is never fatal. It runs inside try/except, logs, and
   leaves the row exactly as the taxonomy wrote it.
5. Historical rows are never enriched — ``_process_window`` already excludes
   ``data.historical`` events from the list this driver receives, so
   pre-enrollment backfill costs zero RPC.

**This module is the phase-1 skeleton.** ``ENRICHERS`` is empty, so the driver
is a no-op on every real row today; what is real is the *shape*: the registry,
the per-chain partition, the failure isolation, and — the part that is not an
optimization — the salience recompute in step 6. Enrichment changes the inputs
``assign_salience`` reads (``safe_exec.*``, ``correlated_events``), so the
mint-time assignment is provisional for enrichable types. Recomputing here,
inside the window transaction and BEFORE the commit that precedes
``_notify_committed_events``, is what guarantees the notifier and the frontend
only ever see the post-enrichment level.

Phase 2 fills ``ENRICHERS`` / ``NEEDS_TX`` and implements ``_fetch_txs``
(deduplicated ``eth_getTransactionByHash`` batch per chain, bounded by
``PSAT_SCAN_MAX_ENRICH_TX_PER_PASS``, over-budget hashes recorded as
``status: "over_budget"`` rather than silently dropped).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from db.models import MonitoredContract, MonitoredEvent
from services.monitoring.chain_rpc import chain_id_for
from services.monitoring.salience import stamp_salience

logger = logging.getLogger(__name__)

# Default budget for the per-pass transaction fetch. Read through
# ``unified_watcher._scan_int_env`` by the phase-2 fetcher; declared here so
# the knob's name and default live with the code that spends it.
ENRICH_TX_BUDGET_ENV = "PSAT_SCAN_MAX_ENRICH_TX_PER_PASS"
DEFAULT_MAX_ENRICH_TX_PER_PASS = 50


@dataclass(frozen=True)
class EnrichmentContext:
    """What an enricher may read besides its own event.

    ``txs`` maps ``tx_hash`` → the RPC transaction object. A hash MISSING from
    the map is a fetch that failed or was skipped over budget — never an
    assertion that the transaction does not exist — so an enricher that needs
    one and cannot find it publishes a status, not a guess.
    """

    chain: str
    chain_id: int
    session: Session
    txs: Mapping[str, dict] = field(default_factory=dict)
    over_budget: frozenset[str] = frozenset()


# An enricher returns the keys to MERGE into ``event.data``, or ``None`` when
# it has nothing to add. It must not mutate the event itself: the driver owns
# the merge, the change bookkeeping, and the salience recompute.
Enricher = Callable[[MonitoredEvent, MonitoredContract, EnrichmentContext], "dict[str, Any] | None"]

# event_type → enricher. Mirrors how ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` already
# keys behaviour off the canonical type. Empty in phase 1.
ENRICHERS: dict[str, Enricher] = {}

# Event types whose enricher wants the top-level transaction. Only these
# contribute hashes to the per-chain fetch, so an empty registry issues no RPC
# at all.
NEEDS_TX: frozenset[str] = frozenset()

# Invariant 8, enforced rather than documented: enrichment is ADDITIVE. These
# are the only ``data`` keys an enricher may write. The list is closed on
# purpose — ``witness_tier`` is read by ``notifier._may_notify`` and
# ``historical`` by the scanner's notify gate, so an enricher that returned
# either would move a side-effect decision from the taxonomy to a decoder. The
# driver is the natural chokepoint: every enricher's output passes through it,
# and a rejected key is logged rather than dropped in silence.
ENRICHABLE_KEYS: frozenset[str] = frozenset(
    {
        "safe_exec",
        "correlated_events",
        "correlated_scope",
        "caused_by",
        "heuristics",
        "salience",
        "salience_basis",
    }
)


def _fetch_txs(
    rpc_url: str | None,
    chain_id: int,
    tx_hashes: list[str],
) -> tuple[dict[str, dict], frozenset[str]]:
    """Transaction objects for *tx_hashes*, plus the hashes skipped over budget.

    Phase-1 stub: returns nothing and issues no RPC. Phase 2 implements this as
    one ``rpc_batch_request_classified`` per chain (passing ``chain_id`` so the
    URL↔chain guard the rest of monitoring uses applies here too), bounded by
    ``ENRICH_TX_BUDGET_ENV``. Per-slot failures are already classified there; a
    failed slot simply leaves its hash out of the returned map, which the
    context's contract reads as "not fetched", never as "no such transaction".
    """
    if not tx_hashes:
        return {}, frozenset()
    logger.debug(
        "Enrichment tx fetch not implemented; %d hash(es) left unfetched on chain %d",
        len(tx_hashes),
        chain_id,
    )
    return {}, frozenset()


def _admit_keys(
    produced: Mapping[str, Any],
    event: MonitoredEvent,
    mc: MonitoredContract,
) -> dict[str, Any]:
    """The subset of *produced* an enricher is allowed to write (invariant 8).

    A rejected key is logged, never dropped in silence: an enricher trying to
    write ``witness_tier`` or ``event_type`` is a bug about who decides what a
    row claims, and it must be visible as one rather than mysteriously
    ineffective.
    """
    admitted = {key: value for key, value in produced.items() if key in ENRICHABLE_KEYS}
    rejected = sorted(set(produced) - ENRICHABLE_KEYS)
    if rejected:
        logger.warning(
            "Enricher for %s on %s returned non-additive key(s) %s; refused",
            event.event_type,
            mc.address,
            ", ".join(rejected),
        )
    return admitted


def _contracts_for(session: Session, events: list[MonitoredEvent]) -> dict[Any, MonitoredContract]:
    """The ``MonitoredContract`` behind each event, in one query.

    Rows minted by ``_process_window`` are detached-then-added instances with
    no relationship loaded, so touching ``event.monitored_contract`` per event
    would emit one SELECT each.
    """
    ids = {event.monitored_contract_id for event in events if event.monitored_contract_id is not None}
    if not ids:
        return {}
    rows = session.execute(select(MonitoredContract).where(MonitoredContract.id.in_(ids))).scalars().all()
    return {mc.id: mc for mc in rows}


def enrich_events(
    session: Session,
    events: list[MonitoredEvent],
    rpc_by_chain: Mapping[str, str],
) -> None:
    """Run the registered enrichers over *events* and re-assign salience.

    Called inside the window transaction, after the ON-CONFLICT insert has
    decided which rows are real (no RPC spend on rows a concurrent scanner
    won) and before the commit that precedes ``_notify_committed_events``.

    Never raises: a failing enricher leaves its row exactly as the taxonomy
    wrote it (§3.0 rule 4), and a failure in the driver itself must not roll
    back a window whose rows are already correct.
    """
    if not events:
        return

    try:
        mc_by_id = _contracts_for(session, events)
    except Exception as exc:
        logger.warning(
            "Enrichment could not load monitored contracts; skipping the pass: %s",
            exc,
            extra={"exc_type": type(exc).__name__},
        )
        return

    # Partition by chain: the transaction fetch is per-chain (one RPC endpoint,
    # one chain_id guard) even though the enrichers are not.
    by_chain: dict[str, list[tuple[MonitoredEvent, MonitoredContract]]] = {}
    for event in events:
        mc = mc_by_id.get(event.monitored_contract_id)
        if mc is None:
            continue
        if not mc.chain:
            # No chain means no endpoint and no chain_id for the URL↔chain
            # guard. Defaulting one here would enrich a row against whatever
            # ethereum answered and publish it as this contract's decode.
            logger.warning(
                "Enrichment skipped for %s: the monitored contract names no chain",
                mc.address,
            )
            continue
        by_chain.setdefault(mc.chain, []).append((event, mc))

    changed: list[tuple[MonitoredEvent, MonitoredContract]] = []

    for chain, pairs in by_chain.items():
        # Deduplicated: two Safe executions in one transaction cost one fetch.
        hashes = sorted(
            {
                event.tx_hash
                for event, _mc in pairs
                if event.event_type in NEEDS_TX and isinstance(event.tx_hash, str) and event.tx_hash
            }
        )
        try:
            # chain_id_for is inside the guard with the fetch it feeds: this
            # function's contract is that it never raises, and chain_rpc is
            # free to become fail-loud on an unknown chain. An unresolvable
            # chain must cost that chain its enrichment, never the window.
            chain_id = chain_id_for(chain)
            txs, over_budget = _fetch_txs(rpc_by_chain.get(chain), chain_id, hashes)
        except Exception as exc:
            logger.warning(
                "Enrichment setup failed for %s; that chain is not enriched this pass: %s",
                chain,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
            continue

        ctx = EnrichmentContext(
            chain=chain,
            chain_id=chain_id,
            session=session,
            txs=txs,
            over_budget=over_budget,
        )

        for event, mc in pairs:
            enricher = ENRICHERS.get(event.event_type)
            if enricher is None:
                continue
            try:
                produced = enricher(event, mc, ctx)
            except Exception as exc:
                logger.warning(
                    "Enricher for %s on %s failed: %s",
                    event.event_type,
                    mc.address,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )
                continue
            if not produced:
                continue
            additive = _admit_keys(produced, event, mc)
            if not additive:
                continue
            merged = dict(event.data or {})
            merged.update(additive)
            event.data = merged
            flag_modified(event, "data")
            changed.append((event, mc))

    # Step 6 — the seam that is part of phase 2's contract, not an
    # optimization. Every row whose data an enricher touched (which includes
    # every row that gained ``correlated_events`` / ``caused_by``) is re-rated
    # here, before the commit and therefore before the notifier and the
    # frontend ever see it.
    for event, mc in changed:
        try:
            stamp_salience(session, event, mc)
        except Exception as exc:
            logger.warning(
                "Salience recompute failed for %s on %s: %s",
                event.event_type,
                mc.address,
                exc,
                extra={"exc_type": type(exc).__name__},
            )
