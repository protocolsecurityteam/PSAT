"""Deployer creation enumeration + coverage honesty (spec §3.3 Class B).

The single Class-B evidence path: the worker-side ladder wire
(``workers/discovery.py``) and the gate-side fixpoint
(``membership_gate.evaluate``'s ``deployer_enumerator``) both consume
``enumerate_with_coverage``, so the two can never disagree on whether an
enumeration licenses exclusivity.

Etherscan attributes a contract to its creation tx's ORIGIN, so the full
creation history of an EOA is its direct creations (``txlist`` entries with an
empty ``to``) UNIONED with the ``create``/``create2`` frames inside its own
sent transactions (``txlistinternal&txhash`` per tx — the by-ADDRESS form
indexes internal frames under the factory, never the originating EOA, and
must not be used here).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Sequence

from sqlalchemy import func, select

from db.models import Contract
from services.clients import etherscan
from services.clients.rpc import chain_id_for_chain_name
from utils.chains import supported_chain_ids
from utils.logging import record_degraded

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from services.discovery.membership_gate import DeployerEnumerator

logger = logging.getLogger(__name__)

#: Cap on one chain's COMBINED creation set (direct ∪ internal) and on each
#: Etherscan ``txlist`` window. A window that fills, or a combined set at the
#: cap, is a truncation, never a complete creation history →
#: ``history_complete=False`` → Class C (spec §3.3).
DEPLOYER_ENUMERATION_CAP = 10_000

#: Per-chain bound on the ``txlistinternal&txhash`` calls one enumeration may
#: spend resolving internal creations. Exceeding it leaves the chain's history
#: unresolvable within budget → the chain stays out of scope and
#: ``history_complete=False`` — a half-enumerated chain must never claim
#: completeness. (Non-empty responses — and mature empties — are PG-cached, so
#: a re-enumeration of the same EOA re-pays little beyond the ``txlist``
#: window.)
INTERNAL_RESOLUTION_TX_BUDGET = 1_000

#: Minimum ``confirmations`` (head − block, straight off the ``txlist``
#: record) before an EMPTY per-txhash internal-trace answer may be frozen in
#: the PG cache: Etherscan's trace indexing lags the head, so a fresh tx's
#: "no internal frames" can be a transient false-empty that would permanently
#: delete a CREATE frame from the EOA's history — ~an hour of mainnet blocks
#: sits comfortably past the observed lag. Non-empty answers are immutable
#: once present and cache unconditionally.
INTERNAL_TRACE_CACHE_MIN_CONFIRMATIONS = 300


def _tx_mature(tx: dict) -> bool:
    """Whether an empty internal-trace answer for *tx* would be a permanent
    fact rather than indexing lag. Only a positive ``confirmations`` reading
    past the floor licenses the cache write — a missing or unparseable field
    is not_determined, never mature."""
    raw = tx.get("confirmations")
    if not isinstance(raw, (str, int)):
        return False
    try:
        return int(raw) >= INTERNAL_TRACE_CACHE_MIN_CONFIRMATIONS
    except ValueError:
        return False


@dataclass(frozen=True)
class DeployerCreation:
    """One enumerated creation. ``factory`` is the CREATE/CREATE2 frame's
    ``from`` for an internal creation; ``None`` = a direct EOA-sent creation,
    never "factory unknown" (an unresolvable frame fails the whole chain)."""

    address: str
    chain_id: int
    factory: str | None = None


def _internal_creations(
    addr: str, chain_id: int, sent_calls: Sequence[tuple[str, bool]]
) -> list[DeployerCreation] | None:
    """CREATE/CREATE2 frames inside the EOA's own sent txs (``(tx_hash,
    mature)`` pairs), or ``None`` when any lookup fails — the chain's history
    is then unresolvable and must not claim completeness. An empty answer is
    frozen in the PG cache only for a mature tx (``cache_empty``)."""
    found: list[DeployerCreation] = []
    for tx_hash, mature in sent_calls:
        try:
            data = etherscan.get(
                "account",
                "txlistinternal",
                chain_id=chain_id,
                empty_result_ok=True,
                cache_empty=mature,
                txhash=tx_hash,
            )
        except Exception as exc:
            logger.warning(
                "deployer txlistinternal resolution failed",
                extra={"deployer": addr, "chain_id": chain_id, "txhash": tx_hash, "exc_type": type(exc).__name__},
            )
            record_degraded(
                phase="deployer_enumeration_internal",
                exc=exc,
                context={"deployer": addr, "chain_id": chain_id, "txhash": tx_hash},
            )
            return None
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list):
            return None
        for frame in result:
            if not isinstance(frame, dict) or frame.get("isError") == "1":
                continue
            target = frame.get("contractAddress")
            factory = frame.get("from")
            if (
                str(frame.get("type", "")).startswith("create")
                and isinstance(target, str)
                and target
                and isinstance(factory, str)
                and factory
            ):
                found.append(DeployerCreation(address=target.lower(), chain_id=chain_id, factory=factory.lower()))
    return found


def enumerate_deployer_creations(deployer: str) -> tuple[list[DeployerCreation], list[int], bool]:
    """(creations, enumerated chain scope, history_complete) for one EOA,
    enumerated on every enabled chain (EOAs are chain-agnostic, spec
    §3.3/§4.3). The scope is recorded so the registry evidence names WHAT was
    enumerated, never a bare ``complete: True``.

    Completeness is POSITIVE evidence: any chain whose ``txlist`` fails, whose
    window or combined creation set hits :data:`DEPLOYER_ENUMERATION_CAP`,
    whose sent-tx count exceeds :data:`INTERNAL_RESOLUTION_TX_BUDGET`, or
    whose internal-frame resolution fails yields ``history_complete=False``
    with that chain out of scope — and an empty enumeration can never license
    exclusivity (it is also the factory-address shape: a contract "deployer"
    sends no transactions of its own).
    """
    addr = deployer.lower()
    created: dict[tuple[str, int], DeployerCreation] = {}
    scope: list[int] = []
    complete = True
    for chain_id in sorted(supported_chain_ids()):
        try:
            data = etherscan.get(
                "account",
                "txlist",
                chain_id=chain_id,
                empty_result_ok=True,
                address=addr,
                startblock="0",
                endblock="99999999",
                sort="asc",
            )
        except Exception as exc:
            logger.warning(
                "deployer txlist enumeration failed",
                extra={"deployer": addr, "chain_id": chain_id, "exc_type": type(exc).__name__},
            )
            record_degraded(
                phase="deployer_enumeration",
                exc=exc,
                context={"deployer": addr, "chain_id": chain_id},
            )
            complete = False
            continue
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list):
            complete = False
            continue
        if len(result) >= DEPLOYER_ENUMERATION_CAP:
            complete = False
            continue
        chain_created: list[DeployerCreation] = []
        sent_calls: list[tuple[str, bool]] = []
        for tx in result:
            if not isinstance(tx, dict):
                continue
            target = tx.get("contractAddress")
            if not tx.get("to") and isinstance(target, str) and target:
                chain_created.append(DeployerCreation(address=target.lower(), chain_id=chain_id))
                continue
            # Only an EOA-SENT, mined-successful call can hold an internal
            # creation attributed to this EOA; ``txlist`` also lists received
            # txs, whose creations belong to their own origins.
            tx_hash = tx.get("hash")
            if (
                (tx.get("from") or "").lower() == addr
                and tx.get("to")
                and tx.get("isError") != "1"
                and isinstance(tx_hash, str)
                and tx_hash
            ):
                sent_calls.append((tx_hash, _tx_mature(tx)))
        if len(sent_calls) > INTERNAL_RESOLUTION_TX_BUDGET:
            logger.warning(
                "deployer internal-resolution budget exceeded",
                extra={"deployer": addr, "chain_id": chain_id, "sent_calls": len(sent_calls)},
            )
            complete = False
            continue
        internal = _internal_creations(addr, chain_id, sent_calls)
        if internal is None:
            complete = False
            continue
        chain_created.extend(internal)
        if len({c.address for c in chain_created}) >= DEPLOYER_ENUMERATION_CAP:
            complete = False
            continue
        scope.append(chain_id)
        for creation in chain_created:
            created.setdefault((creation.address, creation.chain_id), creation)
    creations = sorted(created.values(), key=lambda c: (c.chain_id, c.address))
    if not creations:
        return [], scope, False
    return creations, scope, complete


def enumeration_coverage_gap(
    session: Session, *, deployer: str, created: set[str], scope_chain_ids: set[int]
) -> str | None:
    """Class B soundness check: every KNOWN creation of the EOA — any contracts
    row recording it as deployer, member or candidate, any protocol — must lie
    on an enumerated chain AND appear in the enumerated creation set. A gap is
    an incomplete enumeration (→ Class C), whether from chain scope or from a
    ``contractCreator``-vs-``txlist`` attribution mismatch."""
    rows = session.execute(select(Contract.address, Contract.chain).where(func.lower(Contract.deployer) == deployer))
    for address, chain in rows:
        chain_id = chain_id_for_chain_name(chain or "ethereum")
        if chain_id is None or chain_id not in scope_chain_ids:
            return f"known_creation_on_unenumerated_chain:{(chain or 'ethereum').lower()}"
        if (address or "").lower() not in created:
            return f"known_creation_missing_from_enumeration:{(address or '').lower()}"
    return None


def enumerate_with_coverage(
    session: Session, deployer: str
) -> tuple[list[DeployerCreation], list[int], bool, str | None]:
    """Enumeration with the coverage refusal folded into ``history_complete``
    — the one place a Class-B-licensing enumeration verdict is minted.

    The fourth element distinguishes the two incompleteness shapes (F3): a
    COVERAGE GAP (the raw windows were complete, yet a known creation is
    missing or off-scope — positive counterevidence against a standing Class-B
    license) versus budget/cap/wire incompleteness (absence of evidence,
    which never revokes)."""
    addr = deployer.lower()
    creations, scope, complete = enumerate_deployer_creations(addr)
    gap: str | None = None
    if complete:
        gap = enumeration_coverage_gap(
            session, deployer=addr, created={c.address for c in creations}, scope_chain_ids=set(scope)
        )
        if gap is not None:
            logger.warning(
                "Class B refused: enumeration coverage gap",
                extra={"deployer": addr, "gap": gap},
            )
            complete = False
    return creations, scope, complete, gap


def creation_factories(creations: Sequence[DeployerCreation]) -> dict[str, str]:
    """address → factory for the factory-mediated creations in *creations*."""
    return {c.address: c.factory for c in creations if c.factory}


def session_deployer_enumerator(session: Session) -> DeployerEnumerator:
    """Gate-facing adapter (``membership_gate.DeployerEnumerator``): the scope
    stays internal to the coverage check; the gate consumes only what §3.3
    needs — the creation set and whether it licenses exclusivity. Coverage
    gaps are recorded on the adapter's ``coverage_gaps`` and the full creation
    records (chain + factory attribution) on ``creations`` (the same
    attribute-channel pattern as the re-earn budget's ``exhausted``) so the
    fixpoint can treat gaps as positive counterevidence (F3) and feed the
    member-factory mapping."""
    return _SessionEnumerator(session)


class _SessionEnumerator:
    def __init__(self, session: Session) -> None:
        self._session = session
        self.coverage_gaps: dict[str, str] = {}
        self.creations: dict[str, tuple[DeployerCreation, ...]] = {}

    def __call__(self, deployer: str) -> tuple[Sequence[str], bool]:
        creations, _scope, complete, gap = enumerate_with_coverage(self._session, deployer)
        addr = deployer.lower()
        if gap is not None:
            self.coverage_gaps[addr] = gap
        self.creations[addr] = tuple(creations)
        return sorted({c.address for c in creations}), complete
