"""Deployer creation enumeration with coverage honesty (Class B).

The single Class-B evidence path, used by both ``workers/discovery.py`` and ``membership_gate.evaluate``'s
``deployer_enumerator``, so they can't disagree.

Etherscan attributes a contract to its creation tx's origin, so an EOA's full history is its direct creations
(``txlist`` entries with empty ``to``) plus CREATE/CREATE2 frames inside its own txs (``txlistinternal&txhash`` per tx;
the by-address form indexes frames under the factory and must not be used).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Sequence

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from db.models import (
    DEPLOYER_ENUMERATION_CAP_REACHED,
    DEPLOYER_ENUMERATION_COMPLETE,
    DEPLOYER_ENUMERATION_INTERNAL_BUDGET_EXCEEDED,
    DEPLOYER_ENUMERATION_TIME_BUDGET_EXCEEDED,
    Contract,
    ContractCreationWitness,
    DeployerChainEnumeration,
)
from services.clients import etherscan
from services.clients.rpc import chain_id_for_chain_name
from utils.chains import supported_chain_ids
from utils.logging import record_degraded

if TYPE_CHECKING:
    from services.discovery.membership_gate import DeployerEnumerator

logger = logging.getLogger(__name__)

# Cap on one chain's combined creation set and each ``txlist`` window. Hitting it is truncation, so
# ``history_complete=False`` and Class C.
DEPLOYER_ENUMERATION_CAP = 10_000

# Per-chain budget for ``txlistinternal&txhash`` calls. Exceeding it drops the chain from scope and makes the history
# incomplete.
INTERNAL_RESOLUTION_TX_BUDGET = 1_000


# Wall-clock budget for one EOA's enumeration across chains. A chain unfinished at the deadline is incomplete, like one
# past the internal-resolution budget. Mature internal traces are PG-cached, so a retry resumes faster.
def enumeration_time_budget_s() -> float:
    raw = os.getenv("PSAT_DEPLOYER_ENUMERATION_BUDGET_S", "120")
    try:
        budget = float(raw)
    except ValueError as exc:
        raise ValueError(f"PSAT_DEPLOYER_ENUMERATION_BUDGET_S must be a positive number, got {raw!r}") from exc
    if budget <= 0:
        raise ValueError(f"PSAT_DEPLOYER_ENUMERATION_BUDGET_S must be a positive number, got {budget}")
    return budget


# A chain that ran out of time is retried after this long; nothing about the EOA says when a retry would finish.
TIME_BUDGET_RETRY_S = 3_600

# Confirmations required before caching an empty internal-trace answer: Etherscan's trace index lags the head, and a
# cached false-empty would permanently erase a CREATE frame. Non-empty answers cache immediately.
INTERNAL_TRACE_CACHE_MIN_CONFIRMATIONS = 300


def _tx_mature(tx: dict) -> bool:
    """Whether an empty internal-trace answer for *tx* is permanent.

    Only a positive ``confirmations`` past the floor counts; missing or unparseable is not mature.
    """
    raw = tx.get("confirmations")
    if not isinstance(raw, (str, int)):
        return False
    try:
        return int(raw) >= INTERNAL_TRACE_CACHE_MIN_CONFIRMATIONS
    except ValueError:
        return False


@dataclass(frozen=True)
class DeployerCreation:
    """One enumerated creation.

    ``factory`` is the CREATE frame's ``from`` for internal creations; ``None`` means a direct EOA creation
    (unresolvable frames fail the whole chain).
    """

    address: str
    chain_id: int
    factory: str | None = None


class _TimeBudgetExceeded(Exception):
    pass


def _check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise _TimeBudgetExceeded


def _internal_creations(
    addr: str, chain_id: int, sent_calls: Sequence[tuple[str, bool]], deadline: float | None = None
) -> list[DeployerCreation] | None:
    """CREATE/CREATE2 frames in the EOA's own txs, or ``None`` if any lookup fails (then the chain can't claim
    completeness). Empty answers are cached only for mature txs. Raises ``_TimeBudgetExceeded`` past *deadline*.
    """
    found: list[DeployerCreation] = []

    for tx_hash, mature in sent_calls:
        _check_deadline(deadline)
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


@dataclass(frozen=True)
class _ChainEnumeration:
    """One chain's enumeration. ``outcome`` None is a failed call: never kept, and never complete."""

    outcome: str | None
    creations: tuple[DeployerCreation, ...] = ()
    observed_count: int | None = None
    settled_through_block: int | None = None


def _tx_block(tx: dict) -> int | None:
    raw = tx.get("blockNumber")
    if isinstance(raw, bool) or not isinstance(raw, (str, int)):
        return None
    try:
        block = int(raw, 16) if isinstance(raw, str) and raw.startswith("0x") else int(raw)
    except ValueError:
        return None
    return block if block >= 0 else None


def _settled_through_block(txs: Sequence[dict], sent: Sequence[dict]) -> int | None:
    """The block up to which every creation by the EOA is in the enumeration.

    ``txlist`` is ascending and complete up to its last entry, but an immature tx's internal trace may still be lagging
    (a missing CREATE frame), so the settled range ends before the first one.
    """
    blocks = [_tx_block(tx) for tx in txs]
    if not blocks or any(block is None for block in blocks):
        return None
    settled = max(b for b in blocks if b is not None)
    for tx in sent:
        if not _tx_mature(tx):
            block = _tx_block(tx)
            if block is None:
                return None
            settled = min(settled, block - 1)
    return settled if settled >= 0 else None


def _enumerate_chain(addr: str, chain_id: int, deadline: float | None) -> _ChainEnumeration:
    try:
        _check_deadline(deadline)
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
            return _ChainEnumeration(outcome=None)
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list):
            return _ChainEnumeration(outcome=None)
        if len(result) >= DEPLOYER_ENUMERATION_CAP:
            return _ChainEnumeration(outcome=DEPLOYER_ENUMERATION_CAP_REACHED, observed_count=len(result))
        txs = [tx for tx in result if isinstance(tx, dict)]
        chain_created: list[DeployerCreation] = []
        sent: list[dict] = []
        for tx in txs:
            target = tx.get("contractAddress")
            if not tx.get("to") and isinstance(target, str) and target:
                chain_created.append(DeployerCreation(address=target.lower(), chain_id=chain_id))
                continue
            # Only EOA-sent successful txs can hold its internal creations; ``txlist`` also lists received txs.
            tx_hash = tx.get("hash")
            if (
                (tx.get("from") or "").lower() == addr
                and tx.get("to")
                and tx.get("isError") != "1"
                and isinstance(tx_hash, str)
                and tx_hash
            ):
                sent.append(tx)
        if len(sent) > INTERNAL_RESOLUTION_TX_BUDGET:
            logger.warning(
                "deployer internal-resolution budget exceeded",
                extra={"deployer": addr, "chain_id": chain_id, "sent_calls": len(sent)},
            )
            return _ChainEnumeration(outcome=DEPLOYER_ENUMERATION_INTERNAL_BUDGET_EXCEEDED, observed_count=len(sent))
        internal = _internal_creations(addr, chain_id, [(tx["hash"], _tx_mature(tx)) for tx in sent], deadline)
    except _TimeBudgetExceeded as exc:
        budget_s = enumeration_time_budget_s()
        logger.warning(
            "deployer enumeration time budget exceeded",
            extra={"deployer": addr, "chain_id": chain_id, "budget_s": budget_s},
        )
        record_degraded(
            phase="deployer_enumeration_time_budget",
            exc=exc,
            context={"deployer": addr, "chain_id": chain_id, "budget_s": budget_s},
        )
        return _ChainEnumeration(outcome=DEPLOYER_ENUMERATION_TIME_BUDGET_EXCEEDED)
    if internal is None:
        return _ChainEnumeration(outcome=None)
    chain_created.extend(internal)
    distinct = len({c.address for c in chain_created})
    if distinct >= DEPLOYER_ENUMERATION_CAP:
        return _ChainEnumeration(outcome=DEPLOYER_ENUMERATION_CAP_REACHED, observed_count=distinct)
    unique: dict[str, DeployerCreation] = {}
    for creation in chain_created:
        unique.setdefault(creation.address, creation)
    return _ChainEnumeration(
        outcome=DEPLOYER_ENUMERATION_COMPLETE,
        creations=tuple(unique.values()),
        settled_through_block=_settled_through_block(txs, sent),
    )


def _from_memo(row: DeployerChainEnumeration) -> _ChainEnumeration:
    creations = tuple(
        DeployerCreation(address=str(address), chain_id=row.chain_id, factory=factory if factory else None)
        for address, factory in (row.creations or [])
    )
    return _ChainEnumeration(
        outcome=row.outcome,
        creations=creations,
        observed_count=row.observed_count,
        settled_through_block=row.settled_through_block,
    )


def _memo_stands(session: Session, row: DeployerChainEnumeration) -> bool:
    """Whether a kept enumeration still answers for its EOA and chain.

    The limit outcomes are monotone (an EOA's history only grows), so they stand while the current limit is still
    crossed. A complete one stands until some row names the EOA as deployer of a contract on that chain that it
    doesn't list and that wasn't created inside its settled range: only a newer creation can change it.
    """
    if row.outcome == DEPLOYER_ENUMERATION_INTERNAL_BUDGET_EXCEEDED:
        return row.observed_count is not None and row.observed_count > INTERNAL_RESOLUTION_TX_BUDGET
    if row.outcome == DEPLOYER_ENUMERATION_CAP_REACHED:
        return row.observed_count is not None and row.observed_count >= DEPLOYER_ENUMERATION_CAP
    if row.outcome == DEPLOYER_ENUMERATION_TIME_BUDGET_EXCEEDED:
        age = datetime.now(timezone.utc) - row.enumerated_at
        return age.total_seconds() < TIME_BUDGET_RETRY_S
    if row.outcome != DEPLOYER_ENUMERATION_COMPLETE:
        return False
    listed = {str(address) for address, _factory in (row.creations or [])}
    known = session.execute(
        select(Contract.address, Contract.chain).where(func.lower(Contract.deployer) == row.deployer)
    ).all()
    for address, chain in known:
        addr = (address or "").lower()
        if chain_id_for_chain_name(chain or "ethereum") != row.chain_id or addr in listed:
            continue
        witness = session.get(ContractCreationWitness, (row.chain_id, addr))
        created = witness.creation_block if witness is not None else None
        if created is None or row.settled_through_block is None or created > row.settled_through_block:
            return False
    return True


def _keep(session: Session, addr: str, chain_id: int, outcome: _ChainEnumeration) -> None:
    """Upsert the chain's outcome on its own short transaction, so it is visible to other workers at once and
    survives the caller's rollback. A failed write only costs a later re-enumeration.
    """
    values = {
        "chain_id": chain_id,
        "deployer": addr,
        "outcome": outcome.outcome,
        "creations": (
            [[c.address, c.factory] for c in outcome.creations]
            if outcome.outcome == DEPLOYER_ENUMERATION_COMPLETE
            else None
        ),
        "observed_count": outcome.observed_count,
        "settled_through_block": outcome.settled_through_block,
    }
    stmt = pg_insert(DeployerChainEnumeration).values(**values)
    stmt = stmt.on_conflict_do_update(
        index_elements=["chain_id", "deployer"],
        set_={
            **{k: stmt.excluded[k] for k in values if k not in ("chain_id", "deployer")},
            "enumerated_at": func.now(),
        },
    )
    try:
        with Session(bind=session.get_bind()) as writer:
            writer.execute(stmt)
            writer.commit()
    except Exception as exc:
        record_degraded(phase="deployer_enumeration_keep", exc=exc, context={"deployer": addr, "chain_id": chain_id})
        logger.warning(
            "deployer enumeration not kept",
            extra={"deployer": addr, "chain_id": chain_id, "exc_type": type(exc).__name__},
        )


def _chain_enumeration(session: Session | None, addr: str, chain_id: int, deadline: float | None) -> _ChainEnumeration:
    if session is not None:
        row = session.get(DeployerChainEnumeration, (chain_id, addr), populate_existing=True)
        if row is not None and _memo_stands(session, row):
            return _from_memo(row)
    outcome = _enumerate_chain(addr, chain_id, deadline)
    if session is not None and outcome.outcome is not None:
        _keep(session, addr, chain_id, outcome)
    return outcome


def enumerate_deployer_creations(
    deployer: str, session: Session | None = None
) -> tuple[list[DeployerCreation], list[int], bool]:
    """``(creations, enumerated chain scope, history_complete)`` for one EOA across enabled chains (EOAs are
    chain-agnostic). The scope is recorded so evidence says what was enumerated.

    Completeness must be positive: a failed ``txlist``, a cap hit, an exceeded internal or time budget, or a failed
    internal lookup drops that chain and sets ``history_complete=False``. An empty enumeration never licenses
    exclusivity (it's also what a factory looks like). With a *session*, each chain's kept outcome is reused while it
    stands (``_memo_stands``).
    """
    addr = deployer.lower()
    created: dict[tuple[str, int], DeployerCreation] = {}
    scope: list[int] = []
    complete = True
    deadline = time.monotonic() + enumeration_time_budget_s()
    for chain_id in sorted(supported_chain_ids()):
        outcome = _chain_enumeration(session, addr, chain_id, deadline)
        if outcome.outcome != DEPLOYER_ENUMERATION_COMPLETE:
            complete = False
            continue
        scope.append(chain_id)
        for creation in outcome.creations:
            created.setdefault((creation.address, creation.chain_id), creation)
    creations = sorted(created.values(), key=lambda c: (c.chain_id, c.address))
    if not creations:
        return [], scope, False
    return creations, scope, complete


def enumeration_coverage_gap(
    session: Session, *, deployer: str, created: set[str], scope_chain_ids: set[int]
) -> str | None:
    """Class B soundness: every known creation of the EOA (any contracts row naming it as deployer) must be on an
    enumerated chain and in the enumerated set. A gap, from scope or attribution mismatch, means incomplete (Class
    C).
    """
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
    """Enumeration with the coverage check folded into ``history_complete``; the one place a Class-B verdict is
    minted.

    The fourth element separates a coverage gap (complete windows but a known creation missing: positive
    counterevidence, F3) from budget/cap/wire incompleteness (never revokes).
    """
    addr = deployer.lower()
    creations, scope, complete = enumerate_deployer_creations(addr, session)
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
    """address → factory for factory-mediated creations."""
    return {c.address: c.factory for c in creations if c.factory}


def session_deployer_enumerator(session: Session) -> DeployerEnumerator:
    """Gate-facing adapter (``membership_gate.DeployerEnumerator``): returns only the creation set and whether it
    licenses exclusivity. Coverage gaps go on ``coverage_gaps`` and full records on ``creations`` for the fixpoint
    (F3 counterevidence and the member-factory rule).
    """
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
