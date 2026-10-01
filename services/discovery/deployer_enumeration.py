"""Deployer creation enumeration with coverage honesty (Class B).

The single Class-B evidence path, used by both ``workers/discovery.py`` and ``membership_gate.evaluate``'s
``deployer_enumerator``, so they can't disagree.

Etherscan attributes a contract to its creation tx's origin, so an EOA's full history is its direct creations
(``txlist`` entries with empty ``to``) plus CREATE/CREATE2 frames inside its own txs (``txlistinternal&txhash`` per tx;
the by-address form indexes frames under the factory and must not be used).
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

# Cap on one chain's combined creation set and each ``txlist`` window. Hitting it is truncation, so
# ``history_complete=False`` and Class C.
DEPLOYER_ENUMERATION_CAP = 10_000

# Per-chain budget for ``txlistinternal&txhash`` calls. Exceeding it drops the chain from scope and makes the history
# incomplete. Responses are PG-cached, so re-enumeration is cheap.
INTERNAL_RESOLUTION_TX_BUDGET = 1_000

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


def _internal_creations(
    addr: str, chain_id: int, sent_calls: Sequence[tuple[str, bool]]
) -> list[DeployerCreation] | None:
    """CREATE/CREATE2 frames in the EOA's own txs, or ``None`` if any lookup fails (then the chain can't claim
    completeness). Empty answers are cached only for mature txs.
    """
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
    """``(creations, enumerated chain scope, history_complete)`` for one EOA across enabled chains (EOAs are
    chain-agnostic). The scope is recorded so evidence says what was enumerated.

    Completeness must be positive: a failed ``txlist``, a cap hit, an exceeded internal budget, or a failed internal
    lookup drops that chain and sets ``history_complete=False``. An empty enumeration never licenses exclusivity (it's
    also what a factory looks like).
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
            # Only EOA-sent successful txs can hold its internal creations; ``txlist`` also lists received txs.
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
