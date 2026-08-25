"""Deployer creation enumeration + coverage honesty (spec §3.3 Class B).

The single Class-B evidence path: the worker-side ladder wire
(``workers/discovery.py``) and the gate-side fixpoint
(``membership_gate.evaluate``'s ``deployer_enumerator``) both consume
``enumerate_with_coverage``, so the two can never disagree on whether an
enumeration licenses exclusivity.
"""

from __future__ import annotations

import logging
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

#: One Etherscan ``txlist`` window. A result that fills the window is a
#: truncation, never a complete creation history → ``history_complete=False``
#: → Class C (spec §3.3).
DEPLOYER_ENUMERATION_CAP = 10_000


def enumerate_deployer_creations(deployer: str) -> tuple[list[str], list[int], bool]:
    """(direct creations, enumerated chain scope, history_complete) for one
    EOA, enumerated on every enabled chain (EOAs are chain-agnostic, spec
    §3.3/§4.3). The scope is recorded so the registry evidence names WHAT was
    enumerated, never a bare ``complete: True``.

    Completeness is POSITIVE evidence: any chain whose ``txlist`` fails, fills
    the :data:`DEPLOYER_ENUMERATION_CAP` window, or answers nothing at all
    yields ``history_complete=False`` — an empty enumeration can never license
    exclusivity (it is also the factory-address shape: a contract "deployer"
    sends no transactions of its own).
    """
    addr = deployer.lower()
    created: set[str] = set()
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
        scope.append(chain_id)
        for tx in result:
            if not isinstance(tx, dict):
                continue
            target = tx.get("contractAddress")
            if not tx.get("to") and isinstance(target, str) and target:
                created.add(target.lower())
    if not created:
        return [], scope, False
    return sorted(created), scope, complete


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


def enumerate_with_coverage(session: Session, deployer: str) -> tuple[list[str], list[int], bool, str | None]:
    """Enumeration with the coverage refusal folded into ``history_complete``
    — the one place a Class-B-licensing enumeration verdict is minted.

    The fourth element distinguishes the two incompleteness shapes (F3): a
    COVERAGE GAP (the raw windows were complete, yet a known creation is
    missing or off-scope — positive counterevidence against a standing Class-B
    license) versus budget/cap/wire incompleteness (absence of evidence,
    which never revokes)."""
    addr = deployer.lower()
    history, scope, complete = enumerate_deployer_creations(addr)
    gap: str | None = None
    if complete:
        gap = enumeration_coverage_gap(session, deployer=addr, created=set(history), scope_chain_ids=set(scope))
        if gap is not None:
            logger.warning(
                "Class B refused: enumeration coverage gap",
                extra={"deployer": addr, "gap": gap},
            )
            complete = False
    return history, scope, complete, gap


def session_deployer_enumerator(session: Session) -> DeployerEnumerator:
    """Gate-facing adapter (``membership_gate.DeployerEnumerator``): the scope
    stays internal to the coverage check; the gate consumes only what §3.3
    needs — the creation set and whether it licenses exclusivity. Coverage
    gaps are recorded on the adapter's ``coverage_gaps`` (the same
    attribute-channel pattern as the re-earn budget's ``exhausted``) so the
    fixpoint can treat them as positive counterevidence (F3)."""
    return _SessionEnumerator(session)


class _SessionEnumerator:
    def __init__(self, session: Session) -> None:
        self._session = session
        self.coverage_gaps: dict[str, str] = {}

    def __call__(self, deployer: str) -> tuple[Sequence[str], bool]:
        history, _scope, complete, gap = enumerate_with_coverage(self._session, deployer)
        if gap is not None:
            self.coverage_gaps[deployer.lower()] = gap
        return history, complete
