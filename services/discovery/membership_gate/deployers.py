"""The §3.3 deployer trust ladder and its registry rows."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.models import (
    DEPLOYER_TRUST_CLASS_A,
    DEPLOYER_TRUST_CLASS_B,
    DEPLOYER_TRUST_CLASS_H,
    PROOF_DEPLOYER_TRUST_CLASSES,
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W3_CONTROL,
    WITNESS_RULE_W5_HUMAN,
    Contract,
    ContractMembershipWitness,
    ProtocolDeployer,
)

from .readers import _anchoring_member_factory, _member_anchors_ladder, _perimeter_fact
from .rules import (
    _EVIDENCE_ADDRESS_CAP,
    NONLINEAGE_WITNESS_RULES,
    _require_address,
    _require_positive_int,
    _utcnow,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeployerClassification:
    """Ladder verdict: ``trust_class`` 'A'/'B', or None for Class C (the absence of a row, invariant 7)."""

    trust_class: str | None
    evidence: dict[str, Any]


def _nonlineage_corroborating_member_ids(session: Session, *, protocol_id: int, address: str) -> list[int]:
    """Members deployed by *address* whose membership rests on a non-lineage witness (§3.3 Class B condition 1), also
    holding a non-D2 admitting witness (F2).
    """
    candidates = {
        row[0]
        for row in session.execute(
            select(ContractMembershipWitness.contract_id)
            .join(Contract, ContractMembershipWitness.contract_id == Contract.id)
            .where(
                Contract.protocol_id == protocol_id,
                func.lower(Contract.deployer) == address,
                ContractMembershipWitness.protocol_id == protocol_id,
                ContractMembershipWitness.revoked_at.is_(None),
                ContractMembershipWitness.rule.in_(
                    [WITNESS_RULE_W2_STRUCTURAL, WITNESS_RULE_W3_CONTROL, WITNESS_RULE_W5_HUMAN]
                ),
            )
            .distinct()
        )
    }
    return sorted(
        cid for cid in candidates if _member_anchors_ladder(session, contract_id=cid, protocol_id=protocol_id)
    )


def classify_deployer(
    session: Session,
    *,
    protocol_id: int,
    address: str,
    creation_history: Sequence[str] | None = None,
    history_complete: bool = False,
    creation_factories: Mapping[str, str] | None = None,
) -> DeployerClassification:
    """§3.3 trust-ladder verdict for one EOA (read-only; ``register_deployer`` writes A/B rows).

    ``creation_history`` is the EOA's full Etherscan creation list; ``history_complete=False`` can never reach Class B
    (absence of counterevidence isn't proof).

    ``creation_factories`` (created → factory) feeds the member-factory rule, a deliberate §3.3 deviation: a creation by
    this protocol's own anchoring member factory counts as mapped for exclusivity. It admits nothing itself.
    """
    _require_positive_int(protocol_id, "protocol_id")
    addr = _require_address(address, "address")
    checked_at = _utcnow().isoformat()

    foreign_registry = [
        (row.protocol_id, row.trust_class)
        for row in session.execute(
            select(ProtocolDeployer).where(
                ProtocolDeployer.address == addr,
                ProtocolDeployer.protocol_id != protocol_id,
                ProtocolDeployer.revoked_at.is_(None),
            )
        ).scalars()
    ]
    foreign_members = [
        (row[0], row[1])
        for row in session.execute(
            select(Contract.id, Contract.protocol_id)
            .where(
                func.lower(Contract.deployer) == addr,
                Contract.protocol_id.is_not(None),
                Contract.protocol_id != protocol_id,
            )
            .limit(20)
        )
    ]
    if foreign_registry or foreign_members:
        logger.warning(
            "cross-protocol deployer collision — Class C",
            extra={
                "address": addr,
                "protocol_id": protocol_id,
                "foreign_registry": foreign_registry,
                "foreign_member_contracts": foreign_members,
            },
        )
        return DeployerClassification(
            trust_class=None,
            evidence={
                "reason": "cross_protocol_collision",
                "foreign_registry": foreign_registry,
                "foreign_member_contracts": foreign_members,
                "checked_at": checked_at,
            },
        )

    perimeter = _perimeter_fact(session, protocol_id=protocol_id, address=addr)
    if perimeter is not None:
        return DeployerClassification(
            trust_class=DEPLOYER_TRUST_CLASS_A,
            evidence={"perimeter_fact": perimeter, "checked_at": checked_at},
        )

    # Check corroboration first so EOAs that can't reach Class B never cost an enumeration (``no_complete_enumeration``
    # is what triggers one).
    corroborating = _nonlineage_corroborating_member_ids(session, protocol_id=protocol_id, address=addr)
    if len(corroborating) < 2:
        return DeployerClassification(
            trust_class=None,
            evidence={
                "reason": "insufficient_nonlineage_corroboration",
                "corroborating_member_ids": sorted(corroborating),
                "checked_at": checked_at,
            },
        )

    if creation_history is None or not history_complete:
        return DeployerClassification(
            trust_class=None,
            evidence={"reason": "no_complete_enumeration", "checked_at": checked_at},
        )

    created = {_require_address(a, "creation_history entry") for a in creation_history}
    known: set[str] = set()
    if created:
        # F1: a creation maps in only as a member or a candidate with an unrevoked non-lineage witness, never a bare
        # nomination.
        evidenced_candidates = (
            select(ContractMembershipWitness.contract_id)
            .where(
                ContractMembershipWitness.protocol_id == protocol_id,
                ContractMembershipWitness.revoked_at.is_(None),
                ContractMembershipWitness.rule.in_(sorted(NONLINEAGE_WITNESS_RULES)),
            )
            .scalar_subquery()
        )
        known = {
            row[0].lower()
            for row in session.execute(
                select(Contract.address).where(
                    func.lower(Contract.address).in_(sorted(created)),
                    (Contract.protocol_id == protocol_id)
                    | ((Contract.nominated_protocol_id == protocol_id) & Contract.id.in_(evidenced_candidates)),
                )
            )
        }
    unmapped = sorted(created - known)
    factory_mapped: dict[str, str] = {}
    if unmapped and creation_factories:
        anchoring: dict[str, bool] = {}
        for creation in unmapped:
            factory = creation_factories.get(creation)
            if not isinstance(factory, str) or not factory:
                continue
            factory = factory.lower()
            if factory not in anchoring:
                anchoring[factory] = _anchoring_member_factory(session, protocol_id=protocol_id, factory=factory)
            if anchoring[factory]:
                factory_mapped[creation] = factory
        unmapped = [creation for creation in unmapped if creation not in factory_mapped]
    if unmapped:
        return DeployerClassification(
            trust_class=None,
            evidence={
                "reason": "foreign_or_unknown_creations",
                "unmapped_addresses": unmapped[:_EVIDENCE_ADDRESS_CAP],
                "unmapped_count": len(unmapped),
                "checked_at": checked_at,
            },
        )
    evidence: dict[str, Any] = {
        "corroborating_member_ids": sorted(corroborating),
        "enumeration": {"count": len(created), "complete": True},
        "checked_at": checked_at,
    }
    if factory_mapped:
        # The deciding factories and their child counts.
        evidence["member_factory_mapped"] = {
            "count": len(factory_mapped),
            "factories": sorted(set(factory_mapped.values())),
        }
    return DeployerClassification(trust_class=DEPLOYER_TRUST_CLASS_B, evidence=evidence)


def register_deployer(
    session: Session,
    *,
    protocol_id: int,
    address: str,
    classification: DeployerClassification,
) -> ProtocolDeployer:
    """Upsert the registry row for an A/B verdict.

    Class C raises (invariant 7). H is granted by ``grant_heuristic_deployer``.
    """
    if classification.trust_class not in PROOF_DEPLOYER_TRUST_CLASSES:
        raise ValueError("Class C is the absence of a registry row; nothing to register")
    addr = _require_address(address, "address")
    stmt = pg_insert(ProtocolDeployer).values(
        protocol_id=protocol_id,
        address=addr,
        trust_class=classification.trust_class,
        evidence=classification.evidence,
        observed_at=func.now(),
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_protocol_deployers_protocol_address",
        set_={
            "trust_class": classification.trust_class,
            "evidence": classification.evidence,
            "observed_at": func.now(),
            "revoked_at": None,
            "revocation_reason": None,
        },
    )
    row_id = session.execute(stmt.returning(ProtocolDeployer.id)).scalar_one()
    row = session.get(ProtocolDeployer, row_id)
    assert row is not None  # the upsert just returned this id
    session.refresh(row)
    return row


def _heuristic_registry_row(session: Session, *, protocol_id: int, address: str) -> ProtocolDeployer | None:
    return session.execute(
        select(ProtocolDeployer).where(
            ProtocolDeployer.protocol_id == protocol_id,
            ProtocolDeployer.address == address,
            ProtocolDeployer.trust_class == DEPLOYER_TRUST_CLASS_H,
            ProtocolDeployer.revoked_at.is_(None),
        )
    ).scalar_one_or_none()


def _proof_registry_row(session: Session, *, protocol_id: int, address: str) -> ProtocolDeployer | None:
    """The unrevoked Class-A/B row for (P, E), or None; its existence keeps H unminted (§1)."""
    return session.execute(
        select(ProtocolDeployer).where(
            ProtocolDeployer.protocol_id == protocol_id,
            ProtocolDeployer.address == address,
            ProtocolDeployer.trust_class.in_(sorted(PROOF_DEPLOYER_TRUST_CLASSES)),
            ProtocolDeployer.revoked_at.is_(None),
        )
    ).scalar_one_or_none()
