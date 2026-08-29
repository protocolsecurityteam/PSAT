"""Invariant-8 revocation: the deployer demotion cascade and revocation
quiescence."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from sqlalchemy import cast, or_, select
from sqlalchemy.dialects.postgresql import JSONB

from db.models import (
    ADMITTING_WITNESS_RULES,
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W3_CONTROL,
    WITNESS_RULE_W4_DEPLOYER,
    WITNESS_RULE_W4_FACTORY,
    Contract,
    ContractMembershipWitness,
    ControllerValue,
    ProtocolDeployer,
)

from .admission import demote_member
from .rules import (
    _ADDRESS_RE,
    LINEAGE_REGISTRY_WITNESS_RULES,
    W3_CONTROLLER_PROVENANCE,
    _utcnow,
    active_witnesses,
    revoke_witness,
)
from .transitivity import _witness_fact_holds

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DemotionResult:
    revoked_witness_ids: tuple[int, ...] = ()
    demoted_contract_ids: tuple[int, ...] = ()
    #: Contracts whose corroboration probes must re-run after the demotion.
    reprobe_contract_ids: tuple[int, ...] = ()


def _demote_if_no_verified_witness(
    session: Session,
    *,
    contract_id: int,
    protocol_id: int,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> tuple[list[int], bool]:
    """Invariant 8: demote exactly the members left with no admitting witness
    whose via-fact still verifies; a remaining witness that fails verification
    is revoked in the same pass. Returns (extra revoked ids, demoted?)."""
    contract = session.get(Contract, contract_id)
    if contract is None or contract.protocol_id != protocol_id:
        return [], False
    revoked: list[int] = []
    keep = False
    for row in sorted(active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id), key=lambda r: r.id):
        if row.rule not in ADMITTING_WITNESS_RULES:
            continue
        if _witness_fact_holds(
            session,
            contract=contract,
            protocol_id=protocol_id,
            rule=row.rule,
            evidence=row.evidence,
            via_address=row.via_address,
        ):
            keep = True
        elif revoke_witness(session, row, reason=reason):
            revoked.append(row.id)
    if keep:
        return revoked, False
    demote_member(session, contract=contract, reason=reason, evidence=evidence)
    return revoked, True


def _revoke_deployer_registry_row(
    session: Session, deployer_row: ProtocolDeployer, reason: str
) -> tuple[list[int], list[int]]:
    """Single-level deployer revocation: revoke the registry row, revoke its
    dependent W4 witnesses, demote members left with no verifying witness."""
    if deployer_row.revoked_at is None:
        deployer_row.revoked_at = _utcnow()
        deployer_row.revocation_reason = reason
        logger.info(
            "deployer registry row revoked",
            extra={
                "protocol_id": deployer_row.protocol_id,
                "address": deployer_row.address,
                "trust_class": deployer_row.trust_class,
                "reason": reason,
            },
        )
    dependents = list(
        session.execute(
            select(ContractMembershipWitness)
            .where(
                ContractMembershipWitness.protocol_id == deployer_row.protocol_id,
                ContractMembershipWitness.rule.in_(sorted(LINEAGE_REGISTRY_WITNESS_RULES)),
                ContractMembershipWitness.via_address == deployer_row.address,
                ContractMembershipWitness.revoked_at.is_(None),
            )
            .order_by(ContractMembershipWitness.contract_id, ContractMembershipWitness.id)
        ).scalars()
    )
    revoked: list[int] = []
    affected: set[int] = set()
    for witness in dependents:
        if revoke_witness(session, witness, reason=f"deployer_revoked:{reason}"):
            revoked.append(witness.id)
            affected.add(witness.contract_id)
    demoted: list[int] = []
    for contract_id in sorted(affected):
        extra, was_demoted = _demote_if_no_verified_witness(
            session,
            contract_id=contract_id,
            protocol_id=deployer_row.protocol_id,
            reason=f"deployer_revoked:{reason}",
            evidence={"deployer_address": deployer_row.address, "revoked_witness_ids": revoked},
        )
        revoked.extend(extra)
        if was_demoted:
            demoted.append(contract_id)
    return revoked, demoted


def demote(session: Session, *, deployer_row: ProtocolDeployer, reason: str) -> DemotionResult:
    """Deployer revocation (invariant 8), cascaded to quiescence: dependent
    W4 witnesses are revoked, members left without a verifying witness are
    demoted, and each demotion recursively invalidates the W2/W3 witnesses
    resting on it. All demoted contracts are re-probe candidates."""
    revoked, demoted = _revoke_deployer_registry_row(session, deployer_row, reason)
    result = DemotionResult(
        revoked_witness_ids=tuple(revoked),
        demoted_contract_ids=tuple(demoted),
        reprobe_contract_ids=tuple(demoted),
    )
    return _cascade_deployer_demotions(session, result)


def _cascade_deployer_demotions(session: Session, result: DemotionResult) -> DemotionResult:
    """§3.2 witness invalidation: each demoted member is itself a via-fact —
    recurse the invalidation to quiescence. Terminates because revocations
    only shrink the active witness set."""
    seed: set[str] = set()
    for contract_id in result.demoted_contract_ids:
        contract = session.get(Contract, contract_id)
        addr = (contract.address or "").lower() if contract is not None else ""
        if addr:
            seed.add(addr)
    # A member that kept membership but lost the witness that made it ANCHOR
    # is a changed via-fact too, so every revocation seeds — not only the
    # demotions (same reason as ``_revocation_quiescence``'s frontier).
    if result.revoked_witness_ids:
        seed |= {
            address.lower()
            for (address,) in session.execute(
                select(Contract.address)
                .join(ContractMembershipWitness, ContractMembershipWitness.contract_id == Contract.id)
                .where(
                    ContractMembershipWitness.id.in_(sorted(result.revoked_witness_ids)),
                    Contract.address.is_not(None),
                )
                .distinct()
            )
            if address
        }
    if not seed:
        return result
    revoked, demoted = _revocation_quiescence(session, seed)
    all_demoted = tuple(sorted(set(result.demoted_contract_ids) | set(demoted)))
    return DemotionResult(
        revoked_witness_ids=tuple(sorted(set(result.revoked_witness_ids) | set(revoked))),
        demoted_contract_ids=all_demoted,
        reprobe_contract_ids=all_demoted,
    )


def _controllers_of(session: Session, contract_ids: Sequence[int] | set[int]) -> set[str]:
    """The addresses observed controlling these rows — caller-gating resolved
    controller values plus proxy-admin pointers.

    A controller's exclusivity is a claim about the rows it controls, so when
    one of those rows changes hands the claim must be re-verified. The
    ``d2_exclusive`` arm records no anchor chain and keys its dependent
    witnesses on the controller, so this is the only edge that reaches them."""
    ids = sorted(set(contract_ids))
    if not ids:
        return set()
    out = {
        value.lower()
        for value in session.execute(
            select(ControllerValue.value)
            .where(
                ControllerValue.contract_id.in_(ids),
                ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
            )
            .distinct()
        ).scalars()
        if value
    }
    out |= {
        admin.lower()
        for admin in session.execute(
            select(Contract.admin).where(Contract.id.in_(ids), Contract.admin.is_not(None)).distinct()
        ).scalars()
        if admin
    }
    return {a for a in out if _ADDRESS_RE.match(a)}


def _vias_citing_evidence_address(session: Session, addresses: Sequence[str] | set[str]) -> set[str]:
    """The vias of standing W3 witnesses whose recorded PROOF names one of
    *addresses* — an anchor-chain link or terminal anchor, or the member
    hosting a perimeter-principal fact.

    Invariant 8's trigger for both proof arms: such a witness's via is the
    CONTROLLER, not the address whose facts changed, so a broken proof would
    otherwise never reach the revocation frontier.

    Every arm is written as containment against the ``evidence`` COLUMN, not
    against a ``->`` path expression: only the column form is served by the
    GIN index (``ix_contract_membership_witnesses_evidence``). JSONB
    containment recurses through objects and matches an array when some element
    contains the probe, so the nested shapes below are exact."""
    addrs = sorted({a.lower() for a in addresses if a})
    if not addrs:
        return set()
    conditions = []
    for addr in addrs:
        conditions.append(
            ContractMembershipWitness.evidence.op("@>")(cast({"anchor_chain": {"anchor_address": addr}}, JSONB))
        )
        conditions.append(
            ContractMembershipWitness.evidence.op("@>")(cast({"anchor_chain": {"links": [{"address": addr}]}}, JSONB))
        )
        conditions.append(
            ContractMembershipWitness.evidence.op("@>")(cast({"principal_fact": {"member_address": addr}}, JSONB))
        )
    return {
        (via or "").lower()
        for via in session.execute(
            select(ContractMembershipWitness.via_address)
            .where(
                ContractMembershipWitness.rule == WITNESS_RULE_W3_CONTROL,
                ContractMembershipWitness.revoked_at.is_(None),
                ContractMembershipWitness.via_address.is_not(None),
                or_(*conditions),
            )
            .distinct()
        ).scalars()
        if via
    }


def _revocation_quiescence(session: Session, seed_vias: Sequence[str] | set[str]) -> tuple[list[int], list[int]]:
    """Stratum (i): revoke every active W2/W3/W4 witness whose via-fact no
    longer holds, demote members left with no verifying admitting witness,
    and follow each demotion's own dependents until nothing changes.
    Deterministic (sorted vias, then contract id); terminates because each
    frontier addition consumes a fresh demotion and revocations only shrink."""
    revoked: list[int] = []
    demoted: list[int] = []
    frontier = {a.lower() for a in seed_vias if a}
    while frontier:
        batch = sorted(frontier | _vias_citing_evidence_address(session, frontier))
        frontier = set()
        witnesses = list(
            session.execute(
                select(ContractMembershipWitness)
                .where(
                    ContractMembershipWitness.via_address.in_(batch),
                    ContractMembershipWitness.revoked_at.is_(None),
                    ContractMembershipWitness.rule.in_(
                        [
                            WITNESS_RULE_W2_STRUCTURAL,
                            WITNESS_RULE_W3_CONTROL,
                            WITNESS_RULE_W4_DEPLOYER,
                            WITNESS_RULE_W4_FACTORY,
                        ]
                    ),
                )
                .order_by(ContractMembershipWitness.contract_id, ContractMembershipWitness.id)
            ).scalars()
        )
        affected: set[tuple[int, int]] = set()
        for witness in witnesses:
            contract = session.get(Contract, witness.contract_id)
            holds = contract is not None and _witness_fact_holds(
                session,
                contract=contract,
                protocol_id=witness.protocol_id,
                rule=witness.rule,
                evidence=witness.evidence,
                via_address=witness.via_address,
            )
            if not holds and revoke_witness(session, witness, reason="via_fact_no_longer_holds"):
                revoked.append(witness.id)
                affected.add((witness.contract_id, witness.protocol_id))
        for contract_id, protocol_id in sorted(affected):
            extra, was_demoted = _demote_if_no_verified_witness(
                session, contract_id=contract_id, protocol_id=protocol_id, reason="via_fact_no_longer_holds"
            )
            revoked.extend(extra)
            if was_demoted:
                demoted.append(contract_id)
            # The frontier follows every revocation, not only the demotions.
            # A member that KEEPS membership can still lose the witness that
            # made it anchor (``_member_anchors_ladder``), and the F2 facts
            # resting on that anchoring — factory lineage, principal-keyed W3 —
            # are keyed on this address alone (invariant 8).
            contract = session.get(Contract, contract_id)
            addr = (contract.address or "").lower() if contract is not None else ""
            if addr:
                frontier.add(addr)
    return revoked, demoted
