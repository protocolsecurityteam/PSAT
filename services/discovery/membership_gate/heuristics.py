"""W4-H heuristic deployer affinity: grants, challenges, registry states, and
the trailing fixpoint stratum."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.models import (
    DEPLOYER_TRUST_CLASS_H,
    PROOF_DEPLOYER_TRUST_CLASSES,
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W4H_DEPLOYER_AFFINITY,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    DeployerAffinityChallenge,
    ProtocolDeployer,
)
from services.clients.rpc import chain_id_for_chain_name

from .admission import _attempt_admission, promote
from .deployers import _heuristic_registry_row, _proof_registry_row
from .readers import _secondary_pointer_named, member_for_evidence
from .revocation import demote
from .rules import (
    _ADDRESS_RE,
    _ANCHOR_CHAIN_MAX_DEPTH,
    NONLINEAGE_WITNESS_RULES,
    W4H_ADMISSION_CANDIDATE_SANITY_BOUND,
    W4H_AUTO_REVOKE_AFFINITY,
    W4H_CHALLENGE_QUORUM,
    W4H_EVIDENCE_VERSION,
    W4H_MIN_AFFINITY,
    W4H_MIN_ANCHORS,
    W4H_STATE_ACTIVE,
    W4H_STATE_FROZEN,
    W4H_STATE_REVOKED,
    W4H_STATE_SUSPENDED,
    _require_address,
    _utcnow,
    w1_evidence,
    w4h_evidence,
    witness_is_heuristic,
    write_witness,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# W4-H — heuristic deployer affinity (DEPLOYER_HEURISTIC_SPEC.md §1, §5, §6)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeployerAffinity:
    """The §1 affinity computation for one (protocol, EOA), recomputed from
    stored witness rows only — no network, no enumeration (§7 ruling 3).

    ``affinity`` is None when the denominator is empty: no anchor either way is
    not_determined, never 0.0."""

    anchors: tuple[dict[str, Any], ...]
    anchor_count: int
    foreign_anchor_count: int
    affinity: float | None

    def qualifies(self) -> bool:
        return self.anchor_count >= W4H_MIN_ANCHORS and self.affinity is not None and self.affinity >= W4H_MIN_AFFINITY


def _nonheuristic_nonlineage_witnesses(session: Session, *, address: str):
    """Every ACTIVE non-lineage, non-heuristic witness on a contract the
    persisted creation attribution assigns to *address*, as
    ``(contract, witness)``. This is the ONE observation the affinity metric
    reads: unknown creations never enter the denominator (§1, invariant 4)."""
    for contract, witness in session.execute(
        select(Contract, ContractMembershipWitness)
        .join(ContractMembershipWitness, ContractMembershipWitness.contract_id == Contract.id)
        .where(
            func.lower(Contract.deployer) == address,
            ContractMembershipWitness.revoked_at.is_(None),
            ContractMembershipWitness.rule.in_(sorted(NONLINEAGE_WITNESS_RULES)),
        )
        .order_by(Contract.id, ContractMembershipWitness.id)
    ):
        if witness_is_heuristic(witness):
            continue
        yield contract, witness


def compute_deployer_affinity(session: Session, *, protocol_id: int, address: str) -> DeployerAffinity:
    """§1 affinity for (P, E). Deterministic from stored evidence."""
    addr = _require_address(address, "address")
    own: dict[int, tuple[Contract, set[str]]] = {}
    foreign: set[tuple[int, int]] = set()
    for contract, witness in _nonheuristic_nonlineage_witnesses(session, address=addr):
        if witness.protocol_id == protocol_id:
            own.setdefault(contract.id, (contract, set()))[1].add(witness.rule)
        else:
            foreign.add((witness.protocol_id, contract.id))
    anchors = tuple(
        {
            "contract_id": contract_id,
            "rules": sorted(rules),
            "chain_id": chain_id_for_chain_name(contract.chain),
        }
        for contract_id, (contract, rules) in sorted(own.items())
    )
    denominator = len(anchors) + len(foreign)
    return DeployerAffinity(
        anchors=anchors,
        anchor_count=len(anchors),
        foreign_anchor_count=len(foreign),
        affinity=None if denominator == 0 else round(len(anchors) / denominator, 6),
    )


def sync_deployer_challenges(session: Session, *, deployer_row: ProtocolDeployer) -> int:
    """§5: one challenge row per observed FOREIGN anchor, derived from a real
    witness row for another protocol — never from suspicion. A challenge whose
    foreign witness was revoked is revoked with it. Returns the number of
    distinct contested contracts still standing."""
    observed: dict[int, int] = {}
    for contract, witness in _nonheuristic_nonlineage_witnesses(session, address=deployer_row.address):
        if witness.protocol_id != deployer_row.protocol_id:
            observed.setdefault(witness.id, contract.id)
    existing = list(
        session.execute(
            select(DeployerAffinityChallenge).where(DeployerAffinityChallenge.protocol_deployer_id == deployer_row.id)
        ).scalars()
    )
    known = {row.foreign_witness_id for row in existing if row.revoked_at is None}
    for row in existing:
        if row.revoked_at is None and row.foreign_witness_id not in observed:
            row.revoked_at = _utcnow()
            row.revocation_reason = "foreign_witness_revoked"
            known.discard(row.foreign_witness_id)
    for witness_id, contract_id in sorted(observed.items()):
        if witness_id in known:
            continue
        witness = session.get(ContractMembershipWitness, witness_id)
        if witness is None:
            continue
        session.execute(
            pg_insert(DeployerAffinityChallenge)
            .values(
                protocol_deployer_id=deployer_row.id,
                contract_id=contract_id,
                foreign_protocol_id=witness.protocol_id,
                foreign_witness_id=witness_id,
                observed_at=func.now(),
            )
            .on_conflict_do_update(
                constraint="uq_deployer_affinity_challenge_observation",
                set_={"revoked_at": None, "revocation_reason": None},
            )
        )
    session.flush()
    return len(
        {
            contract_id
            for (contract_id,) in session.execute(
                select(DeployerAffinityChallenge.contract_id).where(
                    DeployerAffinityChallenge.protocol_deployer_id == deployer_row.id,
                    DeployerAffinityChallenge.revoked_at.is_(None),
                )
            )
        }
    )


def heuristic_registry_state(
    session: Session,
    *,
    deployer_row: ProtocolDeployer,
    affinity: DeployerAffinity | None = None,
    challenges: int | None = None,
) -> str:
    """§5, derived from evidence — never a stored flag. ``revoked_at`` is the
    one stored transition (human confirmation, or the automatic auto-revoke a
    prior pass recorded); everything else is recomputed here.

    Reads like a predicate but WRITES by default: when ``challenges`` is not
    supplied it syncs the row's challenge table. Pass a precomputed
    ``affinity``/``challenges`` pair (the W4-H stratum does) to make the call
    a pure reader."""
    if deployer_row.revoked_at is not None:
        return W4H_STATE_REVOKED
    if affinity is None:
        affinity = compute_deployer_affinity(
            session, protocol_id=deployer_row.protocol_id, address=deployer_row.address
        )
    if challenges is None:
        challenges = sync_deployer_challenges(session, deployer_row=deployer_row)
    if affinity.affinity is not None and affinity.affinity < W4H_AUTO_REVOKE_AFFINITY:
        return W4H_STATE_REVOKED
    if challenges >= W4H_CHALLENGE_QUORUM or (affinity.affinity is not None and affinity.affinity < W4H_MIN_AFFINITY):
        return W4H_STATE_FROZEN
    if affinity.anchor_count < W4H_MIN_ANCHORS:
        return W4H_STATE_SUSPENDED
    return W4H_STATE_ACTIVE


def heuristic_live_numbers(affinity: DeployerAffinity, *, challenges: int) -> dict[str, Any]:
    """The recomputable values an H row's evidence records — the drift
    contract shared by the stratum's rewrite-on-drift check and reconcile's
    stale-registry audit. ``anchors`` is order-normalized at derivation
    (sorted by contract id), so an anchor swap that preserves every count is
    still drift: §8.1 promises a reviewer the actual inputs, not just totals."""
    return {
        "anchors": [dict(anchor) for anchor in affinity.anchors],
        "anchor_count": affinity.anchor_count,
        "foreign_anchor_count": affinity.foreign_anchor_count,
        "affinity": affinity.affinity,
        "challenge_count": challenges,
    }


def heuristic_evidence(affinity: DeployerAffinity, *, challenges: int) -> dict[str, Any]:
    """§8.1 H-row evidence: the inputs AND the computation, recorded so a
    reviewer reads the numbers the grant was made on, not just the verdict."""
    return {
        **heuristic_live_numbers(affinity, challenges=challenges),
        "thresholds": {
            "min_anchors": W4H_MIN_ANCHORS,
            "min_affinity": W4H_MIN_AFFINITY,
            "challenge_quorum": W4H_CHALLENGE_QUORUM,
        },
        "computed_at": _utcnow().isoformat(),
        "version": W4H_EVIDENCE_VERSION,
    }


def grant_heuristic_deployer(
    session: Session, *, protocol_id: int, address: str, affinity: DeployerAffinity, challenges: int
) -> ProtocolDeployer | None:
    """Mint or refresh the trust-class-H row for (P, E). Returns None when the
    §1 qualification does not hold, when the quorum is met, or when a proof
    class already covers the EOA — H is granted, never inferred from silence."""
    addr = _require_address(address, "address")
    if not affinity.qualifies() or challenges >= W4H_CHALLENGE_QUORUM:
        return None
    evidence = heuristic_evidence(affinity, challenges=challenges)
    existing = session.execute(
        select(ProtocolDeployer).where(ProtocolDeployer.protocol_id == protocol_id, ProtocolDeployer.address == addr)
    ).scalar_one_or_none()
    if existing is not None:
        # A revoked row is a recorded transition, human or automatic; only an
        # explicit restore lifts it. A standing proof class outranks H (§1).
        if existing.revoked_at is not None or existing.trust_class in PROOF_DEPLOYER_TRUST_CLASSES:
            return None
        existing.trust_class = DEPLOYER_TRUST_CLASS_H
        existing.evidence = evidence
        session.flush()
        return existing
    row = ProtocolDeployer(
        protocol_id=protocol_id,
        address=addr,
        trust_class=DEPLOYER_TRUST_CLASS_H,
        evidence=evidence,
    )
    session.add(row)
    session.flush()
    return row


def _w4h_pairs(
    session: Session, candidate_ids: set[int], *, changed_protocol_ids: set[int], named_addresses: set[str]
) -> list[tuple[int, str]]:
    """(protocol, EOA) pairs the heuristic stratum examines: every pending
    candidate's nominated protocol + deployer, plus the standing H rows this
    run could have moved — those of a protocol the candidates name or whose
    member set changed, and those named by EOA in the run's accumulated scope
    (the triggering delta's deployers, entry-delta members' deployers, and
    round-promoted contracts' deployers — every path that can grow a standing
    row's foreign-anchor count; the same scoping ``_standing_registry_pairs``
    applies to stratum (ii)). An untouched H row's numbers are recomputed on
    its next touch, or by reconcile's audit."""
    pairs: set[tuple[int, str]] = set()
    if candidate_ids:
        pairs |= {
            (int(protocol_id), deployer.lower())
            for protocol_id, deployer in session.execute(
                select(Contract.nominated_protocol_id, Contract.deployer).where(
                    Contract.id.in_(sorted(candidate_ids)),
                    Contract.protocol_id.is_(None),
                    Contract.nominated_protocol_id.is_not(None),
                    Contract.deployer.is_not(None),
                )
            )
            if deployer and _ADDRESS_RE.match(deployer)
        }
    protocol_scope = {protocol_id for protocol_id, _ in pairs} | changed_protocol_ids
    conditions = []
    if protocol_scope:
        conditions.append(ProtocolDeployer.protocol_id.in_(sorted(protocol_scope)))
    if named_addresses:
        conditions.append(ProtocolDeployer.address.in_(sorted(named_addresses)))
    if conditions:
        pairs |= {
            (int(protocol_id), address.lower())
            for protocol_id, address in session.execute(
                select(ProtocolDeployer.protocol_id, ProtocolDeployer.address).where(
                    ProtocolDeployer.trust_class == DEPLOYER_TRUST_CLASS_H,
                    ProtocolDeployer.revoked_at.is_(None),
                    or_(*conditions),
                )
            )
        }
    return sorted(pairs)


def _attempt_w4h_admission(
    session: Session, contract: Contract, *, registry: ProtocolDeployer, affinity: DeployerAffinity
) -> bool:
    """§1 admission for one contract: W1 code-present at (address, chain), the
    persisted creation witness attributes it to the EOA, and the H row's
    qualification was re-verified by the caller at this write (invariant 2)."""
    addr = (contract.address or "").lower()
    chain_id = chain_id_for_chain_name(contract.chain)
    if not addr or chain_id is None:
        return False
    if (contract.deployer or "").lower() != registry.address:
        return False
    code_row = session.get(ContractCreationWitness, (chain_id, addr))
    if code_row is None or code_row.code_absent_at_probe is not False or code_row.code_probe_block is None:
        return False
    if not code_row.creation_tx_hash:
        return False
    assert affinity.affinity is not None  # ``qualifies`` is the caller's gate
    write_witness(
        session,
        contract_id=contract.id,
        protocol_id=registry.protocol_id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=w1_evidence(chain_id=chain_id, code_probe_block=code_row.code_probe_block),
    )
    write_witness(
        session,
        contract_id=contract.id,
        protocol_id=registry.protocol_id,
        rule=WITNESS_RULE_W4H_DEPLOYER_AFFINITY,
        evidence=w4h_evidence(
            deployer_address=registry.address,
            deployer_registry_id=registry.id,
            creation_tx_hash=code_row.creation_tx_hash,
            creation_block=code_row.creation_block,
            affinity_at_grant=affinity.affinity,
            anchors_at_grant=affinity.anchor_count,
        ),
        via_address=registry.address,
    )
    return promote(session, contract=contract, protocol_id=registry.protocol_id)


def _w4h_late_inheritance_seed(session: Session, candidate_ids: set[int]) -> set[int]:
    """§6 late arrival: an implementation discovered AFTER the run that
    admitted its proxy is unreachable if inheritance seeds only from that
    run's promotions — the proof strata refuse the heuristic via, so nothing
    ever closes it. Return every STANDING heuristic-only member whose
    same-contract pointer (implementation / secondary implementations —
    the only edge kinds the pass follows) resolves to a pending candidate.
    Keyed on this run's candidates, never a full member sweep."""
    addresses: dict[str, set[int]] = {}
    if candidate_ids:
        for address, nominated in session.execute(
            select(Contract.address, Contract.nominated_protocol_id).where(
                Contract.id.in_(sorted(candidate_ids)),
                Contract.protocol_id.is_(None),
                Contract.nominated_protocol_id.is_not(None),
            )
        ):
            addr = (address or "").lower()
            if _ADDRESS_RE.match(addr):
                addresses.setdefault(addr, set()).add(int(nominated))
    if not addresses:
        return set()
    matched = sorted(addresses)
    seed: set[int] = set()
    for member in session.execute(
        select(Contract)
        .where(
            Contract.protocol_id.is_not(None),
            func.lower(Contract.implementation).in_(matched) | _secondary_pointer_named(matched),
        )
        .order_by(Contract.id)
    ).scalars():
        assert member.protocol_id is not None  # the WHERE clause guarantees a stamp
        pointed = {
            pointer.lower()
            for pointer in (member.implementation, *(member.secondary_implementations or []))
            if isinstance(pointer, str) and _ADDRESS_RE.match(pointer)
        }
        if not any(member.protocol_id in addresses.get(pointer, ()) for pointer in pointed):
            continue
        # A proven member's pointer edge is the proof strata's W2 already.
        if member_for_evidence(session, contract_id=member.id, protocol_id=member.protocol_id):
            continue
        seed.add(member.id)
    return seed


def _w4h_inheritance_pass(session: Session, heuristic_member_ids: set[int]) -> set[int]:
    """§6 exception: an H-member proxy carries its implementation / secondary
    implementations through W2, with the heuristic status propagated. Bounded
    by the member set it is handed — the derived witnesses are heuristic too,
    so they anchor nothing and cannot widen the frontier past same-contract
    edges."""
    promoted: set[int] = set()
    frontier = set(heuristic_member_ids)
    for _round in range(_ANCHOR_CHAIN_MAX_DEPTH):
        pointers: dict[str, int] = {}
        for member_id in sorted(frontier):
            member = session.get(Contract, member_id)
            if member is None or member.protocol_id is None:
                continue
            for pointer in (member.implementation, *(member.secondary_implementations or [])):
                if isinstance(pointer, str) and _ADDRESS_RE.match(pointer):
                    pointers.setdefault(pointer.lower(), member.protocol_id)
        if not pointers:
            break
        frontier = set()
        for contract in session.execute(
            select(Contract)
            .where(
                Contract.protocol_id.is_(None),
                Contract.nominated_protocol_id.is_not(None),
                func.lower(Contract.address).in_(sorted(pointers)),
            )
            .order_by(Contract.id)
        ).scalars():
            protocol_id = contract.nominated_protocol_id
            if protocol_id is None or pointers.get((contract.address or "").lower()) != protocol_id:
                continue
            if _attempt_admission(session, contract, protocol_id, heuristic_inheritance=True) == "promoted":
                promoted.add(contract.id)
                frontier.add(contract.id)
        if not frontier:
            break
    return promoted


def _w4h_stratum(
    session: Session, candidate_ids: set[int], *, changed_protocol_ids: set[int], named_addresses: set[str]
) -> tuple[set[int], set[int]]:
    """The LAST fixpoint stratum (DEPLOYER_HEURISTIC_SPEC.md §9 invariant 8):
    heuristic promotion runs after proof-rule quiescence and feeds nothing
    back, so the cascade stays terminating and confluent and a heuristic can
    never pre-empt a proof. Returns (promoted, demoted)."""
    promoted: set[int] = set()
    demoted: set[int] = set()
    admitting: dict[tuple[int, str], tuple[ProtocolDeployer, DeployerAffinity]] = {}
    late_seed = _w4h_late_inheritance_seed(session, candidate_ids)
    pairs = set(
        _w4h_pairs(session, candidate_ids, changed_protocol_ids=changed_protocol_ids, named_addresses=named_addresses)
    )
    # Ordering invariant (revocations before inheritance), kept explicit: a
    # late seed's via member can rest on an H row nothing in this run's delta
    # names — dead by live affinity yet still recorded active. Examining the
    # vias' (protocol, deployer) pairs here means a stale row's auto-revoke
    # fires (demoting the via) before the inheritance pass below can read it.
    if late_seed:
        pairs |= {
            (int(protocol_id), deployer.lower())
            for protocol_id, deployer in session.execute(
                select(Contract.protocol_id, Contract.deployer).where(
                    Contract.id.in_(sorted(late_seed)), Contract.deployer.is_not(None)
                )
            )
            if protocol_id is not None and deployer and _ADDRESS_RE.match(deployer)
        }
    for protocol_id, address in sorted(pairs):
        affinity = compute_deployer_affinity(session, protocol_id=protocol_id, address=address)
        row = _heuristic_registry_row(session, protocol_id=protocol_id, address=address)
        if row is None:
            # Challenges are an H-class concept: a standing proof row neither
            # syncs them nor competes with a grant (§1 precedence) — only a
            # REVOKED H row keeps its challenge bookkeeping current here.
            if _proof_registry_row(session, protocol_id=protocol_id, address=address) is not None:
                continue
            challenges = 0
            revoked_h = session.execute(
                select(ProtocolDeployer).where(
                    ProtocolDeployer.protocol_id == protocol_id,
                    ProtocolDeployer.address == address,
                    ProtocolDeployer.trust_class == DEPLOYER_TRUST_CLASS_H,
                )
            ).scalar_one_or_none()
            if revoked_h is not None:
                challenges = sync_deployer_challenges(session, deployer_row=revoked_h)
            row = grant_heuristic_deployer(
                session, protocol_id=protocol_id, address=address, affinity=affinity, challenges=challenges
            )
            if row is None:
                continue
            logger.info(
                "heuristic deployer granted",
                extra={
                    "protocol_id": protocol_id,
                    "address": address,
                    "anchor_count": affinity.anchor_count,
                    "foreign_anchor_count": affinity.foreign_anchor_count,
                    "affinity": affinity.affinity,
                },
            )
            admitting[(protocol_id, address)] = (row, affinity)
            continue
        challenges = sync_deployer_challenges(session, deployer_row=row)
        state = heuristic_registry_state(session, deployer_row=row, affinity=affinity, challenges=challenges)
        # Rewrite the recorded numbers only on drift — an unchanged evaluation
        # must leave the evidence (``computed_at`` included) untouched.
        recorded = row.evidence if isinstance(row.evidence, dict) else {}
        derived = heuristic_live_numbers(affinity, challenges=challenges)
        if any(recorded.get(key) != value for key, value in derived.items()):
            row.evidence = heuristic_evidence(affinity, challenges=challenges)
        if state == W4H_STATE_REVOKED:
            result = demote(session, deployer_row=row, reason="affinity_below_auto_revoke_floor")
            demoted.update(result.demoted_contract_ids)
            continue
        if state == W4H_STATE_ACTIVE:
            admitting[(protocol_id, address)] = (row, affinity)
        else:
            logger.info(
                "heuristic deployer not admitting",
                extra={"protocol_id": protocol_id, "address": address, "state": state},
            )
    for (protocol_id, address), (row, affinity) in sorted(admitting.items()):
        candidates = list(
            session.execute(
                select(Contract)
                .where(
                    Contract.protocol_id.is_(None),
                    Contract.nominated_protocol_id == protocol_id,
                    func.lower(Contract.deployer) == address,
                )
                .order_by(Contract.id)
            ).scalars()
        )
        if len(candidates) > W4H_ADMISSION_CANDIDATE_SANITY_BOUND:
            logger.warning(
                "w4h admission candidates exceed sanity bound",
                extra={"protocol_id": protocol_id, "deployer": address, "count": len(candidates)},
            )
        for contract in candidates:
            if _attempt_w4h_admission(session, contract, registry=row, affinity=affinity):
                promoted.add(contract.id)
    # A via the loop above demoted drops out inside the pass (its stamp is
    # gone), so a revoked row's members carry no late inheritance.
    promoted |= _w4h_inheritance_pass(session, promoted | late_seed)
    return promoted, demoted - promoted
