"""Event-driven evaluation: fact deltas, candidate targeting, and the stratified fixpoint."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.dialects.postgresql import ARRAY

from db.models import (
    DEPLOYER_TRUST_CLASS_A,
    DEPLOYER_TRUST_CLASS_B,
    PROOF_DEPLOYER_TRUST_CLASSES,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    ProtocolDeployer,
    UpgradeEvent,
)
from utils.logging import record_degraded

from .admission import _attempt_admission, defer_membership_dirty
from .deployers import _nonlineage_corroborating_member_ids, classify_deployer, register_deployer
from .heuristics import _w4h_stratum
from .readers import _chain_key, _perimeter_fact, _secondary_pointer_named, principal_addresses
from .revocation import (
    DemotionResult,
    _controllers_of,
    _revocation_quiescence,
    _vias_citing_evidence_address,
    demote,
)
from .rules import _ADDRESS_RE

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FactsDelta:
    """What changed; only candidates these facts can reach are re-checked."""

    new_member_contract_ids: tuple[int, ...] = ()
    # Newly resolved pointer/controller addresses from a fact-writer commit.
    new_edge_addresses: tuple[str, ...] = ()
    changed_deployer_addresses: tuple[str, ...] = ()
    # Contracts whose own stored facts changed, re-checked directly if candidates.
    recheck_contract_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class PromotionResult:
    targeted_contract_ids: tuple[int, ...] = ()
    promoted_contract_ids: tuple[int, ...] = ()
    demoted_contract_ids: tuple[int, ...] = ()
    # Candidates blocked on a probe fact (W1 or creation witness) plus demoted members. The caller
    # schedules probes; the gate never touches the wire.
    reprobe_contract_ids: tuple[int, ...] = ()


# Full-creation-history provider for Class B: ``enumerator(eoa) -> (created_addresses, history_complete)``. Without
# one, Class B can't be minted. May expose ``coverage_gaps`` (F3 counterevidence) and ``creations`` (factory
# attributions) attributes.
DeployerEnumerator = Callable[[str], "tuple[Sequence[str], bool]"]


def _standing_vias_named_by_edges(session: Session, edge_addresses: Sequence[str]) -> set[str]:
    """New edge values naming a standing via-fact (an active W2/W3/W4 via or unrevoked deployer EOA).

    A new observation of one can invalidate facts resting on it, so they seed the revocation stratum.
    """
    addrs = sorted({a.lower() for a in edge_addresses if a})
    if not addrs:
        return set()
    touched = {
        (via or "").lower()
        for via in session.execute(
            select(ContractMembershipWitness.via_address)
            .where(
                ContractMembershipWitness.via_address.in_(addrs),
                ContractMembershipWitness.revoked_at.is_(None),
            )
            .distinct()
        ).scalars()
    }
    touched |= {
        address.lower()
        for address in session.execute(
            select(ProtocolDeployer.address)
            .where(ProtocolDeployer.address.in_(addrs), ProtocolDeployer.revoked_at.is_(None))
            .distinct()
        ).scalars()
    }
    # A non-via address can still be a link in a D1 anchor chain keyed by its controller.
    touched |= _vias_citing_evidence_address(session, addrs)
    return {t for t in touched if t}


def _target_candidates(session: Session, facts_delta: FactsDelta) -> set[int]:
    """Indexed candidate lookups for changed facts."""
    candidate = (Contract.protocol_id.is_(None), Contract.nominated_protocol_id.is_not(None))
    targeted: set[int] = set()

    edge_addrs = {a.lower() for a in facts_delta.new_edge_addresses}
    member_addrs: set[str] = set()
    pointer_addrs: set[str] = set()
    if facts_delta.new_member_contract_ids:
        for row in session.execute(
            select(Contract).where(Contract.id.in_(facts_delta.new_member_contract_ids))
        ).scalars():
            if row.address:
                member_addrs.add(row.address.lower())
            for pointer in (row.implementation, row.beacon, row.admin, *(row.secondary_implementations or [])):
                if pointer:
                    pointer_addrs.add(pointer.lower())
    # A fresh member's principals are fresh perimeter facts (D2 and D1); targeting both directions makes the result
    # independent of write order.
    principal_addrs = principal_addresses(session, facts_delta.new_member_contract_ids)

    # A factory that became a member is new W4-factory lineage for its children.
    factory_children: set[str] = set()
    if member_addrs:
        factory_children = {
            address.lower()
            for (address,) in session.execute(
                select(ContractCreationWitness.address).where(
                    func.lower(ContractCreationWitness.creation_factory).in_(sorted(member_addrs))
                )
            )
            if address
        }

    by_address = edge_addrs | pointer_addrs | principal_addrs | factory_children
    if by_address:
        targeted.update(
            session.execute(
                select(Contract.id).where(*candidate, func.lower(Contract.address).in_(sorted(by_address)))
            ).scalars()
        )

    deployer_addrs = {a.lower() for a in facts_delta.changed_deployer_addresses}
    if deployer_addrs:
        targeted.update(
            session.execute(
                select(Contract.id).where(*candidate, func.lower(Contract.deployer).in_(sorted(deployer_addrs)))
            ).scalars()
        )

    # Candidates reaching the delta through their own facts (a pointer to it, or it as their controller); both
    # directions must target. Fresh edges count too, since they change a standing member's transitivity.
    reach_addrs = edge_addrs | member_addrs | principal_addrs
    if reach_addrs:
        reach_list = sorted(reach_addrs)
        # The candidate's own ``secondary_implementations`` isn't checked: no rule reads it in that direction.
        pointer_named = (
            func.lower(Contract.implementation).in_(reach_list)
            | func.lower(Contract.beacon).in_(reach_list)
            | func.lower(Contract.admin).in_(reach_list)
        )
        targeted.update(session.execute(select(Contract.id).where(*candidate, pointer_named)).scalars())
        targeted.update(
            session.execute(
                select(Contract.id)
                .join(ControllerValue, ControllerValue.contract_id == Contract.id)
                .where(*candidate, func.lower(ControllerValue.value).in_(reach_list))
            ).scalars()
        )

    if facts_delta.recheck_contract_ids:
        targeted.update(
            session.execute(
                select(Contract.id).where(*candidate, Contract.id.in_(sorted(set(facts_delta.recheck_contract_ids))))
            ).scalars()
        )

    # Candidates whose persisted probe reads resolved to a new member or edge value.
    perimeter_delta = sorted(reach_addrs)
    if perimeter_delta:
        targeted.update(
            session.execute(
                select(Contract.id)
                .join(ContractProbeAttempt, ContractProbeAttempt.contract_id == Contract.id)
                .where(
                    *candidate,
                    # ``?|`` because only the operator form uses the GIN index.
                    ContractProbeAttempt.results.op("->")("resolved_addresses").op("?|")(
                        cast(perimeter_delta, ARRAY(Text()))
                    ),
                )
            ).scalars()
        )
    return targeted


def evaluate(
    session: Session,
    facts_delta: FactsDelta,
    *,
    deployer_enumerator: DeployerEnumerator | None = None,
) -> PromotionResult:
    """Targeted gate check for one fact delta (events 2–3): indexed candidate lookup, then the stratified
    fixpoint. Doesn't commit.

    ``changed_deployer_addresses`` forces a ladder re-check of standing registry rows for those EOAs.
    ``new_member_contract_ids`` also seeds revocation: a member another protocol claimed is counterevidence.
    """
    targeted = _target_candidates(session, facts_delta)
    dirty_vias = {a.lower() for a in facts_delta.changed_deployer_addresses if a}
    named_addresses = list(facts_delta.new_edge_addresses)
    entry_member_deployers: set[str] = set()
    if facts_delta.new_member_contract_ids:
        entry_ids = sorted(set(facts_delta.new_member_contract_ids))
        named_addresses.extend(
            address.lower()
            for (address,) in session.execute(
                select(Contract.address).where(Contract.id.in_(entry_ids), Contract.address.is_not(None))
            )
        )
        # Entry-delta members are foreign anchors against other protocols' H rows for their deployer, so add those
        # deployers to the W4-H scope.
        entry_member_deployers = {
            deployer.lower()
            for (deployer,) in session.execute(
                select(Contract.deployer).where(Contract.id.in_(entry_ids), Contract.deployer.is_not(None))
            )
            if deployer and _ADDRESS_RE.match(deployer)
        }
    dirty_vias |= _standing_vias_named_by_edges(session, named_addresses)
    with defer_membership_dirty(session):
        settled = _stratified_fixpoint(
            session,
            targeted,
            dirty_via_addresses=sorted(dirty_vias),
            changed_deployer_addresses=facts_delta.changed_deployer_addresses,
            w4h_extra_addresses=sorted(entry_member_deployers),
            deployer_enumerator=deployer_enumerator,
        )
    return PromotionResult(
        targeted_contract_ids=tuple(sorted(targeted)),
        promoted_contract_ids=settled.promoted_contract_ids,
        demoted_contract_ids=settled.demoted_contract_ids,
        reprobe_contract_ids=settled.reprobe_contract_ids,
    )


def evaluate_committed(
    session: Session,
    facts_delta: FactsDelta,
    *,
    context: str,
    deployer_enumerator: DeployerEnumerator | None = None,
) -> PromotionResult | None:
    """``evaluate`` plus commit, best-effort: failures roll back and return None (settled later or by reconcile).

    Net-new members also enqueue a selection pass, only from this worker entry point, and after the gate commit
    (``create_job`` commits, which would defeat the rollback).
    """
    try:
        result = evaluate(session, facts_delta, deployer_enumerator=deployer_enumerator)
        session.commit()
    except Exception as exc:
        session.rollback()
        record_degraded(phase="membership_gate_evaluate", exc=exc, context={"context": context})
        logger.warning(
            "membership gate evaluation failed",
            extra={"context": context, "exc_type": type(exc).__name__, "error": str(exc)[:300]},
        )
        return None
    if result.promoted_contract_ids:
        from services.discovery.selection_enqueue import enqueue_selection_for_promotions

        enqueue_selection_for_promotions(session, result.promoted_contract_ids, reason="membership_promotion")
    if result.promoted_contract_ids or result.demoted_contract_ids or result.reprobe_contract_ids:
        logger.info(
            "membership gate settled",
            extra={
                "context": context,
                "targeted": len(result.targeted_contract_ids),
                "promoted_contract_ids": list(result.promoted_contract_ids),
                "demoted_contract_ids": list(result.demoted_contract_ids),
                "reprobe_contract_ids": list(result.reprobe_contract_ids),
            },
        )
    return result


def evaluate_role_plane_change(
    session: Session,
    *,
    registry_address: str,
    rows: Sequence[Mapping[str, Any]],
    context: str,
) -> PromotionResult | None:
    """Targeted evaluation for a role-holder plane rewrite.

    The registry and its holders are named as edge addresses so ``_standing_vias_named_by_edges`` revisits dependent
    W3-D1 witnesses. A NULL holder set names nothing.
    """
    registry = (registry_address or "").lower()
    if not _ADDRESS_RE.match(registry):
        return None
    addresses = {registry}
    for row in rows:
        holders = row.get("holders")
        if not isinstance(holders, list):
            continue
        for holder in holders:
            if isinstance(holder, str) and _ADDRESS_RE.match(holder):
                addresses.add(holder.lower())
    registry_rows = tuple(
        sorted(session.execute(select(Contract.id).where(func.lower(Contract.address) == registry)).scalars())
    )
    return evaluate_committed(
        session,
        FactsDelta(new_edge_addresses=tuple(sorted(addresses)), recheck_contract_ids=registry_rows),
        context=context,
    )


def evaluate_principal_change(
    session: Session,
    *,
    contract_id: int,
    addresses: Sequence[str] | set[str],
    context: str,
) -> PromotionResult | None:
    """Targeted evaluation for a ``FunctionPrincipal`` rewrite.

    *addresses* must be the union of principals before and after, since dropped principals are only reachable via the
    pre-image. The contract's own address is named too.
    """
    contract = session.get(Contract, contract_id)
    own = (contract.address or "").lower() if contract is not None else ""
    named = {a.lower() for a in addresses if isinstance(a, str) and _ADDRESS_RE.match(a)}
    if own:
        named.add(own)
    if not named:
        return None
    return evaluate_committed(
        session,
        FactsDelta(new_edge_addresses=tuple(sorted(named)), recheck_contract_ids=(contract_id,)),
        context=context,
    )


# Loud-failure guard only; rounds are bounded by the finite witness space.
_FIXPOINT_ROUND_CAP = 1000


def _stratified_fixpoint(
    session: Session,
    candidate_ids: set[int],
    *,
    dirty_via_addresses: Sequence[str] = (),
    changed_deployer_addresses: Sequence[str] = (),
    w4h_extra_addresses: Sequence[str] = (),
    deployer_enumerator: DeployerEnumerator | None = None,
) -> PromotionResult:
    """Stratified fixpoint.

    Each round: (i) revocations to quiescence, (ii) deployer reclassification, (iii) admissions, in stable sorted order,
    so the result depends only on stored evidence (confluence).

    Termination: within a protocol every predicate is monotone in its member set and a round either grows or shrinks it;
    across protocols a losing claim's witnesses stay non-admitting, so the frontier drains. Collision-revoked registry
    rows aren't re-registered in a run. ``_FIXPOINT_ROUND_CAP`` is only a guard.

    Stratum (ii) checks candidate-named pairs, rows named by ``changed_deployer_addresses``, and rows of protocols whose
    member set shrank (in the same run).
    """
    targeted = set(candidate_ids)
    pending: set[int] = set(targeted)
    dirty_vias: set[str] = {a.lower() for a in dirty_via_addresses if a}
    named_registry_addresses: set[str] = {a.lower() for a in changed_deployer_addresses if a}
    loss_check_protocol_ids: set[int] = set()
    # The EOAs scoping the trailing W4-H stratum: the delta's, round promotions' deployers, and changed protocols.
    w4h_named_addresses: set[str] = set(named_registry_addresses) | {a.lower() for a in w4h_extra_addresses if a}
    member_change_protocol_ids: set[int] = set()
    promoted: set[int] = set()
    demoted: set[int] = set()
    reprobe: set[int] = set()
    # Rows already stamped at entry; subtracted from reported promotions so a demote-then-repromote isn't counted as
    # new.
    members_at_entry: set[int] = set()
    enum_cache: dict[str, tuple[Sequence[str], bool]] = {}

    def fold_demotions(demoted_ids: Sequence[int] | set[int]) -> None:
        """Demotion bookkeeping. Read ``members_at_entry`` off ``promoted`` before shrinking it."""
        demoted.update(demoted_ids)
        members_at_entry.update(set(demoted_ids) - promoted)
        promoted.difference_update(demoted_ids)
        reprobe.update(demoted_ids)
        pending.update(demoted_ids)
        lost_protocol_ids = _protocols_of_demoted(session, demoted_ids)
        loss_check_protocol_ids.update(lost_protocol_ids)
        member_change_protocol_ids.update(lost_protocol_ids)

    for _round in range(_FIXPOINT_ROUND_CAP):
        changed = False

        if dirty_vias:
            revoked_ids, demoted_ids = _revocation_quiescence(session, dirty_vias)
            dirty_vias = set()
            if revoked_ids or demoted_ids:
                changed = True
            fold_demotions(demoted_ids)

        extra_pairs = _standing_registry_pairs(
            session, addresses=named_registry_addresses, protocol_ids=loss_check_protocol_ids
        )
        named_registry_addresses = set()
        loss_check_protocol_ids = set()
        recl_changed, recl_pending, recl_demotion = _reclassify_deployers(
            session,
            pending,
            deployer_enumerator,
            enum_cache,
            extra_pairs=extra_pairs,
        )
        if recl_changed:
            changed = True
        pending.update(recl_pending)
        fold_demotions(recl_demotion.demoted_contract_ids)
        reprobe.update(recl_demotion.reprobe_contract_ids)

        round_promoted: set[int] = set()
        for contract_id in sorted(pending):
            contract = session.get(Contract, contract_id)
            if contract is None or contract.protocol_id is not None:
                continue
            if contract.nominated_protocol_id is None:
                # Unclaimed rows are outside the gate's flow; nomination is the entry ticket.
                continue
            for protocol_id in _admission_protocols(session, contract):
                outcome = _attempt_admission(session, contract, protocol_id)
                if outcome == "promoted":
                    round_promoted.add(contract_id)
                    break
                if outcome == "needs_probe":
                    reprobe.add(contract_id)
        if round_promoted:
            changed = True
            promoted.update(round_promoted)
            pending.difference_update(round_promoted)
            deployer_addrs: set[str] = set()
            promoted_addrs: set[str] = set()
            for contract_id in sorted(round_promoted):
                contract = session.get(Contract, contract_id)
                if contract is None:
                    continue
                if contract.protocol_id is not None:
                    member_change_protocol_ids.add(contract.protocol_id)
                dep = (contract.deployer or "").lower()
                if dep:
                    deployer_addrs.add(dep)
                addr = (contract.address or "").lower()
                if addr:
                    promoted_addrs.add(addr)
            # A promotion is a foreign anchor for other protocols' H rows with the same deployer.
            w4h_named_addresses |= deployer_addrs
            # A promotion is counterevidence for other protocols' standing witnesses, so re-seed revocation with it and
            # the vias citing it.
            dirty_vias |= _standing_vias_named_by_edges(session, sorted(promoted_addrs))
            # ``d2_exclusive`` witnesses are keyed on the controller, reached only through the promoted row's
            # controllers.
            dirty_vias |= _controllers_of(session, round_promoted)
            pending.update(
                _target_candidates(
                    session,
                    FactsDelta(
                        new_member_contract_ids=tuple(sorted(round_promoted)),
                        changed_deployer_addresses=tuple(sorted(deployer_addrs)),
                    ),
                )
            )

        if not changed:
            break
    else:
        raise RuntimeError("membership fixpoint exceeded the round cap — stored evidence did not settle")

    w4h_promoted, w4h_demoted = _w4h_stratum(
        session,
        pending,
        changed_protocol_ids=member_change_protocol_ids,
        named_addresses=w4h_named_addresses,
    )
    promoted.update(w4h_promoted)
    pending.difference_update(w4h_promoted)
    fold_demotions(w4h_demoted)

    reprobe.update(demoted - promoted)
    reprobe.difference_update(promoted)
    return PromotionResult(
        targeted_contract_ids=tuple(sorted(targeted)),
        promoted_contract_ids=tuple(sorted(promoted - members_at_entry)),
        demoted_contract_ids=tuple(sorted(demoted - promoted)),
        reprobe_contract_ids=tuple(sorted(reprobe)),
    )


def _protocols_of_demoted(session: Session, contract_ids: Sequence[int] | set[int]) -> set[int]:
    """Former protocols of just-demoted members, kept in ``nominated_protocol_id``."""
    ids = sorted(set(contract_ids))
    if not ids:
        return set()
    return {
        int(protocol_id)
        for (protocol_id,) in session.execute(
            select(Contract.nominated_protocol_id)
            .where(Contract.id.in_(ids), Contract.nominated_protocol_id.is_not(None))
            .distinct()
        )
    }


def _standing_registry_pairs(session: Session, *, addresses: set[str], protocol_ids: set[int]) -> set[tuple[int, str]]:
    """Unrevoked registry rows named by EOA or owned by a protocol whose members changed."""
    conditions = []
    if addresses:
        conditions.append(ProtocolDeployer.address.in_(sorted(addresses)))
    if protocol_ids:
        conditions.append(ProtocolDeployer.protocol_id.in_(sorted(protocol_ids)))
    if not conditions:
        return set()
    return {
        (int(protocol_id), address.lower())
        for protocol_id, address in session.execute(
            select(ProtocolDeployer.protocol_id, ProtocolDeployer.address).where(
                or_(*conditions), ProtocolDeployer.revoked_at.is_(None)
            )
        )
    }


def _reclassify_deployers(
    session: Session,
    pending: set[int],
    deployer_enumerator: DeployerEnumerator | None,
    enum_cache: dict[str, tuple[Sequence[str], bool]],
    *,
    extra_pairs: set[tuple[int, str]] | None = None,
) -> tuple[bool, set[int], DemotionResult]:
    """Stratum (ii): re-run the ladder for candidate-named pairs plus ``extra_pairs``.

    Registers fresh A/B verdicts; revokes only on positive counterevidence (collision, lost perimeter fact or
    corroboration), never on a missing enumeration.
    """
    extra = set(extra_pairs or ())
    if not pending and not extra:
        return False, set(), DemotionResult()
    candidate_pairs: set[tuple[int, str]] = set()
    if pending:
        candidate_pairs = {
            (int(protocol_id), deployer.lower())
            for protocol_id, deployer in session.execute(
                select(Contract.nominated_protocol_id, Contract.deployer).where(
                    Contract.id.in_(sorted(pending)),
                    Contract.protocol_id.is_(None),
                    Contract.nominated_protocol_id.is_not(None),
                    Contract.deployer.is_not(None),
                )
            )
            if deployer and _ADDRESS_RE.match(deployer)
        }
    pairs = sorted(extra | candidate_pairs)
    changed = False
    new_pending: set[int] = set()
    revoked: set[int] = set()
    demotion_demoted: set[int] = set()
    demotion_reprobe: set[int] = set()
    for protocol_id, deployer in pairs:
        existing = session.execute(
            select(ProtocolDeployer).where(
                ProtocolDeployer.protocol_id == protocol_id,
                ProtocolDeployer.address == deployer,
                ProtocolDeployer.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
        verdict = classify_deployer(session, protocol_id=protocol_id, address=deployer)
        if (
            verdict.trust_class is None
            and deployer_enumerator is not None
            and verdict.evidence.get("reason") == "no_complete_enumeration"
        ):
            if deployer not in enum_cache:
                try:
                    enum_cache[deployer] = deployer_enumerator(deployer)
                except Exception as exc:
                    record_degraded(phase="membership_deployer_enumeration", exc=exc, context={"address": deployer})
                    logger.warning(
                        "deployer enumeration failed",
                        extra={"address": deployer, "exc_type": type(exc).__name__},
                    )
                    enum_cache[deployer] = ((), False)
            history, complete = enum_cache[deployer]
            if complete:
                records: Sequence[Any] = ((getattr(deployer_enumerator, "creations", None) or {}).get(deployer)) or ()
                verdict = classify_deployer(
                    session,
                    protocol_id=protocol_id,
                    address=deployer,
                    creation_history=history,
                    history_complete=True,
                    creation_factories={c.address: c.factory for c in records if getattr(c, "factory", None)},
                )
        if verdict.trust_class is None and verdict.evidence.get("reason") == "cross_protocol_collision":
            # a collision is Class C for every party, so every protocol's proof row for this EOA falls this
            # pass. H is exempt: a foreign observation is a challenge, and the quorum
            # freezes without de-stamping.
            standing = list(
                session.execute(
                    select(ProtocolDeployer)
                    .where(
                        ProtocolDeployer.address == deployer,
                        ProtocolDeployer.trust_class.in_(sorted(PROOF_DEPLOYER_TRUST_CLASSES)),
                        ProtocolDeployer.revoked_at.is_(None),
                    )
                    .order_by(ProtocolDeployer.protocol_id)
                ).scalars()
            )
            for row in standing:
                result = demote(session, deployer_row=row, reason="cross_protocol_collision")
                changed = True
                revoked.update(result.revoked_witness_ids)
                demotion_demoted.update(result.demoted_contract_ids)
                demotion_reprobe.update(result.reprobe_contract_ids)
            continue
        if verdict.trust_class is not None:
            if existing is None or existing.trust_class != verdict.trust_class:
                register_deployer(session, protocol_id=protocol_id, address=deployer, classification=verdict)
                changed = True
                new_pending.update(
                    session.execute(
                        select(Contract.id).where(
                            Contract.protocol_id.is_(None),
                            Contract.nominated_protocol_id == protocol_id,
                            func.lower(Contract.deployer) == deployer,
                        )
                    ).scalars()
                )
        elif existing is not None:
            coverage_gaps: Mapping[str, str] = getattr(deployer_enumerator, "coverage_gaps", None) or {}
            reason: str | None = None
            if (
                existing.trust_class == DEPLOYER_TRUST_CLASS_A
                and _perimeter_fact(session, protocol_id=protocol_id, address=deployer) is None
            ):
                reason = "perimeter_fact_lost"
            elif existing.trust_class == DEPLOYER_TRUST_CLASS_B and verdict.evidence.get("reason") == (
                "foreign_or_unknown_creations"
            ):
                # A fresh enumeration found a creation outside the member/candidate set (which revokes deployer
                # exclusivity).
                reason = "foreign_or_unknown_creations"
            elif existing.trust_class == DEPLOYER_TRUST_CLASS_B and deployer in coverage_gaps:
                # F3: a complete enumeration missing a known creation is counterevidence (unlike cap incompleteness).
                reason = "enumeration_coverage_gap"
            elif (
                existing.trust_class == DEPLOYER_TRUST_CLASS_B
                and len(_nonlineage_corroborating_member_ids(session, protocol_id=protocol_id, address=deployer)) < 2
            ):
                reason = "corroboration_lost"
            if reason is not None:
                result = demote(session, deployer_row=existing, reason=reason)
                changed = True
                revoked.update(result.revoked_witness_ids)
                demotion_demoted.update(result.demoted_contract_ids)
                demotion_reprobe.update(result.reprobe_contract_ids)
    return (
        changed,
        new_pending,
        DemotionResult(
            revoked_witness_ids=tuple(sorted(revoked)),
            demoted_contract_ids=tuple(sorted(demotion_demoted)),
            reprobe_contract_ids=tuple(sorted(demotion_reprobe)),
        ),
    )


def _admission_protocols(session: Session, contract: Contract) -> list[int]:
    """Protocols to evaluate *contract* against, in order: the nominated protocol first, then others whose own facts
    name it (pointers, controllers, upgrade history, deployer registry, recorded witnesses) by id. First valid
    admission wins; losers' witnesses stay recorded but non-admitting.

    Being listed licenses nothing: each attempt uses only that protocol's own edges, so P's facts never admit to Q.
    """
    # Typed nullable; None is filtered below.
    protocols: set[int | None] = set()
    addr = (contract.address or "").lower()
    if addr:
        chain_key = _chain_key(contract.chain)
        member_scope = (
            Contract.protocol_id.is_not(None),
            Contract.id != contract.id,
            func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key,
        )
        # Members whose facts name the candidate (W2 pointers, historical impls, W3-D2 probe reads).
        protocols.update(
            session.execute(
                select(Contract.protocol_id)
                .where(
                    *member_scope,
                    (func.lower(Contract.implementation) == addr)
                    | (func.lower(Contract.beacon) == addr)
                    | (func.lower(Contract.admin) == addr)
                    | _secondary_pointer_named([addr]),
                )
                .distinct()
            ).scalars()
        )
        protocols.update(
            session.execute(
                select(Contract.protocol_id)
                .join(UpgradeEvent, UpgradeEvent.contract_id == Contract.id)
                .where(*member_scope, func.lower(UpgradeEvent.new_impl) == addr)
                .distinct()
            ).scalars()
        )
        protocols.update(
            session.execute(
                select(Contract.protocol_id)
                .join(ContractProbeAttempt, ContractProbeAttempt.contract_id == Contract.id)
                .where(
                    *member_scope,
                    ContractProbeAttempt.results.op("->")("resolved_addresses").op("?|")(cast([addr], ARRAY(Text()))),
                )
                .distinct()
            ).scalars()
        )
        # Not discovered through the candidate's own pointers/controllers (W2 proxy shape, W3-D1): sharing a foreign
        # singleton impl or operator isn't that protocol's claim, and would pull every Safe-style proxy into it. Those
        # still admit for the nominated protocol. Below: W4 registry rows for the deployer.
    deployer = (contract.deployer or "").lower()
    if deployer and _ADDRESS_RE.match(deployer):
        protocols.update(
            session.execute(
                select(ProtocolDeployer.protocol_id)
                .where(ProtocolDeployer.address == deployer, ProtocolDeployer.revoked_at.is_(None))
                .distinct()
            ).scalars()
        )
    # Recorded witnesses (a foreign W5, or earlier attempts); promote re-verifies them.
    protocols.update(
        session.execute(
            select(ContractMembershipWitness.protocol_id)
            .where(
                ContractMembershipWitness.contract_id == contract.id,
                ContractMembershipWitness.revoked_at.is_(None),
            )
            .distinct()
        ).scalars()
    )
    others = {int(p) for p in protocols if p is not None}
    ordered: list[int] = []
    nominated = contract.nominated_protocol_id
    if nominated is not None:
        ordered.append(nominated)
        others.discard(nominated)
    ordered.extend(sorted(others))
    return ordered
