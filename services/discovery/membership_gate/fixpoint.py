"""Event-driven evaluation (spec 3.4): fact deltas, candidate targeting, and
the stratified fixpoint."""

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

from .admission import _attempt_admission
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


# ---------------------------------------------------------------------------
# Event-driven evaluation (spec §3.4 events 2–3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FactsDelta:
    """What just changed: the gate re-checks only candidates these facts can
    reach (spec §3.4 event 2), never the whole table."""

    new_member_contract_ids: tuple[int, ...] = ()
    #: Newly resolved pointer/controller ADDRESSES (proxy impl/beacon/admin
    #: values, controller values) written by a fact-writer commit.
    new_edge_addresses: tuple[str, ...] = ()
    #: Deployer EOAs whose registry row was just written, reclassified, or revoked.
    changed_deployer_addresses: tuple[str, ...] = ()
    #: Contracts whose OWN stored facts just changed (a proxy that gained
    #: pointers, a subject whose controllers were rewritten) — re-checked
    #: directly when they are candidates.
    recheck_contract_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class PromotionResult:
    targeted_contract_ids: tuple[int, ...] = ()
    promoted_contract_ids: tuple[int, ...] = ()
    demoted_contract_ids: tuple[int, ...] = ()
    #: Candidates whose settled verdict is blocked on a probe fact (missing W1
    #: code proof or creation witness) plus demoted members re-queued per
    #: invariant 8. The caller schedules probes; the gate never touches the wire.
    reprobe_contract_ids: tuple[int, ...] = ()


#: Etherscan-style FULL-creation-history provider for §3.3 Class B:
#: ``enumerator(eoa) -> (created_addresses, history_complete)``. Optional —
#: without one the fixpoint can register Class A but never mint Class B
#: (positive exclusivity evidence cannot be derived from the DB alone).
#: An enumerator MAY expose attribute channels the fixpoint reads via getattr:
#: ``coverage_gaps`` (deployer → gap, F3 counterevidence) and ``creations``
#: (deployer → full ``DeployerCreation`` records — the factory attributions
#: for the member-factory mapping rule).
DeployerEnumerator = Callable[[str], "tuple[Sequence[str], bool]"]


def _standing_vias_named_by_edges(session: Session, edge_addresses: Sequence[str]) -> set[str]:
    """Fresh edge values that name a STANDING via-fact — an active W2/W3/W4
    witness's via or an unrevoked deployer-registry EOA. A new observation of
    such an address (a foreign controller value, a new admin pointer) can
    invalidate the exclusivity/perimeter facts resting on it, so these vias
    seed the revocation stratum (§3.2 witness invalidation)."""
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
    # An address that is not a via itself can still be a LINK in a standing
    # D1 anchor chain; the witness resting on it is keyed by its controller.
    touched |= _vias_citing_evidence_address(session, addrs)
    return {t for t in touched if t}


def _target_candidates(session: Session, facts_delta: FactsDelta) -> set[int]:
    """Indexed candidate lookups per §3.4 event 2."""
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
    # A fresh member's own principals are fresh perimeter facts: they admit the
    # principal itself (D2) and anything that principal controls (D1).
    # Targeting both directions here is what makes the settled state
    # independent of whether the promotion or the principal write arrived first.
    principal_addrs = principal_addresses(session, facts_delta.new_member_contract_ids)

    # Children the fresh members are recorded as having minted: a factory that
    # just became a member is new W4-factory lineage for everything it created.
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

    # Candidates REACHING the delta through their OWN stored facts — a
    # candidate proxy whose pointer resolves to it (W2 proxy shape), or a
    # candidate whose stored resolved controller is it (W3 D1). Both
    # directions must target, or the settled state would depend on which
    # side's fact arrived last (invariant 9). Fresh EDGE addresses count as
    # well as fresh members: an edge that names a STANDING member (a role
    # holder written under a member registry) changes that member's
    # transitivity, and only its wards' own controller rows point back at it.
    reach_addrs = edge_addrs | member_addrs | principal_addrs
    if reach_addrs:
        reach_list = sorted(reach_addrs)
        # The candidate's OWN ``secondary_implementations`` is deliberately not
        # probed here: no admitting rule reads it in that direction, so the
        # per-address LIKE it would cost buys no targeting.
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

    # Candidates whose PROBED reads resolved to an address that just became a
    # member or a fresh edge value (the probe persisted the resolved set for
    # exactly this lookup).
    perimeter_delta = sorted(reach_addrs)
    if perimeter_delta:
        targeted.update(
            session.execute(
                select(Contract.id)
                .join(ContractProbeAttempt, ContractProbeAttempt.contract_id == Contract.id)
                .where(
                    *candidate,
                    # ``?|`` (not jsonb_exists_any): only the operator form is
                    # served by the GIN index on results->'resolved_addresses'.
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
    """Targeted gate check for one fact delta (spec §3.4 events 2–3):
    indexed candidate lookup, then the stratified fixpoint. Mutates the
    session without committing — the caller commits.

    ``changed_deployer_addresses`` also forces the §3.3 ladder re-check of any
    STANDING registry row for those EOAs — a registry row is re-examined when
    its deployer is named, not only when a candidate happens to name it.

    ``new_member_contract_ids`` seeds the revocation stratum as well as the
    recall lookup: a member another protocol just claimed is counterevidence
    against every standing proof resting on that address, and a caller may
    name one without naming any edge (invariant 8)."""
    targeted = _target_candidates(session, facts_delta)
    dirty_vias = {a.lower() for a in facts_delta.changed_deployer_addresses if a}
    named_addresses = list(facts_delta.new_edge_addresses)
    if facts_delta.new_member_contract_ids:
        named_addresses.extend(
            address.lower()
            for (address,) in session.execute(
                select(Contract.address).where(
                    Contract.id.in_(sorted(set(facts_delta.new_member_contract_ids))), Contract.address.is_not(None)
                )
            )
        )
    dirty_vias |= _standing_vias_named_by_edges(session, named_addresses)
    settled = _stratified_fixpoint(
        session,
        targeted,
        dirty_via_addresses=sorted(dirty_vias),
        changed_deployer_addresses=facts_delta.changed_deployer_addresses,
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
    """Event-2 hook wrapper: ``evaluate`` + commit, best-effort. A failure
    rolls back and returns None — membership settles at a later event or via
    reconcile; a pipeline stage never fails on the gate.

    Net-new members also enqueue a selection pass for their protocol: this
    wrapper is the WORKER entry point, so the CLI/migration paths (which call
    ``evaluate`` and commit themselves) enqueue nothing. The enqueue runs
    AFTER the gate's own commit — ``create_job`` commits, so running it inside
    the try would land the cascade durably and void the rollback below."""
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
    """§3.4 event 2 for a role-holder plane rewrite — the anchor-chain arm's
    fuel (``_own_controller_links``) and therefore its revocation trigger.

    The registry is a standing via for every W3-D1 witness it controls, and its
    holders appear as anchor-chain links; naming both as edge addresses is what
    makes ``_standing_vias_named_by_edges`` revisit those witnesses. A withheld
    (NULL) holder set names nothing — not_determined contributes no address."""
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
    """§3.4 event 2 for a ``FunctionPrincipal`` rewrite — the fuel and the
    revocation trigger for both principal-keyed W3 arms (invariant 8).

    *addresses* must be the UNION of the principal addresses before and after
    the rewrite: a principal the re-analysis DROPPED names no fact afterwards,
    so only the pre-image can reach the witnesses resting on it. The rewritten
    contract's own address is named too — it is the via of every D2-principal
    witness it hosts, and the ``principal_fact.member_address`` of every
    D1-principal witness it proved."""
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


#: Loud-failure guard only: the fixpoint's own argument bounds rounds by the
#: finite witness/registry space, so hitting this cap is a bug, never load.
_FIXPOINT_ROUND_CAP = 1000


def _stratified_fixpoint(
    session: Session,
    candidate_ids: set[int],
    *,
    dirty_via_addresses: Sequence[str] = (),
    changed_deployer_addresses: Sequence[str] = (),
    deployer_enumerator: DeployerEnumerator | None = None,
) -> PromotionResult:
    """Stratified fixpoint (spec §3.4 event 3, invariants 8+9). Each round
    runs fixed strata — (i) revocations/invalidations to quiescence,
    (ii) deployer registry reclassification, (iii) admissions — iterating in
    stable sorted order, so the settled state is a deterministic function of
    stored evidence, independent of event arrival order (confluence).

    Termination does NOT rest on the witness set only shrinking — a
    re-admission re-arms a revoked row through ``write_witness``. It rests on
    two facts. Within one protocol every re-checked predicate is monotone in
    that protocol's member set, and a round either promotes (member set grows)
    or revokes (it shrinks), so a row cannot oscillate without some other
    protocol's set changing. Across protocols a contested row's LOSING claims
    are consumed, not regenerated — a refused claim's witnesses stay recorded
    but non-admitting — so the cross-protocol frontier drains. A
    collision-revoked registry row is never re-registered within a run.
    ``_FIXPOINT_ROUND_CAP`` is the loud-failure guard, not the bound.

    Stratum (ii) examines (protocol, deployer) pairs from pending candidates
    PLUS every standing registry row named by ``changed_deployer_addresses``
    PLUS every standing registry row of a protocol whose member set just
    shrank (a demotion can void a Class-A anchor or Class-B corroboration —
    invariant 8's trigger, enforced same-run, never left for a later event)."""
    targeted = set(candidate_ids)
    pending: set[int] = set(targeted)
    dirty_vias: set[str] = {a.lower() for a in dirty_via_addresses if a}
    named_registry_addresses: set[str] = {a.lower() for a in changed_deployer_addresses if a}
    loss_check_protocol_ids: set[int] = set()
    #: Run-level accumulators scoping the trailing W4-H stratum: the EOAs the
    #: triggering delta named, and every protocol whose member set moved.
    w4h_named_addresses: set[str] = set(named_registry_addresses)
    member_change_protocol_ids: set[int] = set()
    promoted: set[int] = set()
    demoted: set[int] = set()
    reprobe: set[int] = set()
    #: Rows this run found ALREADY stamped. The admission stratum skips a row
    #: whose ``protocol_id`` is set, so an entry-member can only reach
    #: ``promoted`` by being demoted first — every demotion the fixpoint did
    #: not itself cause therefore names one. Subtracted from the published
    #: promotions so a supersession transient is not reported as net-new.
    members_at_entry: set[int] = set()
    enum_cache: dict[str, tuple[Sequence[str], bool]] = {}

    def fold_demotions(demoted_ids: Sequence[int] | set[int]) -> None:
        """Every stratum's demotion bookkeeping. ``members_at_entry`` must be
        read off ``promoted`` BEFORE it shrinks. A demotion shrinks a member
        set too — its protocol's standing rows get the loss check next round."""
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
                # Unclaimed rows are outside the gate's event flow (§3.1) —
                # nomination is still the entry ticket; only ADMISSION is
                # evidence-keyed across protocols.
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
            # A promotion is new counterevidence for STANDING witnesses too,
            # not only fresh recall: an address this protocol just claimed is
            # proven foreign to every other protocol resting a transitivity
            # proof on it. Re-seed the revocation stratum with the promoted
            # addresses and with the vias whose published anchor chain cites
            # one, so the next round re-verifies them (invariant 8).
            dirty_vias |= _standing_vias_named_by_edges(session, sorted(promoted_addrs))
            # The d2_exclusive arm publishes no chain and keys its witnesses on
            # the CONTROLLER, so a promoted row reaches those witnesses only
            # through its own controllers — exactly the ones whose observed
            # control set this promotion just widened past the protocol.
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
    """Former protocols of just-demoted members — ``demote_member`` preserves
    them in ``nominated_protocol_id`` (invariant 4)."""
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
    """Unrevoked registry rows named by EOA or owned by a protocol whose
    member set changed — the extra stratum-(ii) checks beyond candidate-named
    pairs."""
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
    """Stratum (ii): re-run the §3.3 ladder for every (protocol, deployer)
    pair the pending candidates name, plus ``extra_pairs`` (standing registry
    rows pulled in by a named deployer or a shrunken member set). Registers
    fresh A/B verdicts; revokes an existing row only on POSITIVE
    counterevidence (collision, perimeter fact lost, corroboration lost) — an
    absent enumeration never revokes."""
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
            # Invariant 7: a collision is Class C for EVERY party, never a
            # vote — every protocol's standing PROOF row for this EOA falls in
            # the same pass, each with its full demote cascade. Trust class H
            # is exempt by design (DEPLOYER_HEURISTIC_SPEC.md §4/§5, ruling 2):
            # a foreign observation there is one challenge row, and the quorum
            # freezes the EOA for every holder without de-stamping anyone.
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
                # A FRESH enumeration surfaced a creation outside the
                # member/candidate set — the §3.3 later-foreign-observation
                # revocation; the run can mint no new W4 on this EOA after it.
                reason = "foreign_or_unknown_creations"
            elif existing.trust_class == DEPLOYER_TRUST_CLASS_B and deployer in coverage_gaps:
                # F3: coverage gap — the raw enumeration was complete yet a
                # KNOWN creation is missing or off-scope. Positive
                # counterevidence against the standing license, unlike
                # budget/cap incompleteness (which never revokes).
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
    """Protocols the fixpoint may evaluate *contract* against, in
    deterministic order: the nominated slot's protocol first (the slot stays
    first-nominator-wins recall provenance and keeps first-attempt priority),
    then every OTHER protocol whose OWN-SIDE facts name the candidate — a
    member row's stored pointer/controller/upgrade history, an unrevoked
    registry row for the candidate's deployer, or a recorded witness row —
    in ascending protocol id. The first valid admission wins — a contract
    holds ONE ``protocol_id``; a losing protocol's already-recorded
    witnesses stay recorded-but-non-admitting.

    Listing a protocol here licenses nothing: each attempt derives and
    re-verifies from THAT protocol's own edges/registry only
    (``_derive_admitting_facts``/``promote`` are protocol-scoped), so P's
    facts can never admit to Q."""
    # ``Contract.protocol_id`` is nullable at the type level even under a
    # NOT NULL filter; the None screen happens at ``others`` below.
    protocols: set[int | None] = set()
    addr = (contract.address or "").lower()
    if addr:
        chain_key = _chain_key(contract.chain)
        member_scope = (
            Contract.protocol_id.is_not(None),
            Contract.id != contract.id,
            func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key,
        )
        # Members whose stored facts name the candidate: pointer edges (W2),
        # historical impls (W2), probe reads (W3-D2).
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
        # Deliberately NOT discovered here: protocols reached only through the
        # candidate's OWN stored pointers/controllers (the W2 proxy shape and
        # W3-D1). A candidate delegating to a foreign protocol's shared
        # singleton impl, or sharing an operator with it, is code-reuse or
        # shared-ops — not that protocol's claim on the row — and admitting on
        # it would vacuum every Safe-style proxy into the singleton owner's
        # protocol. Those shapes still admit for the NOMINATED protocol
        # (attempted first, full derivation), where the nomination supplies
        # the corroborating recall.
    # W4 — unrevoked registry rows for the candidate's deployer.
    deployer = (contract.deployer or "").lower()
    if deployer and _ADDRESS_RE.match(deployer):
        protocols.update(
            session.execute(
                select(ProtocolDeployer.protocol_id)
                .where(ProtocolDeployer.address == deployer, ProtocolDeployer.revoked_at.is_(None))
                .distinct()
            ).scalars()
        )
    # Recorded witness rows — a W5 assertion for a foreign protocol, or a
    # prior attempt's rows; promote re-verifies every via-fact regardless.
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
