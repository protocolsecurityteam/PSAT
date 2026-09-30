"""Evidence predicates and stored-fact readers shared by every gate rule."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Sequence

from sqlalchemy import Text, cast, false, func, or_, select
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from db.jsonb import jsonb_has_payload
from db.models import (
    ADMITTING_WITNESS_RULES,
    WITNESS_RULE_W3_CONTROL,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    ProtocolDeployer,
    UpgradeEvent,
)
from services.clients.rpc import chain_id_for_chain_name
from utils.chains import canonical_chain

from .rules import (
    _ADDRESS_RE,
    _TX_HASH_RE,
    NONLINEAGE_WITNESS_RULES,
    W3_CONTROLLER_PROVENANCE,
    W3_DIRECTION_D1,
    W3_PERIMETER_PRINCIPAL_TYPE,
    W3_PRINCIPAL_AUTHORITY_RESOLVERS,
    W3_PRINCIPAL_CONTROLLER_TYPES,
    MembershipState,
    _principal_fact_evidence,
    active_witnesses,
    witness_is_heuristic,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# derived, never a separate status column.


def membership_state(contract: Contract, *, code_absent_at_probe: bool | None = None) -> MembershipState:
    """The derived membership state. ``code_absent_at_probe=None`` (not probed) never proves absence."""
    if contract.protocol_id is not None:
        return "member"
    if contract.nominated_protocol_id is None:
        return "unclaimed"
    if code_absent_at_probe is True:
        return "pruned"
    return "candidate"


def resolve_membership_state(session: Session, contract: Contract) -> MembershipState:
    """``membership_state`` with the probe verdict from ``contract_creation_witnesses``."""
    code_absent: bool | None = None
    chain_id = chain_id_for_chain_name(contract.chain)
    if chain_id is not None and contract.address:
        row = session.get(ContractCreationWitness, (chain_id, contract.address.lower()))
        if row is not None:
            code_absent = row.code_absent_at_probe
    return membership_state(contract, code_absent_at_probe=code_absent)


def _has_nonlineage_witness(session: Session, *, contract_id: int, protocol_id: int) -> bool:
    """Whether the row has an unrevoked non-lineage witness for *protocol_id* (F1); nomination or W4 alone proves
    nothing.
    """
    return (
        session.execute(
            select(ContractMembershipWitness.id)
            .where(
                ContractMembershipWitness.contract_id == contract_id,
                ContractMembershipWitness.protocol_id == protocol_id,
                ContractMembershipWitness.revoked_at.is_(None),
                ContractMembershipWitness.rule.in_(sorted(NONLINEAGE_WITNESS_RULES)),
            )
            .limit(1)
        ).first()
        is not None
    )


def member_for_evidence(session: Session, *, contract_id: int, protocol_id: int) -> bool:
    """Whether this member may serve as another rule's via-fact: False exactly when
    all its active admitting witnesses are heuristic. Heuristic members are full members operationally; the
    boundary is evidentiary, so they have no transitive amplification. A row with no admitting witness isn't a
    heuristic admission.
    """
    admitting = [
        row
        for row in active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id)
        if row.rule in ADMITTING_WITNESS_RULES
    ]
    return not admitting or any(not witness_is_heuristic(row) for row in admitting)


def _member_anchors_ladder(session: Session, *, contract_id: int, protocol_id: int) -> bool:
    """F2: a member whose only admitting witness is W3-D2 (non-transitive), or only heuristic ones, can't
    anchor perimeter or corroboration facts.
    """
    for row in active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id):
        if row.rule not in ADMITTING_WITNESS_RULES or witness_is_heuristic(row):
            continue
        if row.rule != WITNESS_RULE_W3_CONTROL:
            return True
        if isinstance(row.evidence, dict) and row.evidence.get("direction") == W3_DIRECTION_D1:
            return True
    return False


def _anchoring_member_factory_id(session: Session, *, protocol_id: int, factory: str) -> int | None:
    """The id of this protocol's member at *factory* with a non-D2 admitting witness (F2), or None.

    Lowest id wins.
    """
    for member in session.execute(
        select(Contract)
        .where(Contract.protocol_id == protocol_id, func.lower(Contract.address) == factory)
        .order_by(Contract.id)
    ).scalars():
        if _member_anchors_ladder(session, contract_id=member.id, protocol_id=protocol_id):
            return member.id
    return None


def _anchoring_member_factory(session: Session, *, protocol_id: int, factory: str) -> bool:
    """Whether *factory* is this protocol's member with a non-D2 admitting witness.

    Its creations count as mapped for Class B exclusivity and the shared-operator check (a deliberate extension of
    deployer lineage);
    it admits nothing.
    """
    return _anchoring_member_factory_id(session, protocol_id=protocol_id, factory=factory) is not None


@dataclass(frozen=True)
class MemberFactoryLineage:
    factory: str
    member_contract_id: int
    chain_id: int
    creation_tx_hash: str | None


def _member_factory_lineage(
    session: Session, *, protocol_id: int, contract: Contract, factory: str | None = None
) -> MemberFactoryLineage | None:
    """Whether the row's own creation witness names an anchoring member factory of this protocol.

    NULL attribution licenses nothing. ``factory`` pins which one (re-verification).
    """
    chain_id = chain_id_for_chain_name(contract.chain)
    addr = (contract.address or "").lower()
    if chain_id is None or not addr:
        return None
    witness = session.get(ContractCreationWitness, (chain_id, addr))
    named = (witness.creation_factory or "").lower() if witness is not None else ""
    if not named or (factory is not None and named != factory):
        return None
    member_id = _anchoring_member_factory_id(session, protocol_id=protocol_id, factory=named)
    if member_id is None:
        return None
    assert witness is not None  # ``named`` is non-empty only when the row exists
    tx = witness.creation_tx_hash
    return MemberFactoryLineage(
        factory=named,
        member_contract_id=member_id,
        chain_id=chain_id,
        creation_tx_hash=tx.lower() if isinstance(tx, str) and _TX_HASH_RE.match(tx) else None,
    )


def _member_factory_created(session: Session, *, protocol_id: int, contract: Contract) -> bool:
    return _member_factory_lineage(session, protocol_id=protocol_id, contract=contract) is not None


# Witness-fact verification: admission and cascade re-check the edge, never mere witness
# presence.


def _chain_key(chain: str | None) -> str:
    """Mainnet-coalesced chain key, like ``db.queue._mainnet_coalesced_chain``."""
    return ((canonical_chain(chain) or chain) or "ethereum").lower()


def _member_rows_at(session: Session, *, protocol_id: int, address: str, chain_key: str) -> list[Contract]:
    """This protocol's evidence members at (address, chain), excluding heuristic-only members."""
    rows = session.execute(
        select(Contract)
        .where(
            Contract.protocol_id == protocol_id,
            func.lower(Contract.address) == address,
            func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key,
        )
        .order_by(Contract.id)
    ).scalars()
    return [row for row in rows if member_for_evidence(session, contract_id=row.id, protocol_id=protocol_id)]


_PROBE_CONTROLLER_READS = ("owner", "authority", "admin")


def _probe_controller_values(session: Session, contract: Contract) -> set[str]:
    """Controllers the latest probe resolved (owner/authority/admin only; impl/beacon are W2 facts)."""
    chain_id = chain_id_for_chain_name(contract.chain)
    row = session.get(ContractProbeAttempt, (contract.id, chain_id if chain_id is not None else 0))
    if row is None or not isinstance(row.results, dict) or row.results.get("status") != "probed":
        return set()
    reads = row.results.get("reads")
    if not isinstance(reads, dict):
        return set()
    out: set[str] = set()
    for name in _PROBE_CONTROLLER_READS:
        read = reads.get(name)
        value = read.get("value") if isinstance(read, dict) else None
        if isinstance(value, str) and _ADDRESS_RE.match(value):
            out.add(value.lower())
    return out


def _has_controller_value(session: Session, *, contract_id: int, value: str) -> bool:
    return (
        session.execute(
            select(ControllerValue.id)
            .where(
                ControllerValue.contract_id == contract_id,
                func.lower(ControllerValue.value) == value,
                ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
            )
            .limit(1)
        ).first()
        is not None
    )


def _w2_edge_holds(session: Session, *, contract: Contract, member: Contract, edge_kind: str, evidence: dict) -> bool:
    addr = (contract.address or "").lower()
    if not addr or member.id == contract.id:
        return False
    if edge_kind == "implementation":
        return (member.implementation or "").lower() == addr
    if edge_kind == "beacon":
        return (member.beacon or "").lower() == addr
    if edge_kind == "proxy_admin":
        return (member.admin or "").lower() == addr
    if edge_kind == "secondary_implementation":
        return addr in {(s or "").lower() for s in (member.secondary_implementations or [])}
    if edge_kind == "proxy":
        member_addr = (member.address or "").lower()
        return bool(member_addr) and member_addr in {
            (contract.implementation or "").lower(),
            (contract.beacon or "").lower(),
        }
    if edge_kind == "historical_implementation":
        tx = evidence.get("upgrade_tx_hash")
        conditions = [UpgradeEvent.contract_id == member.id, func.lower(UpgradeEvent.new_impl) == addr]
        if isinstance(tx, str):
            conditions.append(func.lower(UpgradeEvent.tx_hash) == tx)
        return session.execute(select(UpgradeEvent.id).where(*conditions).limit(1)).first() is not None
    return False


def _authority_derived_principal():
    """SQL predicate: the principal's ``resolver_path`` is a non-empty list of authority resolutions only (``<@``
    containment). Missing, null or empty never qualifies.
    """
    path = FunctionPrincipal.details.op("->")("resolver_path")
    return (
        (func.jsonb_typeof(path) == "array")
        & (func.jsonb_array_length(path) > 0)
        & path.op("<@")(cast(sorted(W3_PRINCIPAL_AUTHORITY_RESOLVERS), JSONB))
    )


def _member_principal_rows(
    session: Session,
    *,
    protocol_id: int,
    address: str,
    chain_key: str,
    exclude_contract_id: int | None,
    safe_owners: bool,
):
    """Resolved-principal observations of *address* on this protocol's members, by principal row id, as
    ``(function_principal_id, function_id, resolved_type, safe_address, member)``.

    ``safe_owners=True`` reads Safe principals whose signer set contains it. Same-chain members only; authority-derived
    principals only (:data:`W3_PRINCIPAL_AUTHORITY_RESOLVERS`), since caller-set enumerations aren't control.
    """
    member_scope = [
        Contract.protocol_id == protocol_id,
        func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key,
        _authority_derived_principal(),
    ]
    if exclude_contract_id is not None:
        member_scope.append(Contract.id != exclude_contract_id)
    if not safe_owners:
        for fp_id, function_id, resolved_type, member in session.execute(
            select(FunctionPrincipal.id, FunctionPrincipal.function_id, FunctionPrincipal.resolved_type, Contract)
            .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
            .join(Contract, EffectiveFunction.contract_id == Contract.id)
            .where(*member_scope, func.lower(FunctionPrincipal.address) == address)
            .order_by(FunctionPrincipal.id)
        ):
            yield fp_id, function_id, resolved_type, None, member
        return
    # Match owners in Python so casing can't hide a signer; SQL ``ilike`` is a superset prefilter.
    for fp_id, function_id, safe_address, details, member in session.execute(
        select(
            FunctionPrincipal.id,
            FunctionPrincipal.function_id,
            FunctionPrincipal.address,
            FunctionPrincipal.details,
            Contract,
        )
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .join(Contract, EffectiveFunction.contract_id == Contract.id)
        .where(
            *member_scope,
            FunctionPrincipal.resolved_type == "safe",
            jsonb_has_payload(FunctionPrincipal.details),
            FunctionPrincipal.details.op("->")("owners").cast(Text).ilike(f"%{address}%"),
        )
        .order_by(FunctionPrincipal.id)
    ):
        owners = details.get("owners") if isinstance(details, dict) else None
        if not isinstance(owners, list):
            continue
        if any(isinstance(owner, str) and owner.lower() == address for owner in owners):
            yield fp_id, function_id, "safe", (safe_address or "").lower(), member


def _function_principal_fact(
    fp_id: int, function_id: int, member: Contract, resolved_type: str | None
) -> dict[str, Any]:
    return _principal_fact_evidence(
        {
            "kind": "function_principal",
            "function_principal_id": fp_id,
            "function_id": function_id,
            "member_contract_id": member.id,
            "member_address": (member.address or "").lower(),
            "resolved_type": resolved_type,
            "safe_address": None,
        }
    )


def _principal_perimeter_fact(
    session: Session,
    *,
    protocol_id: int,
    address: str,
    chain_key: str,
    exclude_contract_id: int | None = None,
) -> dict[str, Any] | None:
    """Class-A reading for the D1-principal arm: *address* is a resolved EOA principal of a member hosting a
    non-D2 admitting witness (F2). Smallest principal row wins.
    """
    for fp_id, function_id, resolved_type, _safe_address, member in _member_principal_rows(
        session,
        protocol_id=protocol_id,
        address=address,
        chain_key=chain_key,
        exclude_contract_id=exclude_contract_id,
        safe_owners=False,
    ):
        if resolved_type != W3_PERIMETER_PRINCIPAL_TYPE:
            continue
        if not _member_anchors_ladder(session, contract_id=member.id, protocol_id=protocol_id):
            continue
        return _function_principal_fact(fp_id, function_id, member, resolved_type)
    return None


def _d2_principal_facts(
    session: Session, *, protocol_id: int, address: str, chain_key: str, exclude_contract_id: int | None
) -> list[tuple[Contract, dict[str, Any]]]:
    """One D2-principal fact per anchoring member where *address* is a controller-typed principal; smallest row per
    member, members by id.
    """
    facts: dict[int, tuple[Contract, dict[str, Any]]] = {}
    for fp_id, function_id, resolved_type, _safe, member in _member_principal_rows(
        session,
        protocol_id=protocol_id,
        address=address,
        chain_key=chain_key,
        exclude_contract_id=exclude_contract_id,
        safe_owners=False,
    ):
        if resolved_type not in W3_PRINCIPAL_CONTROLLER_TYPES or member.id in facts:
            continue
        if not _member_anchors_ladder(session, contract_id=member.id, protocol_id=protocol_id):
            continue
        facts[member.id] = (member, _function_principal_fact(fp_id, function_id, member, resolved_type))
    return [facts[member_id] for member_id in sorted(facts)]


def _address_proven_foreign(session: Session, *, protocol_id: int, address: str) -> bool:
    """Positive counterevidence that *address* belongs elsewhere: another protocol's member or unrevoked deployer
    row.

    A nomination doesn't count (F1).
    """
    foreign_member = session.execute(
        select(Contract.id)
        .where(
            func.lower(Contract.address) == address,
            Contract.protocol_id.is_not(None),
            Contract.protocol_id != protocol_id,
        )
        .limit(1)
    ).first()
    if foreign_member is not None:
        return True
    return (
        session.execute(
            select(ProtocolDeployer.id)
            .where(
                ProtocolDeployer.address == address,
                ProtocolDeployer.protocol_id != protocol_id,
                ProtocolDeployer.revoked_at.is_(None),
            )
            .limit(1)
        ).first()
        is not None
    )


def _controls_a_foreign_row(session: Session, *, protocol_id: int, controller_address: str) -> bool:
    """Whether this controller is observed controlling a row provably belonging elsewhere (another protocol's member
    or nomination), using the same three sources as ``_controller_is_exclusive``.
    """
    foreign = or_(
        Contract.protocol_id.is_not(None) & (Contract.protocol_id != protocol_id),
        Contract.protocol_id.is_(None)
        & Contract.nominated_protocol_id.is_not(None)
        & (Contract.nominated_protocol_id != protocol_id),
    )
    row = session.execute(
        select(Contract.id)
        .join(ControllerValue, ControllerValue.contract_id == Contract.id)
        .where(
            func.lower(ControllerValue.value) == controller_address,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
            foreign,
        )
        .limit(1)
    ).first()
    if row is None:
        row = session.execute(
            select(Contract.id).where(func.lower(Contract.admin) == controller_address, foreign).limit(1)
        ).first()
    if row is None:
        for candidate in session.execute(
            select(Contract)
            .join(ContractProbeAttempt, ContractProbeAttempt.contract_id == Contract.id)
            .where(
                ContractProbeAttempt.results.op("->")("resolved_addresses").op("?|")(
                    cast([controller_address], ARRAY(Text()))
                ),
                foreign,
            )
            .order_by(Contract.id)
        ).scalars():
            if controller_address in _probe_controller_values(session, candidate):
                row = (candidate.id,)
                break
    if row is None:
        return False
    logger.info(
        "anchor chain refused: controller reaches a foreign row",
        extra={"protocol_id": protocol_id, "controller": controller_address, "foreign_ward": row[0]},
    )
    return True


def _member_ids_subquery(protocol_id: int):
    return select(Contract.id).where(Contract.protocol_id == protocol_id).scalar_subquery()


def _perimeter_fact(session: Session, *, protocol_id: int, address: str) -> dict[str, Any] | None:
    """A resolved principal fact placing *address* in the protocol's control graph (controller value, function
    principal, or Safe signer), on a member with a non-D2 admitting witness (F2).
    """
    for fact, member_id in _perimeter_fact_candidates(session, protocol_id=protocol_id, address=address):
        if _member_anchors_ladder(session, contract_id=member_id, protocol_id=protocol_id):
            return fact
    return None


def _perimeter_fact_candidates(session: Session, *, protocol_id: int, address: str):
    """Every perimeter observation of *address*, as ``(fact, anchoring_member_id)``; the caller checks
    anchoring.
    """
    members = _member_ids_subquery(protocol_id)
    for member_id, controller_id in session.execute(
        select(ControllerValue.contract_id, ControllerValue.controller_id)
        .where(
            ControllerValue.contract_id.in_(members),
            func.lower(ControllerValue.value) == address,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
        )
        .order_by(ControllerValue.contract_id, ControllerValue.id)
    ):
        yield {"kind": "controller_value", "contract_id": member_id, "controller_id": controller_id}, member_id
    # Only authority-derived principals are perimeter observations.
    for fp_id, function_id, member_id in session.execute(
        select(FunctionPrincipal.id, FunctionPrincipal.function_id, EffectiveFunction.contract_id)
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(
            EffectiveFunction.contract_id.in_(members),
            func.lower(FunctionPrincipal.address) == address,
            _authority_derived_principal(),
        )
        .order_by(FunctionPrincipal.id)
    ):
        yield {"kind": "function_principal", "function_principal_id": fp_id, "function_id": function_id}, member_id
    # Match owners in Python; the SQL ``ilike`` prefilter keeps large Safe registries off the wire.
    safe_rows = session.execute(
        select(
            FunctionPrincipal.id, FunctionPrincipal.address, FunctionPrincipal.details, EffectiveFunction.contract_id
        )
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(
            EffectiveFunction.contract_id.in_(members),
            FunctionPrincipal.resolved_type == "safe",
            jsonb_has_payload(FunctionPrincipal.details),
            FunctionPrincipal.details.op("->")("owners").cast(Text).ilike(f"%{address}%"),
        )
        .order_by(FunctionPrincipal.id)
    ).all()
    for fp_id, safe_address, details, member_id in safe_rows:
        owners = details.get("owners") if isinstance(details, dict) else None
        if not isinstance(owners, list):
            continue
        if any(isinstance(owner, str) and owner.lower() == address for owner in owners):
            yield (
                {"kind": "safe_owner", "function_principal_id": fp_id, "safe_address": (safe_address or "").lower()},
                member_id,
            )


def _secondary_pointer_named(addresses: Sequence[str]):
    """Case-folded membership test over ``secondary_implementations``; full addresses only match at element
    boundaries.
    """
    joined = func.lower(func.array_to_string(Contract.secondary_implementations, ","))
    conditions = [joined.like(f"%{address.lower()}%") for address in addresses]
    return or_(*conditions) if conditions else false()


def principal_addresses(session: Session, contract_ids: Sequence[int] | set[int]) -> set[str]:
    """Addresses named by these contracts' ``FunctionPrincipal`` rows, including resolved Safe signer sets.

    A NULL signer set names nothing.
    """
    ids = sorted(set(contract_ids))
    if not ids:
        return set()
    out: set[str] = set()
    for address, details in session.execute(
        select(FunctionPrincipal.address, FunctionPrincipal.details)
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(EffectiveFunction.contract_id.in_(ids))
    ):
        if isinstance(address, str) and _ADDRESS_RE.match(address):
            out.add(address.lower())
        owners = details.get("owners") if isinstance(details, dict) else None
        if isinstance(owners, list):
            for owner in owners:
                if isinstance(owner, str) and _ADDRESS_RE.match(owner):
                    out.add(owner.lower())
    return out
