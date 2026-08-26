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


# ---------------------------------------------------------------------------
# Membership state (spec §3.1) — derived, never a parallel status column
# ---------------------------------------------------------------------------


def membership_state(contract: Contract, *, code_absent_at_probe: bool | None = None) -> MembershipState:
    """Derive the §3.1 state. ``code_absent_at_probe`` is the persisted probe
    verdict for the row's (address, chain); ``None`` = not probed, which can
    never prove absence — the row stays a candidate."""
    if contract.protocol_id is not None:
        return "member"
    if contract.nominated_protocol_id is None:
        return "unclaimed"
    if code_absent_at_probe is True:
        return "pruned"
    return "candidate"


def resolve_membership_state(session: Session, contract: Contract) -> MembershipState:
    """``membership_state`` with the code-probe fact fetched from
    ``contract_creation_witnesses`` for the row's own (address, chain)."""
    code_absent: bool | None = None
    chain_id = chain_id_for_chain_name(contract.chain)
    if chain_id is not None and contract.address:
        row = session.get(ContractCreationWitness, (chain_id, contract.address.lower()))
        if row is not None:
            code_absent = row.code_absent_at_probe
    return membership_state(contract, code_absent_at_probe=code_absent)


def _has_nonlineage_witness(session: Session, *, contract_id: int, protocol_id: int) -> bool:
    """Does the row hold ≥1 unrevoked non-lineage witness for *protocol_id*?
    The F1 membership-evidence test for candidate rows: nomination alone (or
    W4 alone) proves nothing about belonging."""
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
    """DEPLOYER_HEURISTIC_SPEC.md §6: may this member stand as the via-fact of
    another evidence rule? False EXACTLY when its admission is heuristic —
    every active admitting witness it holds is a heuristic one. Heuristic
    members stay full members operationally (``protocol_id`` is unchanged for
    selection, monitoring, scoring, overview); the boundary is evidentiary, so
    a heuristic admission has zero transitive amplification.

    The predicate judges the witness set, not membership: a row with no
    admitting witness at all is not a HEURISTIC admission, and whether it may
    be a member is ``promote``'s question, asked with its own evidence."""
    admitting = [
        row
        for row in active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id)
        if row.rule in ADMITTING_WITNESS_RULES
    ]
    return not admitting or any(not witness_is_heuristic(row) for row in admitting)


def _member_anchors_ladder(session: Session, *, contract_id: int, protocol_id: int) -> bool:
    """§3.2 D2 non-transitivity mirrored into the ladder (F2, same discipline
    as ``_via_is_transitive``): a member whose ONLY admitting witness is W3-D2
    must not anchor perimeter or corroboration facts — its principals would
    license what the D2 entry itself may not. Heuristic witnesses never anchor
    either (DEPLOYER_HEURISTIC_SPEC.md §6)."""
    for row in active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id):
        if row.rule not in ADMITTING_WITNESS_RULES or witness_is_heuristic(row):
            continue
        if row.rule != WITNESS_RULE_W3_CONTROL:
            return True
        if isinstance(row.evidence, dict) and row.evidence.get("direction") == W3_DIRECTION_D1:
            return True
    return False


def _anchoring_member_factory_id(session: Session, *, protocol_id: int, factory: str) -> int | None:
    """The id of this protocol's MEMBER row at *factory* holding a non-D2
    admitting witness (F2), or None. Lowest member id wins, so the published
    via is a function of the evidence set, not of row order (invariant 9)."""
    for member in session.execute(
        select(Contract)
        .where(Contract.protocol_id == protocol_id, func.lower(Contract.address) == factory)
        .order_by(Contract.id)
    ).scalars():
        if _member_anchors_ladder(session, contract_id=member.id, protocol_id=protocol_id):
            return member.id
    return None


def _anchoring_member_factory(session: Session, *, protocol_id: int, factory: str) -> bool:
    """Whether *factory* is this protocol's own MEMBER holding a non-D2
    admitting witness (F2). The member-factory mapping rule (deliberate §3.3
    deviation, owner ruling): a creation minted by the protocol's own member
    factory is a protocol-family creation — it counts as MAPPED in the Class-B
    exclusivity test and is tolerated by the shared-operator kill. Mapping
    only: it admits nothing and mints no witness."""
    return _anchoring_member_factory_id(session, protocol_id=protocol_id, factory=factory) is not None


@dataclass(frozen=True)
class MemberFactoryLineage:
    """The stored creation attribution behind a W4-factory witness."""

    factory: str
    member_contract_id: int
    chain_id: int
    creation_tx_hash: str | None


def _member_factory_lineage(
    session: Session, *, protocol_id: int, contract: Contract, factory: str | None = None
) -> MemberFactoryLineage | None:
    """The stored-attribution arm of the member-factory rule: the row's own
    creation witness names a factory that is an anchoring member of this
    protocol. NULL attribution is not-determined and licenses nothing.
    ``factory``, when given, additionally pins WHICH factory must be named —
    the re-verification path for an already-published witness."""
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


# ---------------------------------------------------------------------------
# Witness-fact verification (spec §3.2 witness invalidation; invariant 6).
# Admission and cascade both re-check the EDGE, never mere witness presence —
# a caller-written witness row is a claim the gate re-verifies, not a license.
# ---------------------------------------------------------------------------


def _chain_key(chain: str | None) -> str:
    """Mainnet-coalesced, canonicalized chain key — the same NULL≡'ethereum'
    dedup convention as ``db.queue._mainnet_coalesced_chain``."""
    return ((canonical_chain(chain) or chain) or "ethereum").lower()


def _member_rows_at(session: Session, *, protocol_id: int, address: str, chain_key: str) -> list[Contract]:
    """This protocol's EVIDENCE members at (address, chain): heuristic-only
    members are excluded (DEPLOYER_HEURISTIC_SPEC.md §6) — every caller here
    reads a member as the via-fact of another rule."""
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
    """Controller addresses the latest §3.5 probe of *contract* resolved
    (owner/authority/admin reads only — impl/beacon reads are W2-shaped facts,
    not control edges)."""
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
    """SQL predicate: the principal row's recorded ``resolver_path`` is a
    non-empty list of AUTHORITY resolutions, end to end. ``<@`` is JSONB array
    containment — every step must be an authority resolver, so a path that
    mixes in a mapping enumeration does not qualify. A missing path, a JSON
    ``null`` path, and an empty list are all not_determined and never qualify."""
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
    """Resolved-principal observations of *address* on this protocol's members,
    in deterministic order (principal row id), as
    ``(function_principal_id, function_id, resolved_type, safe_address, member)``.

    ``safe_owners=False`` reads the principal row whose ADDRESS is *address*;
    ``safe_owners=True`` reads Safe principals whose stored signer set CONTAINS
    it. Only same-chain members are read: a principal fact is an observation on
    a deployment, and a deployment is (address, chain). Only AUTHORITY-derived
    principals are read (:data:`W3_PRINCIPAL_AUTHORITY_RESOLVERS`) — a row the
    resolver produced by enumerating a caller mapping, or with no recorded
    derivation, proves membership of a caller set and not control.
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
    # Owner matching happens in Python so stored casing can never hide a
    # signer; the SQL ``ilike`` is a case-insensitive SUPERSET prefilter only.
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
    """§3.3 Class-A perimeter reading for the D1-principal arm: *address* is a
    resolved EOA principal (:data:`W3_PERIMETER_PRINCIPAL_TYPE`) of a member's
    effective function. The hosting member must itself hold a non-D2 admitting
    witness (F2) — a principal observed only on a D2-only entry licenses
    nothing, since the D2 entry itself is non-transitive.

    Smallest principal row wins, so the published fact is a function of the
    evidence set rather than of row arrival order (invariant 9)."""
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
    """One D2-principal fact per anchoring member on which *address* is a
    resolved controller-typed principal (:data:`W3_PRINCIPAL_CONTROLLER_TYPES`).
    The smallest principal row per member wins; members are returned in id
    order."""
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
    """Positive counterevidence that *address* belongs elsewhere: it is a
    member of another protocol, or another protocol's unrevoked deployer
    registry row. A bare nomination is deliberately NOT counted — it proves
    nothing in either direction (F1)."""
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
    """Ward-side counterevidence for the anchor-chain arm: is this controller
    observed controlling a row that PROVABLY belongs elsewhere — another
    protocol's member, or a row another protocol nominated? The observation set
    is the same three W3 sources ``_controller_is_exclusive`` reads:
    caller-gating controller values, proxy-admin pointers, §3.5 probe reads."""
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
    """A resolved principal fact placing *address* inside the protocol's proven
    control graph: a resolved controller value on a member, a function
    principal of a member, or a resolved Safe signer-set entry. The anchoring
    member must itself hold a non-D2 admitting witness (F2) — a principal
    observed on a D2-only entry never mints a ladder anchor."""
    for fact, member_id in _perimeter_fact_candidates(session, protocol_id=protocol_id, address=address):
        if _member_anchors_ladder(session, contract_id=member_id, protocol_id=protocol_id):
            return fact
    return None


def _perimeter_fact_candidates(session: Session, *, protocol_id: int, address: str):
    """Every §3.3 perimeter observation of *address*, in deterministic order,
    as ``(fact, anchoring_member_id)``. Whether the anchoring member may
    actually anchor is the caller's check."""
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
    # A principal produced by enumerating a caller mapping proves membership
    # of a caller set, not control — only an authority-derived principal is a
    # perimeter observation (invariant 6, :data:`W3_PRINCIPAL_AUTHORITY_RESOLVERS`).
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
    # Owner matching happens in Python so stored casing can never hide a
    # signer: the persisted owner strings are lowercased on read. The SQL
    # ``ilike`` is a case-insensitive SUPERSET prefilter only — it keeps a
    # multi-tenant Safe registry (thousands of delegate rows) off the wire
    # without narrowing what the exact check below accepts.
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
    """Array-membership predicate over ``secondary_implementations``,
    case-folded. A full 0x-address can only match at an element boundary
    ('x' is not a hex digit), so the joined-LIKE form is element-exact."""
    joined = func.lower(func.array_to_string(Contract.secondary_implementations, ","))
    conditions = [joined.like(f"%{address.lower()}%") for address in addresses]
    return or_(*conditions) if conditions else false()


def principal_addresses(session: Session, contract_ids: Sequence[int] | set[int]) -> set[str]:
    """Addresses the stored ``FunctionPrincipal`` rows of these contracts name
    — the principals themselves plus the signer sets of resolved Safe
    principals. The fuel and the revocation trigger for both principal-keyed
    W3 arms; a withheld (NULL) signer set is not_determined and names nothing."""
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
