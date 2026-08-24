"""Contract-membership gate — sole writer of ``Contract.protocol_id``
(DISCOVERY_MEMBERSHIP_GATE_SPEC.md §3–§5).

Membership is an earned fact with a recorded witness: no discovery source's
identity confers it, and no witness field may contain or be derived from LLM
output (invariant 2). Every function here mutates the session without
committing — the caller commits so the gate write lands atomically with the
triggering fact.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Sequence

from sqlalchemy import Text, case, cast, func, select, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.models import (
    ADMITTING_WITNESS_RULES,
    DEPLOYER_TRUST_CLASS_A,
    DEPLOYER_TRUST_CLASS_B,
    DEPLOYER_TRUST_CLASSES,
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W3_CONTROL,
    WITNESS_RULE_W4_DEPLOYER,
    WITNESS_RULE_W5_HUMAN,
    WITNESS_RULE_W6_LLAMA_SEED,
    WITNESS_RULES,
    Contract,
    ContractCreationWitness,
    ContractMembershipWitness,
    ContractProbeAttempt,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    ProtocolDeployer,
)
from services.clients.rpc import chain_id_for_chain_name

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from services.discovery.probes import ProbeResult

logger = logging.getLogger(__name__)

MembershipState = Literal["member", "candidate", "pruned", "unclaimed"]

#: One reason string for both dirty queues: a promotion/demotion changed the
#: member set that enrollment and the score fold read (spec §5.2).
MEMBERSHIP_DIRTY_REASON = "membership_change"

# W2 edge kinds — each names a verified structural link against STORED
# resolution, never a bare ``relationship_type`` (spec §3.2, invariant 6).
W2_EDGE_KINDS = frozenset({"implementation", "proxy", "beacon", "proxy_admin", "secondary_implementation"})

W3_DIRECTION_D1 = "d1"
W3_DIRECTION_D2 = "d2"
# Where a W3 edge may come from (spec §3.2): resolved controller values, a
# resolved proxy-admin slot, or a §3.5 probe read. Never "appears in a
# member's control graph".
W3_SOURCES = frozenset({"controller_values", "proxy_admin_slot", "probe"})

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Class B enumeration evidence is capped so a registry row stays readable;
# the exclusivity verdict itself is over the FULL enumeration.
_EVIDENCE_ADDRESS_CAP = 50


def _require_address(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ADDRESS_RE.match(value):
        raise ValueError(f"{name} must be a 0x-prefixed 20-byte hex address, got {value!r}")
    return value.lower()


def _require_positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive int, got {value!r}")
    return value


def _require_block(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative block number, got {value!r}")
    return value


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Evidence constructors (invariant 2: rule-specific shapes, built here only)
# ---------------------------------------------------------------------------


def w1_evidence(*, chain_id: int, code_probe_block: int) -> dict[str, Any]:
    """W1 code precondition: ``eth_getCode`` ≠ empty at (address, chain), block-stamped."""
    return {
        "chain_id": _require_positive_int(chain_id, "chain_id"),
        "code_probe_block": _require_block(code_probe_block, "code_probe_block"),
        "code_present": True,
    }


def w2_evidence(
    *,
    edge_kind: str,
    member_contract_id: int,
    member_address: str,
    resolved_pointer: str,
) -> dict[str, Any]:
    """W2 structural edge, verified against stored resolution (the pointer the
    member's own row carries), never a bare ``relationship_type``."""
    if edge_kind not in W2_EDGE_KINDS:
        raise ValueError(f"edge_kind must be one of {sorted(W2_EDGE_KINDS)}, got {edge_kind!r}")
    return {
        "edge_kind": edge_kind,
        "member_contract_id": _require_positive_int(member_contract_id, "member_contract_id"),
        "member_address": _require_address(member_address, "member_address"),
        "resolved_pointer": _require_address(resolved_pointer, "resolved_pointer"),
    }


def w3_evidence(
    *,
    direction: str,
    source: str,
    via_address: str,
    via_transitive: bool | None = None,
) -> dict[str, Any]:
    """W3 control edge. D1 (candidate's resolved controller is a TRANSITIVE
    perimeter entity) requires ``via_transitive=True`` — proven, not defaulted.
    D2 (candidate controls a member) admits with a NON-TRANSITIVE perimeter
    entry stamped by construction; the caller may not assert transitivity."""
    if direction not in (W3_DIRECTION_D1, W3_DIRECTION_D2):
        raise ValueError(f"direction must be 'd1' or 'd2', got {direction!r}")
    if source not in W3_SOURCES:
        raise ValueError(f"source must be one of {sorted(W3_SOURCES)}, got {source!r}")
    via = _require_address(via_address, "via_address")
    if direction == W3_DIRECTION_D1:
        if via_transitive is not True:
            raise ValueError("d1 requires via_transitive=True — a proven transitive perimeter entity")
        return {"direction": direction, "source": source, "via": via, "via_transitive": True}
    if via_transitive is not None:
        raise ValueError("d2 does not take via_transitive; its perimeter entry is non-transitive by rule")
    return {"direction": direction, "source": source, "via": via, "perimeter_entry_transitive": False}


def w4_evidence(
    *,
    deployer_address: str,
    deployer_registry_id: int,
    creation_tx_hash: str,
    creation_block: int | None,
) -> dict[str, Any]:
    """W4 deployer lineage: the persisted creation tx plus the registry row it rests on."""
    if not isinstance(creation_tx_hash, str) or not re.match(r"^0x[0-9a-fA-F]{64}$", creation_tx_hash):
        raise ValueError(f"creation_tx_hash must be a 32-byte hex hash, got {creation_tx_hash!r}")
    return {
        "deployer_address": _require_address(deployer_address, "deployer_address"),
        "deployer_registry_id": _require_positive_int(deployer_registry_id, "deployer_registry_id"),
        "creation_tx_hash": creation_tx_hash.lower(),
        "creation_block": None if creation_block is None else _require_block(creation_block, "creation_block"),
    }


def w5_evidence(*, actor: str, asserted_at: datetime) -> dict[str, Any]:
    """W5 human assertion: explicit and attributed (invariant 14)."""
    if not isinstance(actor, str) or not actor.strip():
        raise ValueError("actor is required for a human assertion")
    if not isinstance(asserted_at, datetime):
        raise ValueError("asserted_at must be a datetime")
    return {"actor": actor.strip(), "asserted_at": asserted_at.isoformat()}


def w6_evidence(
    *,
    adapter_slug: str,
    chain_id: int,
    code_probe_block: int,
    listing_url: str | None = None,
) -> dict[str, Any]:
    """W6 DefiLlama seed. Carries its own W1 facts: a seed with no proven code
    is not constructible (invariant 3 binds W6 at the evidence shape)."""
    if not isinstance(adapter_slug, str) or not adapter_slug.strip():
        raise ValueError("adapter_slug is required for a llama-seed witness")
    evidence: dict[str, Any] = {
        "adapter_slug": adapter_slug.strip(),
        "chain_id": _require_positive_int(chain_id, "chain_id"),
        "code_probe_block": _require_block(code_probe_block, "code_probe_block"),
    }
    if listing_url is not None:
        evidence["listing_url"] = listing_url
    return evidence


def _rebuild_evidence(rule: str, evidence: dict[str, Any]) -> dict[str, Any]:
    """Round-trip *evidence* through its rule's constructor. Raises on any
    field the constructor would refuse; the caller compares the result for
    equality so extra/misplaced fields are refused too."""

    def picked(*keys: str) -> dict[str, Any]:
        return {key: evidence.get(key) for key in keys}

    if rule == WITNESS_RULE_W1_CODE:
        return w1_evidence(**picked("chain_id", "code_probe_block"))
    if rule == WITNESS_RULE_W2_STRUCTURAL:
        return w2_evidence(**picked("edge_kind", "member_contract_id", "member_address", "resolved_pointer"))
    if rule == WITNESS_RULE_W3_CONTROL:
        kwargs = picked("direction", "source")
        kwargs["via_address"] = evidence.get("via")
        if evidence.get("direction") == W3_DIRECTION_D1:
            kwargs["via_transitive"] = evidence.get("via_transitive")
        return w3_evidence(**kwargs)
    if rule == WITNESS_RULE_W4_DEPLOYER:
        return w4_evidence(**picked("deployer_address", "deployer_registry_id", "creation_tx_hash", "creation_block"))
    if rule == WITNESS_RULE_W5_HUMAN:
        raw = evidence.get("asserted_at")
        if not isinstance(raw, str):
            raise ValueError("asserted_at must be an ISO-8601 string")
        return w5_evidence(**picked("actor"), asserted_at=datetime.fromisoformat(raw))
    if rule == WITNESS_RULE_W6_LLAMA_SEED:
        return w6_evidence(**picked("adapter_slug", "chain_id", "code_probe_block", "listing_url"))
    raise ValueError(f"no evidence constructor for rule {rule!r}")


def _validate_evidence(rule: str, evidence: Any) -> dict[str, Any]:
    """Invariant 2: a witness row's evidence must be exactly what its rule's
    constructor produces — a hand-rolled dict with the wrong shape is refused."""
    if not isinstance(evidence, dict) or not evidence:
        raise ValueError("evidence must be a non-empty dict built by a rule constructor")
    try:
        rebuilt = _rebuild_evidence(rule, evidence)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"evidence shape invalid for {rule}: {exc}") from exc
    if rebuilt != evidence:
        raise ValueError(f"evidence shape invalid for {rule}: unexpected or non-canonical fields")
    return evidence


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


# ---------------------------------------------------------------------------
# Nomination (spec §3.4 event 1)
# ---------------------------------------------------------------------------


def nominate(session: Session, *, contract: Contract, protocol_id: int, source_tag: str) -> None:
    """Record that a discovery source nominated *contract* for *protocol_id*.

    Sets ``nominated_protocol_id``, never ``protocol_id``. The first
    nomination wins; a differing later one is logged and kept as provenance in
    ``discovery_sources`` only. An existing MEMBER's empty nomination slot
    belongs to its own protocol (demotion provenance, invariant 4) — a foreign
    nomination may never claim it.
    """
    _require_positive_int(protocol_id, "protocol_id")
    if contract.protocol_id is not None:
        if contract.nominated_protocol_id is None:
            contract.nominated_protocol_id = contract.protocol_id
        if protocol_id != contract.protocol_id:
            logger.info(
                "foreign nomination of an existing member recorded as provenance only",
                extra={
                    "contract_id": contract.id,
                    "member_of": contract.protocol_id,
                    "late_protocol_id": protocol_id,
                    "source_tag": source_tag,
                },
            )
    elif contract.nominated_protocol_id is None:
        contract.nominated_protocol_id = protocol_id
    elif contract.nominated_protocol_id != protocol_id:
        logger.info(
            "re-nomination kept first nominator",
            extra={
                "contract_id": contract.id,
                "nominated_protocol_id": contract.nominated_protocol_id,
                "late_protocol_id": protocol_id,
                "source_tag": source_tag,
            },
        )
    if source_tag:
        merged = list(contract.discovery_sources or [])
        if source_tag not in merged:
            merged.append(source_tag)
            contract.discovery_sources = merged


# ---------------------------------------------------------------------------
# Witness primitives
# ---------------------------------------------------------------------------


def write_witness(
    session: Session,
    *,
    contract_id: int,
    protocol_id: int,
    rule: str,
    evidence: dict[str, Any],
    via_address: str | None = None,
) -> ContractMembershipWitness:
    """Race-safe idempotent witness upsert on (contract, protocol, rule, via_address).

    One ``INSERT .. ON CONFLICT`` against the partial unique index the key
    lands on. The unique key admits one row per fact, so a re-observation of a
    REVOKED fact re-arms the SAME row (revocation cleared, evidence refreshed)
    — the revocation itself stays in the log, never in a second row; an
    ACTIVE row keeps its original evidence and ``observed_at``.
    """
    if rule not in WITNESS_RULES:
        raise ValueError(f"rule must be one of {sorted(WITNESS_RULES)}, got {rule!r}")
    _validate_evidence(rule, evidence)
    via = _require_address(via_address, "via_address") if via_address is not None else None
    was_revoked = ContractMembershipWitness.revoked_at.is_not(None)
    stmt = pg_insert(ContractMembershipWitness).values(
        contract_id=contract_id,
        protocol_id=protocol_id,
        rule=rule,
        via_address=via,
        evidence=evidence,
        observed_at=func.now(),
    )
    set_ = {
        "revoked_at": None,
        "evidence": case((was_revoked, stmt.excluded.evidence), else_=ContractMembershipWitness.evidence),
        "observed_at": case((was_revoked, func.now()), else_=ContractMembershipWitness.observed_at),
    }
    if via is None:
        stmt = stmt.on_conflict_do_update(
            index_elements=["contract_id", "protocol_id", "rule"],
            index_where=text("via_address IS NULL"),
            set_=set_,
        )
    else:
        stmt = stmt.on_conflict_do_update(
            index_elements=["contract_id", "protocol_id", "rule", "via_address"],
            index_where=text("via_address IS NOT NULL"),
            set_=set_,
        )
    witness_id = session.execute(stmt.returning(ContractMembershipWitness.id)).scalar_one()
    row = session.get(ContractMembershipWitness, witness_id)
    assert row is not None  # the upsert just returned this id
    session.refresh(row)
    return row


def revoke_witness(session: Session, witness: ContractMembershipWitness, *, reason: str) -> bool:
    """Set ``revoked_at`` (never delete — invariant 4). Returns False when already revoked."""
    if witness.revoked_at is not None:
        return False
    witness.revoked_at = _utcnow()
    logger.info(
        "membership witness revoked",
        extra={
            "witness_id": witness.id,
            "contract_id": witness.contract_id,
            "protocol_id": witness.protocol_id,
            "rule": witness.rule,
            "via_address": witness.via_address,
            "reason": reason,
        },
    )
    return True


def active_witnesses(session: Session, *, contract_id: int, protocol_id: int) -> list[ContractMembershipWitness]:
    """Unrevoked witness rows for (contract, protocol)."""
    return list(
        session.execute(
            select(ContractMembershipWitness).where(
                ContractMembershipWitness.contract_id == contract_id,
                ContractMembershipWitness.protocol_id == protocol_id,
                ContractMembershipWitness.revoked_at.is_(None),
            )
        ).scalars()
    )


# ---------------------------------------------------------------------------
# Promotion / demotion primitives
# ---------------------------------------------------------------------------


def _mark_membership_dirty(session: Session, protocol_id: int) -> None:
    from services.monitoring.enrollment import mark_enrollment_dirty
    from services.scoring.dirty import SCORE_DIRTY_MEMBERSHIP, mark_protocol_score_dirty

    mark_enrollment_dirty(session, protocol_id, MEMBERSHIP_DIRTY_REASON)
    mark_protocol_score_dirty(session, protocol_id, SCORE_DIRTY_MEMBERSHIP)


def promote(session: Session, *, contract: Contract, protocol_id: int) -> bool:
    """Promote to member iff W1 holds (invariant 3) AND ≥1 admitting witness
    is active. Returns whether the contract is a member of *protocol_id* on
    exit; a refusal logs the named missing piece (invariant 5)."""
    _require_positive_int(protocol_id, "protocol_id")
    if contract.protocol_id == protocol_id:
        return True
    if contract.protocol_id is not None:
        logger.error(
            "promotion refused: contract already a member elsewhere",
            extra={"contract_id": contract.id, "member_of": contract.protocol_id, "requested": protocol_id},
        )
        return False
    rows = active_witnesses(session, contract_id=contract.id, protocol_id=protocol_id)
    rules = {row.rule for row in rows}
    # W1 must be a code proof on the CONTRACT'S OWN chain — a witness probed
    # elsewhere (or a row whose chain never resolves) satisfies nothing.
    expected_chain = chain_id_for_chain_name(contract.chain)
    has_w1 = expected_chain is not None and any(
        row.rule == WITNESS_RULE_W1_CODE
        and isinstance(row.evidence, dict)
        and row.evidence.get("chain_id") == expected_chain
        for row in rows
    )
    admitting = sorted(rules & ADMITTING_WITNESS_RULES)
    if not has_w1 or not admitting:
        logger.info(
            "promotion withheld",
            extra={
                "contract_id": contract.id,
                "protocol_id": protocol_id,
                "missing": "w1_code_for_contract_chain" if not has_w1 else "admitting_witness",
                "contract_chain": contract.chain,
                "active_rules": sorted(rules),
            },
        )
        return False
    contract.protocol_id = protocol_id
    _mark_membership_dirty(session, protocol_id)
    logger.info(
        "contract promoted to member",
        extra={"contract_id": contract.id, "protocol_id": protocol_id, "witness_rules": admitting},
    )
    return True


def demote_member(
    session: Session,
    *,
    contract: Contract,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    """Member → candidate: ``protocol_id`` cleared, nomination and witness
    history preserved (invariant 4). Witness revocation is the caller's step —
    this primitive only moves the stamp and marks the queues."""
    protocol_id = contract.protocol_id
    if protocol_id is None:
        return
    if contract.nominated_protocol_id is None:
        contract.nominated_protocol_id = protocol_id
    contract.protocol_id = None
    _mark_membership_dirty(session, protocol_id)
    logger.info(
        "member demoted to candidate",
        extra={
            "contract_id": contract.id,
            "protocol_id": protocol_id,
            "reason": reason,
            "evidence": evidence or {},
        },
    )


# ---------------------------------------------------------------------------
# Deployer trust ladder (spec §3.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeployerClassification:
    """Ladder verdict. ``trust_class`` is 'A'/'B', or None for Class C —
    which is the absence of a registry row, never a row (invariant 7)."""

    trust_class: str | None
    evidence: dict[str, Any]


def _member_ids_subquery(protocol_id: int):
    return select(Contract.id).where(Contract.protocol_id == protocol_id).scalar_subquery()


def _perimeter_fact(session: Session, *, protocol_id: int, address: str) -> dict[str, Any] | None:
    """A resolved principal fact placing *address* inside the protocol's proven
    control graph: a resolved controller value on a member, a function
    principal of a member, or a resolved Safe signer-set entry."""
    members = _member_ids_subquery(protocol_id)
    cv = session.execute(
        select(ControllerValue.contract_id, ControllerValue.controller_id)
        .where(ControllerValue.contract_id.in_(members), func.lower(ControllerValue.value) == address)
        .limit(1)
    ).first()
    if cv is not None:
        return {"kind": "controller_value", "contract_id": cv[0], "controller_id": cv[1]}
    fp = session.execute(
        select(FunctionPrincipal.id, FunctionPrincipal.function_id)
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(EffectiveFunction.contract_id.in_(members), func.lower(FunctionPrincipal.address) == address)
        .limit(1)
    ).first()
    if fp is not None:
        return {"kind": "function_principal", "function_principal_id": fp[0], "function_id": fp[1]}
    # Owner matching happens in Python so stored casing can never hide a
    # signer: the persisted owner strings are lowercased on read.
    safe_rows = session.execute(
        select(FunctionPrincipal.id, FunctionPrincipal.address, FunctionPrincipal.details)
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(
            EffectiveFunction.contract_id.in_(members),
            FunctionPrincipal.resolved_type == "safe",
            FunctionPrincipal.details.is_not(None),
        )
    ).all()
    for fp_id, safe_address, details in safe_rows:
        owners = details.get("owners") if isinstance(details, dict) else None
        if not isinstance(owners, list):
            continue
        if any(isinstance(owner, str) and owner.lower() == address for owner in owners):
            return {"kind": "safe_owner", "function_principal_id": fp_id, "safe_address": (safe_address or "").lower()}
    return None


def classify_deployer(
    session: Session,
    *,
    protocol_id: int,
    address: str,
    creation_history: Sequence[str] | None = None,
    history_complete: bool = False,
) -> DeployerClassification:
    """§3.3 trust-ladder verdict for one EOA. Reads only; ``register_deployer``
    writes the registry row for an A/B verdict.

    ``creation_history`` is the EOA's Etherscan-enumerated FULL creation list;
    ``history_complete=False`` (cap exceeded, not enumerated) can never reach
    Class B — DB-local exclusivity is absence of counterevidence, not proof.
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

    if creation_history is None or not history_complete:
        return DeployerClassification(
            trust_class=None,
            evidence={"reason": "no_complete_enumeration", "checked_at": checked_at},
        )

    corroborating = [
        row[0]
        for row in session.execute(
            select(ContractMembershipWitness.contract_id)
            .join(Contract, ContractMembershipWitness.contract_id == Contract.id)
            .where(
                Contract.protocol_id == protocol_id,
                func.lower(Contract.deployer) == addr,
                ContractMembershipWitness.protocol_id == protocol_id,
                ContractMembershipWitness.revoked_at.is_(None),
                ContractMembershipWitness.rule.in_(
                    [WITNESS_RULE_W2_STRUCTURAL, WITNESS_RULE_W3_CONTROL, WITNESS_RULE_W5_HUMAN]
                ),
            )
            .distinct()
        )
    ]
    if len(corroborating) < 2:
        return DeployerClassification(
            trust_class=None,
            evidence={
                "reason": "insufficient_nonlineage_corroboration",
                "corroborating_member_ids": sorted(corroborating),
                "checked_at": checked_at,
            },
        )

    created = {_require_address(a, "creation_history entry") for a in creation_history}
    known: set[str] = set()
    if created:
        known = {
            row[0].lower()
            for row in session.execute(
                select(Contract.address).where(
                    func.lower(Contract.address).in_(sorted(created)),
                    (Contract.protocol_id == protocol_id) | (Contract.nominated_protocol_id == protocol_id),
                )
            )
        }
    unmapped = sorted(created - known)
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
    return DeployerClassification(
        trust_class=DEPLOYER_TRUST_CLASS_B,
        evidence={
            "corroborating_member_ids": sorted(corroborating),
            "enumeration": {"count": len(created), "complete": True},
            "checked_at": checked_at,
        },
    )


def register_deployer(
    session: Session,
    *,
    protocol_id: int,
    address: str,
    classification: DeployerClassification,
) -> ProtocolDeployer:
    """Upsert the registry row for a Class A/B verdict. A Class C verdict may
    never produce a row (invariant 7) — raise instead of writing."""
    if classification.trust_class not in DEPLOYER_TRUST_CLASSES:
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


@dataclass(frozen=True)
class DemotionResult:
    revoked_witness_ids: tuple[int, ...] = ()
    demoted_contract_ids: tuple[int, ...] = ()
    #: Contracts whose corroboration probes must re-run after the demotion.
    reprobe_contract_ids: tuple[int, ...] = ()


def demote(session: Session, *, deployer_row: ProtocolDeployer, reason: str) -> DemotionResult:
    """Single-level deployer revocation (invariant 8): revoke the registry
    row, revoke its dependent W4 witnesses, demote exactly the members left
    with no unrevoked witness. Contracts to re-probe are returned; the
    recursive cascade to quiescence is ``_cascade_deployer_demotions``."""
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
            select(ContractMembershipWitness).where(
                ContractMembershipWitness.protocol_id == deployer_row.protocol_id,
                ContractMembershipWitness.rule == WITNESS_RULE_W4_DEPLOYER,
                ContractMembershipWitness.via_address == deployer_row.address,
                ContractMembershipWitness.revoked_at.is_(None),
            )
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
        remaining = active_witnesses(session, contract_id=contract_id, protocol_id=deployer_row.protocol_id)
        if any(row.rule in ADMITTING_WITNESS_RULES for row in remaining):
            continue
        contract = session.get(Contract, contract_id)
        if contract is None or contract.protocol_id != deployer_row.protocol_id:
            continue
        demote_member(
            session,
            contract=contract,
            reason=f"deployer_revoked:{reason}",
            evidence={"deployer_address": deployer_row.address, "revoked_witness_ids": revoked},
        )
        demoted.append(contract_id)
    result = DemotionResult(
        revoked_witness_ids=tuple(revoked),
        demoted_contract_ids=tuple(demoted),
        reprobe_contract_ids=tuple(demoted),
    )
    return _cascade_deployer_demotions(session, result)


def _cascade_deployer_demotions(session: Session, result: DemotionResult) -> DemotionResult:
    """Extension point (invariant 8, spec §3.2 witness invalidation): recursive
    via-fact invalidation to quiescence — a later lane. Single level passes through."""
    return result


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


@dataclass(frozen=True)
class PromotionResult:
    targeted_contract_ids: tuple[int, ...] = ()
    promoted_contract_ids: tuple[int, ...] = ()
    demoted_contract_ids: tuple[int, ...] = ()


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

    by_address = edge_addrs | pointer_addrs
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

    # Candidates whose PROBED reads resolved to an address that just became a
    # member or a fresh edge value (the probe persisted the resolved set for
    # exactly this lookup).
    perimeter_delta = sorted(edge_addrs | member_addrs)
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


def evaluate(session: Session, facts_delta: FactsDelta) -> PromotionResult:
    """Targeted gate check for one fact delta. Wave 0 delivers the candidate
    targeting; the stratified fixpoint is ``_stratified_fixpoint``."""
    targeted = _target_candidates(session, facts_delta)
    settled = _stratified_fixpoint(session, targeted)
    return PromotionResult(
        targeted_contract_ids=tuple(sorted(targeted)),
        promoted_contract_ids=settled.promoted_contract_ids,
        demoted_contract_ids=settled.demoted_contract_ids,
    )


def _stratified_fixpoint(session: Session, candidate_ids: set[int]) -> PromotionResult:
    """Extension point (spec §3.4 event 3): fixed-order rounds — (i)
    revocations to quiescence, (ii) deployer/perimeter reclassification,
    (iii) admissions — implemented by a later lane. Changes no state here."""
    return PromotionResult(targeted_contract_ids=tuple(sorted(candidate_ids)))


# ---------------------------------------------------------------------------
# Probe delegation (spec §3.5)
# ---------------------------------------------------------------------------


def probe(session: Session, contract: Contract) -> "ProbeResult":
    """Run the §3.5 corroboration probe for *contract* and persist its results."""
    from services.discovery.probes import run_probe

    return run_probe(session, contract)
