"""W3 transitivity: anchor chains, controller exclusivity, and via-fact re-verification (``_witness_fact_holds``)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select

from db.jsonb import jsonb_has_payload
from db.models import (
    ADMITTING_WITNESS_RULES,
    WITNESS_RULE_W1_CODE,
    WITNESS_RULE_W2_STRUCTURAL,
    WITNESS_RULE_W3_CONTROL,
    WITNESS_RULE_W4_DEPLOYER,
    WITNESS_RULE_W4_FACTORY,
    WITNESS_RULE_W4H_DEPLOYER_AFFINITY,
    WITNESS_RULE_W5_HUMAN,
    WITNESS_RULE_W6_LLAMA_SEED,
    Contract,
    ControllerValue,
    EffectiveFunction,
    FunctionPrincipal,
    RoleHolderPlane,
)
from services.clients.rpc import chain_id_for_chain_name

from .deployers import _heuristic_registry_row, _proof_registry_row
from .readers import (
    _address_proven_foreign,
    _chain_key,
    _controls_a_foreign_row,
    _d2_principal_facts,
    _has_controller_value,
    _has_nonlineage_witness,
    _member_factory_created,
    _member_factory_lineage,
    _member_rows_at,
    _perimeter_fact_candidates,
    _principal_perimeter_fact,
    _probe_controller_values,
    _w2_edge_holds,
    member_for_evidence,
)
from .rules import (
    _ADDRESS_RE,
    _ANCHOR_CHAIN_MAX_DEPTH,
    _ANCHOR_ROLE_NAMES,
    _DEFAULT_ADMIN_ROLE_HASH,
    _PROVEN_ROLE_NAME_BASES,
    W2_HEURISTIC_VIA_KEY,
    W2_SAME_CONTRACT_EDGE_KINDS,
    W3_CONTROLLER_PROVENANCE,
    W3_D2_SOURCES,
    W3_DIRECTION_D1,
    W3_DIRECTION_D2,
    W3_SET_VALUED_LINK_KINDS,
    active_witnesses,
    witness_is_heuristic,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TransitivityProof:
    """Which arm proved a W3-D1 via transitive; ``anchor_chain`` or ``principal_fact`` set accordingly."""

    arm: str
    anchor_chain: dict[str, Any] | None = None
    principal_fact: dict[str, Any] | None = None


def _via_transitivity(
    session: Session,
    *,
    protocol_id: int,
    via_address: str,
    chain_key: str,
    exclude_contract_id: int | None = None,
    in_progress: frozenset[str] = frozenset(),
    depth: int = 0,
) -> TransitivityProof | None:
    """W3-D1: the via is transitive if it's a member through an independent witness (w2/w4/w5/w6 or w3-d1); or a
    D2 controller proven exclusive; or (spec extension, ``_anchor_chain_for``) a D2-only member controller whose
    own controllers root in the anchored perimeter; or (owner ruling) a perimeter-principal EOA of an anchoring
    member.

    Strongest arm first so re-derivation is stable. Every arm is monotone in the member set, so the
    fixpoint can't oscillate. The candidate never counts toward its own license.
    """
    if via_address in in_progress:
        return None
    for member in _member_rows_at(session, protocol_id=protocol_id, address=via_address, chain_key=chain_key):
        rows = active_witnesses(session, contract_id=member.id, protocol_id=protocol_id)
        has_d2 = False
        for row in rows:
            if row.rule not in ADMITTING_WITNESS_RULES or witness_is_heuristic(row):
                continue
            if row.rule != WITNESS_RULE_W3_CONTROL:
                return TransitivityProof("independent_witness")
            direction = row.evidence.get("direction") if isinstance(row.evidence, dict) else None
            if direction == W3_DIRECTION_D1:
                return TransitivityProof("independent_witness")
            has_d2 = True
        if not has_d2:
            continue
        if _controller_is_exclusive(
            session,
            protocol_id=protocol_id,
            controller_address=via_address,
            chain_key=chain_key,
            exclude_contract_ids={member.id} | ({exclude_contract_id} if exclude_contract_id is not None else set()),
        ):
            return TransitivityProof("d2_exclusive")
        chain = _anchor_chain_for(
            session,
            protocol_id=protocol_id,
            controller=member,
            chain_key=chain_key,
            in_progress=in_progress | {via_address},
            depth=depth,
        )
        if chain is not None:
            return TransitivityProof("anchor_chain", chain)
    fact = _principal_perimeter_fact(
        session,
        protocol_id=protocol_id,
        address=via_address,
        chain_key=chain_key,
        exclude_contract_id=exclude_contract_id,
    )
    if fact is None:
        return None
    # shared-operator warning as positive counterevidence: a perimeter principal controlling a provably foreign row
    # licenses nothing.
    if _address_proven_foreign(session, protocol_id=protocol_id, address=via_address):
        logger.info(
            "perimeter-principal transitivity refused: via is proven foreign",
            extra={"protocol_id": protocol_id, "via": via_address},
        )
        return None
    if _controls_a_foreign_row(session, protocol_id=protocol_id, controller_address=via_address):
        return None
    return TransitivityProof("perimeter_principal", principal_fact=fact)


@dataclass(frozen=True)
class _ControllerLink:
    kind: str
    address: str
    detail: str | None

    def as_evidence(self, *, from_address: str) -> dict[str, Any]:
        return {"from": from_address, "address": self.address, "kind": self.kind, "detail": self.detail}


def _role_hash_anchors(plane: RoleHolderPlane) -> bool:
    """Whether this plane row is an upgrade/admin-class role: DEFAULT_ADMIN_ROLE (zero word) or a keccak-proven
    ``role_name``. A NULL holder set contributes nothing.
    """
    if not isinstance(plane.holders, list) or not plane.holders:
        return False
    if (plane.role_hash or "").lower() == _DEFAULT_ADMIN_ROLE_HASH:
        return True
    return plane.role_name in _ANCHOR_ROLE_NAMES and plane.role_name_basis in _PROVEN_ROLE_NAME_BASES


def _own_controller_links(session: Session, *, protocol_id: int, controller: Contract) -> list[_ControllerLink]:
    """The resolved controllers of *controller*: the three W3 sources plus admin-class AccessControl role holders and
    Safe signers. Sorted; self-references and the zero address dropped.
    """
    own = (controller.address or "").lower()
    links: dict[tuple[str, str, str | None], _ControllerLink] = {}

    def add(kind: str, address: Any, detail: str | None) -> None:
        if not isinstance(address, str) or not _ADDRESS_RE.match(address):
            return
        addr = address.lower()
        if addr == own or int(addr, 16) == 0:
            return
        links[(kind, addr, detail)] = _ControllerLink(kind=kind, address=addr, detail=detail)

    for (value,) in session.execute(
        select(ControllerValue.value)
        .where(
            ControllerValue.contract_id == controller.id,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
        )
        .distinct()
    ):
        add("owner_or_authority", value, "controller_values")
    add("proxy_admin", controller.admin, "proxy_admin_slot")
    for value in sorted(_probe_controller_values(session, controller)):
        add("probe_read", value, "probe")

    chain_id = chain_id_for_chain_name(controller.chain)
    if chain_id is not None and own:
        for plane in session.execute(
            select(RoleHolderPlane)
            .where(RoleHolderPlane.chain_id == chain_id, func.lower(RoleHolderPlane.registry_address) == own)
            .order_by(RoleHolderPlane.role_hash)
        ).scalars():
            if not _role_hash_anchors(plane):
                continue
            for holder in plane.holders or []:
                add("role_holder", holder, (plane.role_hash or "").lower())

    if own:
        # Signer sets read from this protocol's members only (not demoted rows), newest row winning.
        for details, member_id in session.execute(
            select(FunctionPrincipal.details, Contract.id)
            .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
            .join(Contract, EffectiveFunction.contract_id == Contract.id)
            .where(
                func.lower(FunctionPrincipal.address) == own,
                FunctionPrincipal.resolved_type == "safe",
                jsonb_has_payload(FunctionPrincipal.details),
                Contract.protocol_id == protocol_id,
            )
            .order_by(FunctionPrincipal.id.desc())
        ):
            if not member_for_evidence(session, contract_id=member_id, protocol_id=protocol_id):
                continue
            owners = details.get("owners") if isinstance(details, dict) else None
            if isinstance(owners, list):
                for owner in owners:
                    add("safe_signer", owner, own)
            break

    return sorted(links.values(), key=lambda link: (link.kind, link.address, link.detail or ""))


def _independent_anchor_rule(
    session: Session,
    *,
    contract_id: int,
    protocol_id: int,
    blocked: frozenset[str],
    depth: int = 0,
) -> str | None:
    """The rule by which this member is anchored independently of *blocked*, the anchor-chain cycle break.

    W3-D2 never anchors; W5/W6 anchor outright; W2/W3-D1 only via an independently anchored member. Smallest rule name
    wins.
    """
    contract = session.get(Contract, contract_id)
    if contract is None:
        return None
    chain_key = _chain_key(contract.chain)
    anchoring: set[str] = set()
    for row in sorted(active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id), key=lambda r: r.id):
        if row.rule not in ADMITTING_WITNESS_RULES or row.rule in anchoring or witness_is_heuristic(row):
            continue
        evidence = row.evidence if isinstance(row.evidence, dict) else {}
        if row.rule == WITNESS_RULE_W3_CONTROL and evidence.get("direction") != W3_DIRECTION_D1:
            continue
        via = (row.via_address or "").lower()
        if not via:
            anchoring.add(row.rule)
            continue
        if via in blocked:
            continue
        if row.rule == WITNESS_RULE_W4_DEPLOYER:
            anchoring.add(row.rule)
            continue
        if depth >= _ANCHOR_CHAIN_MAX_DEPTH:
            continue
        for member in _member_rows_at(session, protocol_id=protocol_id, address=via, chain_key=chain_key):
            if member.id == contract_id:
                continue
            if (
                _independent_anchor_rule(
                    session,
                    contract_id=member.id,
                    protocol_id=protocol_id,
                    blocked=blocked | {via},
                    depth=depth + 1,
                )
                is not None
            ):
                anchoring.add(row.rule)
                break
    return min(anchoring) if anchoring else None


def _perimeter_anchor(session: Session, *, protocol_id: int, address: str, blocked: frozenset[str]) -> str | None:
    """The anchor-chain arm's perimeter reading: narrower than the ladder's (the member must anchor independently of
    *blocked*, and ``safe_owner`` never anchors). Returns the anchoring rule, or None.
    """
    for fact, member_id in _perimeter_fact_candidates(session, protocol_id=protocol_id, address=address):
        if fact.get("kind") == "safe_owner":
            continue
        rule = _independent_anchor_rule(session, contract_id=member_id, protocol_id=protocol_id, blocked=blocked)
        if rule is not None:
            return rule
    return None


def _link_root(
    session: Session,
    *,
    protocol_id: int,
    address: str,
    chain_key: str,
    in_progress: frozenset[str],
    depth: int,
    require_member_terminal: bool,
) -> dict[str, Any] | None:
    """Where a controller link terminates: an independently anchored member, a perimeter principal of one, or
    recursively a D2-only member controller that anchors. Returns the chain suffix, or None.

    ``require_member_terminal`` binds set-valued links to a member anchor, and the element itself must be an
    independently anchored member.
    """
    for member in _member_rows_at(session, protocol_id=protocol_id, address=address, chain_key=chain_key):
        rule = _independent_anchor_rule(session, contract_id=member.id, protocol_id=protocol_id, blocked=in_progress)
        if rule is not None:
            return {"links": [], "anchor_address": address, "anchor_kind": "member", "anchor_rule": rule}
    if not require_member_terminal:
        anchor = _perimeter_anchor(session, protocol_id=protocol_id, address=address, blocked=in_progress)
        if anchor is not None:
            return {
                "links": [],
                "anchor_address": address,
                "anchor_kind": "perimeter_principal",
                "anchor_rule": anchor,
            }
    if require_member_terminal or depth + 1 >= _ANCHOR_CHAIN_MAX_DEPTH:
        # A set element here is a D2-only member, which isn't an anchor.
        return None
    for member in _member_rows_at(session, protocol_id=protocol_id, address=address, chain_key=chain_key):
        nested = _anchor_chain_for(
            session,
            protocol_id=protocol_id,
            controller=member,
            chain_key=chain_key,
            in_progress=in_progress | {address},
            depth=depth + 1,
        )
        if nested is not None:
            return nested
    return None


def _anchor_chain_for(
    session: Session,
    *,
    protocol_id: int,
    controller: Contract,
    chain_key: str,
    in_progress: frozenset[str],
    depth: int,
) -> dict[str, Any] | None:
    """Controller-chain extension: a D2-only member controller is transitive when at least one of its own
    controller links
    roots in the anchored perimeter, none is proven foreign, and it controls no foreign row. Set-valued links root
    only at member anchors. Returns the anchor-chain evidence, or None.
    """
    if depth >= _ANCHOR_CHAIN_MAX_DEPTH:
        return None
    own = (controller.address or "").lower()
    links = _own_controller_links(session, protocol_id=protocol_id, controller=controller)
    if not links:
        return None
    for link in links:
        if _address_proven_foreign(session, protocol_id=protocol_id, address=link.address):
            logger.info(
                "anchor chain refused: controller set names a foreign address",
                extra={"protocol_id": protocol_id, "controller": own, "foreign_link": link.address},
            )
            return None
    for link in links:
        if link.address in in_progress:
            continue
        root = _link_root(
            session,
            protocol_id=protocol_id,
            address=link.address,
            chain_key=chain_key,
            in_progress=in_progress,
            depth=depth,
            require_member_terminal=link.kind in W3_SET_VALUED_LINK_KINDS,
        )
        if root is None:
            continue
        if _controls_a_foreign_row(session, protocol_id=protocol_id, controller_address=own):
            return None
        return {
            "links": [link.as_evidence(from_address=own), *root["links"]],
            "anchor_address": root["anchor_address"],
            "anchor_kind": root["anchor_kind"],
            "anchor_rule": root["anchor_rule"],
        }
    return None


def _controller_is_exclusive(
    session: Session,
    *,
    protocol_id: int,
    controller_address: str,
    chain_key: str,
    exclude_contract_ids: set[int],
) -> bool:
    """Shared-operator kill: every contract the controller is observed controlling on its chain maps into
    this protocol's member/candidate set, with at least one proven member (heuristic-only members are tolerated
    but never the proof). Any foreign or unclaimed observation refuses. ``call_target``/NULL rows aren't control
    observations.
    """
    chain_scope = func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key
    controlled: dict[int, Contract] = {}
    for row in session.execute(
        select(Contract)
        .join(ControllerValue, ControllerValue.contract_id == Contract.id)
        .where(
            func.lower(ControllerValue.value) == controller_address,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
            chain_scope,
        )
        .distinct()
    ).scalars():
        controlled[row.id] = row
    for row in session.execute(
        select(Contract).where(func.lower(Contract.admin) == controller_address, chain_scope)
    ).scalars():
        controlled[row.id] = row
    member_seen = False
    for cid in sorted(controlled):
        if cid in exclude_contract_ids:
            continue
        row = controlled[cid]
        if (row.address or "").lower() == controller_address:
            continue
        if row.protocol_id == protocol_id:
            if member_for_evidence(session, contract_id=row.id, protocol_id=protocol_id):
                member_seen = True
            continue
        # F1: candidates count only with real evidence.
        if (
            row.protocol_id is None
            and row.nominated_protocol_id == protocol_id
            and _has_nonlineage_witness(session, contract_id=row.id, protocol_id=protocol_id)
        ):
            continue
        # Children of the protocol's own member factory are protocol-family, not foreign.
        if _member_factory_created(session, protocol_id=protocol_id, contract=row):
            continue
        return False
    return member_seen


def _witness_fact_holds(
    session: Session,
    *,
    contract: Contract,
    protocol_id: int,
    rule: str,
    evidence: Any,
    via_address: str | None,
) -> bool:
    """Whether this witness's via-fact still holds. W1, W5 and W6 have none and hold as recorded."""
    if rule in (WITNESS_RULE_W1_CODE, WITNESS_RULE_W5_HUMAN, WITNESS_RULE_W6_LLAMA_SEED):
        return True
    evidence = evidence if isinstance(evidence, dict) else {}
    via = (via_address or "").lower()
    if rule == WITNESS_RULE_W4_DEPLOYER:
        if not via or (contract.deployer or "").lower() != via:
            return False
        return _proof_registry_row(session, protocol_id=protocol_id, address=via) is not None
    if rule == WITNESS_RULE_W4H_DEPLOYER_AFFINITY:
        # A heuristic witness holds while its H row is unrevoked; freezing only stops new admissions.
        if not via or (contract.deployer or "").lower() != via:
            return False
        return _heuristic_registry_row(session, protocol_id=protocol_id, address=via) is not None
    if rule == WITNESS_RULE_W4_FACTORY:
        # Re-derived: the attribution must still name this factory, which must still anchor.
        if not via:
            return False
        return _member_factory_lineage(session, protocol_id=protocol_id, contract=contract, factory=via) is not None
    chain_key = _chain_key(contract.chain)
    if rule == WITNESS_RULE_W2_STRUCTURAL:
        member = session.get(Contract, evidence.get("member_contract_id"))
        if member is None or member.protocol_id != protocol_id or _chain_key(member.chain) != chain_key:
            return False
        if evidence.get(W2_HEURISTIC_VIA_KEY) is True:
            # re-verified without the evidence-membership test, but only for same-contract edges.
            if evidence.get("edge_kind") not in W2_SAME_CONTRACT_EDGE_KINDS:
                return False
        elif not member_for_evidence(session, contract_id=member.id, protocol_id=protocol_id):
            return False
        return _w2_edge_holds(
            session, contract=contract, member=member, edge_kind=evidence.get("edge_kind"), evidence=evidence
        )
    if rule == WITNESS_RULE_W3_CONTROL:
        if not via:
            return False
        direction = evidence.get("direction")
        source = evidence.get("source")
        addr = (contract.address or "").lower()
        if direction == W3_DIRECTION_D2:
            if source == "function_principal":
                # F2 re-checked here: a host demoted to D2-only stops anchoring, and its principal facts fall (invariant
                # 8).
                return any(
                    member.address and member.address.lower() == via
                    for member, _fact in _d2_principal_facts(
                        session,
                        protocol_id=protocol_id,
                        address=addr,
                        chain_key=chain_key,
                        exclude_contract_id=contract.id,
                    )
                )
            if source not in W3_D2_SOURCES:
                return False
            for member in _member_rows_at(session, protocol_id=protocol_id, address=via, chain_key=chain_key):
                if member.id == contract.id:
                    continue
                if source == "proxy_admin_slot" and (member.admin or "").lower() == addr:
                    return True
                if source == "probe" and addr in _probe_controller_values(session, member):
                    return True
            return False
        if direction == W3_DIRECTION_D1:
            proof = _via_transitivity(
                session,
                protocol_id=protocol_id,
                via_address=via,
                chain_key=chain_key,
                exclude_contract_id=contract.id,
            )
            if proof is None:
                return False
            recorded = evidence.get("anchor_chain")
            recorded_principal = evidence.get("principal_fact")
            # A published proof must still be citable as-is; a different arm, anchor or host is a new fact to re-derive.
            if proof.arm == "anchor_chain":
                if recorded_principal is not None:
                    return False
                assert proof.anchor_chain is not None
                if isinstance(recorded, dict) and proof.anchor_chain.get("anchor_address") != recorded.get(
                    "anchor_address"
                ):
                    return False
            elif proof.arm == "perimeter_principal":
                if recorded is not None:
                    return False
                assert proof.principal_fact is not None
                if isinstance(recorded_principal, dict) and proof.principal_fact.get(
                    "member_contract_id"
                ) != recorded_principal.get("member_contract_id"):
                    return False
            elif recorded is not None or recorded_principal is not None:
                return False
            if source == "controller_values":
                return _has_controller_value(session, contract_id=contract.id, value=via)
            if source == "proxy_admin_slot":
                return (contract.admin or "").lower() == via
            if source == "probe":
                return via in _probe_controller_values(session, contract)
            return False
        return False
    return False
