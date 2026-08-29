"""W3 transitivity: anchor chains, controller exclusivity, and via-fact
re-verification (``_witness_fact_holds``)."""

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
    """Which §3.2 arm proved a W3-D1 via transitive. ``anchor_chain`` is set
    only for the anchored-authority-chain arm; ``principal_fact`` only for the
    §3.3 perimeter-principal arm."""

    arm: str
    anchor_chain: dict[str, Any] | None = None
    principal_fact: dict[str, Any] | None = None


def _via_is_transitive(
    session: Session,
    *,
    protocol_id: int,
    via_address: str,
    chain_key: str,
    exclude_contract_id: int | None = None,
) -> bool:
    return (
        _via_transitivity(
            session,
            protocol_id=protocol_id,
            via_address=via_address,
            chain_key=chain_key,
            exclude_contract_id=exclude_contract_id,
        )
        is not None
    )


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
    """§3.2 W3-D1: TRANSITIVE ⇔ the via is a member through an INDEPENDENT
    witness (w2/w4/w5/w6 or w3-d1), or a D2 controller proven exclusive —
    every contract it is observed to control belongs to this protocol — or
    (spec §3.2 EXTENSION, see ``_anchor_chain_for``) a D2-only member
    controller whose OWN resolved controllers root in the protocol's
    independently anchored perimeter — or (owner ruling, salvage wave) a
    resolved perimeter-principal EOA of an anchoring member, the same §3.3
    Class-A inference already accepted for deployer EOAs.

    Arms are tried strongest-first and the principal arm last, so a via that
    gains a stronger proof publishes the stronger one and re-derivation is
    stable across rounds (invariant 9). Every arm is MONOTONE in the member set
    — growing it can add transitivity, never withdraw it — which is what keeps
    the fixpoint from oscillating a candidate between promoted and demoted.

    The candidate under evaluation never counts toward its own license."""
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
    # §3.2's shared-operator warning applied as POSITIVE counterevidence rather
    # than as a positive-exclusivity requirement (which absence of foreign rows
    # could never supply): a perimeter principal observed controlling a row
    # that provably belongs elsewhere licenses nothing here.
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
    """One resolved controller of a controller, controller-type-agnostic."""

    kind: str
    address: str
    detail: str | None

    def as_evidence(self, *, from_address: str) -> dict[str, Any]:
        return {"from": from_address, "address": self.address, "kind": self.kind, "detail": self.detail}


def _role_hash_anchors(plane: RoleHolderPlane) -> bool:
    """Is this plane row an UPGRADE/ADMIN-class role? Keyed off role IDENTITY:
    DEFAULT_ADMIN_ROLE is the zero word, everything else needs a keccak-proven
    ``role_name`` (``db/models/roles.py`` — a name nobody proved keys nothing).
    A withheld ``holders`` (NULL) is not_determined and contributes nothing."""
    if not isinstance(plane.holders, list) or not plane.holders:
        return False
    if (plane.role_hash or "").lower() == _DEFAULT_ADMIN_ROLE_HASH:
        return True
    return plane.role_name in _ANCHOR_ROLE_NAMES and plane.role_name_basis in _PROVEN_ROLE_NAME_BASES


def _own_controller_links(session: Session, *, protocol_id: int, controller: Contract) -> list[_ControllerLink]:
    """The resolved controllers of *controller* itself, from the three W3
    sources already codified (caller-gating controller values, the proxy-admin
    slot, §3.5 probe reads) plus two set-valued authorities: AccessControl role
    holders of an upgrade/admin-class role on this registry, and the signer set
    of a Safe. Deterministic (sorted); self-references and the zero address are
    dropped — they name no separate authority."""
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
        # The Safe under evaluation is the LINK: its signer set is its own
        # controller set. Read off this protocol's MEMBERS only — a demoted
        # row's stale analysis is not this protocol's observation — and the
        # NEWEST such row wins, so a re-analysis supersedes what it replaced.
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
    """The admitting rule by which this member is anchored INDEPENDENTLY of
    every address in *blocked* — the anchor-chain arm's cycle break. W3-D2
    never anchors (§3.2 non-transitivity); W5/W6 rest on no via-fact at all and
    anchor outright; W2/W3-D1 anchor only when their via names a member that is
    itself independently anchored, so a chain cannot bootstrap itself through a
    hop resting on the address under evaluation.

    Of several anchoring witnesses the SMALLEST rule name wins, not the oldest
    row: the published rule is then a function of the evidence set, not of the
    order the rows were written (invariant 9)."""
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
    """The anchor-chain arm's reading of the same observations, narrower than
    the §3.3 ladder's on two counts: the anchoring member must be anchored
    INDEPENDENTLY of *blocked*, and a ``safe_owner`` fact never anchors — only
    the ladder, which names signer-set entries explicitly, reads those.
    Returns the anchoring member's admitting rule, or None."""
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
    """Where a controller link terminates: an independently anchored member at
    *address*, a §3.3 perimeter principal of such a member, or — recursively —
    a D2-only member controller that itself anchors through its own
    controllers. Returns the chain suffix (links already walked stay with the
    caller), or None when the link roots nowhere.

    ``require_member_terminal`` binds a set-valued link (:data:`W3_SET_VALUED_LINK_KINDS`)
    to an anchor of kind ``member``. It binds the ELEMENT as well as the
    terminal: the element must itself be an independently anchored member, so
    the recursive branch demands exactly what the direct branch does and a set
    element cannot enter the walk on a D2-only entry."""
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
        # A set element that reached here is a D2-only member (the direct
        # branch above already refused it), which is not an anchor.
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
    """Spec §3.2 EXTENSION (deliberate; the owner folds it into the spec text).

    A D2-only member controller is TRANSITIVE when its own resolved
    controllers root in this protocol's independently anchored perimeter:
    ≥1 link roots, no link is proven foreign, and the controller is observed
    controlling no foreign row. A SET-valued link
    (:data:`W3_SET_VALUED_LINK_KINDS`) roots only at an anchor of kind
    ``member``.

    Returns the anchor-chain evidence, or None."""
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
    """Shared-operator kill (spec §3.2): every contract the controller is
    observed to control (caller-gating resolved controller values +
    proxy-admin pointers) maps into this protocol's member/candidate set, with
    ≥1 member proven under ``member_for_evidence`` — a heuristic-only member
    is not_determined: tolerated as protocol-family, never the mandatory
    proof (DEPLOYER_HEURISTIC_SPEC.md §9 invariant 3). Control is observed on
    a deployment, and a deployment is (address, chain), so the controlled set
    is scoped to the controller's chain (same NULL≡'ethereum' convention as
    ``_member_rows_at``). Any foreign or unclaimed observation refuses —
    revocable, mirroring Class B. A ``call_target``/NULL-provenance row is not
    an observation of control, so it neither licenses nor refuses here."""
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
        # F1: a candidate tolerates the exclusivity check only with real
        # membership evidence — a bare nomination proves nothing.
        if (
            row.protocol_id is None
            and row.nominated_protocol_id == protocol_id
            and _has_nonlineage_witness(session, contract_id=row.id, protocol_id=protocol_id)
        ):
            continue
        # Member-factory rule (§3.3 deviation): a child of the protocol's own
        # member factory is a protocol-family observation, not a foreign one.
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
    """Does the via-fact this witness rests on still hold? W1 (block-stamped
    probe), W5 (attributed assertion) and W6 (externally revocable seed) have
    no via-fact and hold as recorded."""
    if rule in (WITNESS_RULE_W1_CODE, WITNESS_RULE_W5_HUMAN, WITNESS_RULE_W6_LLAMA_SEED):
        return True
    evidence = evidence if isinstance(evidence, dict) else {}
    via = (via_address or "").lower()
    if rule == WITNESS_RULE_W4_DEPLOYER:
        if not via or (contract.deployer or "").lower() != via:
            return False
        return _proof_registry_row(session, protocol_id=protocol_id, address=via) is not None
    if rule == WITNESS_RULE_W4H_DEPLOYER_AFFINITY:
        # A standing heuristic witness holds while its H registry row is
        # UNREVOKED (DEPLOYER_HEURISTIC_SPEC.md §5): a frozen or suspended row
        # stops new admissions and flags, it does not de-stamp what stands.
        if not via or (contract.deployer or "").lower() != via:
            return False
        return _heuristic_registry_row(session, protocol_id=protocol_id, address=via) is not None
    if rule == WITNESS_RULE_W4_FACTORY:
        # Re-derived, never trusted: the stored attribution must still name
        # this factory AND the factory must still be an anchoring member —
        # its demotion is what revokes this witness (invariant 8).
        if not via:
            return False
        return _member_factory_lineage(session, protocol_id=protocol_id, contract=contract, factory=via) is not None
    chain_key = _chain_key(contract.chain)
    if rule == WITNESS_RULE_W2_STRUCTURAL:
        member = session.get(Contract, evidence.get("member_contract_id"))
        if member is None or member.protocol_id != protocol_id or _chain_key(member.chain) != chain_key:
            return False
        if evidence.get(W2_HEURISTIC_VIA_KEY) is True:
            # §6 exception: the via is a heuristic member, so the edge is
            # re-verified without the evidence-membership test — but only for a
            # same-contract edge kind, which ``w2_evidence`` already pins.
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
                # F2 is re-checked here, not only at derivation: a hosting
                # member demoted to a D2-only entry stops anchoring, and the
                # principal fact it hosts must fall with it (invariant 8).
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
            # A witness that PUBLISHED a proof must still be able to cite it: a
            # re-proof by a different arm, at a different anchor, or off a
            # different hosting member is a different fact and gets re-derived
            # with its own evidence (invariant 8).
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
