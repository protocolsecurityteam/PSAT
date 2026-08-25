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
from typing import TYPE_CHECKING, Any, Callable, Literal, Mapping, Sequence

from sqlalchemy import Text, case, cast, false, func, or_, select, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert

from db.jsonb import jsonb_has_payload
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
    Protocol,
    ProtocolDeployer,
    RoleHolderPlane,
    UpgradeEvent,
)
from services.clients.rpc import chain_id_for_chain_name
from utils.chains import UnknownChainError, canonical_chain, chain_by_id
from utils.logging import record_degraded

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from services.discovery.deployer_enumeration import DeployerCreation
    from services.discovery.probes import ProbeResult

logger = logging.getLogger(__name__)

MembershipState = Literal["member", "candidate", "pruned", "unclaimed"]

#: One reason string for both dirty queues: a promotion/demotion changed the
#: member set that enrollment and the score fold read (spec §5.2).
MEMBERSHIP_DIRTY_REASON = "membership_change"

#: The DefiLlama worker's ``discovery_sources`` tag — the W6 provenance key.
DEFILLAMA_SOURCE_TAG = "defillama"

# W2 edge kinds — each names a verified structural link against STORED
# resolution, never a bare ``relationship_type`` (spec §3.2, invariant 6).
# ``historical_implementation`` verifies against the member proxy's stored
# ``UpgradeEvent`` rows (the observed upgrade tx rides in the evidence).
W2_EDGE_KINDS = frozenset(
    {"implementation", "proxy", "beacon", "proxy_admin", "secondary_implementation", "historical_implementation"}
)

W3_DIRECTION_D1 = "d1"
W3_DIRECTION_D2 = "d2"
# Where a W3 edge may come from (spec §3.2): resolved controller values, a
# resolved proxy-admin slot, or a §3.5 probe read. Never "appears in a
# member's control graph".
W3_SOURCES = frozenset({"controller_values", "proxy_admin_slot", "probe"})

#: Non-lineage witness rules — evidence a row BELONGS beyond deployer lineage.
#: A bare nomination or a W4-only row is NOT evidence of belonging: §3.3's
#: literal "member/candidate set" wording is deliberately narrowed here
#: (owner ruling) to uphold §0 — an LLM-sourced nomination must never convert
#: a shared deployer's foreign creation into exclusivity corroboration.
NONLINEAGE_WITNESS_RULES = frozenset(
    {WITNESS_RULE_W2_STRUCTURAL, WITNESS_RULE_W3_CONTROL, WITNESS_RULE_W5_HUMAN, WITNESS_RULE_W6_LLAMA_SEED}
)

#: The one ``ControllerValue.authority_provenance`` that is a control edge
#: (invariant 6): the value gates callers. ``call_target`` is an integration
#: operand (nativeWrapper, endpoint, stETH — the WETH9/EndpointV2/Lido
#: overreach shape), and NULL provenance is not-determined — neither may
#: stand in for a W3 witness, a perimeter fact, or an exclusivity
#: observation. Probe reads (§3.5 owner/authority/admin slots) are
#: caller-gating by construction and carry no provenance column.
W3_CONTROLLER_PROVENANCE = "caller_gate"

#: Anchor-chain link kinds (spec §3.2 extension, see ``_own_controller_links``).
W3_ANCHOR_LINK_KINDS = frozenset({"owner_or_authority", "proxy_admin", "probe_read", "role_holder", "safe_signer"})

#: How an anchor-chain terminates: at a member holding a non-D2 admitting
#: witness, or at a §3.3 perimeter principal of such a member.
W3_ANCHOR_KINDS = frozenset({"member", "perimeter_principal"})

#: Link kinds that name a SET of keys rather than one authority. A set-valued
#: link may terminate only at an independently anchored MEMBER: membership of
#: such a set is affiliation, and affiliation is not control.
W3_SET_VALUED_LINK_KINDS = frozenset({"role_holder", "safe_signer"})

#: OZ ``AccessControl``'s DEFAULT_ADMIN_ROLE is the zero word — the one role
#: identity provable from the hash alone.
_DEFAULT_ADMIN_ROLE_HASH = "0x" + "0" * 64

#: Role names that name an UPGRADE/ADMIN-class authority over a registry.
#: Read only off a keccak-proven ``role_name`` (``role_name_basis``) — a name
#: nobody proved a preimage for keys nothing (``db/models/roles.py``).
_ANCHOR_ROLE_NAMES = frozenset({"DEFAULT_ADMIN_ROLE", "PROPOSER_ROLE", "TIMELOCK_ADMIN_ROLE"})
_PROVEN_ROLE_NAME_BASES = frozenset({"keccak_preimage", "accesscontrol_default_admin_literal"})

#: Defensive bound on the anchor-chain walk; the in-progress set already makes
#: it terminate, so exceeding this is a bug, never load.
_ANCHOR_CHAIN_MAX_DEPTH = 8

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ROLE_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

#: The ONE ``detail`` each singleton link kind may carry — the W3 source it
#: was read from. Set-valued kinds carry an identity instead (role hash /
#: Safe address), checked by shape.
_LINK_DETAIL_BY_KIND = {
    "owner_or_authority": "controller_values",
    "proxy_admin": "proxy_admin_slot",
    "probe_read": "probe",
}

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
    upgrade_tx_hash: str | None = None,
) -> dict[str, Any]:
    """W2 structural edge, verified against stored resolution (the pointer the
    member's own row carries), never a bare ``relationship_type``.
    ``upgrade_tx_hash`` belongs to ``historical_implementation`` only — the
    upgrade tx the stored ``UpgradeEvent`` row observed (may be unrecorded)."""
    if edge_kind not in W2_EDGE_KINDS:
        raise ValueError(f"edge_kind must be one of {sorted(W2_EDGE_KINDS)}, got {edge_kind!r}")
    evidence: dict[str, Any] = {
        "edge_kind": edge_kind,
        "member_contract_id": _require_positive_int(member_contract_id, "member_contract_id"),
        "member_address": _require_address(member_address, "member_address"),
        "resolved_pointer": _require_address(resolved_pointer, "resolved_pointer"),
    }
    if edge_kind == "historical_implementation":
        if upgrade_tx_hash is not None:
            if not isinstance(upgrade_tx_hash, str) or not re.match(r"^0x[0-9a-fA-F]{64}$", upgrade_tx_hash):
                raise ValueError(f"upgrade_tx_hash must be a 32-byte hex hash, got {upgrade_tx_hash!r}")
            evidence["upgrade_tx_hash"] = upgrade_tx_hash.lower()
        else:
            evidence["upgrade_tx_hash"] = None
    elif upgrade_tx_hash is not None:
        raise ValueError("upgrade_tx_hash is historical_implementation evidence only")
    return evidence


def _anchor_chain_evidence(anchor_chain: Any) -> dict[str, Any]:
    """Canonicalize the anchor-chain proof carried by a D1 witness: the ordered
    links walked from the via out to the terminal anchor, plus that anchor and
    the witness rule anchoring it. Rebuilt field-for-field so the round-trip is
    exact and two runs over the same facts emit identical evidence."""
    if not isinstance(anchor_chain, Mapping):
        raise ValueError("anchor_chain must be a mapping")
    raw_links = anchor_chain.get("links")
    if not isinstance(raw_links, (list, tuple)) or not raw_links:
        raise ValueError("anchor_chain.links must be a non-empty list")
    links: list[dict[str, Any]] = []
    for raw in raw_links:
        if not isinstance(raw, Mapping):
            raise ValueError("anchor_chain link must be a mapping")
        kind = raw.get("kind")
        if kind not in W3_ANCHOR_LINK_KINDS:
            raise ValueError(f"anchor_chain link kind must be one of {sorted(W3_ANCHOR_LINK_KINDS)}, got {kind!r}")
        detail = raw.get("detail")
        # The detail is a closed set per kind, never free text: it is the W3
        # source or the identity the link was read under.
        if kind in _LINK_DETAIL_BY_KIND:
            if detail != _LINK_DETAIL_BY_KIND[kind]:
                raise ValueError(f"anchor_chain {kind} detail must be {_LINK_DETAIL_BY_KIND[kind]!r}, got {detail!r}")
        elif kind == "role_holder":
            if not isinstance(detail, str) or not _ROLE_HASH_RE.match(detail) or detail != detail.lower():
                raise ValueError(f"anchor_chain role_holder detail must be a lowercase role hash, got {detail!r}")
        elif kind == "safe_signer":
            detail = _require_address(detail, "anchor_chain safe_signer detail")
        else:
            raise ValueError(f"no detail rule for anchor_chain link kind {kind!r}")
        link = {
            "from": _require_address(raw.get("from"), "anchor_chain link from"),
            "address": _require_address(raw.get("address"), "anchor_chain link address"),
            "kind": kind,
            "detail": detail,
        }
        if set(raw) != set(link):
            raise ValueError("anchor_chain link has unexpected fields")
        links.append(link)
    anchor_kind = anchor_chain.get("anchor_kind")
    if anchor_kind not in W3_ANCHOR_KINDS:
        raise ValueError(f"anchor_kind must be one of {sorted(W3_ANCHOR_KINDS)}, got {anchor_kind!r}")
    anchor_rule = anchor_chain.get("anchor_rule")
    if anchor_rule not in ADMITTING_WITNESS_RULES:
        raise ValueError(f"anchor_rule must be an admitting witness rule, got {anchor_rule!r}")
    rebuilt = {
        "links": links,
        "anchor_address": _require_address(anchor_chain.get("anchor_address"), "anchor_address"),
        "anchor_kind": anchor_kind,
        "anchor_rule": anchor_rule,
    }
    if set(anchor_chain) != set(rebuilt):
        raise ValueError("anchor_chain has unexpected fields")
    return rebuilt


def w3_evidence(
    *,
    direction: str,
    source: str,
    via_address: str,
    via_transitive: bool | None = None,
    anchor_chain: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """W3 control edge. D1 (candidate's resolved controller is a TRANSITIVE
    perimeter entity) requires ``via_transitive=True`` — proven, not defaulted.
    D2 (candidate controls a member) admits with a NON-TRANSITIVE perimeter
    entry stamped by construction; the caller may not assert transitivity.

    ``anchor_chain`` is present exactly when transitivity was proven by the
    anchored-authority-chain arm (spec §3.2 extension, ``_via_transitivity``);
    it records WHICH chain fact proved it. Its absence means the via was
    transitive on its own witnesses."""
    if direction not in (W3_DIRECTION_D1, W3_DIRECTION_D2):
        raise ValueError(f"direction must be 'd1' or 'd2', got {direction!r}")
    if source not in W3_SOURCES:
        raise ValueError(f"source must be one of {sorted(W3_SOURCES)}, got {source!r}")
    via = _require_address(via_address, "via_address")
    if direction == W3_DIRECTION_D1:
        if via_transitive is not True:
            raise ValueError("d1 requires via_transitive=True — a proven transitive perimeter entity")
        evidence: dict[str, Any] = {"direction": direction, "source": source, "via": via, "via_transitive": True}
        if anchor_chain is not None:
            evidence["anchor_chain"] = _anchor_chain_evidence(anchor_chain)
        return evidence
    if via_transitive is not None:
        raise ValueError("d2 does not take via_transitive; its perimeter entry is non-transitive by rule")
    if anchor_chain is not None:
        raise ValueError("anchor_chain is d1 evidence only")
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
        kwargs = picked("edge_kind", "member_contract_id", "member_address", "resolved_pointer")
        if evidence.get("edge_kind") == "historical_implementation":
            kwargs["upgrade_tx_hash"] = evidence.get("upgrade_tx_hash")
        return w2_evidence(**kwargs)
    if rule == WITNESS_RULE_W3_CONTROL:
        kwargs = picked("direction", "source")
        kwargs["via_address"] = evidence.get("via")
        if evidence.get("direction") == W3_DIRECTION_D1:
            kwargs["via_transitive"] = evidence.get("via_transitive")
            if "anchor_chain" in evidence:
                kwargs["anchor_chain"] = evidence.get("anchor_chain")
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
# Nomination (spec §3.4 event 1) + W5 human assertion (spec §5.2, invariant 14)
# ---------------------------------------------------------------------------

#: ``jobs.request`` key carrying a serialized :class:`HumanAssertion` from the
#: admin submission edge to the discovery fetch path.
HUMAN_ASSERTION_REQUEST_KEY = "human_assertion"


@dataclass(frozen=True)
class HumanAssertion:
    """An admin's explicit membership assertion: actor + timestamp, never a
    source tag (invariant 14)."""

    actor: str
    asserted_at: datetime


def human_assertion_request_payload(assertion: HumanAssertion) -> dict[str, str]:
    """The JSON shape :data:`HUMAN_ASSERTION_REQUEST_KEY` carries on a job request."""
    if not isinstance(assertion.actor, str) or not assertion.actor.strip():
        raise ValueError("actor is required for a human assertion")
    return {"actor": assertion.actor.strip(), "asserted_at": assertion.asserted_at.isoformat()}


def human_assertion_from_request(request: Any) -> HumanAssertion | None:
    """Parse :data:`HUMAN_ASSERTION_REQUEST_KEY` off a job request dict.
    Returns ``None`` — never a defaulted actor/timestamp — when the payload is
    absent or malformed."""
    if not isinstance(request, Mapping):
        return None
    payload = request.get(HUMAN_ASSERTION_REQUEST_KEY)
    if not isinstance(payload, Mapping):
        return None
    actor = payload.get("actor")
    raw_ts = payload.get("asserted_at")
    if not isinstance(actor, str) or not actor.strip() or not isinstance(raw_ts, str):
        return None
    try:
        asserted_at = datetime.fromisoformat(raw_ts)
    except ValueError:
        return None
    return HumanAssertion(actor=actor.strip(), asserted_at=asserted_at)


def nominate(
    session: Session,
    *,
    contract: Contract,
    protocol_id: int,
    source_tag: str,
    human_assertion: HumanAssertion | None = None,
) -> None:
    """Record that a discovery source nominated *contract* for *protocol_id*.

    Sets ``nominated_protocol_id``, never ``protocol_id``. The first
    nomination wins; a differing later one is logged and kept as provenance in
    ``discovery_sources`` only. An existing MEMBER's empty nomination slot
    belongs to its own protocol (demotion provenance, invariant 4) — a foreign
    nomination may never claim it.

    ``human_assertion`` (spec §5.2 W5) writes the W5 witness for
    *protocol_id* and attempts promotion — which still requires W1
    (invariant 3): an assertion on an unprobed/unroutable chain yields a
    candidate-with-W5-witness, not a member.
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
    if human_assertion is not None:
        # A member of ANOTHER protocol accepts no foreign W5 row — the
        # assertion is provenance in the log only (invariant 1 posture).
        if contract.protocol_id not in (None, protocol_id):
            logger.info(
                "human assertion for a foreign protocol not recorded on a member",
                extra={
                    "contract_id": contract.id,
                    "member_of": contract.protocol_id,
                    "asserted_protocol_id": protocol_id,
                    "actor": human_assertion.actor,
                },
            )
            return
        if contract.id is None:
            session.flush()
        write_witness(
            session,
            contract_id=contract.id,
            protocol_id=protocol_id,
            rule=WITNESS_RULE_W5_HUMAN,
            evidence=w5_evidence(actor=human_assertion.actor, asserted_at=human_assertion.asserted_at),
        )
        promote(session, contract=contract, protocol_id=protocol_id)


def seed_llama_witness(session: Session, *, contract: Contract) -> bool:
    """W6 seed for the contract's claimed protocol (spec §3.2): the
    ``defillama`` source tag plus a code-present probe on the row's own chain.
    The ONE producer of W6 rows — the live probe/intake paths and the re-earn
    migration both mint through here. A row already carrying a W6 row, active
    OR revoked, is left alone: re-observing the same listing is not new
    evidence, so a revoked seed (§3.2 revocation story) is never re-armed."""
    protocol_id = contract.protocol_id if contract.protocol_id is not None else contract.nominated_protocol_id
    if protocol_id is None or DEFILLAMA_SOURCE_TAG not in (contract.discovery_sources or []):
        return False
    chain_id = chain_id_for_chain_name(contract.chain)
    if chain_id is None or not contract.address:
        return False
    code_row = session.get(ContractCreationWitness, (chain_id, contract.address.lower()))
    if code_row is None or code_row.code_probe_block is None or code_row.code_absent_at_probe:
        return False
    if contract.id is None:
        session.flush()
    existing = session.execute(
        select(ContractMembershipWitness.id)
        .where(
            ContractMembershipWitness.contract_id == contract.id,
            ContractMembershipWitness.protocol_id == protocol_id,
            ContractMembershipWitness.rule == WITNESS_RULE_W6_LLAMA_SEED,
        )
        .limit(1)
    ).first()
    if existing is not None:
        return False
    protocol = session.get(Protocol, protocol_id)
    if protocol is None:
        return False
    # Adapter provenance: the DefiLlama family slug when resolved, else the
    # protocol name the adapter scan matched on.
    adapter_slug = protocol.canonical_slug or protocol.name
    write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W6_LLAMA_SEED,
        evidence=w6_evidence(
            adapter_slug=adapter_slug,
            chain_id=chain_id,
            code_probe_block=code_row.code_probe_block,
        ),
    )
    return True


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


def _member_anchors_ladder(session: Session, *, contract_id: int, protocol_id: int) -> bool:
    """§3.2 D2 non-transitivity mirrored into the ladder (F2, same discipline
    as ``_via_is_transitive``): a member whose ONLY admitting witness is W3-D2
    must not anchor perimeter or corroboration facts — its principals would
    license what the D2 entry itself may not."""
    for row in active_witnesses(session, contract_id=contract_id, protocol_id=protocol_id):
        if row.rule not in ADMITTING_WITNESS_RULES:
            continue
        if row.rule != WITNESS_RULE_W3_CONTROL:
            return True
        if isinstance(row.evidence, dict) and row.evidence.get("direction") == W3_DIRECTION_D1:
            return True
    return False


def _anchoring_member_factory(session: Session, *, protocol_id: int, factory: str) -> bool:
    """Whether *factory* is this protocol's own MEMBER holding a non-D2
    admitting witness (F2). The member-factory mapping rule (deliberate §3.3
    deviation, owner ruling): a creation minted by the protocol's own member
    factory is a protocol-family creation — it counts as MAPPED in the Class-B
    exclusivity test and is tolerated by the shared-operator kill. Mapping
    only: it admits nothing and mints no witness."""
    for member in session.execute(
        select(Contract)
        .where(Contract.protocol_id == protocol_id, func.lower(Contract.address) == factory)
        .order_by(Contract.id)
    ).scalars():
        if _member_anchors_ladder(session, contract_id=member.id, protocol_id=protocol_id):
            return True
    return False


def _member_factory_created(session: Session, *, protocol_id: int, contract: Contract) -> bool:
    """The stored-attribution arm of the member-factory rule: the row's own
    creation witness names a factory that is an anchoring member of this
    protocol. NULL attribution is not-determined and licenses nothing."""
    chain_id = chain_id_for_chain_name(contract.chain)
    addr = (contract.address or "").lower()
    if chain_id is None or not addr:
        return False
    witness = session.get(ContractCreationWitness, (chain_id, addr))
    factory = (witness.creation_factory or "").lower() if witness is not None else ""
    if not factory:
        return False
    return _anchoring_member_factory(session, protocol_id=protocol_id, factory=factory)


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
    return list(
        session.execute(
            select(Contract)
            .where(
                Contract.protocol_id == protocol_id,
                func.lower(Contract.address) == address,
                func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key,
            )
            .order_by(Contract.id)
        ).scalars()
    )


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


@dataclass(frozen=True)
class TransitivityProof:
    """Which §3.2 arm proved a W3-D1 via transitive. ``anchor_chain`` is set
    only for the anchored-authority-chain arm."""

    arm: str
    anchor_chain: dict[str, Any] | None = None


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
    independently anchored perimeter.
    The candidate under evaluation never counts toward its own license."""
    if via_address in in_progress:
        return None
    for member in _member_rows_at(session, protocol_id=protocol_id, address=via_address, chain_key=chain_key):
        rows = active_witnesses(session, contract_id=member.id, protocol_id=protocol_id)
        has_d2 = False
        for row in rows:
            if row.rule not in ADMITTING_WITNESS_RULES:
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
    return None


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
        row = session.execute(
            select(FunctionPrincipal.details)
            .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
            .join(Contract, EffectiveFunction.contract_id == Contract.id)
            .where(
                func.lower(FunctionPrincipal.address) == own,
                FunctionPrincipal.resolved_type == "safe",
                jsonb_has_payload(FunctionPrincipal.details),
                Contract.protocol_id == protocol_id,
            )
            .order_by(FunctionPrincipal.id.desc())
            .limit(1)
        ).first()
        details = row[0] if row is not None else None
        owners = details.get("owners") if isinstance(details, dict) else None
        if isinstance(owners, list):
            for owner in owners:
                add("safe_signer", owner, own)

    return sorted(links.values(), key=lambda link: (link.kind, link.address, link.detail or ""))


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
        if row.rule not in ADMITTING_WITNESS_RULES or row.rule in anchoring:
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
    exclude_contract_ids: set[int],
) -> bool:
    """Shared-operator kill (spec §3.2): every contract the controller is
    observed to control (caller-gating resolved controller values +
    proxy-admin pointers) maps into this protocol's member/candidate set, with
    ≥1 proven member. Any foreign or unclaimed observation refuses —
    revocable, mirroring Class B. A ``call_target``/NULL-provenance row is not
    an observation of control, so it neither licenses nor refuses here."""
    controlled: dict[int, Contract] = {}
    for row in session.execute(
        select(Contract)
        .join(ControllerValue, ControllerValue.contract_id == Contract.id)
        .where(
            func.lower(ControllerValue.value) == controller_address,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
        )
        .distinct()
    ).scalars():
        controlled[row.id] = row
    for row in session.execute(select(Contract).where(func.lower(Contract.admin) == controller_address)).scalars():
        controlled[row.id] = row
    member_seen = False
    for cid in sorted(controlled):
        if cid in exclude_contract_ids:
            continue
        row = controlled[cid]
        if (row.address or "").lower() == controller_address:
            continue
        if row.protocol_id == protocol_id:
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
        return (
            session.execute(
                select(ProtocolDeployer.id)
                .where(
                    ProtocolDeployer.protocol_id == protocol_id,
                    ProtocolDeployer.address == via,
                    ProtocolDeployer.revoked_at.is_(None),
                )
                .limit(1)
            ).first()
            is not None
        )
    chain_key = _chain_key(contract.chain)
    if rule == WITNESS_RULE_W2_STRUCTURAL:
        member = session.get(Contract, evidence.get("member_contract_id"))
        if member is None or member.protocol_id != protocol_id or _chain_key(member.chain) != chain_key:
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
            for member in _member_rows_at(session, protocol_id=protocol_id, address=via, chain_key=chain_key):
                if member.id == contract.id:
                    continue
                if source == "controller_values" and _has_controller_value(session, contract_id=member.id, value=addr):
                    return True
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
            # A witness that PUBLISHED an anchor chain must still be able to
            # cite it: a re-proof at a different anchor is a different fact and
            # gets re-derived with its own evidence (invariant 8).
            if isinstance(recorded, dict) and proof.arm == "anchor_chain":
                assert proof.anchor_chain is not None
                if proof.anchor_chain.get("anchor_address") != recorded.get("anchor_address"):
                    return False
            elif isinstance(recorded, dict) and proof.arm != "anchor_chain":
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
    is active AND its via-fact verifies against stored resolution — a witness
    row a caller wrote is a claim, not a license. Returns whether the contract
    is a member of *protocol_id* on exit; a refusal logs the named missing
    piece (invariant 5)."""
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
    # The LATEST persisted probe verdict outranks any stale active W1 row: a
    # later code-absent probe is proven-absent (§3.1), and proven-absent can
    # never promote.
    if expected_chain is not None and contract.address:
        code_row = session.get(ContractCreationWitness, (expected_chain, contract.address.lower()))
        if code_row is not None and code_row.code_absent_at_probe is True:
            logger.info(
                "promotion withheld",
                extra={
                    "contract_id": contract.id,
                    "protocol_id": protocol_id,
                    "missing": "code_present_at_latest_probe",
                    "contract_chain": contract.chain,
                    "active_rules": sorted(rules),
                },
            )
            return False
    has_w1 = expected_chain is not None and any(
        row.rule == WITNESS_RULE_W1_CODE
        and isinstance(row.evidence, dict)
        and row.evidence.get("chain_id") == expected_chain
        for row in rows
    )
    admitting = sorted(
        {
            row.rule
            for row in rows
            if row.rule in ADMITTING_WITNESS_RULES
            and _witness_fact_holds(
                session,
                contract=contract,
                protocol_id=protocol_id,
                rule=row.rule,
                evidence=row.evidence,
                via_address=row.via_address,
            )
        }
    )
    if not has_w1 or not admitting:
        logger.info(
            "promotion withheld",
            extra={
                "contract_id": contract.id,
                "protocol_id": protocol_id,
                "missing": "w1_code_for_contract_chain" if not has_w1 else "verified_admitting_witness",
                "contract_chain": contract.chain,
                "active_rules": sorted(rules),
            },
        )
        return False
    contract.protocol_id = protocol_id
    if contract.nominated_protocol_id != protocol_id:
        # Proof supersedes provenance: the earned membership realigns the
        # nomination slot so the demotion restore stays coherent. The first
        # nominator's identity survives in ``discovery_sources`` and here.
        if contract.nominated_protocol_id is not None:
            logger.info(
                "promotion supersedes foreign nomination slot",
                extra={
                    "contract_id": contract.id,
                    "protocol_id": protocol_id,
                    "prior_nominated_protocol_id": contract.nominated_protocol_id,
                },
            )
        contract.nominated_protocol_id = protocol_id
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
    principal of a member, or a resolved Safe signer-set entry. The anchoring
    member must itself hold a non-D2 admitting witness (F2) — a principal
    observed on a D2-only entry never mints a ladder anchor."""
    for fact, member_id in _perimeter_fact_candidates(session, protocol_id=protocol_id, address=address):
        if _member_anchors_ladder(session, contract_id=member_id, protocol_id=protocol_id):
            return fact
    return None


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
    for fp_id, function_id, member_id in session.execute(
        select(FunctionPrincipal.id, FunctionPrincipal.function_id, EffectiveFunction.contract_id)
        .join(EffectiveFunction, FunctionPrincipal.function_id == EffectiveFunction.id)
        .where(EffectiveFunction.contract_id.in_(members), func.lower(FunctionPrincipal.address) == address)
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


def _nonlineage_corroborating_member_ids(session: Session, *, protocol_id: int, address: str) -> list[int]:
    """Members deployed by *address* whose membership rests on a NON-lineage
    witness (§3.3 Class B condition 1). The member must also hold a non-D2
    admitting witness (F2) — a D2-only entry is non-transitive and must not
    corroborate exclusivity."""
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
    """§3.3 trust-ladder verdict for one EOA. Reads only; ``register_deployer``
    writes the registry row for an A/B verdict.

    ``creation_history`` is the EOA's Etherscan-enumerated FULL creation list;
    ``history_complete=False`` (cap exceeded, not enumerated) can never reach
    Class B — DB-local exclusivity is absence of counterevidence, not proof.

    ``creation_factories`` (created address → factory address, from the
    enumeration's internal CREATE frames) feeds the member-factory mapping
    rule — a DELIBERATE §3.3 deviation (owner ruling): a creation minted by
    this protocol's own anchoring MEMBER factory counts as mapped in the
    exclusivity test. Mapping only — it admits nothing and mints no witness.
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

    # Corroboration before completeness: an EOA that cannot reach Class B
    # regardless of its creation history must never cost an enumeration —
    # ``no_complete_enumeration`` is the one reason that invites callers (and
    # the fixpoint's ``deployer_enumerator``) to pay for one.
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
        # F1: a creation "maps in" only as a member or as a candidate holding
        # ≥1 unrevoked non-lineage witness — never on a bare nomination.
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
        # The deciding attribution for the member-factory-mapped creations
        # rides in the evidence: which factories, and how many children each.
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


#: ``discovery_sources`` tag for rows a complete Class-B enumeration surfaced.
ENUMERATION_SOURCE_TAG = "deployer_enumeration"

#: Bound on rows one enumeration may nominate. The tail is NOT lost recall
#: silently: the overflow is recorded as degraded, and the next complete
#: enumeration of the same EOA re-surfaces it (nomination is idempotent).
ENUMERATION_NOMINATION_CAP = 1_000


def nominate_enumerated_creations(
    session: Session,
    *,
    protocol_id: int,
    deployer: str,
    creations: "Sequence[DeployerCreation]",
) -> list[int]:
    """Enumeration-driven nomination: a COMPLETE enumeration's creations with
    no contracts row become candidates of *protocol_id* (free recall — the
    probe/evidence path still gates everything; F1 keeps a bare nomination out
    of the Class-B mapping test, so this can never manufacture exclusivity).
    Returns the new candidate ids; the caller queues their probes."""
    _require_positive_int(protocol_id, "protocol_id")
    addr = _require_address(deployer, "deployer")
    missing: list[tuple[str, str]] = []
    for creation in sorted(creations, key=lambda c: (c.chain_id, c.address)):
        target = (creation.address or "").lower()
        if not _ADDRESS_RE.match(target) or target == addr:
            continue
        try:
            chain_name = chain_by_id(creation.chain_id).name
        except UnknownChainError:
            continue
        existing = session.execute(
            select(Contract.id)
            .where(
                func.lower(Contract.address) == target,
                func.lower(func.coalesce(Contract.chain, "ethereum")) == _chain_key(chain_name),
            )
            .limit(1)
        ).first()
        if existing is None:
            missing.append((target, chain_name))
    if len(missing) > ENUMERATION_NOMINATION_CAP:
        overflow = len(missing) - ENUMERATION_NOMINATION_CAP
        record_degraded(
            phase="deployer_enumeration_nomination",
            exc=RuntimeError(f"{overflow} enumerated creations past the nomination cap"),
            context={"deployer": addr, "protocol_id": protocol_id, "cap": ENUMERATION_NOMINATION_CAP},
        )
        logger.warning(
            "enumeration nomination cap exceeded",
            extra={"deployer": addr, "protocol_id": protocol_id, "missing": len(missing)},
        )
        missing = missing[:ENUMERATION_NOMINATION_CAP]
    new_ids: list[int] = []
    for target, chain_name in missing:
        row = Contract(address=target, chain=chain_name, deployer=addr)
        session.add(row)
        session.flush()
        nominate(session, contract=row, protocol_id=protocol_id, source_tag=ENUMERATION_SOURCE_TAG)
        new_ids.append(row.id)
    if new_ids:
        logger.info(
            "enumerated creations nominated",
            extra={"deployer": addr, "protocol_id": protocol_id, "contract_ids": new_ids[:50], "count": len(new_ids)},
        )
    return new_ids


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
                ContractMembershipWitness.rule == WITNESS_RULE_W4_DEPLOYER,
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
                ControllerValue.value.is_not(None),
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


def _vias_citing_anchor_link(session: Session, addresses: Sequence[str] | set[str]) -> set[str]:
    """The vias of standing W3-D1 witnesses whose recorded ``anchor_chain``
    names one of *addresses* — as a walked link or as the terminal anchor.

    Invariant 8's trigger for the anchored-chain arm: such a witness's via is
    the CONTROLLER, so a broken link would otherwise never reach the revocation
    frontier.

    Both arms are written as containment against the ``evidence`` COLUMN, not
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
        batch = sorted(frontier | _vias_citing_anchor_link(session, frontier))
        frontier = set()
        witnesses = list(
            session.execute(
                select(ContractMembershipWitness)
                .where(
                    ContractMembershipWitness.via_address.in_(batch),
                    ContractMembershipWitness.revoked_at.is_(None),
                    ContractMembershipWitness.rule.in_(
                        [WITNESS_RULE_W2_STRUCTURAL, WITNESS_RULE_W3_CONTROL, WITNESS_RULE_W4_DEPLOYER]
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
                contract = session.get(Contract, contract_id)
                addr = (contract.address or "").lower() if contract is not None else ""
                if addr:
                    frontier.add(addr)
    return revoked, demoted


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
#: for the member-factory mapping rule and the chain identities for
#: enumeration-driven nomination).
DeployerEnumerator = Callable[[str], "tuple[Sequence[str], bool]"]


def _secondary_pointer_named(addresses: Sequence[str]):
    """Array-membership predicate over ``secondary_implementations``,
    case-folded. A full 0x-address can only match at an element boundary
    ('x' is not a hex digit), so the joined-LIKE form is element-exact."""
    joined = func.lower(func.array_to_string(Contract.secondary_implementations, ","))
    conditions = [joined.like(f"%{address.lower()}%") for address in addresses]
    return or_(*conditions) if conditions else false()


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
    touched |= _vias_citing_anchor_link(session, addrs)
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

    # Candidates REACHING the delta through their OWN stored facts — a
    # candidate proxy whose pointer resolves to it (W2 proxy shape), or a
    # candidate whose stored resolved controller is it (W3 D1). Both
    # directions must target, or the settled state would depend on which
    # side's fact arrived last (invariant 9). Fresh EDGE addresses count as
    # well as fresh members: an edge that names a STANDING member (a role
    # holder written under a member registry) changes that member's
    # transitivity, and only its wards' own controller rows point back at it.
    reach_addrs = edge_addrs | member_addrs
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

    for _round in range(_FIXPOINT_ROUND_CAP):
        changed = False

        if dirty_vias:
            revoked_ids, demoted_ids = _revocation_quiescence(session, dirty_vias)
            dirty_vias = set()
            if revoked_ids or demoted_ids:
                changed = True
            demoted.update(demoted_ids)
            members_at_entry.update(set(demoted_ids) - promoted)
            promoted.difference_update(demoted_ids)
            reprobe.update(demoted_ids)
            pending.update(demoted_ids)
            loss_check_protocol_ids.update(_protocols_of_demoted(session, demoted_ids))

        extra_pairs = _standing_registry_pairs(
            session, addresses=named_registry_addresses, protocol_ids=loss_check_protocol_ids
        )
        named_registry_addresses = set()
        loss_check_protocol_ids = set()
        recl_changed, recl_pending, recl_nominated, recl_demotion = _reclassify_deployers(
            session,
            pending,
            deployer_enumerator,
            enum_cache,
            extra_pairs=extra_pairs,
        )
        if recl_changed:
            changed = True
        pending.update(recl_pending)
        # Enumeration-driven nominations are candidates blocked on a probe
        # fact (no W1, no probe attempt) — queued out, never settled blind.
        pending.update(recl_nominated)
        reprobe.update(recl_nominated)
        demoted.update(recl_demotion.demoted_contract_ids)
        members_at_entry.update(set(recl_demotion.demoted_contract_ids) - promoted)
        promoted.difference_update(recl_demotion.demoted_contract_ids)
        reprobe.update(recl_demotion.reprobe_contract_ids)
        pending.update(recl_demotion.demoted_contract_ids)
        # A stratum-(ii) demotion shrinks a member set too — its protocol's
        # standing rows get the same loss check next round.
        loss_check_protocol_ids.update(_protocols_of_demoted(session, recl_demotion.demoted_contract_ids))

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
) -> tuple[bool, set[int], set[int], DemotionResult]:
    """Stratum (ii): re-run the §3.3 ladder for every (protocol, deployer)
    pair the pending candidates name, plus ``extra_pairs`` (standing registry
    rows pulled in by a named deployer or a shrunken member set). Registers
    fresh A/B verdicts; revokes an existing row only on POSITIVE
    counterevidence (collision, perimeter fact lost, corroboration lost) — an
    absent enumeration never revokes. The third element is the ids a complete
    enumeration NOMINATED (``nominate_enumerated_creations``) — candidates
    blocked on a probe fact until the caller probes them."""
    extra = set(extra_pairs or ())
    if not pending and not extra:
        return False, set(), set(), DemotionResult()
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
    nominated: set[int] = set()
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
                new_ids = nominate_enumerated_creations(
                    session, protocol_id=protocol_id, deployer=deployer, creations=records
                )
                if new_ids:
                    changed = True
                    nominated.update(new_ids)
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
            # vote — every protocol's standing registry row for this EOA
            # falls in the same pass, each with its full demote cascade.
            standing = list(
                session.execute(
                    select(ProtocolDeployer)
                    .where(ProtocolDeployer.address == deployer, ProtocolDeployer.revoked_at.is_(None))
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
        nominated,
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
        # historical impls (W2), caller-gating controller values and probe
        # reads (W3-D2).
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
                .join(ControllerValue, ControllerValue.contract_id == Contract.id)
                .where(
                    *member_scope,
                    func.lower(ControllerValue.value) == addr,
                    ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
                )
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


def _attempt_admission(session: Session, contract: Contract, protocol_id: int) -> str | None:
    """Stratum (iii) for one candidate: derive admitting witnesses from stored
    facts (each verified at derivation AND again in ``promote``), bind W1 from
    the persisted code probe, promote. Returns ``"promoted"``,
    ``"needs_probe"`` (verdict blocked on a probe fact — invariant 5's named
    missing piece), or ``None`` (no admissible evidence / proven-absent)."""
    addr = (contract.address or "").lower()
    if not addr:
        return None
    chain_id = chain_id_for_chain_name(contract.chain)
    code_row = session.get(ContractCreationWitness, (chain_id, addr)) if chain_id is not None else None
    code_absent = code_row.code_absent_at_probe if code_row is not None else None
    if code_absent is True:
        return None
    derived, w4_blocked_on_creation = _derive_admitting_facts(session, contract, protocol_id)
    has_admitting = bool(derived) or any(
        row.rule in ADMITTING_WITNESS_RULES
        for row in active_witnesses(session, contract_id=contract.id, protocol_id=protocol_id)
    )
    if not has_admitting:
        return "needs_probe" if w4_blocked_on_creation else None
    if chain_id is None:
        return None
    if code_absent is None:
        return "needs_probe"
    assert code_row is not None and code_row.code_probe_block is not None  # paired columns (schema CHECK)
    write_witness(
        session,
        contract_id=contract.id,
        protocol_id=protocol_id,
        rule=WITNESS_RULE_W1_CODE,
        evidence=w1_evidence(chain_id=chain_id, code_probe_block=code_row.code_probe_block),
    )
    for rule, evidence, via_address in derived:
        write_witness(
            session,
            contract_id=contract.id,
            protocol_id=protocol_id,
            rule=rule,
            evidence=evidence,
            via_address=via_address,
        )
    if promote(session, contract=contract, protocol_id=protocol_id):
        return "promoted"
    return "needs_probe" if w4_blocked_on_creation else None


_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def _derive_admitting_facts(
    session: Session, contract: Contract, protocol_id: int
) -> tuple[list[tuple[str, dict[str, Any], str]], bool]:
    """W2/W3/W4 facts provable from stored resolution for one candidate,
    in deterministic order. Only control/lineage edges are consulted —
    control-graph presence and dependency rows never appear here
    (invariant 6). Returns ``(facts, w4_blocked_on_creation_witness)``."""
    addr = (contract.address or "").lower()
    chain_key = _chain_key(contract.chain)
    derived: list[tuple[str, dict[str, Any], str]] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: str, evidence: dict[str, Any], via: str) -> None:
        key = (rule, via)
        if key not in seen:
            seen.add(key)
            derived.append((rule, evidence, via))

    member_scope = (
        Contract.protocol_id == protocol_id,
        Contract.id != contract.id,
        func.lower(func.coalesce(Contract.chain, "ethereum")) == chain_key,
    )

    # W2 — members whose stored pointers resolve to the candidate.
    pointer_members = list(
        session.execute(
            select(Contract)
            .where(
                *member_scope,
                (func.lower(Contract.implementation) == addr)
                | (func.lower(Contract.beacon) == addr)
                | (func.lower(Contract.admin) == addr)
                | _secondary_pointer_named([addr]),
            )
            .order_by(Contract.id)
        ).scalars()
    )
    for member in pointer_members:
        for edge_kind in ("implementation", "beacon", "proxy_admin", "secondary_implementation"):
            if _w2_edge_holds(session, contract=contract, member=member, edge_kind=edge_kind, evidence={}):
                add(
                    WITNESS_RULE_W2_STRUCTURAL,
                    w2_evidence(
                        edge_kind=edge_kind,
                        member_contract_id=member.id,
                        member_address=member.address,
                        resolved_pointer=addr,
                    ),
                    (member.address or "").lower(),
                )
                break

    # W2 — the candidate is a proxy whose resolved impl/beacon is a member.
    for pointer in ((contract.implementation or "").lower(), (contract.beacon or "").lower()):
        if not pointer or not _ADDRESS_RE.match(pointer):
            continue
        for member in _member_rows_at(session, protocol_id=protocol_id, address=pointer, chain_key=chain_key):
            if member.id == contract.id:
                continue
            add(
                WITNESS_RULE_W2_STRUCTURAL,
                w2_evidence(
                    edge_kind="proxy",
                    member_contract_id=member.id,
                    member_address=member.address,
                    resolved_pointer=(member.address or "").lower(),
                ),
                (member.address or "").lower(),
            )

    # W2 — historical impl of a member proxy, per stored UpgradeEvent rows.
    seen_event_members: set[int] = set()
    for event, member in session.execute(
        select(UpgradeEvent, Contract)
        .join(Contract, UpgradeEvent.contract_id == Contract.id)
        .where(*member_scope, func.lower(UpgradeEvent.new_impl) == addr)
        .order_by(Contract.id, UpgradeEvent.block_number.asc().nulls_last(), UpgradeEvent.id)
    ):
        if member.id in seen_event_members:
            continue
        seen_event_members.add(member.id)
        tx = event.tx_hash if isinstance(event.tx_hash, str) and _TX_HASH_RE.match(event.tx_hash) else None
        add(
            WITNESS_RULE_W2_STRUCTURAL,
            w2_evidence(
                edge_kind="historical_implementation",
                member_contract_id=member.id,
                member_address=member.address,
                resolved_pointer=addr,
                upgrade_tx_hash=tx.lower() if tx else None,
            ),
            (member.address or "").lower(),
        )

    # W3 D2 — the candidate is a caller-gating resolved controller of a member.
    for member in session.execute(
        select(Contract)
        .join(ControllerValue, ControllerValue.contract_id == Contract.id)
        .where(
            *member_scope,
            func.lower(ControllerValue.value) == addr,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
        )
        .distinct()
        .order_by(Contract.id)
    ).scalars():
        add(
            WITNESS_RULE_W3_CONTROL,
            w3_evidence(direction=W3_DIRECTION_D2, source="controller_values", via_address=member.address),
            (member.address or "").lower(),
        )
    for member in session.execute(
        select(Contract)
        .join(ContractProbeAttempt, ContractProbeAttempt.contract_id == Contract.id)
        .where(
            *member_scope,
            ContractProbeAttempt.results.op("->")("resolved_addresses").op("?|")(cast([addr], ARRAY(Text()))),
        )
        .distinct()
        .order_by(Contract.id)
    ).scalars():
        if addr in _probe_controller_values(session, member):
            add(
                WITNESS_RULE_W3_CONTROL,
                w3_evidence(direction=W3_DIRECTION_D2, source="probe", via_address=member.address),
                (member.address or "").lower(),
            )

    # W3 D1 — the candidate's resolved controller is a TRANSITIVE perimeter
    # entity (the gate proves transitivity here; a caller cannot assert it).
    own_controllers: list[tuple[str, str]] = []
    for (value,) in session.execute(
        select(ControllerValue.value)
        .where(
            ControllerValue.contract_id == contract.id,
            ControllerValue.authority_provenance == W3_CONTROLLER_PROVENANCE,
        )
        .distinct()
    ):
        if value:
            own_controllers.append(("controller_values", value.lower()))
    admin_pointer = (contract.admin or "").lower()
    if admin_pointer:
        own_controllers.append(("proxy_admin_slot", admin_pointer))
    for value in sorted(_probe_controller_values(session, contract)):
        own_controllers.append(("probe", value))
    for source, via in sorted(own_controllers):
        if not _ADDRESS_RE.match(via) or via == addr or int(via, 16) == 0:
            continue
        if ("w3_control", via) in seen:
            continue
        proof = _via_transitivity(
            session, protocol_id=protocol_id, via_address=via, chain_key=chain_key, exclude_contract_id=contract.id
        )
        if proof is not None:
            add(
                WITNESS_RULE_W3_CONTROL,
                w3_evidence(
                    direction=W3_DIRECTION_D1,
                    source=source,
                    via_address=via,
                    via_transitive=True,
                    anchor_chain=proof.anchor_chain,
                ),
                via,
            )

    # W4 — deployer lineage through the registry.
    w4_blocked = False
    deployer = (contract.deployer or "").lower()
    if deployer and _ADDRESS_RE.match(deployer):
        registry = session.execute(
            select(ProtocolDeployer).where(
                ProtocolDeployer.protocol_id == protocol_id,
                ProtocolDeployer.address == deployer,
                ProtocolDeployer.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
        if registry is not None:
            chain_id = chain_id_for_chain_name(contract.chain)
            creation = session.get(ContractCreationWitness, (chain_id, addr)) if chain_id is not None else None
            if creation is not None and creation.creation_tx_hash:
                add(
                    WITNESS_RULE_W4_DEPLOYER,
                    w4_evidence(
                        deployer_address=deployer,
                        deployer_registry_id=registry.id,
                        creation_tx_hash=creation.creation_tx_hash,
                        creation_block=creation.creation_block,
                    ),
                    deployer,
                )
            else:
                w4_blocked = True
    return derived, w4_blocked


# ---------------------------------------------------------------------------
# Probe delegation (spec §3.5)
# ---------------------------------------------------------------------------


def probe(session: Session, contract: Contract) -> "ProbeResult":
    """Run the §3.5 corroboration probe for *contract* and persist its results."""
    from services.discovery.probes import run_probe

    return run_probe(session, contract)
