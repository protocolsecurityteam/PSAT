"""Witness vocabulary and rules: rule constants, evidence constructors and
validation, and the witness-row primitives."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Mapping

from sqlalchemy import case, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

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
    WITNESS_RULES,
    ContractMembershipWitness,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

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
# resolved proxy-admin slot, a §3.5 probe read, or a resolved FunctionPrincipal
# of a member's effective function. Never "appears in a member's control graph".
W3_SOURCES = frozenset({"controller_values", "proxy_admin_slot", "probe", "function_principal"})

#: The sources a D2 witness — which admits the CONTROLLER itself — may rest on.
#: ``controller_values`` is excluded: those rows record a bare caller gate
#: (:data:`W3_CONTROLLER_PROVENANCE`), which is a proven fact about who may call
#: an entry point and NOT a governance derivation. LayerZero's
#: ``if (msg.sender != endpoint) revert`` on the delivery entry point is
#: indistinguishable at the predicate level from ``msg.sender != _owner``, so
#: the shape admits an integration counterparty (EndpointV2, and through its
#: owner slot OneSig) exactly as readily as an authority. The governance
#: derivations keep admitting: a probed ``owner()``/``authority()``/``admin()``
#: read, a resolved proxy-admin slot, and an authority-derived
#: ``FunctionPrincipal`` (:data:`W3_PRINCIPAL_AUTHORITY_RESOLVERS`) each resolve
#: an authority rather than a caller set. The caller-gate rows stay recorded and
#: keep feeding monitoring, scoring and the D1/anchor-chain reads of a
#: candidate's OWN controllers — they simply admit nobody.
W3_D2_SOURCES = frozenset({"proxy_admin_slot", "probe", "function_principal"})

#: ``FunctionPrincipal.resolved_type`` values that name a CONTROLLER for the
#: D2-principal arm. ``eoa`` is excluded: an EOA is not deployed code, so a
#: CONTRACT candidate whose address carries an eoa-typed principal row is a
#: resolution artifact, and resting membership on it would rest it on a
#: misresolution. NULL/unknown is not_determined and proves nothing either.
W3_PRINCIPAL_CONTROLLER_TYPES = frozenset({"timelock", "safe", "contract"})

#: ``FunctionPrincipal.details['resolver_path']`` steps that resolve an
#: AUTHORITY — a role store, a roles-authority contract, an owner/authority
#: getter, an authority storage slot, or a materialized external authority
#: check. A principal edge admits only when the principal's OWN recorded
#: derivation is one of these end to end.
#:
#: Everything else is membership of a caller SET, which is not control:
#: ``param_keyed_mapping_enumeration`` enumerates a mapping the contract's own
#: writers populate (an ERC-1155 ``isApprovedForAll`` operator set resolves
#: exactly here), and an absent/null path means the resolver derived no
#: authority at all — not_determined, which may never stand in for a witness.
#: This is the invariant-6 line for principal edges: it is what refuses the §2
#: overreach shape the dev DB carries, where Seaport and the NFT marketplace
#: TransferManagers are resolved principals of a member NFT's transfer entry
#: point with no authority derivation behind them.
W3_PRINCIPAL_AUTHORITY_RESOLVERS = frozenset(
    {
        "enumerable_role_store",
        "solmate_roles_authority",
        "live_getter_resolution",
        "authority_getter_basis",
        "live_slot_resolution",
        "external_check_materialized",
    }
)

#: The §3.3 perimeter observations a principal-keyed W3 witness may record.
#: ``safe_owner`` (signer-set containment) is recordable but never proves D1
#: transitivity — the same line ``_perimeter_anchor`` already draws.
W3_PRINCIPAL_FACT_KINDS = frozenset({"function_principal", "safe_owner"})

#: The ONE resolved type that proves D1 transitivity through a perimeter
#: principal (§3.3 Class A: "the EOA is a resolved principal inside the
#: protocol's proven control graph"). Restricting the arm to EOAs is what keeps
#: it MONOTONE in the member set: an EOA is not deployed code, so it can never
#: itself become a member and the arm's verdict cannot be withdrawn by a later
#: promotion. Every richer type is a contract, whose transitivity §3.2 decides
#: from its OWN witnesses — a shared operator's affiliation with one member
#: must never license every ward it also controls.
W3_PERIMETER_PRINCIPAL_TYPE = "eoa"

#: Non-lineage witness rules — evidence a row BELONGS beyond deployer lineage.
#: A bare nomination or a W4-only row is NOT evidence of belonging: §3.3's
#: literal "member/candidate set" wording is deliberately narrowed here
#: (owner ruling) to uphold §0 — an LLM-sourced nomination must never convert
#: a shared deployer's foreign creation into exclusivity corroboration.
NONLINEAGE_WITNESS_RULES = frozenset(
    {WITNESS_RULE_W2_STRUCTURAL, WITNESS_RULE_W3_CONTROL, WITNESS_RULE_W5_HUMAN, WITNESS_RULE_W6_LLAMA_SEED}
)

#: Rules whose via-fact is a ``protocol_deployers`` row, so revoking that row
#: revokes them (DEPLOYER_HEURISTIC_SPEC.md §5; gate invariant 8).
LINEAGE_REGISTRY_WITNESS_RULES = frozenset({WITNESS_RULE_W4_DEPLOYER, WITNESS_RULE_W4H_DEPLOYER_AFFINITY})

#: HEURISTIC witness rules (DEPLOYER_HEURISTIC_SPEC.md §6): admitted on
#: measured affinity, not on proof. A heuristic witness is invisible to every
#: evidence rule — including W4-H's own anchor counting — so a false admission
#: has zero transitive amplification. It is NOT in
#: :data:`NONLINEAGE_WITNESS_RULES`: w4h is lineage.
HEURISTIC_WITNESS_RULES = frozenset({WITNESS_RULE_W4H_DEPLOYER_AFFINITY})

#: W2 evidence flag for the ONE §6 exception: this structural edge was derived
#: from a HEURISTIC member. The derived witness is heuristic itself — the
#: status propagates, never launders.
W2_HEURISTIC_VIA_KEY = "heuristic_via"

#: The §6 same-contract structural edges: a proxy and its implementation are one
#: logical contract, so an H-member proxy carries them. Different-entity edges
#: (proxy admin, the beacon contract itself, factory children, every control
#: edge) never inherit.
W2_SAME_CONTRACT_EDGE_KINDS = frozenset({"implementation", "secondary_implementation"})

#: The one ``ControllerValue.authority_provenance`` that is a control edge
#: (invariant 6): the value gates callers. ``call_target`` is an integration
#: operand (nativeWrapper, endpoint, stETH — the WETH9/EndpointV2/Lido
#: overreach shape), and NULL provenance is not-determined — neither may
#: stand in for a W3 witness, a perimeter fact, or an exclusivity
#: observation. Probe reads (§3.5 owner/authority/admin slots) are
#: caller-gating by construction and carry no provenance column.
W3_CONTROLLER_PROVENANCE = "caller_gate"

#: W4-H qualification thresholds (DEPLOYER_HEURISTIC_SPEC.md §1/§5). Recorded
#: in every H row's evidence, so a granted row carries the rule it was granted
#: under rather than only the verdict.
W4H_MIN_ANCHORS = 2
W4H_MIN_AFFINITY = 0.9
#: Hysteresis floor: admission needs ≥ 0.9, a standing grant survives to 0.5.
W4H_AUTO_REVOKE_AFFINITY = 0.5
W4H_CHALLENGE_QUORUM = 3
W4H_EVIDENCE_VERSION = 1
#: Visibility line, not a cap (DEPLOYER_HEURISTIC_SPEC.md §7 ruling 3): an
#: admission-candidate set past this bound warns loudly so a nomination flood
#: is seen before it becomes the next junk-row incident.
W4H_ADMISSION_CANDIDATE_SANITY_BOUND = 50

#: Derived H-registry states (§5) — never stored flags. ``revoked_at`` is the
#: one stored transition; everything else is recomputed from the evidence.
W4H_STATE_ACTIVE = "active"
W4H_STATE_FROZEN = "frozen"
W4H_STATE_SUSPENDED = "suspended"
W4H_STATE_REVOKED = "revoked"

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
_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")

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
    heuristic_via: bool = False,
) -> dict[str, Any]:
    """W2 structural edge, verified against stored resolution (the pointer the
    member's own row carries), never a bare ``relationship_type``.
    ``upgrade_tx_hash`` belongs to ``historical_implementation`` only — the
    upgrade tx the stored ``UpgradeEvent`` row observed (may be unrecorded).

    ``heuristic_via=True`` records the DEPLOYER_HEURISTIC_SPEC.md §6 exception:
    the member this edge rests on is itself a heuristic member, and the derived
    witness inherits that status (§6 invariant 1 — a heuristic membership is
    never presented as proven)."""
    if edge_kind not in W2_EDGE_KINDS:
        raise ValueError(f"edge_kind must be one of {sorted(W2_EDGE_KINDS)}, got {edge_kind!r}")
    if heuristic_via and edge_kind not in W2_SAME_CONTRACT_EDGE_KINDS:
        raise ValueError(f"heuristic inheritance is same-contract only, got edge_kind {edge_kind!r}")
    evidence: dict[str, Any] = {
        "edge_kind": edge_kind,
        "member_contract_id": _require_positive_int(member_contract_id, "member_contract_id"),
        "member_address": _require_address(member_address, "member_address"),
        "resolved_pointer": _require_address(resolved_pointer, "resolved_pointer"),
    }
    if heuristic_via:
        evidence[W2_HEURISTIC_VIA_KEY] = True
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


def _principal_fact_evidence(fact: Any) -> dict[str, Any]:
    """Canonicalize the resolved-principal observation a principal-keyed W3
    witness rests on: which member hosts it, on which effective function, and
    what the principal resolved to. Rebuilt field-for-field (nullable fields
    always present) so the round-trip is exact and two runs over the same facts
    emit identical evidence."""
    if not isinstance(fact, Mapping):
        raise ValueError("principal_fact must be a mapping")
    kind = fact.get("kind")
    if kind not in W3_PRINCIPAL_FACT_KINDS:
        raise ValueError(f"principal_fact kind must be one of {sorted(W3_PRINCIPAL_FACT_KINDS)}, got {kind!r}")
    resolved_type = fact.get("resolved_type")
    if resolved_type is not None and (not isinstance(resolved_type, str) or not resolved_type.strip()):
        raise ValueError(f"principal_fact resolved_type must be a non-empty string or None, got {resolved_type!r}")
    safe_address = fact.get("safe_address")
    if kind == "safe_owner":
        safe_address = _require_address(safe_address, "principal_fact safe_address")
    elif safe_address is not None:
        raise ValueError("principal_fact safe_address is safe_owner evidence only")
    rebuilt = {
        "kind": kind,
        "function_principal_id": _require_positive_int(
            fact.get("function_principal_id"), "principal_fact function_principal_id"
        ),
        "function_id": _require_positive_int(fact.get("function_id"), "principal_fact function_id"),
        "member_contract_id": _require_positive_int(
            fact.get("member_contract_id"), "principal_fact member_contract_id"
        ),
        "member_address": _require_address(fact.get("member_address"), "principal_fact member_address"),
        "resolved_type": resolved_type,
        "safe_address": safe_address,
    }
    if set(fact) != set(rebuilt):
        raise ValueError("principal_fact has unexpected fields")
    return rebuilt


def w3_evidence(
    *,
    direction: str,
    source: str,
    via_address: str,
    via_transitive: bool | None = None,
    anchor_chain: Mapping[str, Any] | None = None,
    principal_fact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """W3 control edge. D1 (candidate's resolved controller is a TRANSITIVE
    perimeter entity) requires ``via_transitive=True`` — proven, not defaulted.
    D2 (candidate controls a member) admits with a NON-TRANSITIVE perimeter
    entry stamped by construction; the caller may not assert transitivity.

    ``anchor_chain`` is present exactly when transitivity was proven by the
    anchored-authority-chain arm (spec §3.2 extension, ``_via_transitivity``);
    it records WHICH chain fact proved it. ``principal_fact`` is present
    exactly when it was proven by the §3.3 perimeter-principal arm, or — on a
    D2 witness — when the control edge itself is a resolved FunctionPrincipal
    of the member. The two proofs are mutually exclusive; absence of both on a
    D1 witness means the via was transitive on its own witnesses."""
    if direction not in (W3_DIRECTION_D1, W3_DIRECTION_D2):
        raise ValueError(f"direction must be 'd1' or 'd2', got {direction!r}")
    if source not in W3_SOURCES:
        raise ValueError(f"source must be one of {sorted(W3_SOURCES)}, got {source!r}")
    if anchor_chain is not None and principal_fact is not None:
        raise ValueError("anchor_chain and principal_fact are alternative proofs; at most one may be recorded")
    via = _require_address(via_address, "via_address")
    if direction == W3_DIRECTION_D1:
        if source == "function_principal":
            raise ValueError("function_principal is a d2 source; a d1 witness names how the CANDIDATE was read")
        if via_transitive is not True:
            raise ValueError("d1 requires via_transitive=True — a proven transitive perimeter entity")
        evidence: dict[str, Any] = {"direction": direction, "source": source, "via": via, "via_transitive": True}
        if anchor_chain is not None:
            evidence["anchor_chain"] = _anchor_chain_evidence(anchor_chain)
        if principal_fact is not None:
            evidence["principal_fact"] = _principal_fact_evidence(principal_fact)
        return evidence
    if via_transitive is not None:
        raise ValueError("d2 does not take via_transitive; its perimeter entry is non-transitive by rule")
    if anchor_chain is not None:
        raise ValueError("anchor_chain is d1 evidence only")
    if source not in W3_D2_SOURCES:
        raise ValueError(f"d2 source must be one of {sorted(W3_D2_SOURCES)}, got {source!r}")
    if (source == "function_principal") != (principal_fact is not None):
        raise ValueError("a function_principal d2 witness records its principal_fact, and only it")
    evidence = {"direction": direction, "source": source, "via": via, "perimeter_entry_transitive": False}
    if principal_fact is not None:
        fact = _principal_fact_evidence(principal_fact)
        if fact["kind"] != "function_principal":
            raise ValueError("a d2 principal_fact names the candidate's own principal row")
        if fact["resolved_type"] not in W3_PRINCIPAL_CONTROLLER_TYPES:
            raise ValueError(
                f"d2 principal_fact resolved_type must be one of {sorted(W3_PRINCIPAL_CONTROLLER_TYPES)}, "
                f"got {fact['resolved_type']!r}"
            )
        evidence["principal_fact"] = fact
    return evidence


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


def w4_factory_evidence(
    *,
    factory_address: str,
    factory_member_contract_id: int,
    chain_id: int,
    creation_tx_hash: str | None,
) -> dict[str, Any]:
    """W4 factory lineage: the recorded ``creation_factory`` attribution plus
    the member factory it names. ``creation_tx_hash`` may be NULL — the factory
    attribution and the creating tx are independent columns of the creation
    witness, and the attribution alone is what this rule rests on."""
    if creation_tx_hash is not None and (
        not isinstance(creation_tx_hash, str) or not re.match(r"^0x[0-9a-fA-F]{64}$", creation_tx_hash)
    ):
        raise ValueError(f"creation_tx_hash must be a 32-byte hex hash or None, got {creation_tx_hash!r}")
    return {
        "factory_address": _require_address(factory_address, "factory_address"),
        "factory_member_contract_id": _require_positive_int(factory_member_contract_id, "factory_member_contract_id"),
        "chain_id": _require_positive_int(chain_id, "chain_id"),
        "creation_tx_hash": None if creation_tx_hash is None else creation_tx_hash.lower(),
    }


def w4h_evidence(
    *,
    deployer_address: str,
    deployer_registry_id: int,
    creation_tx_hash: str,
    creation_block: int | None,
    affinity_at_grant: float,
    anchors_at_grant: int,
) -> dict[str, Any]:
    """W4-H heuristic deployer lineage (DEPLOYER_HEURISTIC_SPEC.md §8.2). The
    grant-time affinity and anchor count are HISTORICAL RECORD — what the
    computation said when the witness was minted — not a re-verified claim; the
    live numbers live on the registry row."""
    if not isinstance(creation_tx_hash, str) or not re.match(r"^0x[0-9a-fA-F]{64}$", creation_tx_hash):
        raise ValueError(f"creation_tx_hash must be a 32-byte hex hash, got {creation_tx_hash!r}")
    if not isinstance(affinity_at_grant, float) or not (0.0 <= affinity_at_grant <= 1.0):
        raise ValueError(f"affinity_at_grant must be a float in [0, 1], got {affinity_at_grant!r}")
    return {
        "deployer_address": _require_address(deployer_address, "deployer_address"),
        "deployer_registry_id": _require_positive_int(deployer_registry_id, "deployer_registry_id"),
        "creation_tx_hash": creation_tx_hash.lower(),
        "creation_block": None if creation_block is None else _require_block(creation_block, "creation_block"),
        "affinity_at_grant": affinity_at_grant,
        "anchors_at_grant": _require_positive_int(anchors_at_grant, "anchors_at_grant"),
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
        if W2_HEURISTIC_VIA_KEY in evidence:
            kwargs["heuristic_via"] = evidence.get(W2_HEURISTIC_VIA_KEY)
        return w2_evidence(**kwargs)
    if rule == WITNESS_RULE_W3_CONTROL:
        kwargs = picked("direction", "source")
        kwargs["via_address"] = evidence.get("via")
        if evidence.get("direction") == W3_DIRECTION_D1:
            kwargs["via_transitive"] = evidence.get("via_transitive")
            if "anchor_chain" in evidence:
                kwargs["anchor_chain"] = evidence.get("anchor_chain")
        if "principal_fact" in evidence:
            kwargs["principal_fact"] = evidence.get("principal_fact")
        return w3_evidence(**kwargs)
    if rule == WITNESS_RULE_W4_DEPLOYER:
        return w4_evidence(**picked("deployer_address", "deployer_registry_id", "creation_tx_hash", "creation_block"))
    if rule == WITNESS_RULE_W4_FACTORY:
        return w4_factory_evidence(
            **picked("factory_address", "factory_member_contract_id", "chain_id", "creation_tx_hash")
        )
    if rule == WITNESS_RULE_W4H_DEPLOYER_AFFINITY:
        return w4h_evidence(
            **picked(
                "deployer_address",
                "deployer_registry_id",
                "creation_tx_hash",
                "creation_block",
                "affinity_at_grant",
                "anchors_at_grant",
            )
        )
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


def witness_is_heuristic(witness: ContractMembershipWitness) -> bool:
    """Is this row a HEURISTIC witness (DEPLOYER_HEURISTIC_SPEC.md §6)? Either
    a heuristic rule outright, or the §6 same-contract structural edge derived
    from a heuristic member, which carries the status rather than laundering
    it."""
    if witness.rule in HEURISTIC_WITNESS_RULES:
        return True
    return (
        witness.rule == WITNESS_RULE_W2_STRUCTURAL
        and isinstance(witness.evidence, dict)
        and witness.evidence.get(W2_HEURISTIC_VIA_KEY) is True
    )
