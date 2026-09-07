"""Turn effective-permission results into evidence-backed capability claims."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import (
    Analysis,
    Assessment,
    Authority,
    Claim,
    Effect,
    EffectFamily,
    EffectKind,
    Entity,
    Evidence,
    Proposition,
)
from services.policy.capability_surface import capability_role_grants
from services.static.claims.matchers import discover
from services.static.claims.registry import entry_for, is_registered

from .functions import resolve_function
from .keys import content_key, entity_key, entity_record
from .keys import json_value as _json
from .slices import prune_unreferenced_entities, remove_analysis_slice
from .static import effect_targets
from .validation import checked


def _entity(result: Assessment, chain_id: int, principal: Mapping[str, Any]) -> tuple[str, Entity] | None:
    address = principal.get("address")
    if not isinstance(address, str) or not address:
        return None
    key, entity = entity_record(chain_id, address, str(principal.get("resolved_type") or "unknown"))
    result["entities"][key] = entity
    return key, entity


def _principal_lookup(permission: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Known principal detail keyed by normalized address."""

    out: dict[str, Mapping[str, Any]] = {}

    def add(value: object) -> None:
        if not isinstance(value, Mapping):
            return
        address = value.get("address")
        if isinstance(address, str) and address:
            out[address.lower()] = value

    add(permission.get("direct_owner"))
    for grant in permission.get("authority_roles") or []:
        if isinstance(grant, Mapping):
            for principal in grant.get("principals") or []:
                add(principal)
    for controller in permission.get("controllers") or []:
        if isinstance(controller, Mapping):
            for principal in controller.get("principals") or []:
                add(principal)
    for principal in permission.get("signature_witnesses") or []:
        add(principal)
    return out


def _entity_for_address(
    result: Assessment,
    chain_id: int,
    address: object,
    principals: Mapping[str, Mapping[str, Any]],
) -> str | None:
    if not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        return None
    normalized = address.lower()
    key = entity_key(chain_id, normalized)
    if key in result["entities"]:
        return key
    principal = principals.get(normalized, {"address": normalized, "resolved_type": "unknown"})
    entity = _entity(result, chain_id, principal)
    return entity[0] if entity is not None else None


def _conditions(value: Mapping[str, Any]) -> list[JsonValue]:
    raw = value.get("conditions")
    return [_json(condition) for condition in raw] if isinstance(raw, list) else []


def _with_conditions(authority: Authority, conditions: list[JsonValue]) -> Authority:
    if conditions:
        combined = [*authority.get("conditions", []), *conditions]
        authority["conditions"] = list({json.dumps(item, sort_keys=True): item for item in combined}.values())
    return authority


def _authority_from_capability(
    result: Assessment,
    chain_id: int,
    capability: Mapping[str, Any],
    principals: Mapping[str, Mapping[str, Any]],
) -> Authority | None:
    """Lower resolved capability algebra into the public Authority vocabulary."""

    kind = capability.get("kind")
    conditions = _conditions(capability)
    if kind == "conditional_universal":
        return _with_conditions({"kind": "public"}, conditions)
    if kind in ("OR", "AND"):
        children = capability.get("children")
        lowered = [
            _authority_from_capability(result, chain_id, child, principals)
            for child in (children if isinstance(children, list) else [])
            if isinstance(child, Mapping)
        ]
        if kind == "AND" and any(child is None for child in lowered):
            return {"kind": "expression", "expression": _json(capability)}
        lowered = [child for child in lowered if child is not None]
        if not lowered:
            return None
        authority = lowered[0] if len(lowered) == 1 else {"kind": "any" if kind == "OR" else "all", "children": lowered}
        return _with_conditions(cast(Authority, authority), conditions)
    if kind == "finite_set" and capability.get("membership_quality") == "exact":
        authorities: list[Authority] = []
        role_members: set[str] = set()
        for grant in capability_role_grants(dict(capability)) or []:
            members = [principal["address"] for principal in grant["principals"]]
            entities = sorted(
                {
                    entity
                    for member in members
                    if (entity := _entity_for_address(result, chain_id, member, principals)) is not None
                }
            )
            role_members.update(member.lower() for member in members)
            if entities:
                authorities.append({"kind": "role", "role": str(grant["role"]), "entities": entities})
        members = capability.get("members")
        if isinstance(members, list):
            for member in members:
                if not isinstance(member, str) or member.lower() in role_members:
                    continue
                entity = _entity_for_address(result, chain_id, member, principals)
                if entity is not None:
                    authorities.append({"kind": "entity", "entity": entity})
        unique = {json.dumps(authority, sort_keys=True): authority for authority in authorities}
        ordered = [unique[key] for key in sorted(unique)]
        if ordered:
            authority = ordered[0] if len(ordered) == 1 else {"kind": "any", "children": ordered}
            return _with_conditions(cast(Authority, authority), conditions)
        return None
    return {
        "kind": "expression",
        "expression": _json(capability),
        "conditions": conditions,
    }


def _authorities(
    result: Assessment, chain_id: int, permission: Mapping[str, Any]
) -> tuple[Authority | None, str | None]:
    capability_expr = permission.get("capability_expr")
    if isinstance(capability_expr, Mapping):
        capability_kind = capability_expr.get("kind")
        if permission.get("status") == "unsupported" or capability_kind == "unsupported":
            reason = capability_expr.get("unsupported_reason")
            return None, str(reason or "unsupported_authority_expression")
        if permission.get("status") == "resolved_empty":
            return None, None
        authority = _authority_from_capability(result, chain_id, capability_expr, _principal_lookup(permission))
        if authority is not None:
            return authority, None
        return None, "authority_not_determined"

    return None, "authority_not_determined"


def _effect_claims(assessment: Assessment, function: str) -> list[tuple[str, Claim]]:
    out: list[tuple[str, Claim]] = []
    for claim_key, claim in assessment["claims"].items():
        proposition = claim["proposition"]
        if proposition["kind"] == "function_effect" and proposition.get("function") == function:
            out.append((claim_key, claim))
    return out


def _ensure_embedded_effect_claims(
    result: Assessment,
    permission: Mapping[str, Any],
    function: str,
) -> tuple[list[str], list[str]]:
    raw_claims = permission.get("claims")
    if not isinstance(raw_claims, list):
        return [], []
    claim_keys: list[str] = []
    evidence_keys: list[str] = []
    existing_kinds = {
        existing_effect["kind"]
        for _, claim in _effect_claims(result, function)
        if (existing_effect := claim["proposition"].get("effect")) is not None
    }
    for raw in raw_claims:
        if not isinstance(raw, Mapping):
            continue
        kind = raw.get("claim_id")
        witness = raw.get("witness")
        tier = raw.get("tier")
        if (
            not isinstance(kind, str)
            or kind in existing_kinds
            or not is_registered(kind)
            or not isinstance(witness, Mapping)
        ):
            continue
        entry = entry_for(kind)
        observation = _json(witness)
        evidence_key = content_key(
            "evidence",
            {
                "contract": result["contract"],
                "method": "policy_derivation",
                "function": function,
                "claim": kind,
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "method": "policy_derivation",
            "subject_kind": "function",
            "subject": function,
            "observation": observation,
            "producer": f"policy.claims.{kind}",
            "version": "policy/1",
            "locator": _json({"tier": tier}),
        }
        result["evidence"][evidence_key] = evidence
        evidence_keys.append(evidence_key)
        affected = [
            signature
            for signature in witness.get("affected_functions") or []
            if isinstance(signature, str) and signature in result["functions"]
        ]
        effect: Effect = {
            "kind": cast(EffectKind, kind),
            "family": cast(EffectFamily, entry.consumer_family),
            "targets": effect_targets(permission, witness),
            "affected_functions": sorted(set(affected)),
        }
        proposition: Proposition = {
            "kind": "function_effect",
            "function": function,
            "effect": effect,
        }
        claim_key = content_key("claim", {"contract": result["contract"], "proposition": proposition})
        result["claims"][claim_key] = {
            "proposition": proposition,
            "rule": f"{kind}/{tier}",
            "evidence": [evidence_key],
            "claims": [],
        }
        claim_keys.append(claim_key)
    return claim_keys, evidence_keys


def add_policy(assessment: Assessment, permissions: Mapping[str, Any], *, chain_id: int) -> Assessment:
    """Add current authority-capability claims to ``assessment``."""

    discover()
    result = cast(Assessment, copy.deepcopy(assessment))
    remove_analysis_slice(result, "policy.capabilities")
    raw_functions = permissions.get("functions")
    permission_items = raw_functions if isinstance(raw_functions, list) else []
    omissions: list[dict[str, str]] = []
    claim_keys: list[str] = []
    evidence_keys: list[str] = []
    completed = 0

    for permission in permission_items:
        if not isinstance(permission, Mapping):
            continue
        function, function_problem = resolve_function(result, permission)
        if function is None:
            omissions.append(
                {
                    "target_kind": "contract",
                    "target": result["contract"]["deployment_address"],
                    "reason": f"policy_function_not_in_contract:{function_problem}",
                }
            )
            continue

        embedded_claim_keys, embedded_evidence_keys = _ensure_embedded_effect_claims(result, permission, function)
        claim_keys.extend(embedded_claim_keys)
        evidence_keys.extend(embedded_evidence_keys)
        effects = _effect_claims(result, function)
        authority, unresolved_reason = _authorities(result, chain_id, permission)
        observation_source: dict[str, Any] = {
            "authority_openness": permission.get("authority_openness"),
            "authority_public": permission.get("authority_public"),
            "direct_owner": permission.get("direct_owner"),
            "authority_roles": permission.get("authority_roles"),
            "controllers": permission.get("controllers") or [],
            "signature_witnesses": permission.get("signature_witnesses") or [],
            "notes": permission.get("notes") or [],
        }
        for optional_field in (
            "capability_expr",
            "conditions",
            "status",
            "state_changing",
            "state_writes",
            "sinks",
            "writer_selectors",
        ):
            if optional_field in permission:
                observation_source[optional_field] = permission[optional_field]
        observation = _json(observation_source)
        evidence_key = content_key(
            "evidence",
            {
                "contract": result["contract"],
                "method": "policy_derivation",
                "function": function,
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "method": "policy_derivation",
            "subject_kind": "function",
            "subject": function,
            "observation": observation,
            "producer": "policy.capability",
            "version": str(permissions.get("schema_version") or "policy/1"),
            "locator": _json(
                {
                    "function": function,
                    "abi_signature": permission.get("abi_signature"),
                    "selector": permission.get("selector"),
                }
            ),
        }
        result["evidence"][evidence_key] = evidence
        evidence_keys.append(evidence_key)

        if unresolved_reason is not None:
            omissions.append({"target_kind": "function", "target": function, "reason": unresolved_reason})
            continue
        completed += 1

        if authority is None:
            # A resolved-empty authority set is a completed negative result, not
            # a failure and not a capability claim. Its observation remains
            # evidence so relational projections can reproduce the empty row.
            continue

        authority_proposition: Proposition = {
            "kind": "function_authority",
            "authority": authority,
            "function": function,
        }
        authority_claim_key = content_key(
            "claim",
            {"contract": result["contract"], "proposition": authority_proposition},
        )
        result["claims"][authority_claim_key] = {
            "proposition": authority_proposition,
            "rule": "policy.function_authority/v1",
            "evidence": [evidence_key],
            "claims": [],
        }
        claim_keys.append(authority_claim_key)

        for effect_claim_key, effect_claim in effects:
            effect_proposition = effect_claim["proposition"]
            effect = effect_proposition.get("effect")
            if effect_proposition["kind"] != "function_effect" or effect is None:
                continue
            proposition: Proposition = {
                "kind": "authority_capability",
                "authority": authority,
                "function": function,
                "effect": effect,
            }
            claim_key = content_key("claim", {"contract": result["contract"], "proposition": proposition})
            result["claims"][claim_key] = {
                "proposition": proposition,
                "rule": "policy.authority_capability/v1",
                "evidence": [evidence_key],
                "claims": [authority_claim_key, effect_claim_key],
            }
            claim_keys.append(claim_key)

    status = "completed" if not omissions else ("partial" if completed else "failed")
    receipt: Analysis = {
        "detector": "policy.capabilities",
        "version": str(permissions.get("schema_version") or "policy/1"),
        "status": status,
        "targets_total": len(permission_items),
        "targets_completed": completed,
        "omissions": omissions,
        "diagnostics": [],
        "claims": sorted(set(claim_keys)),
        "evidence": sorted(set(evidence_keys)),
    }
    result["analyses"].append(receipt)
    prune_unreferenced_entities(result)
    return checked(result)


__all__ = ["add_policy"]
