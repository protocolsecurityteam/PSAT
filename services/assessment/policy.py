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
from services.static.claims.matchers import discover
from services.static.claims.registry import entry_for, is_registered

from .keys import content_key, entity_key
from .slices import prune_unreferenced_entities, remove_analysis_slice
from .validation import checked


def _json(value: Any) -> JsonValue:
    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))


def _entity(result: Assessment, chain_id: int, principal: Mapping[str, Any]) -> tuple[str, Entity] | None:
    address = principal.get("address")
    if not isinstance(address, str) or not address:
        return None
    normalized = address.lower()
    resolved_type = str(principal.get("resolved_type") or "unknown")
    contract_types = {"safe", "timelock", "proxy_admin", "contract", "cross_chain_authority"}
    key = entity_key(chain_id, normalized)
    entity: Entity = {
        "chain_id": chain_id,
        "address": normalized,
        "kind": "contract" if resolved_type in contract_types else "account",
        "tags": [] if resolved_type in ("eoa", "contract", "unknown") else [resolved_type],
    }
    result["entities"][key] = entity
    return key, entity


def _authorities(
    result: Assessment, chain_id: int, permission: Mapping[str, Any]
) -> tuple[Authority | None, str | None]:
    capability_expr = permission.get("capability_expr")
    if isinstance(capability_expr, Mapping):
        capability_kind = capability_expr.get("kind")
        if permission.get("status") == "unsupported" or capability_kind == "unsupported":
            reason = capability_expr.get("unsupported_reason")
            return None, str(reason or "unsupported_authority_expression")
        raw_conditions = permission.get("conditions")
        if not isinstance(raw_conditions, list):
            raw_conditions = capability_expr.get("conditions")
        conditions = raw_conditions if isinstance(raw_conditions, list) else []
        return {
            "kind": "expression",
            "expression": _json(capability_expr),
            "conditions": [_json(condition) for condition in conditions],
        }, None

    openness = permission.get("authority_openness")
    if openness == "open" or permission.get("authority_public") is True:
        return {"kind": "public"}, None

    authorities: list[Authority] = []
    direct = permission.get("direct_owner")
    if isinstance(direct, Mapping):
        entity = _entity(result, chain_id, direct)
        if entity is not None:
            authorities.append({"kind": "entity", "entity": entity[0]})

    roles = permission.get("authority_roles")
    role_unresolved = roles is None
    if isinstance(roles, list):
        for grant in roles:
            if not isinstance(grant, Mapping):
                continue
            entity_ids: list[str] = []
            principals = grant.get("principals")
            if isinstance(principals, list):
                for principal in principals:
                    if isinstance(principal, Mapping) and (entity := _entity(result, chain_id, principal)) is not None:
                        entity_ids.append(entity[0])
            if entity_ids:
                authorities.append(
                    {
                        "kind": "role",
                        "role": str(grant.get("role")),
                        "entities": sorted(set(entity_ids)),
                    }
                )

    controllers = permission.get("controllers")
    if isinstance(controllers, list):
        for controller in controllers:
            if not isinstance(controller, Mapping):
                continue
            principals = controller.get("principals")
            if not isinstance(principals, list):
                continue
            for principal in principals:
                if isinstance(principal, Mapping) and (entity := _entity(result, chain_id, principal)) is not None:
                    authorities.append({"kind": "entity", "entity": entity[0]})

    witnesses = permission.get("signature_witnesses")
    if isinstance(witnesses, list):
        for principal in witnesses:
            if isinstance(principal, Mapping) and (entity := _entity(result, chain_id, principal)) is not None:
                authorities.append({"kind": "entity", "entity": entity[0]})

    unique: list[Authority] = []
    seen: set[str] = set()
    for authority in authorities:
        key = json.dumps(authority, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(authority)
    if len(unique) == 1:
        return unique[0], None
    if unique:
        return {"kind": "any", "children": unique}, None
    if permission.get("status") == "resolved_empty":
        return None, None
    if role_unresolved:
        return None, "role_principals_not_determined"
    return None, "authority_not_determined"


def _targets(permission: Mapping[str, Any], witness: Mapping[str, Any]) -> list[dict[str, str]]:
    flags = witness.get("flags")
    if isinstance(flags, list):
        targets: list[dict[str, str]] = []
        for flag in flags:
            if not isinstance(flag, Mapping) or not isinstance(flag.get("var"), str):
                continue
            target = {"kind": "state", "value": str(flag["var"])}
            if isinstance(flag.get("member"), str) and flag.get("member"):
                target["member"] = str(flag["member"])
            targets.append(target)
        if targets:
            return targets
    targets: list[dict[str, str]] = []
    state_names: set[str] = set()
    writes = permission.get("state_writes")
    if isinstance(writes, list):
        for write in writes:
            if not isinstance(write, Mapping) or not isinstance(write.get("var"), str):
                continue
            state_names.add(str(write["var"]))
    targets.extend({"kind": "state", "value": name} for name in sorted(state_names))
    sinks = permission.get("sinks")
    if isinstance(sinks, list):
        for sink in sinks:
            if not isinstance(sink, Mapping) or sink.get("origin") == "guard":
                continue
            raw_target = sink.get("target")
            if isinstance(raw_target, str) and raw_target and raw_target not in state_names:
                targets.append({"kind": "operation", "value": raw_target})
    return targets


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
            "targets": _targets(permission, witness),
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
        signature = permission.get("abi_signature") or permission.get("function")
        function = signature if isinstance(signature, str) and signature in result["functions"] else None
        if function is None:
            omissions.append(
                {
                    "target_kind": "contract",
                    "target": result["contract"]["deployment_address"],
                    "reason": f"policy_function_not_in_contract:{signature}",
                }
            )
            continue

        embedded_claim_keys, embedded_evidence_keys = _ensure_embedded_effect_claims(result, permission, function)
        claim_keys.extend(embedded_claim_keys)
        evidence_keys.extend(embedded_evidence_keys)
        effects = _effect_claims(result, function)
        authority, unresolved_reason = _authorities(result, chain_id, permission)
        if unresolved_reason is not None:
            omissions.append(
                {
                    "target_kind": "function",
                    "target": function,
                    "reason": unresolved_reason,
                }
            )
            continue
        completed += 1
        if authority is None:
            # A resolved-empty authority set is a completed negative result, not
            # a failure and not a capability claim.
            continue

        observation = _json(
            {
                "authority_openness": permission.get("authority_openness"),
                "authority_public": permission.get("authority_public"),
                "direct_owner": permission.get("direct_owner"),
                "authority_roles": permission.get("authority_roles"),
                "controllers": permission.get("controllers") or [],
                "signature_witnesses": permission.get("signature_witnesses") or [],
            }
        )
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
            "locator": _json({"function": signature}),
        }
        result["evidence"][evidence_key] = evidence
        evidence_keys.append(evidence_key)

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
                "claims": [effect_claim_key],
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
