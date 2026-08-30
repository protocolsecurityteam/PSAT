"""Turn effective-permission results into evidence-backed capability claims."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import (
    Account,
    Analysis,
    Assessment,
    AtomicAuthority,
    Authority,
    AuthorityCapability,
    Basis,
    Claim,
    Effect,
    EffectFamily,
    EffectKind,
    EffectTarget,
    Entity,
    Evidence,
    FunctionEffect,
    Omission,
)
from services.static.claims.matchers import discover
from services.static.claims.registry import entry_for, is_registered

from .ids import stable_id
from .validation import checked


def _json(value: Any) -> JsonValue:
    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))


def _account(chain_id: int, address: str) -> Account:
    normalized = address.lower()
    account_id = stable_id("account", {"chain_id": chain_id, "address": normalized})
    return {"id": account_id, "chain_id": chain_id, "address": normalized}


def _entity(result: Assessment, chain_id: int, principal: Mapping[str, Any]) -> Entity | None:
    address = principal.get("address")
    if not isinstance(address, str) or not address:
        return None
    account = _account(chain_id, address)
    result["accounts"][account["id"]] = account
    resolved_type = str(principal.get("resolved_type") or "unknown")
    contract_types = {"safe", "timelock", "proxy_admin", "contract", "cross_chain_authority"}
    entity_id = stable_id("entity", {"account_id": account["id"]})
    entity: Entity = {
        "id": entity_id,
        "account_id": account["id"],
        "kind": "contract" if resolved_type in contract_types else "account",
        "tags": [] if resolved_type in ("eoa", "contract", "unknown") else [resolved_type],
    }
    result["entities"][entity_id] = entity
    return entity


def _authorities(
    result: Assessment, chain_id: int, permission: Mapping[str, Any]
) -> tuple[Authority | None, str | None]:
    openness = permission.get("authority_openness")
    if openness == "open" or permission.get("authority_public") is True:
        return {"kind": "public"}, None

    authorities: list[AtomicAuthority] = []
    direct = permission.get("direct_owner")
    if isinstance(direct, Mapping):
        entity = _entity(result, chain_id, direct)
        if entity is not None:
            authorities.append({"kind": "entity", "entity_id": entity["id"]})

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
                        entity_ids.append(entity["id"])
            if entity_ids:
                authorities.append(
                    {
                        "kind": "role",
                        "role": str(grant.get("role")),
                        "entity_ids": sorted(set(entity_ids)),
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
                    authorities.append({"kind": "entity", "entity_id": entity["id"]})

    witnesses = permission.get("signature_witnesses")
    if isinstance(witnesses, list):
        for principal in witnesses:
            if isinstance(principal, Mapping) and (entity := _entity(result, chain_id, principal)) is not None:
                authorities.append({"kind": "entity", "entity_id": entity["id"]})

    unique: list[AtomicAuthority] = []
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


def _targets(permission: Mapping[str, Any], witness: Mapping[str, Any]) -> list[EffectTarget]:
    flags = witness.get("flags")
    if isinstance(flags, list):
        targets: list[EffectTarget] = []
        for flag in flags:
            if not isinstance(flag, Mapping) or not isinstance(flag.get("var"), str):
                continue
            target: EffectTarget = {"kind": "state", "value": str(flag["var"])}
            if isinstance(flag.get("member"), str) and flag.get("member"):
                target["member"] = str(flag["member"])
            targets.append(target)
        if targets:
            return targets
    raw_targets = permission.get("effect_targets")
    if not isinstance(raw_targets, list):
        return []
    return [{"kind": "operation", "value": target} for target in raw_targets if isinstance(target, str) and target]


def _function_ids(assessment: Assessment) -> dict[str, str]:
    out: dict[str, str] = {}
    for function_id, function in assessment["functions"].items():
        out[function["signature"]] = function_id
    return out


def _effect_claims(assessment: Assessment, function_id: str) -> list[Claim]:
    out: list[Claim] = []
    for claim in assessment["claims"].values():
        proposition = claim["proposition"]
        if proposition["kind"] == "function_effect" and proposition["function_id"] == function_id:
            out.append(claim)
    return out


def _ensure_embedded_effect_claims(
    result: Assessment,
    permission: Mapping[str, Any],
    function_id: str,
    ids_by_signature: Mapping[str, str],
) -> None:
    raw_claims = permission.get("claims")
    if not isinstance(raw_claims, list):
        return
    existing_kinds = {
        claim["proposition"]["effect"]["kind"]
        for claim in _effect_claims(result, function_id)
        if claim["proposition"]["kind"] == "function_effect"
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
        evidence_id = stable_id(
            "evidence",
            {
                "scope": result["scope"],
                "method": "policy_derivation",
                "function_id": function_id,
                "claim": kind,
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "id": evidence_id,
            "method": "policy_derivation",
            "subject": {"kind": "function", "id": function_id},
            "observation": observation,
            "source": {
                "producer": f"policy.claims.{kind}",
                "version": "policy/1",
                "locator": _json({"tier": tier}),
            },
            "scope": result["scope"],
        }
        result["evidence"][evidence_id] = evidence
        affected = [
            ids_by_signature[signature]
            for signature in witness.get("affected_functions") or []
            if isinstance(signature, str) and signature in ids_by_signature
        ]
        effect: Effect = {
            "kind": cast(EffectKind, kind),
            "family": cast(EffectFamily, entry.consumer_family),
            "targets": _targets(permission, witness),
            "affected_functions": sorted(set(affected)),
        }
        proposition: FunctionEffect = {
            "kind": "function_effect",
            "function_id": function_id,
            "effect": effect,
        }
        claim_id = stable_id("claim", {"scope": result["scope"], "proposition": proposition})
        result["claims"][claim_id] = {
            "id": claim_id,
            "proposition": proposition,
            "basis": {
                "rule": f"{kind}/{tier}",
                "evidence_ids": [evidence_id],
                "claim_ids": [],
            },
            "scope": result["scope"],
        }


def add_policy(assessment: Assessment, permissions: Mapping[str, Any], *, chain_id: int) -> Assessment:
    """Add current authority-capability claims to ``assessment``."""

    discover()
    result = cast(Assessment, copy.deepcopy(assessment))
    ids_by_signature = _function_ids(result)
    raw_functions = permissions.get("functions")
    permission_items = raw_functions if isinstance(raw_functions, list) else []
    omissions: list[Omission] = []
    claim_ids: list[str] = []
    evidence_ids: list[str] = []
    completed = 0

    for permission in permission_items:
        if not isinstance(permission, Mapping):
            continue
        signature = permission.get("abi_signature") or permission.get("function")
        function_id = ids_by_signature.get(signature) if isinstance(signature, str) else None
        if function_id is None:
            omissions.append(
                {
                    "target_kind": "contract",
                    "target_id": result["contract"]["id"],
                    "reason": f"policy_function_not_in_contract:{signature}",
                }
            )
            continue

        _ensure_embedded_effect_claims(result, permission, function_id, ids_by_signature)
        effects = _effect_claims(result, function_id)
        authority, unresolved_reason = _authorities(result, chain_id, permission)
        if unresolved_reason is not None:
            omissions.append(
                {
                    "target_kind": "function",
                    "target_id": function_id,
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
        evidence_id = stable_id(
            "evidence",
            {
                "scope": result["scope"],
                "method": "policy_derivation",
                "function_id": function_id,
                "observation": observation,
            },
        )
        evidence: Evidence = {
            "id": evidence_id,
            "method": "policy_derivation",
            "subject": {"kind": "function", "id": function_id},
            "observation": observation,
            "source": {
                "producer": "policy.capability",
                "version": str(permissions.get("schema_version") or "policy/legacy"),
                "locator": _json({"function": signature}),
            },
            "scope": result["scope"],
        }
        result["evidence"][evidence_id] = evidence
        evidence_ids.append(evidence_id)

        for effect_claim in effects:
            effect_proposition = effect_claim["proposition"]
            if effect_proposition["kind"] != "function_effect":
                continue
            proposition: AuthorityCapability = {
                "kind": "authority_capability",
                "authority": authority,
                "function_id": function_id,
                "effect": effect_proposition["effect"],
            }
            claim_id = stable_id("claim", {"scope": result["scope"], "proposition": proposition})
            basis: Basis = {
                "rule": "policy.authority_capability/v1",
                "evidence_ids": [evidence_id],
                "claim_ids": [effect_claim["id"]],
            }
            result["claims"][claim_id] = {
                "id": claim_id,
                "proposition": proposition,
                "basis": basis,
                "scope": result["scope"],
            }
            claim_ids.append(claim_id)

    status = "completed" if not omissions else ("partial" if completed else "failed")
    receipt: Analysis = {
        "detector": "policy.capabilities",
        "version": str(permissions.get("schema_version") or "policy/legacy"),
        "status": status,
        "coverage": {
            "targets_total": len(permission_items),
            "targets_completed": completed,
            "omissions": omissions,
        },
        "diagnostics": [],
        "claim_ids": sorted(set(claim_ids)),
        "evidence_ids": sorted(set(evidence_ids)),
    }
    result["analyses"] = [item for item in result["analyses"] if item["detector"] != "policy.capabilities"]
    result["analyses"].append(receipt)
    return checked(result)


__all__ = ["add_policy"]
