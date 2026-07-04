"""Principal/effective-function shaping for governance views."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from db.models import EffectiveFunction, FunctionPrincipal


def _function_principal_payload(
    fp: FunctionPrincipal,
    principal_lookup: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    address = fp.address
    lookup = principal_lookup.get(address.lower()) if principal_lookup and address else None
    resolved_type = fp.resolved_type
    details = dict(lookup.get("details") or {}) if lookup else {}
    if isinstance(fp.details, dict):
        details.update(fp.details)

    if lookup:
        lookup_type = lookup.get("resolved_type")
        if lookup_type and resolved_type in (None, "", "unknown", "contract"):
            resolved_type = str(lookup_type)

    payload = {
        "address": fp.address,
        "resolved_type": resolved_type,
        "source_controller_id": fp.origin,
        "principal_type": fp.principal_type,
        "details": details,
    }
    if lookup and lookup.get("label"):
        payload["label"] = lookup["label"]
    return payload


def _is_generic_authority_contract_principal(principal: dict[str, Any]) -> bool:
    details = principal.get("details")
    return (
        principal.get("resolved_type") == "contract"
        and isinstance(details, dict)
        and bool(details.get("authority_kind"))
    )


def _role_value_from_origin(origin: str | None) -> int | str:
    prefix = "role "
    if not origin:
        return "?"
    if origin.startswith(prefix):
        suffix = origin[len(prefix) :]
        if suffix.isdigit():
            return int(suffix)
        return suffix or "?"
    return origin


def _build_company_function_entry(
    ef: EffectiveFunction,
    principals: list[FunctionPrincipal],
    principal_lookup: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    direct_owner = None
    controllers_by_label: dict[str, dict[str, Any]] = {}
    authority_roles_by_key: dict[str, dict[str, Any]] = {}
    signature_witnesses: list[dict[str, Any]] = []

    for fp in principals:
        principal_dict = _function_principal_payload(fp, principal_lookup)

        if fp.principal_type == "direct_owner":
            if direct_owner is None:
                direct_owner = principal_dict
            continue

        if fp.principal_type == "signature_witness":
            signature_witnesses.append(principal_dict)
            continue

        if fp.principal_type == "authority_role":
            role_value = _role_value_from_origin(fp.origin)
            role_entry = authority_roles_by_key.setdefault(
                str(role_value),
                {
                    "role": role_value,
                    "principals": [],
                },
            )
            role_entry["principals"].append(principal_dict)
            continue

        label = fp.origin or "controller"
        controller_entry = controllers_by_label.setdefault(
            label,
            {
                "label": label,
                "controller_id": label,
                "source": label,
                "principals": [],
            },
        )
        controller_entry["principals"].append(principal_dict)

    authority_roles = list(authority_roles_by_key.values())
    if not authority_roles and ef.authority_roles:
        authority_roles = list(ef.authority_roles)

    controllers = list(controllers_by_label.values())
    has_more_specific_controller = any(
        any(not _is_generic_authority_contract_principal(principal) for principal in entry.get("principals", []))
        for entry in controllers
    )
    if has_more_specific_controller:
        controllers = [
            entry
            for entry in controllers
            if not entry.get("principals")
            or not all(_is_generic_authority_contract_principal(principal) for principal in entry["principals"])
        ]

    entry: dict[str, Any] = {
        "function": ef.abi_signature or ef.function_name,
        "selector": ef.selector,
        "effect_labels": list(ef.effect_labels or []),
        "effect_targets": list(ef.effect_targets or []),
        "claims": list(getattr(ef, "claims", None) or []),
        "action_summary": ef.action_summary,
        "authority_public": ef.authority_public,
        "controllers": controllers,
        "authority_roles": authority_roles,
        "direct_owner": direct_owner,
        "signature_witnesses": signature_witnesses,
    }

    capability_expr = getattr(ef, "capability_expr", None)
    if capability_expr is not None:
        entry["capability_expr"] = capability_expr
    conditions = getattr(ef, "conditions", None)
    if conditions is not None:
        entry["conditions"] = conditions
    status = getattr(ef, "status", None)
    if status is not None:
        entry["status"] = status

    return entry
