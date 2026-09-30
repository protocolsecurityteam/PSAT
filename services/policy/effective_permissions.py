#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import is_dataclass
from pathlib import Path
from typing import Any, Mapping, cast

from eth_utils.crypto import keccak

from schemas.contract_analysis import ContractAnalysis
from schemas.control_tracking import ControlSnapshot, coerce_resolved_controller_type
from schemas.effective_permissions import (
    AuthorityRoleGrant,
    EffectiveFunctionPermission,
    EffectivePermissions,
    PrincipalResolution,
    ResolvedAddressType,
    ResolvedControllerGrant,
    ResolvedPrincipal,
)
from services.policy.capability_surface import (
    capability_role_grants,
    capability_surface_openness,
    capability_surface_status,
    project_capability_surface,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (
    _split_top_level,
    has_no_selector,
    is_canonical_abi_signature,
)
from utils.logging import record_degraded

logger = logging.getLogger(__name__)

ELEMENTARY_TYPE_PREFIXES = (
    "address",
    "uint",
    "int",
    "bool",
    "bytes",
    "string",
    "fixed",
    "ufixed",
    "tuple",
)


def _lower_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).lower()


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _normalize_abi_type(type_name: str) -> str:
    stripped = type_name.strip()
    if not stripped:
        return stripped

    if stripped.startswith("DynArray[") and stripped.endswith("]"):
        inner = stripped[len("DynArray[") : -1]
        parts = inner.split(",", 1)
        return f"{_normalize_abi_type(parts[0])}[]"
    if stripped.startswith("HashMap[") and stripped.endswith("]"):
        return "mapping"
    if stripped.startswith("String[") and stripped.endswith("]"):
        return "string"
    if stripped.startswith("Bytes[") and stripped.endswith("]"):
        return "bytes"
    if stripped.endswith("]"):
        if "[" not in stripped:
            return "address"
        base, suffix = stripped.split("[", 1)
        return f"{_normalize_abi_type(base)}[{suffix}"

    # Already canonical; parentheses can't appear in a type name.
    if stripped.startswith("(") and stripped.endswith(")"):
        members = [m for m in _split_top_level(stripped[1:-1]) if m.strip()]
        return "(" + ",".join(_normalize_abi_type(m) for m in members) + ")"

    if stripped.startswith(ELEMENTARY_TYPE_PREFIXES):
        return stripped

    # ``A.B`` is a type nested in ``A``, provably not a contract (no nested contracts), and its real lowering isn't
    # recoverable from a name. Leave it so a derived selector fails closed.
    if "." in stripped:
        return stripped

    # Usually a contract reference; the canonical map resolves the rest.
    return "address"


def _abi_signature(function_signature: str) -> str:
    if "(" not in function_signature or not function_signature.endswith(")"):
        return function_signature
    name, args = function_signature.split("(", 1)
    args = args[:-1]
    if not args:
        return f"{name}()"
    raw_args: list[str] = []
    current: list[str] = []
    depth = 0
    for char in args:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(depth - 1, 0)
        if char == "," and depth == 0:
            piece = "".join(current).strip()
            if piece:
                raw_args.append(piece)
            current = []
            continue
        current.append(char)
    piece = "".join(current).strip()
    if piece:
        raw_args.append(piece)
    normalized_args = ",".join(_normalize_abi_type(arg) for arg in raw_args)
    return f"{name}({normalized_args})"


def _canonical_signature_map(predicate_trees: Mapping[str, Any] | None) -> dict[str, str]:
    """``full_name -> canonical ABI signature`` precomputed from Slither, so selectors match ``msg.sig`` for
    enum/struct params that string normalization can't lower.
    """
    if not isinstance(predicate_trees, dict):
        return {}
    canonical = predicate_trees.get("canonical_signatures")
    if not isinstance(canonical, dict):
        return {}
    return {
        str(name): str(sig)
        for name, sig in canonical.items()
        if isinstance(sig, str) and "(" in sig and sig.endswith(")")
    }


def _abi_signature_and_selector(
    function_signature: str, canonical_signatures: Mapping[str, str]
) -> tuple[str, str | None]:
    """``(abi_signature, selector)``, preferring the canonical map.

    ``None`` selector when the fallback couldn't fully lower: a hash of an unlowered type would be a selector the chain
    never dispatches. ``""`` for fallback/receive, which provably have none (``db/effect_cache.py``'s sentinel).
    """
    abi_sig = canonical_signatures.get(function_signature) or _abi_signature(function_signature)
    if has_no_selector(abi_sig):
        return abi_sig, ""
    if not is_canonical_abi_signature(abi_sig):
        return abi_sig, None
    return abi_sig, "0x" + keccak(text=abi_sig).hex()[:8]


def _resolved_principal(
    address: str,
    resolved_type: ResolvedAddressType,
    details: dict[str, object],
    *,
    source_contract: str | None = None,
    source_controller_id: str | None = None,
) -> ResolvedPrincipal:
    payload: ResolvedPrincipal = {
        "address": address,
        "resolved_type": resolved_type,
        "details": details,
    }
    if source_contract is not None:
        payload["source_contract"] = source_contract
    if source_controller_id is not None:
        payload["source_controller_id"] = source_controller_id
    return payload


def _known_principals(*snapshots: Mapping[str, Any] | None) -> dict[str, ResolvedPrincipal]:
    known: dict[str, ResolvedPrincipal] = {}
    for snapshot in snapshots:
        if not snapshot:
            continue
        contract_name = str(snapshot.get("contract_name", ""))
        controller_values = snapshot.get("controller_values", {})
        if not isinstance(controller_values, dict):
            continue
        for controller_id, value in controller_values.items():
            if not isinstance(controller_id, str) or not isinstance(value, dict):
                continue
            address_raw = value.get("value", "")
            address = _lower_string(address_raw)
            if not address.startswith("0x"):
                continue
            details_raw = value.get("details", {})
            details = dict(details_raw) if isinstance(details_raw, dict) else {}
            known[address] = _resolved_principal(
                address,
                coerce_resolved_controller_type(value.get("resolved_type")),
                details,
                source_contract=contract_name,
                source_controller_id=controller_id,
            )
    return known


def _principal_for_address(address: str, known: dict[str, ResolvedPrincipal]) -> ResolvedPrincipal:
    normalized = address.lower()
    return known.get(normalized) or _resolved_principal(normalized, "unknown", {})


def _controller_lookup(snapshot: Mapping[str, Any] | None) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    lookup: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    controller_values = (snapshot or {}).get("controller_values", {})
    if not isinstance(controller_values, dict):
        return lookup
    for controller_id, value in controller_values.items():
        if not isinstance(controller_id, str) or not isinstance(value, dict):
            continue
        source = str(value.get("source", controller_id))
        lookup.setdefault(source, []).append((controller_id, value))
    return lookup


def _controller_grants_for_refs(
    controller_refs: list[str],
    controller_lookup: dict[str, list[tuple[str, dict[str, Any]]]],
    known: dict[str, ResolvedPrincipal],
) -> list[ResolvedControllerGrant]:
    grants: list[ResolvedControllerGrant] = []
    seen: set[str] = set()
    for ref in controller_refs:
        for controller_id, value in controller_lookup.get(ref, []):
            if controller_id in seen:
                continue
            seen.add(controller_id)
            raw_value = _lower_string(value.get("value", ""))
            principals: list[ResolvedPrincipal] = []
            notes: list[str] = []
            details_raw = value.get("details", {})
            details = dict(details_raw) if isinstance(details_raw, dict) else {}
            raw_principals = details.get("resolved_principals", [])
            if isinstance(raw_principals, list):
                for principal in raw_principals:
                    if not isinstance(principal, dict):
                        continue
                    address = str(principal.get("address", "")).lower()
                    if not address.startswith("0x"):
                        continue
                    principal_details_raw = principal.get("details", {})
                    principal_details = dict(principal_details_raw) if isinstance(principal_details_raw, dict) else {}
                    principals.append(
                        _resolved_principal(
                            address,
                            coerce_resolved_controller_type(principal.get("resolved_type")),
                            principal_details,
                            source_controller_id=controller_id,
                        )
                    )
            if (
                raw_value.startswith("0x")
                and len(raw_value) == 42
                and raw_value != "0x0000000000000000000000000000000000000000"
            ):
                kind = controller_id.split(":", 1)[0] if ":" in controller_id else "unknown"
                if not principals and kind in {"state_variable", "singleton_slot", "computed"}:
                    principals.append(_principal_for_address(raw_value, known))
            elif raw_value and not principals:
                notes.append(f"value={raw_value}")
            kind = controller_id.split(":", 1)[0] if ":" in controller_id else "unknown"
            if not principals:
                continue
            grants.append(
                {
                    "controller_id": controller_id,
                    "label": ref,
                    "source": ref,
                    "kind": kind,
                    "principals": principals,
                    "notes": notes,
                }
            )
    return grants


def _normalize_capability_output(
    capability_resolver_output: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Resolver output may be dataclasses or serialized dicts; normalize to dicts."""
    if not capability_resolver_output:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for fn_signature, cap in capability_resolver_output.items():
        if cap is None:
            continue
        if isinstance(cap, dict):
            cap_dict = dict(cap)
            if not isinstance(cap_dict.get("kind"), str):
                cap_dict = _unsupported_capability("malformed_semantic_capability")
            out[str(fn_signature)] = cap_dict
            continue
        if is_dataclass(cap):
            try:
                from services.resolution.capability_resolver import capability_to_dict

                cap_dict = capability_to_dict(cap)  # pyright: ignore[reportArgumentType]
                if not isinstance(cap_dict.get("kind"), str):
                    cap_dict = _unsupported_capability("malformed_semantic_capability")
                out[str(fn_signature)] = cap_dict
            except Exception as exc:
                record_degraded(
                    phase="capability_serialization",
                    exc=exc,
                    context={"fn_signature": str(fn_signature)},
                )
                logger.warning(
                    "Failed to serialize CapabilityExpr for function %s: %s",
                    fn_signature,
                    exc,
                )
                out[str(fn_signature)] = _unsupported_capability("malformed_semantic_capability")
            continue
        out[str(fn_signature)] = _unsupported_capability("malformed_semantic_capability")
    return out


def _unsupported_capability(reason: str) -> dict[str, Any]:
    return {
        "kind": "unsupported",
        "unsupported_reason": reason,
        "membership_quality": "exact",
        "confidence": "check_only",
    }


def _public_capability() -> dict[str, Any]:
    return {
        "kind": "conditional_universal",
        "conditions": [],
        "membership_quality": "exact",
        "confidence": "enumerable",
    }


def _effects_by_function(
    effects: Mapping[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    if not isinstance(effects, dict):
        return {}
    functions = effects.get("functions")
    if not isinstance(functions, dict):
        return {}
    return {str(fn_sig): record for fn_sig, record in functions.items() if isinstance(record, dict)}


def _predicate_trees_by_function(predicate_trees: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(predicate_trees, dict):
        return {}
    trees = predicate_trees.get("trees")
    if not isinstance(trees, dict):
        return {}
    return {str(fn_sig): tree for fn_sig, tree in trees.items() if isinstance(tree, dict)}


def _guard_uncertain_signatures(predicate_trees: Mapping[str, Any] | None) -> frozenset[str]:
    """Caller guards the static stage couldn't lower; failed closed as ``unsupported``, never public."""
    if not isinstance(predicate_trees, dict):
        return frozenset()
    flagged = predicate_trees.get("guard_extraction_uncertain")
    if not isinstance(flagged, (list, set, tuple)):
        return frozenset()
    return frozenset(str(sig) for sig in flagged)


def _controller_refs_from_tree(tree: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(tree, dict):
        return []
    refs: list[str] = []
    seen: set[str] = set()

    def add(name: Any) -> None:
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            refs.append(name)

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        if node.get("op") == "LEAF":
            leaf = node.get("leaf") or {}
            if not isinstance(leaf, dict):
                return
            for operand in leaf.get("operands") or []:
                if isinstance(operand, dict) and operand.get("source") == "state_variable":
                    add(operand.get("state_variable_name"))
            descriptor = leaf.get("set_descriptor") or {}
            if isinstance(descriptor, dict):
                authority = descriptor.get("authority_contract") or {}
                if isinstance(authority, dict):
                    address_source = authority.get("address_source") or {}
                    if isinstance(address_source, dict) and address_source.get("source") == "state_variable":
                        add(address_source.get("state_variable_name"))
                for key_source in descriptor.get("key_sources") or []:
                    if isinstance(key_source, dict) and key_source.get("source") == "state_variable":
                        add(key_source.get("state_variable_name"))
            return
        for child in node.get("children") or []:
            visit(child)

    visit(tree)
    return refs


_SENSITIVE_SINK_KINDS = frozenset({"state_write", "external_call", "delegatecall", "contract_creation", "selfdestruct"})


def _effect_record_has_sensitive_sink(record: Mapping[str, Any]) -> bool:
    for sink in record.get("sinks") or []:
        if isinstance(sink, dict) and sink.get("kind") in _SENSITIVE_SINK_KINDS:
            return True
    return False


def _effect_record_is_state_changing_entry_point(record: Mapping[str, Any]) -> bool:
    """Selector-bearing, non-view, non-pure entry point, from the static stage's verified mutability."""
    return record.get("state_changing") is True


MUTABILITY_FIELDS = ("state_changing", "state_writes", "sinks", "writer_selectors")

_NOT_DETERMINED: dict[str, Any] = dict.fromkeys(MUTABILITY_FIELDS)


def _is_unselectored_entry_point(signature: str) -> bool:
    return signature.split("(")[0] in ("fallback", "receive")


def _mutability_fields(record: Mapping[str, Any]) -> dict[str, Any]:
    """Project an ``EffectInfo`` onto the four mutability columns.

    ``None`` means not determined, distinct from ``false``/``[]``. Measured on 2415 production records:

    * **No record or malformed field** — a missing effects artifact is a live production branch.
    * **fallback/receive** — ``state_changing`` is not determined (no selector isn't proof of no mutation: WETH9's
    fallback writes ``balanceOf``). Sinks and writes are published.
    * **view/pure with derived writes** (100 records) — the compiler forbids SSTORE, so these are OZ-v5 namespaced
    getters and struct copies. Trust the compiler for ``state_changing``; withhold everything derived from the same
    lowering, including ``sinks``.

    Empty ``state_writes`` on a view is not a contradiction.
    """
    if not isinstance(record, Mapping) or not record:
        return dict(_NOT_DETERMINED)

    signature = str(record.get("function") or "")
    raw_state_changing = record.get("state_changing")
    state_changing = raw_state_changing if isinstance(raw_state_changing, bool) else None

    out: dict[str, Any] = {
        "state_changing": None if _is_unselectored_entry_point(signature) else state_changing,
        "state_writes": record.get("state_writes"),
        "sinks": record.get("sinks"),
        "writer_selectors": record.get("writer_selectors"),
    }
    if not isinstance(out["state_writes"], list):
        out["state_writes"] = None
    if not isinstance(out["sinks"], list):
        out["sinks"] = None
    if not isinstance(out["writer_selectors"], list) or not all(
        isinstance(sel, str) for sel in out["writer_selectors"]
    ):
        out["writer_selectors"] = None

    contradicts_view = (
        state_changing is False and not _is_unselectored_entry_point(signature) and bool(out["state_writes"])
    )
    if contradicts_view:
        out["state_writes"] = None
        out["sinks"] = None
        out["writer_selectors"] = None
    return out


def _function_records_from_semantic_artifacts(
    *,
    capability_dicts: Mapping[str, dict[str, Any]],
    effects_by_function: Mapping[str, dict[str, Any]],
    predicate_trees_by_function: Mapping[str, dict[str, Any]],
    resolver_output_available: bool,
    guard_uncertain_signatures: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Records for capabilities ∪ trees ∪ sensitive-sink effects, plus every state-changing ABI entry point, so a
    mutator gated in inline assembly surfaces as ``unsupported`` instead of vanishing. Such rows carry no
    principals.
    """
    sink_signatures = {
        signature for signature, record in effects_by_function.items() if _effect_record_has_sensitive_sink(record)
    }
    abi_mutability_signatures = {
        signature
        for signature, record in effects_by_function.items()
        if _effect_record_is_state_changing_entry_point(record)
    }

    signatures = set(capability_dicts)
    signatures.update(predicate_trees_by_function)
    signatures.update(sink_signatures)
    signatures.update(abi_mutability_signatures)

    # Authority unresolved (gate outside the IR): unsupported, never public.
    abi_only_signatures = (
        abi_mutability_signatures - set(capability_dicts) - set(predicate_trees_by_function) - sink_signatures
    )

    # Assembly-originated state effects share the blindness: the gate may be assembly too. Only for state-changing entry
    # points: a proxy fallback that just delegatecalls has no gate by design and stays public.
    assembly_only_signatures = (
        {
            signature
            for signature, record in effects_by_function.items()
            if record.get("assembly_state_access") and _effect_record_is_state_changing_entry_point(record)
        }
        - set(capability_dicts)
        - set(predicate_trees_by_function)
    )

    records: list[dict[str, Any]] = []
    for signature in sorted(signatures):
        effect_info = effects_by_function.get(signature) or {}
        record: dict[str, Any] = {
            "function": signature,
            "controller_refs": _controller_refs_from_tree(predicate_trees_by_function.get(signature)),
            "effect_targets": list(effect_info.get("effect_targets") or []),
            "effect_labels": list(effect_info.get("effect_labels") or []),
            "claims": list(effect_info.get("claims") or []),
            "action_summary": effect_info.get("action_summary") or "Performs a contract action.",
            **_mutability_fields(effect_info),
        }
        if signature not in capability_dicts:
            if signature in predicate_trees_by_function:
                record["capability_expr"] = _unsupported_capability("missing_semantic_capability_for_predicate_tree")
                record["status"] = "unsupported"
            elif signature in guard_uncertain_signatures:
                # A caller guard was seen but not lowered: fail closed. Checked first so this specific evidence isn't
                # shadowed by the generic reason.
                record["capability_expr"] = _unsupported_capability("guard_extraction_uncertain")
                record["status"] = "unsupported"
            elif signature in abi_only_signatures or signature in assembly_only_signatures:
                record["capability_expr"] = _unsupported_capability("assembly_only_authority_not_extracted")
                record["status"] = "unsupported"
            elif resolver_output_available:
                record["capability_expr"] = _public_capability()
                record["status"] = "public"
                record["authority_public"] = True
            else:
                record["capability_expr"] = _unsupported_capability("missing_semantic_capability_resolver_output")
                record["status"] = "unsupported"
        records.append(record)
    return records


def _column_values_for_capability(cap_dict: dict[str, Any]) -> dict[str, Any]:
    """Mirror of the writer's per-kind rules, for read-only callers that don't invoke the writer."""
    surface = project_capability_surface(cap_dict)
    conditions = surface.conditions
    out: dict[str, Any] = {
        "capability_expr": dict(cap_dict),
        "conditions": conditions or None,
        "status": capability_surface_status(cap_dict, surface),
        "authority_public": surface.authority_public,
        "authority_openness": capability_surface_openness(cap_dict, surface),
    }
    return out


def build_effective_permissions(
    target_analysis: Mapping[str, Any] | ContractAnalysis,
    *,
    target_snapshot: Mapping[str, Any] | ControlSnapshot | None = None,
    authority_snapshot: Mapping[str, Any] | ControlSnapshot | None = None,
    artifact_paths: dict[str, str] | None = None,
    principal_resolution: PrincipalResolution | None = None,
    predicate_trees: Mapping[str, Any] | None = None,
    capability_resolver_output: Mapping[str, Any] | None = None,
    effects: Mapping[str, Any] | None = None,
) -> EffectivePermissions:
    """Build the ``effective_permissions`` artifact from the resolver's per-function CapabilityExpr dict and the
    ``effects`` artifact.
    """
    contract_address = target_analysis["subject"]["address"].lower()
    contract_name = target_analysis["subject"]["name"]

    known = _known_principals(target_snapshot, authority_snapshot)
    controller_lookup = _controller_lookup(target_snapshot)
    canonical_signatures = _canonical_signature_map(predicate_trees)
    capability_dicts = _normalize_capability_output(capability_resolver_output)
    effects_by_function = _effects_by_function(effects)
    predicate_tree_functions = _predicate_trees_by_function(predicate_trees)
    guard_uncertain_signatures = _guard_uncertain_signatures(predicate_trees)
    function_records = _function_records_from_semantic_artifacts(
        capability_dicts=capability_dicts,
        effects_by_function=effects_by_function,
        predicate_trees_by_function=predicate_tree_functions,
        resolver_output_available=capability_resolver_output is not None,
        guard_uncertain_signatures=guard_uncertain_signatures,
    )

    functions: list[EffectiveFunctionPermission] = []
    for function_record in function_records:
        abi_signature, selector = _abi_signature_and_selector(function_record["function"], canonical_signatures)
        controller_refs = sorted(set(function_record.get("controller_refs", [])))
        direct_owner = None

        notes: list[str] = []
        controller_grants = _controller_grants_for_refs(
            controller_refs,
            controller_lookup,
            known,
        )

        fn_signature = function_record["function"]
        effects_record = effects_by_function.get(fn_signature) or {}
        semantic_effect_labels = effects_record.get("effect_labels") if effects_record else None
        semantic_effect_targets = effects_record.get("effect_targets") if effects_record else None
        semantic_action_summary = effects_record.get("action_summary") if effects_record else None
        semantic_claims = effects_record.get("claims") if effects_record else None

        effect_labels_out = (
            list(semantic_effect_labels)
            if isinstance(semantic_effect_labels, list)
            else list(function_record.get("effect_labels", []))
        )
        claims_out = (
            list(semantic_claims) if isinstance(semantic_claims, list) else list(function_record.get("claims", []))
        )
        effect_targets_out = (
            list(semantic_effect_targets)
            if isinstance(semantic_effect_targets, list)
            else list(function_record.get("effect_targets", []))
        )
        action_summary_out = (
            semantic_action_summary
            if isinstance(semantic_action_summary, str) and semantic_action_summary
            else function_record.get("action_summary", "Performs a contract action.")
        )

        # Three-state role half from whichever capability this record carries (resolver's, else the policy-minted one);
        # ``None`` only when there's no capability.
        resolved_capability = capability_dicts.get(fn_signature)
        minted_capability = function_record.get("capability_expr")
        role_source_capability = (
            resolved_capability
            if resolved_capability is not None
            else (minted_capability if isinstance(minted_capability, dict) else None)
        )
        authority_roles_out = cast(
            "list[AuthorityRoleGrant] | None",
            capability_role_grants(role_source_capability) if role_source_capability is not None else None,
        )

        function_permission: EffectiveFunctionPermission = {
            "function": fn_signature,
            "abi_signature": abi_signature,
            "selector": selector,
            "direct_owner": direct_owner,
            "authority_public": False,
            "authority_roles": authority_roles_out,
            "controllers": controller_grants,
            "effect_targets": effect_targets_out,
            "effect_labels": effect_labels_out,
            "claims": claims_out,
            "action_summary": action_summary_out,
            "notes": notes,
        }
        # Must survive this hop or the columns are NULL in production while record-level tests pass.
        mutability = _mutability_fields(effects_record)
        function_permission["state_changing"] = mutability["state_changing"]
        function_permission["state_writes"] = mutability["state_writes"]
        function_permission["sinks"] = mutability["sinks"]
        function_permission["writer_selectors"] = mutability["writer_selectors"]

        cap_dict = capability_dicts.get(fn_signature)
        if cap_dict is not None:
            cap_columns = _column_values_for_capability(cap_dict)
            function_permission["capability_expr"] = cap_columns["capability_expr"]
            if cap_columns["conditions"] is not None:
                function_permission["conditions"] = cap_columns["conditions"]
            if cap_columns["status"] is not None:
                function_permission["status"] = cap_columns["status"]
            if cap_columns["authority_public"]:
                function_permission["authority_public"] = True
            # The writer reads it from the record; dropping it left NULL, which means "pre-column row" and is false
            # here.
            function_permission["authority_openness"] = cap_columns["authority_openness"]
        else:
            if function_record.get("capability_expr") is not None:
                function_permission["capability_expr"] = function_record["capability_expr"]
            if function_record.get("conditions") is not None:
                function_permission["conditions"] = function_record["conditions"]
            if function_record.get("status") is not None:
                function_permission["status"] = function_record["status"]
            if function_record.get("authority_public") is True:
                function_permission["authority_public"] = True
            # Policy-minted capabilities get the same openness projection; an absent key would publish a NULL that
            # misstates the row.
            if isinstance(minted_capability, dict):
                minted_surface = project_capability_surface(minted_capability)
                function_permission["authority_openness"] = capability_surface_openness(
                    minted_capability, minted_surface
                )

        functions.append(function_permission)

    return {
        "schema_version": "0.1",
        "contract_address": contract_address,
        "contract_name": contract_name,
        "authority_contract": None,
        "principal_resolution": principal_resolution
        or {
            "status": "complete",
            "reason": "Semantic capability resolver output was joined into the permission view.",
        },
        "artifacts": artifact_paths or {},
        "functions": functions,
    }


def write_effective_permissions_from_files(
    target_analysis_path: Path,
    *,
    target_snapshot_path: Path | None = None,
    authority_snapshot_path: Path | None = None,
    resolved_control_graph_path: Path | None = None,
    output_path: Path | None = None,
    principal_resolution: PrincipalResolution | None = None,
) -> Path:
    target_analysis = _load_json(target_analysis_path)
    target_snapshot = _load_json(target_snapshot_path) if target_snapshot_path else None
    authority_snapshot = _load_json(authority_snapshot_path) if authority_snapshot_path else None

    artifact_paths = {
        "target_analysis": str(target_analysis_path),
    }
    if target_snapshot_path:
        artifact_paths["target_snapshot"] = str(target_snapshot_path)
    if authority_snapshot_path:
        artifact_paths["authority_snapshot"] = str(authority_snapshot_path)
    if resolved_control_graph_path:
        artifact_paths["resolved_control_graph"] = str(resolved_control_graph_path)

    payload = build_effective_permissions(
        target_analysis,
        target_snapshot=target_snapshot,
        authority_snapshot=authority_snapshot,
        artifact_paths=artifact_paths,
        principal_resolution=principal_resolution,
    )
    if output_path is None:
        output_path = target_analysis_path.with_name("effective_permissions.json")
    output_path.write_text(json.dumps(payload, indent=2) + "\n")
    return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve effective permissions from semantic contract-analysis artifacts."
    )
    parser.add_argument("target_analysis", help="Path to target contract_analysis.json")
    parser.add_argument("--target-snapshot", help="Optional path to target control_snapshot.json")
    parser.add_argument("--authority-snapshot", help="Optional path to authority control_snapshot.json")
    parser.add_argument("--out", help="Optional path to effective_permissions.json")
    args = parser.parse_args()

    output_path = write_effective_permissions_from_files(
        Path(args.target_analysis),
        target_snapshot_path=Path(args.target_snapshot) if args.target_snapshot else None,
        authority_snapshot_path=Path(args.authority_snapshot) if args.authority_snapshot else None,
        output_path=Path(args.out) if args.out else None,
    )
    logger.info("Effective permissions written", extra={"output_path": str(output_path)})


if __name__ == "__main__":
    main()
