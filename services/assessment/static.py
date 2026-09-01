"""Build the canonical static Assessment from analyzer facts.

The current static pipeline still emits its historical artifacts while the
single-PR rewrite is in progress.  This module is the cutover boundary: it
turns those facts into stable domain objects, evidence-backed claims, and
static_facts receipts.  Downstream stages will update this document rather than
inventing another stage-shaped source of truth.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import (
    Analysis,
    Assessment,
    Claim,
    Contract,
    Controller,
    Diagnostic,
    Effect,
    EffectFamily,
    EffectKind,
    Evidence,
    EvidenceMethod,
    Function,
    Proposition,
)
from services.static.claims.matchers import discover
from services.static.claims.registry import entry_for, is_registered

from .keys import content_key, entity_key
from .validation import checked


def _json(value: Any) -> JsonValue:
    """Normalize analyzer values to the JSON domain once, at ingress."""

    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))


def _selector(info: Mapping[str, Any]) -> str | None:
    value = info.get("abi_selector") or info.get("selector")
    return value if isinstance(value, str) and value else None


def _functions(effects: Mapping[str, Any]) -> dict[str, Function]:
    raw_functions = effects.get("functions")
    if not isinstance(raw_functions, Mapping):
        return {}
    functions: dict[str, Function] = {}
    for signature, raw in sorted(raw_functions.items(), key=lambda item: str(item[0])):
        if not isinstance(signature, str) or not isinstance(raw, Mapping):
            continue
        selector = _selector(raw)
        state_changing = raw.get("state_changing")
        functions[signature] = {
            "selector": selector,
            "state_changing": state_changing if isinstance(state_changing, bool) else None,
        }
    return functions


def _controllers(static_facts: Mapping[str, Any]) -> dict[str, Controller]:
    raw_controllers = static_facts.get("controller_tracking")
    if not isinstance(raw_controllers, list):
        return {}
    controllers: dict[str, Controller] = {}
    for raw in raw_controllers:
        if not isinstance(raw, Mapping):
            continue
        local_id = raw.get("controller_id")
        if not isinstance(local_id, str) or not local_id:
            continue
        controllers[local_id] = {
            "label": str(raw.get("label") or local_id),
            "kind": str(raw.get("kind") or "unknown"),
            "source": _json(raw.get("source")),
            "read_strategy": _json(raw.get("read_spec")),
            "tracking": _json(
                {
                    "mode": raw.get("tracking_mode"),
                    "writer_functions": raw.get("writer_functions") or [],
                    "associated_events": raw.get("associated_events") or [],
                    "polling_sources": raw.get("polling_sources") or [],
                    "notes": raw.get("notes") or [],
                    "authority_provenance": raw.get("authority_provenance"),
                }
            ),
        }
    return controllers


def _iter_mandatory_state_reads(tree: Any) -> set[tuple[str, str | None]]:
    reads: set[tuple[str, str | None]] = set()

    def walk(node: Any, mandatory: bool) -> None:
        if not isinstance(node, Mapping):
            return
        op = node.get("op")
        if op == "LEAF":
            if not mandatory:
                return
            leaf = node.get("leaf")
            if not isinstance(leaf, Mapping):
                return
            operands = leaf.get("operands")
            if not isinstance(operands, list):
                return
            for operand in operands:
                if not isinstance(operand, Mapping):
                    continue
                variable = operand.get("state_variable_name")
                if not isinstance(variable, str) or not variable:
                    continue
                member_path = operand.get("member_path")
                member = member_path[0] if isinstance(member_path, list) and member_path else None
                reads.add((variable, member if isinstance(member, str) else None))
            return
        child_mandatory = mandatory and op != "OR"
        children = node.get("children")
        if isinstance(children, list):
            for child in children:
                walk(child, child_mandatory)

    walk(tree, True)
    return reads


def _reads_by_function(predicate_trees: Mapping[str, Any]) -> dict[str, set[tuple[str, str | None]]]:
    trees = predicate_trees.get("trees")
    if not isinstance(trees, Mapping):
        return {}
    return {
        signature: _iter_mandatory_state_reads(tree) for signature, tree in trees.items() if isinstance(signature, str)
    }


def _pause_flags(witness: Mapping[str, Any]) -> set[tuple[str, str | None]]:
    flags = witness.get("flags")
    if not isinstance(flags, list):
        return set()
    out: set[tuple[str, str | None]] = set()
    for flag in flags:
        if not isinstance(flag, Mapping):
            continue
        variable = flag.get("var")
        member = flag.get("member")
        if isinstance(variable, str) and variable:
            out.add((variable, member if isinstance(member, str) and member else None))
    return out


def _pair_matches(left: tuple[str, str | None], right: tuple[str, str | None]) -> bool:
    return left[0] == right[0] and (left[1] == right[1] or left[1] is None or right[1] is None)


def _pause_victims(
    witness: Mapping[str, Any],
    reads_by_signature: Mapping[str, set[tuple[str, str | None]]],
    functions: Mapping[str, Function],
) -> list[str]:
    recorded = witness.get("affected_functions")
    if isinstance(recorded, list):
        return sorted(
            {
                signature
                for signature in recorded
                if isinstance(signature, str)
                and signature in functions
                and functions[signature]["state_changing"] is True
            }
        )
    flags = _pause_flags(witness)
    if not flags:
        return []
    victims: list[str] = []
    for signature, reads in reads_by_signature.items():
        function = functions.get(signature)
        if function is None or function["state_changing"] is not True:
            continue
        if any(_pair_matches(flag, read) for flag in flags for read in reads):
            victims.append(signature)
    return sorted(set(victims))


def _effect_targets(info: Mapping[str, Any], witness: Mapping[str, Any]) -> list[dict[str, str]]:
    flags = _pause_flags(witness)
    if flags:
        flag_targets: list[dict[str, str]] = []
        for variable, member in sorted(flags, key=lambda pair: (pair[0], pair[1] or "")):
            target = {
                "kind": "state",
                "value": variable,
            }
            if member is not None:
                target["member"] = member
            flag_targets.append(target)
        return flag_targets

    writes = info.get("state_writes")
    state_names: set[str] = set()
    if isinstance(writes, list):
        state_names = {str(write.get("var")) for write in writes if isinstance(write, Mapping) and write.get("var")}
    targets: list[dict[str, str]] = []
    for name in sorted(state_names):
        targets.append({"kind": "state", "value": name})
    sinks = info.get("sinks")
    if not isinstance(sinks, list):
        return targets
    for sink in sinks:
        if not isinstance(sink, Mapping) or sink.get("origin") == "guard":
            continue
        raw = sink.get("target")
        if not isinstance(raw, str) or not raw or raw in state_names:
            continue
        kind = "account" if raw.startswith("0x") and len(raw) == 42 else "operation"
        targets.append({"kind": kind, "value": raw})
    return targets


def _evidence_method(tier: object) -> EvidenceMethod:
    if tier == "standard_exact":
        return "standard"
    if tier == "behavioral_observed":
        return "fork_execution"
    if tier == "policy_derived":
        return "policy_derivation"
    return "static_ir"


def _claims_and_evidence(
    *,
    contract: Contract,
    effects: Mapping[str, Any],
    predicate_trees: Mapping[str, Any],
    functions: Mapping[str, Function],
) -> tuple[dict[str, Claim], dict[str, Evidence], dict[str, list[str]]]:
    raw_functions = effects.get("functions")
    if not isinstance(raw_functions, Mapping):
        return {}, {}, {}
    reads = _reads_by_function(predicate_trees)
    claims: dict[str, Claim] = {}
    evidence: dict[str, Evidence] = {}
    claim_keys_by_kind: dict[str, list[str]] = {}

    for signature, info in sorted(raw_functions.items(), key=lambda item: str(item[0])):
        if not isinstance(signature, str) or not isinstance(info, Mapping):
            continue
        if signature not in functions:
            continue
        raw_claims = info.get("claims")
        if not isinstance(raw_claims, list):
            continue
        for raw_claim in raw_claims:
            if not isinstance(raw_claim, Mapping):
                continue
            kind = raw_claim.get("claim_id")
            tier = raw_claim.get("tier")
            witness = raw_claim.get("witness")
            if not isinstance(kind, str) or not is_registered(kind) or not isinstance(witness, Mapping):
                continue
            registry_entry = entry_for(kind)
            method = _evidence_method(tier)
            observation = _json(witness)
            evidence_key = content_key(
                "evidence",
                {
                    "contract": contract,
                    "method": method,
                    "function": signature,
                    "claim": kind,
                    "observation": observation,
                },
            )
            evidence[evidence_key] = {
                "method": method,
                "subject_kind": "function",
                "subject": signature,
                "observation": observation,
                "producer": f"static.claims.{kind}",
                "version": str(effects.get("claims_schema_version") or "claims/1"),
                "locator": _json({"function": signature, "tier": tier}),
            }
            affected = _pause_victims(witness, reads, functions) if kind in ("pause.set", "pause.unset") else []
            effect: Effect = {
                "kind": cast(EffectKind, kind),
                "family": cast(EffectFamily, registry_entry.consumer_family),
                "targets": _effect_targets(info, witness),
                "affected_functions": affected,
            }
            proposition: Proposition = {
                "kind": "function_effect",
                "function": signature,
                "effect": effect,
            }
            claim_key = content_key("claim", {"contract": contract, "proposition": proposition})
            claims[claim_key] = {
                "proposition": proposition,
                "rule": f"{kind}/{tier}",
                "evidence": [evidence_key],
                "claims": [],
            }
            claim_keys_by_kind.setdefault(kind, []).append(claim_key)

    return claims, evidence, claim_keys_by_kind


def _claim_analyses(
    *,
    effects: Mapping[str, Any],
    functions: Mapping[str, Function],
    claim_keys_by_kind: Mapping[str, list[str]],
    evidence: Mapping[str, Evidence],
    predicate_trees_ok: bool,
) -> list[Analysis]:
    raw_analyses = effects.get("claim_analyses")
    raw_diagnostics = effects.get("claim_diagnostics")
    diagnostics_by_kind: dict[str, list[Diagnostic]] = {}
    if isinstance(raw_diagnostics, list):
        for raw in raw_diagnostics:
            if not isinstance(raw, Mapping):
                continue
            kind = raw.get("claim_id")
            if not isinstance(kind, str):
                continue
            signature = raw.get("function")
            diagnostic: Diagnostic = {
                "severity": "degraded",
                "code": str(raw.get("exc_type") or "ClaimMatcherError"),
                "message": str(raw.get("message") or "claim matcher failed"),
            }
            if isinstance(signature, str) and signature in functions:
                diagnostic["target_kind"] = "function"
                diagnostic["target"] = signature
            diagnostics_by_kind.setdefault(kind, []).append(diagnostic)

    evidence_by_claim_kind: dict[str, list[str]] = {}
    for evidence_key, item in evidence.items():
        producer = item["producer"]
        if producer.startswith("static.claims."):
            evidence_by_claim_kind.setdefault(producer.removeprefix("static.claims."), []).append(evidence_key)

    analyses: list[Analysis] = []
    if isinstance(raw_analyses, Mapping):
        for kind, raw in sorted(raw_analyses.items(), key=lambda item: str(item[0])):
            if not isinstance(kind, str) or not isinstance(raw, Mapping):
                continue
            omissions: list[dict[str, str]] = []
            raw_omissions = raw.get("omissions")
            if isinstance(raw_omissions, list):
                for omission in raw_omissions:
                    if not isinstance(omission, Mapping):
                        continue
                    signature = omission.get("function")
                    if isinstance(signature, str) and signature in functions:
                        omissions.append(
                            {
                                "target_kind": "function",
                                "target": signature,
                                "reason": str(omission.get("reason") or "claim_matcher_omitted"),
                            }
                        )

            status = raw.get("status")
            total = raw.get("targets_total")
            completed = raw.get("targets_completed")
            if kind in ("pause.set", "pause.unset") and not predicate_trees_ok:
                status = "failed"
                total = len(functions)
                completed = 0
                omissions = [
                    {"target_kind": "function", "target": signature, "reason": "predicate_trees_unavailable"}
                    for signature in functions
                ]
            analyses.append(
                {
                    "detector": kind,
                    "version": str(effects.get("claims_schema_version") or "claims/1"),
                    "status": status if status in ("completed", "partial", "failed") else "partial",
                    "targets_total": total if isinstance(total, int) else len(functions),
                    "targets_completed": completed if isinstance(completed, int) else 0,
                    "omissions": omissions,
                    "diagnostics": diagnostics_by_kind.get(kind, []),
                    "claims": sorted(claim_keys_by_kind.get(kind, [])),
                    "evidence": sorted(evidence_by_claim_kind.get(kind, [])),
                }
            )
    return analyses


def build_static_assessment(
    *,
    chain_id: int,
    address: str,
    contract_name: str,
    code_hash: str | None,
    source_hash: str | None,
    static_facts: Mapping[str, Any],
    effects: Mapping[str, Any],
    predicate_trees: Mapping[str, Any],
) -> Assessment:
    """Build the static-stage canonical assessment."""

    discover()
    normalized_address = address.lower()
    contract: Contract = {
        "chain_id": chain_id,
        "address": normalized_address,
        "deployment_address": normalized_address,
        "name": contract_name,
        "code_hash": code_hash,
        "source_hash": source_hash,
    }
    functions = _functions(effects)
    controllers = _controllers(static_facts)
    root_entity_key = entity_key(chain_id, normalized_address)
    claims, evidence, claim_keys_by_kind = _claims_and_evidence(
        contract=contract,
        effects=effects,
        predicate_trees=predicate_trees,
        functions=functions,
    )
    static_observation = _json(
        {
            "subject": static_facts.get("subject") or {},
            "summary": static_facts.get("summary") or {},
            "role_definitions": (
                (static_facts.get("semantic_control") or {}).get("role_definitions")
                if isinstance(static_facts.get("semantic_control"), Mapping)
                else []
            )
            or [],
        }
    )
    static_evidence_key = content_key(
        "evidence",
        {"contract": contract, "method": "static_ir", "producer": "static.facts", "observation": static_observation},
    )
    evidence[static_evidence_key] = {
        "method": "static_ir",
        "subject_kind": "contract",
        "subject": normalized_address,
        "observation": static_observation,
        "producer": "static.facts",
        "version": str(static_facts.get("schema_version") or "static/1"),
        "locator": _json({"section": "summary"}),
    }
    predicate_trees_ok = "error" not in predicate_trees and isinstance(predicate_trees.get("trees"), Mapping)
    analyses = _claim_analyses(
        effects=effects,
        functions=functions,
        claim_keys_by_kind=claim_keys_by_kind,
        evidence=evidence,
        predicate_trees_ok=predicate_trees_ok,
    )
    effects_ok = "error" not in effects and isinstance(effects.get("functions"), Mapping)
    facts_omissions: list[dict[str, str]] = []
    facts_diagnostics: list[Diagnostic] = []
    if not predicate_trees_ok:
        facts_omissions.append(
            {
                "target_kind": "contract",
                "target": normalized_address,
                "reason": "predicate_trees_unavailable",
            }
        )
        facts_diagnostics.append(
            {
                "severity": "degraded",
                "code": "PredicateTreesUnavailable",
                "message": str(predicate_trees.get("error") or "predicate tree artifact is absent or invalid"),
                "target_kind": "contract",
                "target": normalized_address,
            }
        )
    if not effects_ok:
        facts_omissions.append(
            {
                "target_kind": "contract",
                "target": normalized_address,
                "reason": "effects_unavailable",
            }
        )
        facts_diagnostics.append(
            {
                "severity": "degraded",
                "code": "EffectsUnavailable",
                "message": str(effects.get("error") or "effects artifact is absent or invalid"),
                "target_kind": "contract",
                "target": normalized_address,
            }
        )
    facts_status = "completed" if not facts_omissions else ("partial" if predicate_trees_ok or effects_ok else "failed")
    facts_receipt: Analysis = {
        "detector": "static.facts",
        "version": str(effects.get("schema_version") or predicate_trees.get("schema_version") or "static/1"),
        "status": facts_status,
        "targets_total": 2,
        "targets_completed": int(predicate_trees_ok) + int(effects_ok),
        "omissions": facts_omissions,
        "diagnostics": facts_diagnostics,
        "claims": [],
        "evidence": [static_evidence_key],
    }
    analyses.insert(0, facts_receipt)
    assessment: Assessment = {
        "schema_version": "assessment/2",
        "contract": contract,
        "functions": functions,
        "controllers": controllers,
        "entities": {
            root_entity_key: {
                "chain_id": chain_id,
                "address": normalized_address,
                "kind": "contract",
                "tags": [],
            }
        },
        "claims": claims,
        "evidence": evidence,
        "analyses": analyses,
    }
    return checked(assessment)


__all__ = ["build_static_assessment"]
