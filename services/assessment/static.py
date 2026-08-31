"""Build the canonical static Assessment from analyzer facts.

The current static pipeline still emits its historical artifacts while the
single-PR rewrite is in progress.  This module is the cutover boundary: it
turns those facts into stable domain objects, evidence-backed claims, and
analysis receipts.  Downstream stages will update this document rather than
inventing another stage-shaped source of truth.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from pydantic import JsonValue

from schemas.assessment import (
    Account,
    Analysis,
    Assessment,
    Basis,
    Claim,
    Contract,
    Controller,
    Diagnostic,
    Effect,
    EffectFamily,
    EffectKind,
    EffectTarget,
    Evidence,
    EvidenceMethod,
    Function,
    FunctionEffect,
    Omission,
    Scope,
)
from services.static.claims.matchers import discover
from services.static.claims.registry import entry_for, is_registered

from .ids import stable_id
from .validation import checked


def _json(value: Any) -> JsonValue:
    """Normalize legacy analyzer values to the JSON domain once, at ingress."""

    return cast(JsonValue, json.loads(json.dumps(value, sort_keys=True, default=str)))


def _account_id(chain_id: int, address: str) -> str:
    return stable_id("account", {"chain_id": chain_id, "address": address.lower()})


def _contract_id(chain_id: int, address: str, code_hash: str | None, source_hash: str | None) -> str:
    return stable_id(
        "contract",
        {
            "chain_id": chain_id,
            "address": address.lower(),
            "code_hash": code_hash,
            "source_hash": source_hash,
        },
    )


def _function_id(contract_id: str, signature: str, selector: str | None) -> str:
    return stable_id("function", {"contract_id": contract_id, "signature": signature, "selector": selector})


def _selector(info: Mapping[str, Any]) -> str | None:
    value = info.get("abi_selector") or info.get("selector")
    return value if isinstance(value, str) and value else None


def _functions(contract_id: str, effects: Mapping[str, Any]) -> tuple[dict[str, Function], dict[str, str]]:
    raw_functions = effects.get("functions")
    if not isinstance(raw_functions, Mapping):
        return {}, {}
    functions: dict[str, Function] = {}
    ids_by_signature: dict[str, str] = {}
    for signature, raw in sorted(raw_functions.items(), key=lambda item: str(item[0])):
        if not isinstance(signature, str) or not isinstance(raw, Mapping):
            continue
        selector = _selector(raw)
        function_id = _function_id(contract_id, signature, selector)
        state_changing = raw.get("state_changing")
        functions[function_id] = {
            "id": function_id,
            "contract_id": contract_id,
            "signature": signature,
            "selector": selector,
            "state_changing": state_changing if isinstance(state_changing, bool) else None,
        }
        ids_by_signature[signature] = function_id
    return functions, ids_by_signature


def _controllers(contract_id: str, analysis: Mapping[str, Any]) -> dict[str, Controller]:
    raw_controllers = analysis.get("controller_tracking")
    if not isinstance(raw_controllers, list):
        return {}
    controllers: dict[str, Controller] = {}
    for raw in raw_controllers:
        if not isinstance(raw, Mapping):
            continue
        local_id = raw.get("controller_id")
        if not isinstance(local_id, str) or not local_id:
            continue
        controller_id = stable_id("controller", {"contract_id": contract_id, "controller_id": local_id})
        controllers[controller_id] = {
            "id": controller_id,
            "contract_id": contract_id,
            "key": local_id,
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
    ids_by_signature: Mapping[str, str],
) -> list[str]:
    recorded = witness.get("affected_functions")
    if isinstance(recorded, list):
        return sorted(
            {
                function_id
                for signature in recorded
                if isinstance(signature, str)
                and (function_id := ids_by_signature.get(signature)) is not None
                and functions[function_id]["state_changing"] is True
            }
        )
    flags = _pause_flags(witness)
    if not flags:
        return []
    victims: list[str] = []
    for signature, reads in reads_by_signature.items():
        function_id = ids_by_signature.get(signature)
        function = functions.get(function_id) if function_id is not None else None
        if function is None or function["state_changing"] is not True:
            continue
        if any(_pair_matches(flag, read) for flag in flags for read in reads):
            victims.append(function["id"])
    return sorted(set(victims))


def _effect_targets(info: Mapping[str, Any], witness: Mapping[str, Any]) -> list[EffectTarget]:
    flags = _pause_flags(witness)
    if flags:
        flag_targets: list[EffectTarget] = []
        for variable, member in sorted(flags, key=lambda pair: (pair[0], pair[1] or "")):
            target: EffectTarget = {
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
    raw_targets = info.get("effect_targets")
    if not isinstance(raw_targets, list):
        return []
    targets: list[EffectTarget] = []
    for raw in raw_targets:
        if not isinstance(raw, str) or not raw:
            continue
        if raw in state_names:
            kind = "state"
        elif raw.startswith("0x") and len(raw) == 42:
            kind = "account"
        else:
            kind = "operation"
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
    scope: Scope,
    effects: Mapping[str, Any],
    predicate_trees: Mapping[str, Any],
    functions: Mapping[str, Function],
    ids_by_signature: Mapping[str, str],
) -> tuple[dict[str, Claim], dict[str, Evidence], dict[str, list[str]]]:
    raw_functions = effects.get("functions")
    if not isinstance(raw_functions, Mapping):
        return {}, {}, {}
    reads = _reads_by_function(predicate_trees)
    claims: dict[str, Claim] = {}
    evidence: dict[str, Evidence] = {}
    claim_ids_by_kind: dict[str, list[str]] = {}

    for signature, info in sorted(raw_functions.items(), key=lambda item: str(item[0])):
        if not isinstance(signature, str) or not isinstance(info, Mapping):
            continue
        function_id = ids_by_signature.get(signature)
        if function_id is None:
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
            evidence_id = stable_id(
                "evidence",
                {
                    "scope": scope,
                    "method": method,
                    "function_id": function_id,
                    "claim": kind,
                    "observation": observation,
                },
            )
            evidence[evidence_id] = {
                "id": evidence_id,
                "method": method,
                "subject": {"kind": "function", "id": function_id},
                "observation": observation,
                "source": {
                    "producer": f"static.claims.{kind}",
                    "version": str(effects.get("claims_schema_version") or "claims/legacy"),
                    "locator": _json({"function": signature, "tier": tier}),
                },
                "scope": scope,
            }
            affected = (
                _pause_victims(witness, reads, functions, ids_by_signature)
                if kind in ("pause.set", "pause.unset")
                else []
            )
            effect: Effect = {
                "kind": cast(EffectKind, kind),
                "family": cast(EffectFamily, registry_entry.consumer_family),
                "targets": _effect_targets(info, witness),
                "affected_functions": affected,
            }
            proposition: FunctionEffect = {
                "kind": "function_effect",
                "function_id": function_id,
                "effect": effect,
            }
            basis: Basis = {
                "rule": f"{kind}/{tier}",
                "evidence_ids": [evidence_id],
                "claim_ids": [],
            }
            claim_id = stable_id("claim", {"scope": scope, "proposition": proposition})
            claims[claim_id] = {
                "id": claim_id,
                "proposition": proposition,
                "basis": basis,
                "scope": scope,
            }
            claim_ids_by_kind.setdefault(kind, []).append(claim_id)

    return claims, evidence, claim_ids_by_kind


def _claim_analyses(
    *,
    effects: Mapping[str, Any],
    ids_by_signature: Mapping[str, str],
    claim_ids_by_kind: Mapping[str, list[str]],
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
            if isinstance(signature, str) and signature in ids_by_signature:
                diagnostic["target_kind"] = "function"
                diagnostic["target_id"] = ids_by_signature[signature]
            diagnostics_by_kind.setdefault(kind, []).append(diagnostic)

    evidence_by_claim_kind: dict[str, list[str]] = {}
    for evidence_id, item in evidence.items():
        producer = item["source"]["producer"]
        if producer.startswith("static.claims."):
            evidence_by_claim_kind.setdefault(producer.removeprefix("static.claims."), []).append(evidence_id)

    analyses: list[Analysis] = []
    if isinstance(raw_analyses, Mapping):
        for kind, raw in sorted(raw_analyses.items(), key=lambda item: str(item[0])):
            if not isinstance(kind, str) or not isinstance(raw, Mapping):
                continue
            omissions: list[Omission] = []
            raw_omissions = raw.get("omissions")
            if isinstance(raw_omissions, list):
                for omission in raw_omissions:
                    if not isinstance(omission, Mapping):
                        continue
                    signature = omission.get("function")
                    if isinstance(signature, str) and signature in ids_by_signature:
                        omissions.append(
                            {
                                "target_kind": "function",
                                "target_id": ids_by_signature[signature],
                                "reason": str(omission.get("reason") or "claim_matcher_omitted"),
                            }
                        )

            status = raw.get("status")
            total = raw.get("targets_total")
            completed = raw.get("targets_completed")
            if kind in ("pause.set", "pause.unset") and not predicate_trees_ok:
                status = "failed"
                total = len(ids_by_signature)
                completed = 0
                omissions = [
                    {"target_kind": "function", "target_id": function_id, "reason": "predicate_trees_unavailable"}
                    for function_id in ids_by_signature.values()
                ]
            analyses.append(
                {
                    "detector": kind,
                    "version": str(effects.get("claims_schema_version") or "claims/legacy"),
                    "status": status if status in ("completed", "partial", "failed") else "partial",
                    "coverage": {
                        "targets_total": total if isinstance(total, int) else len(ids_by_signature),
                        "targets_completed": completed if isinstance(completed, int) else 0,
                        "omissions": omissions,
                    },
                    "diagnostics": diagnostics_by_kind.get(kind, []),
                    "claim_ids": sorted(claim_ids_by_kind.get(kind, [])),
                    "evidence_ids": sorted(evidence_by_claim_kind.get(kind, [])),
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
    analysis: Mapping[str, Any],
    effects: Mapping[str, Any],
    predicate_trees: Mapping[str, Any],
) -> Assessment:
    """Build the static-stage canonical assessment."""

    discover()
    normalized_address = address.lower()
    account_id = _account_id(chain_id, normalized_address)
    contract_id = _contract_id(chain_id, normalized_address, code_hash, source_hash)
    account: Account = {"id": account_id, "chain_id": chain_id, "address": normalized_address}
    contract: Contract = {
        "id": contract_id,
        "account_id": account_id,
        "name": contract_name,
        "code_hash": code_hash,
        "source_hash": source_hash,
    }
    scope: Scope = {
        "contract_id": contract_id,
        "account_id": account_id,
        "code_hash": code_hash,
        "source_hash": source_hash,
    }
    functions, ids_by_signature = _functions(contract_id, effects)
    controllers = _controllers(contract_id, analysis)
    root_entity_id = stable_id("entity", {"account_id": account_id})
    claims, evidence, claim_ids_by_kind = _claims_and_evidence(
        scope=scope,
        effects=effects,
        predicate_trees=predicate_trees,
        functions=functions,
        ids_by_signature=ids_by_signature,
    )
    predicate_trees_ok = "error" not in predicate_trees and isinstance(predicate_trees.get("trees"), Mapping)
    analyses = _claim_analyses(
        effects=effects,
        ids_by_signature=ids_by_signature,
        claim_ids_by_kind=claim_ids_by_kind,
        evidence=evidence,
        predicate_trees_ok=predicate_trees_ok,
    )
    effects_ok = "error" not in effects and isinstance(effects.get("functions"), Mapping)
    facts_omissions: list[Omission] = []
    facts_diagnostics: list[Diagnostic] = []
    if not predicate_trees_ok:
        facts_omissions.append(
            {
                "target_kind": "contract",
                "target_id": contract_id,
                "reason": "predicate_trees_unavailable",
            }
        )
        facts_diagnostics.append(
            {
                "severity": "degraded",
                "code": "PredicateTreesUnavailable",
                "message": str(predicate_trees.get("error") or "predicate tree artifact is absent or invalid"),
                "target_kind": "contract",
                "target_id": contract_id,
            }
        )
    if not effects_ok:
        facts_omissions.append(
            {
                "target_kind": "contract",
                "target_id": contract_id,
                "reason": "effects_unavailable",
            }
        )
        facts_diagnostics.append(
            {
                "severity": "degraded",
                "code": "EffectsUnavailable",
                "message": str(effects.get("error") or "effects artifact is absent or invalid"),
                "target_kind": "contract",
                "target_id": contract_id,
            }
        )
    facts_status = "completed" if not facts_omissions else ("partial" if predicate_trees_ok or effects_ok else "failed")
    facts_receipt: Analysis = {
        "detector": "static.facts",
        "version": str(effects.get("schema_version") or predicate_trees.get("schema_version") or "static/legacy"),
        "status": facts_status,
        "coverage": {
            "targets_total": 2,
            "targets_completed": int(predicate_trees_ok) + int(effects_ok),
            "omissions": facts_omissions,
        },
        "diagnostics": facts_diagnostics,
        "claim_ids": [],
        "evidence_ids": [],
    }
    analyses.insert(0, facts_receipt)
    assessment: Assessment = {
        "schema_version": "assessment/1",
        "scope": scope,
        "accounts": {account_id: account},
        "contract": contract,
        "functions": functions,
        "controllers": controllers,
        "entities": {
            root_entity_id: {
                "id": root_entity_id,
                "account_id": account_id,
                "kind": "contract",
                "tags": [],
            }
        },
        "authority_edges": [],
        "dependency_edges": [],
        "claims": claims,
        "evidence": evidence,
        "analyses": analyses,
    }
    return checked(assessment)


__all__ = ["build_static_assessment"]
