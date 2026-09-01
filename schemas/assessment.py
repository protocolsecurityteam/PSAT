"""The canonical evidence-backed Assessment wire.

The public model intentionally has twelve records. Domain objects use natural
keys inside their Assessment maps; only claims and evidence use content keys so
they can be referenced without embedding and duplicating whole derivation
graphs. Failures and omissions belong to Analysis, never to Claim.
"""

from __future__ import annotations

from typing import Literal

from pydantic import JsonValue
from typing_extensions import NotRequired, TypedDict

AssessmentVersion = Literal["assessment/2"]
EntityKind = Literal["account", "contract"]
EffectKind = Literal[
    "authority.grant",
    "authority.replace",
    "authorized_caller.rotate",
    "callee_pointer.rotate",
    "contract_deployment",
    "delegatecall.execute",
    "erc20.approve",
    "erc20.transfer",
    "erc20.transfer_from",
    "exec.arbitrary",
    "flow.in",
    "flow.out",
    "gov.delegate",
    "lz_oapp.set_delegate",
    "lz_oapp.set_peer",
    "ownership.accept",
    "ownership.renounce",
    "ownership.transfer",
    "pause.set",
    "pause.unset",
    "proxy.admin_change",
    "rate_limit.consume",
    "roles.configure",
    "roles.grant",
    "roles.revoke",
    "safe.module_mgmt",
    "safe.set_guard",
    "safe.signer_mgmt",
    "supply.burn",
    "supply.mint",
    "timelock.cancel",
    "timelock.execute",
    "timelock.schedule",
    "timelock.set_delay",
    "transfer_policy.configure",
    "upgrade.implementation",
    "value_router",
    "weth.deposit",
    "weth.withdraw",
]
EffectFamily = Literal["control_plane", "flow", "exec", "user_plane", "fact"]
EffectTargetKind = Literal["state", "function", "account", "asset", "code", "role", "operation"]
EvidenceMethod = Literal[
    "source",
    "static_ir",
    "predicate_tree",
    "standard",
    "rpc",
    "storage",
    "event",
    "execution",
    "fork_execution",
    "graph_resolution",
    "policy_derivation",
]
AuthorityKind = Literal["public", "entity", "controller", "role", "any", "all", "expression"]
PropositionKind = Literal[
    "function_effect",
    "authority_capability",
    "authority_relationship",
    "entity_classification",
]
SubjectKind = Literal["contract", "function", "controller", "entity", "effect"]
AnalysisStatus = Literal["completed", "partial", "failed"]
DiagnosticSeverity = Literal["degraded", "error"]
TargetKind = Literal["contract", "function", "controller", "entity", "effect"]


class Contract(TypedDict):
    chain_id: int
    address: str
    deployment_address: str
    name: str
    code_hash: str | None
    source_hash: str | None


class Function(TypedDict):
    selector: str | None
    state_changing: bool | None


class Controller(TypedDict):
    label: str
    kind: str
    source: JsonValue
    read_strategy: JsonValue
    tracking: JsonValue


class Entity(TypedDict):
    chain_id: int
    address: str
    kind: EntityKind
    tags: list[str]


class Effect(TypedDict):
    kind: EffectKind
    family: EffectFamily
    targets: list[dict[str, str]]
    affected_functions: list[str]


class Authority(TypedDict):
    """One recursive authority expression; fields are checked by ``kind``."""

    kind: AuthorityKind
    entity: NotRequired[str]
    controller: NotRequired[str]
    role: NotRequired[str]
    entities: NotRequired[list[str]]
    children: NotRequired[list[Authority]]
    expression: NotRequired[JsonValue]
    conditions: NotRequired[list[JsonValue]]


class Proposition(TypedDict):
    """One discriminated proposition; fields are checked by ``kind``."""

    kind: PropositionKind
    function: NotRequired[str]
    effect: NotRequired[Effect]
    authority: NotRequired[Authority]
    target: NotRequired[str]
    relationship: NotRequired[str]
    entity: NotRequired[str]
    entity_kind: NotRequired[EntityKind]
    tags: NotRequired[list[str]]


class Evidence(TypedDict):
    method: EvidenceMethod
    subject_kind: SubjectKind
    subject: str
    observation: JsonValue
    producer: str
    version: str
    locator: JsonValue


class Claim(TypedDict):
    proposition: Proposition
    rule: str
    evidence: list[str]
    claims: list[str]


class Diagnostic(TypedDict):
    severity: DiagnosticSeverity
    code: str
    message: str
    target_kind: NotRequired[TargetKind]
    target: NotRequired[str]


class Analysis(TypedDict):
    detector: str
    version: str
    status: AnalysisStatus
    targets_total: int
    targets_completed: int
    omissions: list[dict[str, str]]
    diagnostics: list[Diagnostic]
    claims: list[str]
    evidence: list[str]


class Assessment(TypedDict):
    schema_version: AssessmentVersion
    contract: Contract
    functions: dict[str, Function]
    controllers: dict[str, Controller]
    entities: dict[str, Entity]
    claims: dict[str, Claim]
    evidence: dict[str, Evidence]
    analyses: list[Analysis]


def assessment_problems(assessment: Assessment) -> list[str]:
    """Return semantic cross-reference violations not expressible by TypedDict."""

    problems: list[str] = []

    def check_authority(authority: Authority, path: str) -> None:
        kind = authority["kind"]
        if kind == "entity":
            entity = authority.get("entity")
            if entity not in assessment["entities"]:
                problems.append(f"{path}.entity: entity is missing")
        elif kind == "controller":
            controller = authority.get("controller")
            if controller not in assessment["controllers"]:
                problems.append(f"{path}.controller: controller is missing")
        elif kind == "role":
            if not authority.get("role"):
                problems.append(f"{path}.role: role is missing")
            for entity in authority.get("entities", []):
                if entity not in assessment["entities"]:
                    problems.append(f"{path}.entities: {entity} is missing")
        elif kind in ("any", "all"):
            children = authority.get("children")
            if not children:
                problems.append(f"{path}.children: expression is empty")
            for index, child in enumerate(children or []):
                check_authority(child, f"{path}.children.{index}")
        elif kind == "expression" and "expression" not in authority:
            problems.append(f"{path}.expression: expression is missing")

    contract = assessment["contract"]
    if contract["address"] != contract["address"].lower():
        problems.append("contract.address: address is not normalized")
    if contract["deployment_address"] != contract["deployment_address"].lower():
        problems.append("contract.deployment_address: address is not normalized")

    for key, entity in assessment["entities"].items():
        expected = f"{entity['chain_id']}:{entity['address'].lower()}"
        if key != expected:
            problems.append(f"entities.{key}: map key does not match chain and address")

    subject_maps: dict[str, object] = {
        "contract": {contract["address"]: contract},
        "function": assessment["functions"],
        "controller": assessment["controllers"],
        "entity": assessment["entities"],
    }
    for key, evidence in assessment["evidence"].items():
        subject_map = subject_maps.get(evidence["subject_kind"])
        if isinstance(subject_map, dict) and evidence["subject"] not in subject_map:
            problems.append(f"evidence.{key}.subject: {evidence['subject_kind']} is missing")

    for key, claim in assessment["claims"].items():
        for evidence_key in claim["evidence"]:
            if evidence_key not in assessment["evidence"]:
                problems.append(f"claims.{key}.evidence: {evidence_key} is missing")
        for input_claim_key in claim["claims"]:
            if input_claim_key not in assessment["claims"]:
                problems.append(f"claims.{key}.claims: {input_claim_key} is missing")

        proposition = claim["proposition"]
        kind = proposition["kind"]
        if kind in ("function_effect", "authority_capability"):
            function = proposition.get("function")
            effect = proposition.get("effect")
            if function not in assessment["functions"]:
                problems.append(f"claims.{key}.proposition.function: function is missing")
            if effect is None:
                problems.append(f"claims.{key}.proposition.effect: effect is missing")
            else:
                for affected in effect["affected_functions"]:
                    if affected not in assessment["functions"]:
                        problems.append(f"claims.{key}.effect.affected_functions: {affected} is missing")
            if kind == "authority_capability":
                authority = proposition.get("authority")
                if authority is None:
                    problems.append(f"claims.{key}.proposition.authority: authority is missing")
                else:
                    check_authority(authority, f"claims.{key}.proposition.authority")
        elif kind == "authority_relationship":
            authority = proposition.get("authority")
            if authority is None:
                problems.append(f"claims.{key}.proposition.authority: authority is missing")
            else:
                check_authority(authority, f"claims.{key}.proposition.authority")
            if proposition.get("target") not in assessment["entities"]:
                problems.append(f"claims.{key}.proposition.target: entity is missing")
            if not proposition.get("relationship"):
                problems.append(f"claims.{key}.proposition.relationship: relationship is missing")
        elif kind == "entity_classification":
            if proposition.get("entity") not in assessment["entities"]:
                problems.append(f"claims.{key}.proposition.entity: entity is missing")

    for index, analysis in enumerate(assessment["analyses"]):
        if analysis["targets_completed"] > analysis["targets_total"]:
            problems.append(f"analyses.{index}: completed targets exceed total targets")
        for claim_key in analysis["claims"]:
            if claim_key not in assessment["claims"]:
                problems.append(f"analyses.{index}.claims: {claim_key} is missing")
        for evidence_key in analysis["evidence"]:
            if evidence_key not in assessment["evidence"]:
                problems.append(f"analyses.{index}.evidence: {evidence_key} is missing")
    return problems


__all__ = [
    "Analysis",
    "AnalysisStatus",
    "Assessment",
    "AssessmentVersion",
    "Authority",
    "AuthorityKind",
    "Claim",
    "Contract",
    "Controller",
    "Diagnostic",
    "Effect",
    "EffectFamily",
    "EffectKind",
    "EffectTargetKind",
    "Entity",
    "EntityKind",
    "Evidence",
    "EvidenceMethod",
    "Function",
    "Proposition",
    "PropositionKind",
    "SubjectKind",
    "TargetKind",
    "assessment_problems",
]
