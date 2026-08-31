"""Canonical evidence-backed assessment wire.

The pipeline's durable output is an :class:`Assessment`: domain objects,
supported claims, the evidence supporting them, and analysis receipts that
record coverage and failures.  A claim never represents a failure or a
rejection.  Absence is interpreted through the matching ``Analysis`` receipt:
complete coverage can support an empty result; partial or failed coverage
cannot.

The vocabulary deliberately uses domain names (``Contract``, ``Function``,
``Evidence``) rather than transport-oriented ``*Ref`` / ``*Model`` names.
Relationships cross the wire by stable ids.
"""

from __future__ import annotations

from typing import Literal, TypeAlias

from pydantic import JsonValue
from typing_extensions import NotRequired, TypedDict

AssessmentVersion = Literal["assessment/1"]

AccountId: TypeAlias = str
ContractId: TypeAlias = str
FunctionId: TypeAlias = str
ControllerId: TypeAlias = str
EntityId: TypeAlias = str
EvidenceId: TypeAlias = str
ClaimId: TypeAlias = str


class Account(TypedDict):
    id: AccountId
    chain_id: int
    address: str


class Block(TypedDict):
    chain_id: int
    number: int
    hash: str


class Scope(TypedDict):
    contract_id: ContractId
    account_id: AccountId
    code_hash: str | None
    source_hash: str | None
    block: NotRequired[Block]


class Contract(TypedDict):
    id: ContractId
    account_id: AccountId
    name: str
    code_hash: str | None
    source_hash: str | None


class Function(TypedDict):
    id: FunctionId
    contract_id: ContractId
    signature: str
    selector: str | None
    state_changing: bool | None


class Controller(TypedDict):
    id: ControllerId
    contract_id: ContractId
    key: str
    label: str
    kind: str
    source: JsonValue
    read_strategy: JsonValue
    tracking: JsonValue


EntityKind = Literal["account", "contract"]


class Entity(TypedDict):
    id: EntityId
    account_id: AccountId
    kind: EntityKind
    tags: list[str]


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


class EffectTarget(TypedDict):
    kind: EffectTargetKind
    value: str
    member: NotRequired[str]


class Effect(TypedDict):
    kind: EffectKind
    family: EffectFamily
    targets: list[EffectTarget]
    affected_functions: list[FunctionId]


SubjectKind = Literal["account", "contract", "function", "controller", "entity", "effect"]


class Subject(TypedDict):
    kind: SubjectKind
    id: str


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


class EvidenceSource(TypedDict):
    producer: str
    version: str
    locator: JsonValue


class Evidence(TypedDict):
    id: EvidenceId
    method: EvidenceMethod
    subject: Subject
    observation: JsonValue
    source: EvidenceSource
    scope: Scope


class Basis(TypedDict):
    rule: str
    evidence_ids: list[EvidenceId]
    claim_ids: list[ClaimId]


class PublicAuthority(TypedDict):
    kind: Literal["public"]


class EntityAuthority(TypedDict):
    kind: Literal["entity"]
    entity_id: EntityId


class ControllerAuthority(TypedDict):
    kind: Literal["controller"]
    controller_id: ControllerId


class RoleAuthority(TypedDict):
    kind: Literal["role"]
    role: str
    entity_ids: list[EntityId]


AtomicAuthority: TypeAlias = PublicAuthority | EntityAuthority | ControllerAuthority | RoleAuthority


class AnyAuthority(TypedDict):
    kind: Literal["any"]
    children: list[AtomicAuthority]


class AllAuthority(TypedDict):
    kind: Literal["all"]
    children: list[AtomicAuthority]


Authority: TypeAlias = AtomicAuthority | AnyAuthority | AllAuthority


class FunctionEffect(TypedDict):
    kind: Literal["function_effect"]
    function_id: FunctionId
    effect: Effect


class AuthorityCapability(TypedDict):
    kind: Literal["authority_capability"]
    authority: Authority
    function_id: FunctionId
    effect: Effect


class AuthorityRelationship(TypedDict):
    kind: Literal["authority_relationship"]
    authority: Authority
    target_id: str
    relationship: str


class EntityClassification(TypedDict):
    kind: Literal["entity_classification"]
    entity_id: EntityId
    entity_kind: EntityKind
    tags: list[str]


Proposition: TypeAlias = FunctionEffect | AuthorityCapability | AuthorityRelationship | EntityClassification


class AuthorityEdge(TypedDict):
    authority_id: EntityId
    target_id: EntityId
    relationship: str
    claim_id: ClaimId


class DependencyEdge(TypedDict):
    source_id: EntityId
    target_id: EntityId
    relationship: str
    evidence_ids: list[EvidenceId]


class Claim(TypedDict):
    id: ClaimId
    proposition: Proposition
    basis: Basis
    scope: Scope


AnalysisStatus = Literal["completed", "partial", "failed"]
DiagnosticSeverity = Literal["degraded", "error"]
TargetKind = Literal["contract", "function", "controller", "entity", "effect"]


class Omission(TypedDict):
    target_kind: TargetKind
    target_id: str
    reason: str


class Coverage(TypedDict):
    targets_total: int
    targets_completed: int
    omissions: list[Omission]


class Diagnostic(TypedDict):
    severity: DiagnosticSeverity
    code: str
    message: str
    target_kind: NotRequired[TargetKind]
    target_id: NotRequired[str]


class Analysis(TypedDict):
    detector: str
    version: str
    status: AnalysisStatus
    coverage: Coverage
    diagnostics: list[Diagnostic]
    claim_ids: list[ClaimId]
    evidence_ids: list[EvidenceId]


class Assessment(TypedDict):
    schema_version: AssessmentVersion
    scope: Scope
    accounts: dict[AccountId, Account]
    contract: Contract
    functions: dict[FunctionId, Function]
    controllers: dict[ControllerId, Controller]
    entities: dict[EntityId, Entity]
    authority_edges: list[AuthorityEdge]
    dependency_edges: list[DependencyEdge]
    claims: dict[ClaimId, Claim]
    evidence: dict[EvidenceId, Evidence]
    analyses: list[Analysis]


__all__ = [
    "Account",
    "AccountId",
    "AllAuthority",
    "Analysis",
    "AnalysisStatus",
    "AnyAuthority",
    "Assessment",
    "AssessmentVersion",
    "AtomicAuthority",
    "Authority",
    "AuthorityCapability",
    "AuthorityEdge",
    "AuthorityRelationship",
    "Basis",
    "Block",
    "Claim",
    "ClaimId",
    "Contract",
    "ContractId",
    "Controller",
    "ControllerAuthority",
    "ControllerId",
    "Coverage",
    "Diagnostic",
    "DependencyEdge",
    "Effect",
    "EffectFamily",
    "EffectKind",
    "EffectTarget",
    "Entity",
    "EntityAuthority",
    "EntityClassification",
    "EntityId",
    "Evidence",
    "EvidenceId",
    "EvidenceMethod",
    "EvidenceSource",
    "Function",
    "FunctionEffect",
    "FunctionId",
    "Omission",
    "Proposition",
    "PublicAuthority",
    "RoleAuthority",
    "Scope",
    "Subject",
    "assessment_problems",
]


def assessment_problems(assessment: Assessment) -> list[str]:
    """Cross-reference violations that TypedDict shape validation cannot see."""

    problems: list[str] = []

    def check_authority(authority: Authority, path: str) -> None:
        if authority["kind"] == "entity":
            if authority["entity_id"] not in assessment["entities"]:
                problems.append(f"{path}.entity_id: entity is missing")
        elif authority["kind"] == "controller":
            if authority["controller_id"] not in assessment["controllers"]:
                problems.append(f"{path}.controller_id: controller is missing")
        elif authority["kind"] == "role":
            for entity_id in authority["entity_ids"]:
                if entity_id not in assessment["entities"]:
                    problems.append(f"{path}.entity_ids: {entity_id} is missing")
        elif authority["kind"] == "any":
            for index, child in enumerate(authority["children"]):
                check_authority(child, f"{path}.children.{index}")
        elif authority["kind"] == "all":
            for index, child in enumerate(authority["children"]):
                check_authority(child, f"{path}.children.{index}")

    collections = (
        ("accounts", assessment["accounts"]),
        ("functions", assessment["functions"]),
        ("controllers", assessment["controllers"]),
        ("entities", assessment["entities"]),
        ("claims", assessment["claims"]),
        ("evidence", assessment["evidence"]),
    )
    for name, values in collections:
        for key, value in values.items():
            if value["id"] != key:
                problems.append(f"{name}.{key}: map key does not match object id {value['id']}")

    if assessment["scope"]["account_id"] not in assessment["accounts"]:
        problems.append("scope.account_id: account is missing")
    if assessment["scope"]["contract_id"] != assessment["contract"]["id"]:
        problems.append("scope.contract_id: does not name contract.id")
    if assessment["contract"]["account_id"] not in assessment["accounts"]:
        problems.append("contract.account_id: account is missing")

    for function_id, function in assessment["functions"].items():
        if function["contract_id"] != assessment["contract"]["id"]:
            problems.append(f"functions.{function_id}.contract_id: does not name contract.id")
    for controller_id, controller in assessment["controllers"].items():
        if controller["contract_id"] != assessment["contract"]["id"]:
            problems.append(f"controllers.{controller_id}.contract_id: does not name contract.id")
    for entity_id, entity in assessment["entities"].items():
        if entity["account_id"] not in assessment["accounts"]:
            problems.append(f"entities.{entity_id}.account_id: account is missing")

    for evidence_id, evidence in assessment["evidence"].items():
        subject = evidence["subject"]
        subject_maps = {
            "account": assessment["accounts"],
            "contract": {assessment["contract"]["id"]: assessment["contract"]},
            "function": assessment["functions"],
            "controller": assessment["controllers"],
            "entity": assessment["entities"],
        }
        subject_map = subject_maps.get(subject["kind"])
        if subject_map is not None and subject["id"] not in subject_map:
            problems.append(f"evidence.{evidence_id}.subject: {subject['kind']} is missing")

    for claim_id, claim in assessment["claims"].items():
        for evidence_id in claim["basis"]["evidence_ids"]:
            if evidence_id not in assessment["evidence"]:
                problems.append(f"claims.{claim_id}.basis.evidence_ids: {evidence_id} is missing")
        for input_claim_id in claim["basis"]["claim_ids"]:
            if input_claim_id not in assessment["claims"]:
                problems.append(f"claims.{claim_id}.basis.claim_ids: {input_claim_id} is missing")
        proposition = claim["proposition"]
        if proposition["kind"] == "function_effect":
            if proposition["function_id"] not in assessment["functions"]:
                problems.append(f"claims.{claim_id}.proposition.function_id: function is missing")
            for function_id in proposition["effect"]["affected_functions"]:
                if function_id not in assessment["functions"]:
                    problems.append(f"claims.{claim_id}.effect.affected_functions: {function_id} is missing")
        elif proposition["kind"] == "authority_capability":
            if proposition["function_id"] not in assessment["functions"]:
                problems.append(f"claims.{claim_id}.proposition.function_id: function is missing")
            for function_id in proposition["effect"]["affected_functions"]:
                if function_id not in assessment["functions"]:
                    problems.append(f"claims.{claim_id}.effect.affected_functions: {function_id} is missing")
            check_authority(proposition["authority"], f"claims.{claim_id}.proposition.authority")
        elif proposition["kind"] == "authority_relationship":
            check_authority(proposition["authority"], f"claims.{claim_id}.proposition.authority")
            if proposition["target_id"] not in assessment["entities"]:
                problems.append(f"claims.{claim_id}.proposition.target_id: entity is missing")
        elif proposition["kind"] == "entity_classification":
            if proposition["entity_id"] not in assessment["entities"]:
                problems.append(f"claims.{claim_id}.proposition.entity_id: entity is missing")

    for index, edge in enumerate(assessment["authority_edges"]):
        if edge["authority_id"] not in assessment["entities"]:
            problems.append(f"authority_edges.{index}.authority_id: entity is missing")
        if edge["target_id"] not in assessment["entities"]:
            problems.append(f"authority_edges.{index}.target_id: entity is missing")
        if edge["claim_id"] not in assessment["claims"]:
            problems.append(f"authority_edges.{index}.claim_id: claim is missing")
    for index, edge in enumerate(assessment["dependency_edges"]):
        if edge["source_id"] not in assessment["entities"] or edge["target_id"] not in assessment["entities"]:
            problems.append(f"dependency_edges.{index}: endpoint entity is missing")
        for evidence_id in edge["evidence_ids"]:
            if evidence_id not in assessment["evidence"]:
                problems.append(f"dependency_edges.{index}.evidence_ids: {evidence_id} is missing")

    for index, analysis in enumerate(assessment["analyses"]):
        for claim_id in analysis["claim_ids"]:
            if claim_id not in assessment["claims"]:
                problems.append(f"analyses.{index}.claim_ids: {claim_id} is missing")
        for evidence_id in analysis["evidence_ids"]:
            if evidence_id not in assessment["evidence"]:
                problems.append(f"analyses.{index}.evidence_ids: {evidence_id} is missing")
    return problems
