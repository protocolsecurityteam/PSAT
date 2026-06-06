"""Common schema aliases and shared shapes used across PSAT services."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Generic, TypeVar

from typing_extensions import NotRequired, TypedDict

Address = str
AbiSignature = str
BlockNumber = int
ChainId = int
ChainName = str
FunctionSelector = str
HexString = str
StorageSlot = str
TxHash = str

ContractId = str
ArtifactKind = str

JsonScalar = str | int | float | bool | None
JsonArray = list[Any]
JsonObject = dict[str, Any]
JsonValue = JsonScalar | JsonArray | JsonObject

PipelineStage = str
OnChainPrincipalType = str
PrincipalType = str
CapabilityKind = str
CapabilityMembershipQuality = str
CapabilityConfidence = str
CapabilitySubject = str

StagePayloadT = TypeVar("StagePayloadT")


class Contract(TypedDict):
    address: Address
    chain_id: ChainId
    name: str | None
    label: str | None
    is_proxy: bool
    proxy_address: Address | None
    implementation_addresses: list[Address]
    admin_addresses: list[Address]
    beacon_addresses: list[Address]
    deployer_address: Address | None
    proxy_type: str | None


class StageContext(TypedDict):
    schema_version: str
    stage: PipelineStage
    chain_id: ChainId
    run_id: NotRequired[str | None]
    job_id: NotRequired[str | None]
    company: NotRequired[str | None]
    protocol_id: NotRequired[int | None]
    block_number: NotRequired[BlockNumber | None]
    rpc_url: NotRequired[str | None]
    artifact_root: NotRequired[str | None]
    requested_at: NotRequired[str | None]


class ContractStageRequest(TypedDict, Generic[StagePayloadT]):
    context: StageContext
    contract: Contract
    data: StagePayloadT
    metadata: NotRequired["ServiceBoundaryMetadata"]
    artifacts: NotRequired[dict[str, ArtifactReference]]


class StageArtifact(TypedDict, Generic[StagePayloadT]):
    kind: ArtifactKind
    stage: PipelineStage
    schema_version: str
    context: StageContext
    data: StagePayloadT
    artifacts: dict[str, ArtifactReference]
    contract: NotRequired[Contract]
    errors: NotRequired[list[JsonObject]]
    sources: NotRequired[list[ArtifactReference]]


class Principal(TypedDict):
    address: Address
    type: PrincipalType
    label: str | None
    details: JsonObject


class FunctionSurface(TypedDict):
    function: str
    abi_signature: AbiSignature
    selector: FunctionSelector
    effect_targets: list[str]
    effect_labels: list[str]
    action_summary: str


class Capability(TypedDict, total=False):
    kind: CapabilityKind
    members: list[Address]
    threshold: JsonObject
    blacklist: list[Address]
    signer: "Capability"
    check: JsonObject
    conditions: list[JsonObject]
    unsupported_reason: str
    children: list["Capability"]
    membership_quality: CapabilityMembershipQuality
    confidence: CapabilityConfidence
    last_indexed_block: BlockNumber
    trace: list[JsonObject]
    subject: CapabilitySubject


class ArtifactReference(TypedDict, total=False):
    name: str
    schema_version: str
    storage_key: str
    content_type: str
    sha256: str


class SourceBundle(TypedDict):
    contract_name: str
    compiler_version: str | None
    source_verified: bool
    language: str
    evm_version: str | None
    source_format: str
    files: dict[str, str]
    remappings: list[str]
    build_settings: JsonObject


class ServiceBoundaryMetadata(TypedDict, total=False):
    context: StageContext
    schema_version: str
    job_id: str
    run_name: str
    stage: PipelineStage
    company: str | None
    artifacts: dict[str, ArtifactReference]
    errors: list[JsonObject]


def _address_list(value: Iterable[Address | None] | Address | None) -> list[Address]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.lower()] if value else []
    out: list[Address] = []
    seen: set[Address] = set()
    for item in value:
        if not isinstance(item, str) or not item:
            continue
        address = item.lower()
        if address in seen:
            continue
        seen.add(address)
        out.append(address)
    return out


def make_contract(
    *,
    address: Address,
    chain_id: ChainId | str | None = 1,
    name: str | None = None,
    label: str | None = None,
    is_proxy: bool = False,
    proxy_address: Address | None = None,
    implementation_addresses: Iterable[Address | None] | Address | None = None,
    admin_addresses: Iterable[Address | None] | Address | None = None,
    beacon_addresses: Iterable[Address | None] | Address | None = None,
    deployer_address: Address | None = None,
    proxy_type: str | None = None,
) -> Contract:
    try:
        normalized_chain_id = int(chain_id or 1)
    except (TypeError, ValueError):
        normalized_chain_id = 1
    return {
        "address": address.lower(),
        "chain_id": normalized_chain_id,
        "name": name,
        "label": label,
        "is_proxy": is_proxy,
        "proxy_address": proxy_address.lower() if isinstance(proxy_address, str) and proxy_address else None,
        "implementation_addresses": _address_list(implementation_addresses),
        "admin_addresses": _address_list(admin_addresses),
        "beacon_addresses": _address_list(beacon_addresses),
        "deployer_address": deployer_address.lower()
        if isinstance(deployer_address, str) and deployer_address
        else None,
        "proxy_type": proxy_type,
    }


def contract_key(contract: Contract) -> ContractId:
    return f"{contract['chain_id']}:{contract['address'].lower()}"


def make_stage_context(
    *,
    schema_version: str,
    stage: PipelineStage,
    chain_id: ChainId,
    run_id: str | None = None,
    job_id: str | None = None,
    company: str | None = None,
    protocol_id: int | None = None,
    block_number: BlockNumber | None = None,
    rpc_url: str | None = None,
    artifact_root: str | None = None,
    requested_at: str | None = None,
) -> StageContext:
    context: StageContext = {
        "schema_version": schema_version,
        "stage": stage,
        "chain_id": int(chain_id),
    }
    if run_id is not None:
        context["run_id"] = run_id
    if job_id is not None:
        context["job_id"] = job_id
    if company is not None:
        context["company"] = company
    if protocol_id is not None:
        context["protocol_id"] = protocol_id
    if block_number is not None:
        context["block_number"] = block_number
    if rpc_url is not None:
        context["rpc_url"] = rpc_url
    if artifact_root is not None:
        context["artifact_root"] = artifact_root
    if requested_at is not None:
        context["requested_at"] = requested_at
    return context


__all__ = [
    "AbiSignature",
    "Address",
    "ArtifactReference",
    "ArtifactKind",
    "BlockNumber",
    "Capability",
    "CapabilityConfidence",
    "CapabilityKind",
    "CapabilityMembershipQuality",
    "CapabilitySubject",
    "ChainId",
    "ChainName",
    "Contract",
    "ContractId",
    "contract_key",
    "ContractStageRequest",
    "FunctionSurface",
    "FunctionSelector",
    "HexString",
    "JsonArray",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "make_contract",
    "make_stage_context",
    "OnChainPrincipalType",
    "PipelineStage",
    "Principal",
    "PrincipalType",
    "ServiceBoundaryMetadata",
    "SourceBundle",
    "StageArtifact",
    "StageContext",
    "StorageSlot",
    "TxHash",
]
