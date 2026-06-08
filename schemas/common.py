"""Common schema aliases and shared shapes used across PSAT services."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from enum import Enum
from typing import Any, Generic, TypeVar

from typing_extensions import NotRequired, TypedDict

logger = logging.getLogger(__name__)

Address = str
BlockNumber = int
ChainId = int
HexString = str
TxHash = str

JsonObject = dict[str, Any]


class PrincipalType(str, Enum):
    UNKNOWN = "unknown"
    ZERO = "zero"
    EOA = "eoa"
    CONTRACT = "contract"
    SAFE = "safe"
    TIMELOCK = "timelock"
    PROXY_ADMIN = "proxy_admin"


OnChainPrincipalType = PrincipalType


class CapabilityKind(str, Enum):
    FINITE_SET = "finite_set"
    THRESHOLD_GROUP = "threshold_group"
    COFINITE_BLACKLIST = "cofinite_blacklist"
    SIGNATURE_WITNESS = "signature_witness"
    EXTERNAL_CHECK_ONLY = "external_check_only"
    CONDITIONAL_UNIVERSAL = "conditional_universal"
    UNSUPPORTED = "unsupported"
    AND = "AND"
    OR = "OR"


class CapabilityMembershipQuality(str, Enum):
    EXACT = "exact"
    LOWER_BOUND = "lower_bound"
    UPPER_BOUND = "upper_bound"


class CapabilityConfidence(str, Enum):
    ENUMERABLE = "enumerable"
    PARTIAL = "partial"
    CHECK_ONLY = "check_only"


CapabilitySubject = str

StagePayloadT = TypeVar("StagePayloadT")


class Contract(TypedDict):
    address: Address
    chain_id: ChainId
    name: str | None  # contract name like "UniswapV2Pair"
    label: str | None  # human-friendly label like "Uniswap V2 USDC/ETH Pair"
    is_proxy: bool
    proxy_address: Address | None
    implementation_addresses: list[Address]
    admin_addresses: list[Address]
    beacon_addresses: list[Address]
    deployer_address: Address | None
    proxy_type: str | None


class StageContext(TypedDict):
    schema_version: str
    stage: str
    chain_id: NotRequired[ChainId]
    run_id: NotRequired[str | None]
    job_id: NotRequired[str | None]
    company: NotRequired[str | None]
    protocol_id: NotRequired[int | None]
    block_number: NotRequired[BlockNumber | None]
    artifact_root: NotRequired[str | None]
    requested_at: NotRequired[str | None]


class ContractStageRequest(TypedDict, Generic[StagePayloadT]):
    context: StageContext
    contract: Contract
    data: StagePayloadT
    metadata: NotRequired["ServiceBoundaryMetadata"]
    artifacts: NotRequired[dict[str, ArtifactReference]]


class StageArtifact(TypedDict, Generic[StagePayloadT]):
    kind: str
    stage: str
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
    abi_signature: str
    selector: str
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
    stage: str
    company: str | None
    artifacts: dict[str, ArtifactReference]
    errors: list[JsonObject]


def _address_list(value: Iterable[Address | None] | Address | None) -> list[Address]:
    if value is None:
        return []
    if isinstance(value, str):
        return [_normalize_contract_address(value, context="contract address list")] if value else []
    out: list[Address] = []
    seen: set[Address] = set()
    for item in value:
        if item is None or item == "":
            continue
        address = _normalize_contract_address(item, context="contract address list")
        if address in seen:
            continue
        seen.add(address)
        out.append(address)
    return out


def _normalize_contract_address(value: Address | None, *, context: str) -> Address:
    if not isinstance(value, str) or not value.startswith("0x") or len(value) != 42:
        logger.error("%s requires 20-byte 0x address, got %r", context, value)
        raise ValueError(f"{context} requires 20-byte 0x address, got {value!r}")
    try:
        bytes.fromhex(value[2:])
    except ValueError as exc:
        logger.error("%s received malformed address hex: %r", context, value)
        raise ValueError(f"{context} received malformed address hex: {value!r}") from exc
    return value.lower()


def make_contract(
    *,
    address: Address,
    chain_id: ChainId | str,
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
        from utils.rpc import require_supported_chain_id

        normalized_chain_id = require_supported_chain_id(chain_id=chain_id, context=f"contract {address}")
    except RuntimeError as exc:
        logger.error("contract requires supported chain_id for address=%r: %s", address, exc)
        raise ValueError(str(exc)) from exc
    normalized_address = _normalize_contract_address(address, context="contract")
    return {
        "address": normalized_address,
        "chain_id": normalized_chain_id,
        "name": name,
        "label": label,
        "is_proxy": is_proxy,
        "proxy_address": _normalize_contract_address(proxy_address, context="contract proxy_address")
        if proxy_address
        else None,
        "implementation_addresses": _address_list(implementation_addresses),
        "admin_addresses": _address_list(admin_addresses),
        "beacon_addresses": _address_list(beacon_addresses),
        "deployer_address": _normalize_contract_address(deployer_address, context="contract deployer_address")
        if deployer_address
        else None,
        "proxy_type": proxy_type,
    }


def contract_key(contract: Contract) -> str:
    return f"{contract['chain_id']}:{contract['address'].lower()}"


def make_stage_context(
    *,
    schema_version: str,
    stage: str,
    chain_id: ChainId | None = None,
    run_id: str | None = None,
    job_id: str | None = None,
    company: str | None = None,
    protocol_id: int | None = None,
    block_number: BlockNumber | None = None,
    artifact_root: str | None = None,
    requested_at: str | None = None,
) -> StageContext:
    context: StageContext = {
        "schema_version": schema_version,
        "stage": stage,
    }
    if chain_id is not None:
        try:
            from utils.rpc import require_supported_chain_id

            context["chain_id"] = require_supported_chain_id(chain_id=chain_id, context=f"stage context {stage}")
        except RuntimeError as exc:
            logger.error("stage context %s requires supported chain_id=%r: %s", stage, chain_id, exc)
            raise ValueError(str(exc)) from exc
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
    if artifact_root is not None:
        context["artifact_root"] = artifact_root
    if requested_at is not None:
        context["requested_at"] = requested_at
    return context


__all__ = [
    "Address",
    "ArtifactReference",
    "BlockNumber",
    "Capability",
    "CapabilityConfidence",
    "CapabilityKind",
    "CapabilityMembershipQuality",
    "CapabilitySubject",
    "ChainId",
    "Contract",
    "contract_key",
    "ContractStageRequest",
    "FunctionSurface",
    "HexString",
    "JsonObject",
    "make_contract",
    "make_stage_context",
    "OnChainPrincipalType",
    "Principal",
    "PrincipalType",
    "ServiceBoundaryMetadata",
    "SourceBundle",
    "StageArtifact",
    "StageContext",
    "TxHash",
]
