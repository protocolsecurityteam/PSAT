"""Schemas owned by monitoring services."""

from __future__ import annotations

from typing_extensions import NotRequired, TypedDict

from schemas.common import (
    Address,
    BlockNumber,
    Contract,
    ContractStageRequest,
    HexString,
    JsonObject,
    StageArtifact,
    TxHash,
)


class MonitoringEventFilter(TypedDict, total=False):
    event_types: list[str]
    addresses: list[Address]
    topics: list[HexString]


class MonitoringRequest(TypedDict):
    event_filter: MonitoringEventFilter | None
    needs_polling: bool
    is_active: bool


class MonitoringPlan(TypedDict):
    schema_version: str
    contract: Contract
    event_topics: list[HexString]
    polling_sources: list[str]
    needs_polling: bool
    config: JsonObject


class MonitoringEvent(TypedDict, total=False):
    contract: Contract
    event_type: str
    block_number: BlockNumber
    tx_hash: TxHash | None
    log_index: int | None
    payload: JsonObject


class MonitoringPayload(TypedDict):
    plan: MonitoringPlan
    latest_events: NotRequired[list[MonitoringEvent]]


MonitoringStageRequest = ContractStageRequest[MonitoringRequest]
MonitoringArtifact = StageArtifact[MonitoringPayload]


__all__ = [
    "MonitoringEvent",
    "MonitoringEventFilter",
    "MonitoringArtifact",
    "MonitoringPayload",
    "MonitoringPlan",
    "MonitoringRequest",
    "MonitoringStageRequest",
]
