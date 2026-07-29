"""Pydantic request models for the FastAPI surface.

Kept separate from ``schemas/`` output models because these mirror the HTTP
request payloads, not the artifact-output JSON shape.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator, model_validator


class AnalyzeRequest(BaseModel):
    address: str | None = Field(default=None, min_length=42, max_length=42)

    @field_validator("address")
    @classmethod
    def _lowercase_address(cls, v: str | None) -> str | None:
        # One canonical form in the DB: the job row and request are joined
        # case-insensitively everywhere else, but exact-match consumers (spawn
        # dedup, listing joins) must never see a checksummed variant.
        return v.lower() if isinstance(v, str) else v

    company: str | None = Field(default=None, min_length=1)
    dapp_urls: list[str] | None = None
    defillama_protocol: str | None = Field(default=None, min_length=1)
    name: str | None = None
    chain: str | None = None
    chain_id: int | None = Field(default=None, ge=1)
    wait: int | None = Field(default=None, ge=1, le=120)
    analyze_limit: int = Field(default=5, ge=1, le=200)
    rpc_url: str | None = None
    force: bool = Field(
        default=False,
        description="Bench-only: skip the static-cache discovery shortcut so every stage re-runs cold.",
    )

    @model_validator(mode="after")
    def _validate_target(self) -> "AnalyzeRequest":
        # address + company is allowed (address is target, company is context)
        primary = [self.address, self.dapp_urls, self.defillama_protocol]
        company_only = self.company and not any(primary)
        has_primary = sum(bool(t) for t in primary) == 1
        if not has_primary and not company_only:
            raise ValueError("Provide exactly one of: address, company, dapp_urls, defillama_protocol")
        return self


class ProtocolSubscribeRequest(BaseModel):
    discord_webhook_url: str = Field(min_length=1, description="Discord webhook URL for protocol event notifications.")
    label: str | None = None
    event_filter: dict | None = Field(default=None, description='Optional filter: {"event_types": ["upgraded", ...]}')

    @field_validator("event_filter")
    @classmethod
    def validate_event_filter(cls, v: dict | None) -> dict | None:
        if v is None:
            return v
        if "event_types" not in v:
            raise ValueError(
                'event_filter must contain an \'event_types\' key, e.g. {"event_types": ["upgraded", "paused"]}'
            )
        event_types = v["event_types"]
        if not isinstance(event_types, list):
            raise ValueError(f"event_filter.event_types must be a list of strings, got {type(event_types).__name__}")
        # Lazy import — avoids pulling the monitoring stack into every
        # process that imports request schemas (workers, scripts, etc.).
        from services.monitoring.event_topics import ALL_EVENT_TOPICS

        valid_types = set(ALL_EVENT_TOPICS.values()) | {"state_changed_poll"}
        for et in event_types:
            if not isinstance(et, str):
                raise ValueError(f"event_filter.event_types entries must be strings, got {type(et).__name__}")
            if et not in valid_types:
                raise ValueError(f"Unknown event type: '{et}'. Valid types: {sorted(valid_types)}")
        return v


def _reject_analyzer_owned_tracking_keys(value: dict | None) -> dict | None:
    """``tracked_topics`` is not a caller-settable flag.

    ``services/monitoring/unified_watcher._scan_topics_union`` unions
    ``monitoring_config->'tracked_topics'`` over every active row straight into
    the live scan filter, so a caller-supplied entry decides what the scanner
    decodes chain-wide. It is an ANALYSIS output — the governance topics
    ``enrollment._load_tracking_plan_artifacts`` read off the tracking-plan
    artifact — and a caller has no witnessed value for it.

    Rejected rather than dropped precisely because of that side effect: a
    silently discarded list would leave the caller believing those topics are
    being scanned. ``tracking_plan_not_determined`` is NOT rejected here — the
    route overwrites it (``routers.monitored._stamp_caller_supplied``), which
    defeats forgery without breaking a read-modify-write of a stamped row.
    """
    if isinstance(value, dict) and "tracked_topics" in value:
        raise ValueError(
            "monitoring_config.tracked_topics is derived from the contract's tracking-plan "
            "artifact and cannot be supplied by a caller; it feeds the live scan filter"
        )
    return value


class UpsertMonitoredContractRequest(BaseModel):
    address: str = Field(min_length=42, max_length=42)
    chain: str = "ethereum"
    contract_type: str = "regular"
    monitoring_config: dict | None = None
    needs_polling: bool = False
    is_active: bool = True

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
            raise ValueError("address must be a 20-byte hex address")
        return value.lower()

    @field_validator("monitoring_config")
    @classmethod
    def validate_monitoring_config(cls, value: dict | None) -> dict | None:
        return _reject_analyzer_owned_tracking_keys(value)


class AddAuditRequest(BaseModel):
    url: str = Field(min_length=1)
    pdf_url: str | None = None
    auditor: str = Field(min_length=1)
    title: str = Field(min_length=1)
    date: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_repo: str | None = None


class UpdateMonitoredContractRequest(BaseModel):
    monitoring_config: dict | None = Field(default=None, description="Updated monitoring config flags")
    is_active: bool | None = Field(default=None, description="Toggle monitoring on/off")
    needs_polling: bool | None = Field(default=None, description="Toggle storage-slot polling")

    @field_validator("monitoring_config")
    @classmethod
    def validate_monitoring_config(cls, value: dict | None) -> dict | None:
        # Same rule as the upsert: PATCH replaces the config wholesale, so it is
        # the same door into the scan filter.
        return _reject_analyzer_owned_tracking_keys(value)


class AddressLabelUpsert(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    note: str | None = Field(default=None, max_length=2000)


__all__ = [
    "AddAuditRequest",
    "AddressLabelUpsert",
    "AnalyzeRequest",
    "ProtocolSubscribeRequest",
    "UpdateMonitoredContractRequest",
    "UpsertMonitoredContractRequest",
]
