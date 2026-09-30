"""Pydantic request models for the FastAPI surface."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from schemas.control_tracking import MonitoredContractType

# So no ingest path accepts a 42-char string that isn't hex.
_HEX_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

_DISCORD_WEBHOOK_HOSTS = {"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"}

_DAPP_URLS_MAX = 50


def _require_http_url(value: str) -> str:
    # Only http(s) is inert when rendered as an href (``javascript:``/``data:``/``file:`` aren't).
    if urlparse(value).scheme.lower() not in ("http", "https"):
        raise ValueError("URL must use the http or https scheme")
    return value


class AnalyzeRequest(BaseModel):
    address: str | None = Field(default=None, min_length=42, max_length=42)

    @field_validator("address")
    @classmethod
    def _lowercase_address(cls, v: str | None) -> str | None:
        # Exact-match consumers (spawn dedup, listing joins) must never see a checksummed variant.
        if not isinstance(v, str):
            return v
        v = v.lower()
        if not _HEX_ADDRESS_RE.fullmatch(v):
            raise ValueError("address must be a 20-byte hex address")
        return v

    company: str | None = Field(default=None, min_length=1)
    dapp_urls: list[str] | None = None

    @field_validator("dapp_urls")
    @classmethod
    def _validate_dapp_urls(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        if len(v) > _DAPP_URLS_MAX:
            raise ValueError(f"dapp_urls accepts at most {_DAPP_URLS_MAX} entries")
        for url in v:
            _require_http_url(url)
        return v

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

    @field_validator("discord_webhook_url")
    @classmethod
    def _validate_discord_webhook_url(cls, v: str) -> str:
        # The monitor POSTs findings here, so https on a Discord host only. The host comes from ``connect_host`` so a
        # backslash/userinfo trick that urllib3 dials elsewhere is rejected.
        from utils.egress import UnsafeUrlError, connect_host

        if urlparse(v).scheme.lower() != "https":
            raise ValueError("discord_webhook_url must be an https URL on a Discord host")
        try:
            host = connect_host(v)
        except UnsafeUrlError:
            raise ValueError("discord_webhook_url must be an https URL on a Discord host") from None
        if host.lower() not in _DISCORD_WEBHOOK_HOSTS:
            raise ValueError("discord_webhook_url must be an https URL on a Discord host")
        return v

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
        # Lazy: keeps the monitoring stack out of every importer.
        from services.monitoring.event_topics import ALL_EVENT_TOPICS

        valid_types = set(ALL_EVENT_TOPICS.values()) | {"state_changed_poll"}
        for et in event_types:
            if not isinstance(et, str):
                raise ValueError(f"event_filter.event_types entries must be strings, got {type(et).__name__}")
            if et not in valid_types:
                raise ValueError(f"Unknown event type: '{et}'. Valid types: {sorted(valid_types)}")
        return v


# Analysis outputs the live monitor acts on; a caller has no witnessed value. Rejected rather than dropped, since
# dropping would let the caller believe the monitor uses them.
#
# The other keys: ``watch_*`` only gate notification (settable); ``tracking_plan_not_determined`` is overwritten by the
# route; the ``*_stale_since`` stamps mean nothing alone; ``scan_gaps`` is rejected below.
_ANALYZER_OWNED_CONFIG_KEYS = {
    "tracked_topics": (
        "monitoring_config.tracked_topics is derived from the contract's tracking-plan "
        "artifact and cannot be supplied by a caller; it feeds the live scan filter"
    ),
    "polling_plan": (
        "monitoring_config.polling_plan is derived from the contract's tracking-plan "
        "artifact and cannot be supplied by a caller; the poller issues its entries "
        "as eth_call/eth_getStorageAt and mints state_changed_poll findings from them"
    ),
}


# ``scan_gaps`` is written only by operator clamp tooling and survives every rebuild, so a fabricated entry would be
# indistinguishable and permanent.
_SCANNER_OWNED_CONFIG_KEYS = {
    "scan_gaps": (
        "monitoring_config.scan_gaps records block intervals this row's scanner never "
        "covered and is written only by the cursor-clamp repair; it cannot be supplied "
        "by a caller"
    ),
}


def _reject_analyzer_owned_config_keys(value: dict | None) -> dict | None:
    """``tracked_topics``, ``polling_plan`` and ``scan_gaps`` are not caller-settable.

    ``tracked_topics`` feeds the chain-wide scan filter directly. ``polling_plan`` is acted on: each entry becomes an
    RPC read and a published ``state_changed_poll`` event from a slot no analyzer witnessed; the provenance stamp can't
    cover that, since the event carries none. ``scan_gaps`` is an observation claim the caller can't witness and it
    survives rebuilds.
    """
    if not isinstance(value, dict):
        return value
    for key, message in {**_ANALYZER_OWNED_CONFIG_KEYS, **_SCANNER_OWNED_CONFIG_KEYS}.items():
        if key in value:
            raise ValueError(message)
    return value


class UpsertMonitoredContractRequest(BaseModel):
    address: str = Field(min_length=42, max_length=42)
    chain: str = "ethereum"
    contract_type: MonitoredContractType = "regular"
    monitoring_config: dict | None = None
    needs_polling: bool = False
    is_active: bool = True

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        if not _HEX_ADDRESS_RE.fullmatch(value):
            raise ValueError("address must be a 20-byte hex address")
        return value.lower()

    @field_validator("monitoring_config")
    @classmethod
    def validate_monitoring_config(cls, value: dict | None) -> dict | None:
        return _reject_analyzer_owned_config_keys(value)


class AddAuditRequest(BaseModel):
    url: str = Field(min_length=1)
    pdf_url: str | None = None
    auditor: str = Field(min_length=1)
    title: str = Field(min_length=1)
    date: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source_repo: str | None = None

    @field_validator("url", "pdf_url")
    @classmethod
    def _validate_audit_url(cls, v: str | None) -> str | None:
        # Rendered as admin links; a non-http(s) scheme would be an executable href.
        if v is None:
            return v
        return _require_http_url(v)


class UpdateMonitoredContractRequest(BaseModel):
    monitoring_config: dict | None = Field(default=None, description="Updated monitoring config flags")
    is_active: bool | None = Field(default=None, description="Toggle monitoring on/off")
    needs_polling: bool | None = Field(default=None, description="Toggle storage-slot polling")

    @field_validator("monitoring_config")
    @classmethod
    def validate_monitoring_config(cls, value: dict | None) -> dict | None:
        # PATCH replaces the config wholesale, so it's the same door.
        return _reject_analyzer_owned_config_keys(value)


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
