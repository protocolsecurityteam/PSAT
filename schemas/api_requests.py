"""Pydantic request models for the FastAPI surface.

Kept separate from ``schemas/`` output models because these mirror the HTTP
request payloads, not the artifact-output JSON shape.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from schemas.observations import MonitoredContractType

#: A 20-byte lowercase-or-checksummed hex address. Shared by every request
#: model so no ingest path accepts a 42-char string that is not actually hex.
_HEX_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

#: The only hosts a Discord webhook can legitimately live on.
_DISCORD_WEBHOOK_HOSTS = {"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"}

_DAPP_URLS_MAX = 50


def _require_http_url(value: str) -> str:
    # A URL leaves this service as an href or an outbound fetch; only http(s)
    # is inert to the click that ``javascript:``/``data:``/``file:`` schemes weaponize.
    if urlparse(value).scheme.lower() not in ("http", "https"):
        raise ValueError("URL must use the http or https scheme")
    return value


class AnalyzeRequest(BaseModel):
    address: str | None = Field(default=None, min_length=42, max_length=42)

    @field_validator("address")
    @classmethod
    def _lowercase_address(cls, v: str | None) -> str | None:
        # One canonical form in the DB: the job row and request are joined
        # case-insensitively everywhere else, but exact-match consumers (spawn
        # dedup, listing joins) must never see a checksummed variant.
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

    @field_validator("discord_webhook_url")
    @classmethod
    def _validate_discord_webhook_url(cls, v: str) -> str:
        # The monitor POSTs findings to this URL; it must be an https endpoint on
        # a Discord host and nothing else — no arbitrary outbound target. Host is
        # derived via the shared egress helper (lazy-imported to keep the request
        # schemas free of the outbound-HTTP stack) so this gate reads the same
        # authority the client would dial — a backslash/userinfo host that
        # ``urlparse`` reports as Discord but urllib3 dials elsewhere is rejected.
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


#: The ``monitoring_config`` keys ``enrollment._build_monitoring_config`` derives
#: from analysis and the live monitor then ACTS on. Both are ANALYSIS outputs —
#: read off the tracking-plan artifact by ``enrollment._load_observation_plan_artifacts``
#: / ``polling_plan.build_polling_plan`` — and a caller has no witnessed value for
#: either. Rejected rather than dropped: each drives the monitor on the wire, so a
#: silently discarded value would leave the caller believing the monitor is doing
#: something it is not.
#:
#: These are the only two analysis-derived keys. The rest of the config splits as:
#: the ``watch_*`` booleans, which only gate whether an already-detected event
#: notifies (``unified_watcher._should_watch``) — no wire call, no minted finding,
#: so a caller preference and settable; ``observation_plan_not_determined``, which the
#: route OWNS by overwriting (``routers.monitored._stamp_caller_supplied``),
#: defeating forgery without breaking a read-modify-write of a stamped row; the two
#: staleness stamps (``tracked_topics_stale_since`` / ``polling_plan_stale_since``),
#: which are meaningless without the analyzer-owned keys they date and so cannot
#: assert anything on their own; and ``scan_gaps``, rejected below.
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


#: Keys the SCANNER owns: records of what monitoring did or did not observe.
#: ``scan_gaps`` names block intervals a row's scanner never covered — written
#: only by the operator-run cursor-clamp tooling and carried across every
#: config rebuild by ``observation_plan_state.preserve_scan_plane_facts``. That
#: durability is exactly why it cannot be caller-settable: a fabricated entry
#: would be indistinguishable from a clamp-authored one and would outlive every
#: subsequent enrollment, asserting a coverage hole (or, by omission, continuous
#: coverage) that nothing observed.
_SCANNER_OWNED_CONFIG_KEYS = {
    "scan_gaps": (
        "monitoring_config.scan_gaps records block intervals this row's scanner never "
        "covered and is written only by the cursor-clamp repair; it cannot be supplied "
        "by a caller"
    ),
}


def _reject_analyzer_owned_config_keys(value: dict | None) -> dict | None:
    """``tracked_topics``, ``polling_plan`` and ``scan_gaps`` are not caller-settable.

    ``services/monitoring/unified_watcher._scan_topics_union`` unions
    ``monitoring_config->'tracked_topics'`` over every active row straight into
    the live scan filter, so a caller-supplied entry decides what the scanner
    decodes chain-wide.

    ``polling_plan`` goes further — it is acted on, not merely filtered on:
    ``unified_watcher.poll_for_state_changes`` turns each entry into an
    ``eth_call``/``eth_getStorageAt`` (``_rpc_call_for_entry``) and
    ``_apply_poll_result`` mints a ``state_changed_poll`` ``MonitoredEvent``
    keyed on the entry's own ``field`` name — a published finding on the monitor
    surface derived from a slot no analyzer witnessed. The caller-provenance
    stamp cannot substitute for this rejection: the stamp records where the
    CONFIG came from, while the event the plan produces carries no provenance
    at all.

    ``scan_gaps`` is the scanner's own record rather than an analysis output,
    but it fails the same test: it is a claim about what was observed, a caller
    has no witness for it, and it now survives every config rebuild.
    """
    if value is None:
        return None
    for key, message in {**_ANALYZER_OWNED_CONFIG_KEYS, **_SCANNER_OWNED_CONFIG_KEYS}.items():
        if key in value:
            raise ValueError(message)
    from services.monitoring.config import load_monitoring_config

    return dict(load_monitoring_config(value))


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
        # These are rendered as links on the admin surface; a non-http(s) scheme
        # would become an executable href.
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
        # Same rule as the upsert: PATCH replaces the config wholesale, so it is
        # the same door into the scan filter and the poller.
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
