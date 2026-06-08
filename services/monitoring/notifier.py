"""Discord notification dispatch for proxy upgrade and governance events."""

from __future__ import annotations

import logging

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    Job,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
    ProxySubscription,
    ProxyUpgradeEvent,
)
from services.monitoring.event_topics import _HANDROLLED_EVENT_TYPE_TO_TAGS
from utils.rpc import require_supported_chain_id

logger = logging.getLogger(__name__)

DISCORD_TIMEOUT = 10


def _format_embed(event: ProxyUpgradeEvent) -> dict:
    """Build a Discord embed dict for a single upgrade event."""
    proxy = event.watched_proxy
    label = proxy.label or proxy.proxy_address
    fields = [
        {"name": "Proxy", "value": f"`{proxy.proxy_address}`", "inline": True},
        {"name": "Chain ID", "value": str(proxy.chain_id), "inline": True},
        {"name": "Event", "value": event.event_type, "inline": True},
        {"name": "New Implementation", "value": f"`{event.new_implementation}`", "inline": False},
    ]
    if event.old_implementation:
        fields.insert(3, {"name": "Old Implementation", "value": f"`{event.old_implementation}`", "inline": False})
    if event.block_number:
        fields.append({"name": "Block", "value": str(event.block_number), "inline": True})
    if event.tx_hash:
        fields.append({"name": "Tx", "value": f"`{event.tx_hash}`", "inline": False})

    return {
        "title": f"Proxy Upgrade: {label}",
        "color": 0xFF9900,
        "fields": fields,
    }


def _send_discord(webhook_url: str, embed: dict) -> None:
    resp = requests.post(
        webhook_url,
        json={"embeds": [embed]},
        timeout=DISCORD_TIMEOUT,
    )
    if not resp.ok:
        logger.warning("Discord webhook failed (%s): %s", resp.status_code, resp.text[:200])


def notify_upgrades(session: Session, events: list[ProxyUpgradeEvent]) -> None:
    """Send Discord notifications for detected upgrade events.

    Looks up all subscriptions for each event's watched proxy and POSTs
    to each configured Discord webhook. Failures are logged, never raised.
    """
    if not events:
        return

    proxy_ids = {e.watched_proxy_id for e in events}
    subs = (
        session.execute(
            select(ProxySubscription).where(
                ProxySubscription.watched_proxy_id.in_(proxy_ids),
                ProxySubscription.discord_webhook_url.isnot(None),
            )
        )
        .scalars()
        .all()
    )

    if not subs:
        return

    subs_by_proxy: dict[str, list[ProxySubscription]] = {}
    for sub in subs:
        subs_by_proxy.setdefault(str(sub.watched_proxy_id), []).append(sub)

    sent = 0
    for event in events:
        proxy_subs = subs_by_proxy.get(str(event.watched_proxy_id), [])
        if not proxy_subs:
            continue

        embed = _format_embed(event)
        for sub in proxy_subs:
            try:
                _send_discord(sub.discord_webhook_url, embed)  # type: ignore[arg-type]  # filtered by isnot(None)
                sent += 1
            except Exception as exc:
                logger.warning(
                    "Discord notification failed for subscription %s: %s",
                    sub.id,
                    exc,
                    extra={"exc_type": type(exc).__name__},
                )

    if sent:
        logger.info("Sent %d Discord notification(s) for %d event(s)", sent, len(events))


# ---------------------------------------------------------------------------
# Protocol-level governance event notifications
# ---------------------------------------------------------------------------

# Embed color resolution. Two-tier:
#
#   1. Per-write-target color map — the bulk of colors derive from
#      what state the emitter mutated. ``pendingOwner`` (intent)
#      naturally orange where ``owner`` (commit) is red, etc.
#   2. Per-event_type overrides for outcome- or phase-paired events
#      whose tags collide. ``safe_tx_executed`` and ``safe_tx_failed``
#      both have ``writes=["_safe_op"]``; the success/failure split
#      doesn't fall out of the tag structure (the schema deliberately
#      doesn't carry outcome flags), so it stays event_type-keyed.
#      Same shape for timelock scheduled vs executed.

_DEFAULT_EMBED_COLOR = 0x95A5A6  # neutral grey for unrecognized events

_WRITE_TARGET_TO_COLOR: dict[str, int] = {
    # RED — committed control-graph changes
    "owner": 0xFF0000,
    "authority": 0xFF0000,
    "paused": 0xFF0000,
    # ORANGE — upgrade-shape mutations + intent-phase ownership / impl
    "pendingOwner": 0xFF9900,
    "pendingImplementation": 0xFF9900,
    "implementation": 0xFF9900,
    "beacon": 0xFF9900,
    "facets": 0xFF9900,
    "admin": 0xFF9900,
    # BLUE — Safe signer set changes
    "owners": 0x3498DB,
    # AMBER — operational parameters
    "_roles": 0xF39C12,
    "threshold": 0xF39C12,
    "min_delay": 0xF39C12,
}

# Resolution order: when an event has multiple writes (e.g. Ownable2Step
# acceptOwnership writes both owner and pendingOwner), the more-critical
# color wins. Listed in priority order — first matching write target
# determines the color.
_COLOR_PRIORITY: tuple[str, ...] = (
    "owner",
    "authority",
    "paused",
    "pendingOwner",
    "pendingImplementation",
    "implementation",
    "beacon",
    "facets",
    "admin",
    "owners",
    "_roles",
    "threshold",
    "min_delay",
)

_EVENT_TYPE_COLOR_OVERRIDES: dict[str, int] = {
    # Outcome-paired Safe execution events
    "safe_tx_executed": 0x2ECC71,  # green — success
    "safe_module_executed": 0x2ECC71,
    "safe_tx_failed": 0xE74C3C,  # red — reverted
    "safe_module_failed": 0xE74C3C,
    # Phase-paired Timelock ops
    "timelock_scheduled": 0x3498DB,  # blue — queued
    "timelock_executed": 0xFF9900,  # orange — applied
    # Synthetic poll event — has no tags, has no decoder
    "state_changed_poll": 0x9B59B6,  # purple
}


def _resolve_embed_color(event_type: str, data: dict | None) -> int:
    """Pick the Discord embed color for an event.

    Per-event_type overrides win for outcome- / phase-paired events
    whose writes collide. Otherwise walks ``effect_tags.writes`` in
    priority order and returns the first matching write target's color.
    Synthesizes tags from event_type for legacy events that lack them.
    """
    override = _EVENT_TYPE_COLOR_OVERRIDES.get(event_type)
    if override is not None:
        return override
    tags = (data or {}).get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = set(tags.get("writes") or [])
    for write_target in _COLOR_PRIORITY:
        if write_target in writes:
            return _WRITE_TARGET_TO_COLOR[write_target]
    return _DEFAULT_EMBED_COLOR


# Per-write-target render specs for ``_format_governance_embed``. Each
# entry is a list of ``(label, data_key, inline)`` tuples. The renderer
# walks ``effect_tags.writes``, looks up the spec, and appends one
# Discord field per entry whose ``data[data_key]`` is populated.
# Dedup is keyed by ``data_key`` so two writes that share a render arg
# (Ownable2Step commit phase: owner + pendingOwner both → new_owner)
# don't produce duplicate fields.
#
# Convention: render specs name the user-facing label, NOT the slot.
# A write to ``admin`` renders "Old Admin" / "New Admin" — the slot
# name is an implementation detail. Underscore-prefixed targets
# (``_roles``, ``_timelock_op``, ``_safe_op``) are activity markers
# with no canonical "before/after"; the render spec just surfaces the
# meaningful event args.
_WRITE_TARGET_TO_RENDER: dict[str, list[tuple[str, str, bool]]] = {
    "owner": [
        ("Old Owner", "old_owner", False),
        ("New Owner", "new_owner", False),
    ],
    # Ownable2Step ``transferOwnership`` (intent) writes pendingOwner;
    # the canonical semantic-key aliases land in old_owner / new_owner.
    "pendingOwner": [
        ("Old Owner", "old_owner", False),
        ("New Owner", "new_owner", False),
    ],
    "authority": [
        ("Old Authority", "old_authority", False),
        ("New Authority", "new_authority", False),
    ],
    "implementation": [
        ("New Implementation", "implementation", False),
    ],
    "beacon": [
        ("Beacon", "beacon", False),
    ],
    "facets": [
        # Diamond cuts: the upgrade-history decoder stores the first
        # facet under ``implementation`` for backward compat with the
        # generic proxy-upgrade rendering.
        ("New Implementation", "implementation", False),
    ],
    "admin": [
        ("Old Admin", "previous_admin", False),
        ("New Admin", "new_admin", False),
    ],
    "paused": [
        # paused / unpaused share writes=["paused"]; the renderer
        # surfaces the account that flipped the flag.
        ("Account", "account", False),
    ],
    "_roles": [
        ("Role", "role", False),
        ("Account", "account", True),
        ("Sender", "sender", True),
    ],
    "owners": [
        ("Signer", "owner", False),
    ],
    "threshold": [
        ("New Threshold", "threshold", True),
    ],
    "min_delay": [
        ("Old Delay", "old_delay", True),
        ("New Delay", "new_delay", True),
    ],
}


def _render_event_value(value: object) -> str:
    """Format an event data value for Discord display. Wrap hex strings
    in backticks (addresses, bytes32 roles); everything else as bare str."""
    if isinstance(value, str) and value.startswith("0x"):
        return f"`{value}`"
    return str(value)


def _generic_render_fallback(
    write_target: str,
    data: dict,
    seen_keys: set[str],
) -> list[dict]:
    """Render fields for a write target with no entry in ``_WRITE_TARGET_TO_RENDER``.

    Custom slots (``protocolAdmin``, ``feeRecipient``, …) flow through
    here. The decoder populated ``data[input_name]`` for every event
    arg, so we look for ``data["new<Cap>"]`` then ``data[write_target]``
    and surface the value under a humanized "New <Cap>" label.

    Underscore-prefixed targets are synthetic markers (no real data arg) —
    skip them silently.
    """
    if write_target.startswith("_"):
        return []
    cap = write_target[:1].upper() + write_target[1:]
    for data_key, label in ((f"new{cap}", f"New {cap}"), (write_target, cap)):
        if data_key in seen_keys:
            continue
        value = data.get(data_key)
        if value is None or value == "":
            continue
        seen_keys.add(data_key)
        return [{"name": label, "value": _render_event_value(value), "inline": False}]
    return []


def _format_governance_embed(event: MonitoredEvent, session: Session) -> dict:
    """Build a Discord embed for a governance/monitoring event."""
    mc = event.monitored_contract
    data = event.data or {}

    # Resolve protocol and contract names from DB if linked
    protocol_name = None
    contract_name = None
    if mc.protocol_id:
        proto = session.get(Protocol, mc.protocol_id)
        if proto and proto.name:
            protocol_name = proto.name
    if mc.contract_id:
        contract = session.get(Contract, mc.contract_id)
        if contract and contract.contract_name:
            contract_name = contract.contract_name

    # Build title with names when available
    if contract_name:
        title_label = contract_name
    else:
        title_label = f"{mc.address[:10]}...{mc.address[-4:]}"
    if protocol_name:
        title = f"{protocol_name}: {event.event_type} on {title_label}"
    else:
        title = f"Protocol Event: {event.event_type} on {title_label}"

    fields = [
        {"name": "Contract", "value": f"`{mc.address}`", "inline": True},
        {"name": "Chain ID", "value": str(mc.chain_id), "inline": True},
        {"name": "Event", "value": event.event_type, "inline": True},
    ]
    if contract_name:
        fields.insert(0, {"name": "Name", "value": contract_name, "inline": True})

    # Event-specific fields. Two paths:
    #   1. state_changed_poll is a synthetic poll event with no decoder
    #      and no effect_tags — render its (field, old, new) shape
    #      directly.
    #   2. Everything else flows through the tag-driven render table:
    #      walk effect_tags.writes, look up the render spec, append
    #      one Discord field per spec entry whose data key is populated.
    #      Hand-rolled and per-contract events both carry effect_tags
    #      from their decoders; legacy events without tags synthesize
    #      them from event_type via _HANDROLLED_EVENT_TYPE_TO_TAGS.
    if event.event_type == "state_changed_poll":
        if data.get("field"):
            fields.append({"name": "Field", "value": data["field"], "inline": True})
        if data.get("old_value"):
            fields.append({"name": "Old", "value": f"`{data['old_value']}`", "inline": True})
        if data.get("new_value"):
            fields.append({"name": "New", "value": f"`{data['new_value']}`", "inline": True})
    else:
        tags = data.get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event.event_type) or {}
        writes = tags.get("writes") or []
        seen_keys: set[str] = set()
        for write_target in writes:
            if not isinstance(write_target, str):
                continue
            spec = _WRITE_TARGET_TO_RENDER.get(write_target)
            if spec is None:
                fields.extend(_generic_render_fallback(write_target, data, seen_keys))
                continue
            for label, data_key, inline in spec:
                if data_key in seen_keys:
                    continue
                value = data.get(data_key)
                if value is None or value == "":
                    continue
                seen_keys.add(data_key)
                fields.append({"name": label, "value": _render_event_value(value), "inline": inline})

    if event.block_number:
        fields.append({"name": "Block", "value": str(event.block_number), "inline": True})
    if event.tx_hash:
        fields.append({"name": "Tx", "value": f"`{event.tx_hash}`", "inline": False})

    # If a re-analysis job was queued for this event, note it.
    reanalysis_job_id = data.get("reanalysis_job_id")
    if reanalysis_job_id:
        short_id = str(reanalysis_job_id)[:8]
        fields.append(
            {
                "name": "Re-analysis",
                "value": f"Running new analysis to evaluate changes (Job `{short_id}`)",
                "inline": False,
            }
        )

    color = _resolve_embed_color(event.event_type, data)

    return {
        "title": title,
        "color": color,
        "fields": fields,
    }


# Legacy "Signers" UI grouping listed only the three signer events;
# downstream we added safe_tx_* and safe_module_* under the same group.
# When a user-saved webhook filter only contains the historical types,
# treat it as covering the whole group so the new event types still
# flow through. Keys are 'seed' types; values are the additions to
# allow alongside them.
_FILTER_GROUP_EXPANSIONS: dict[str, set[str]] = {
    "signer_added": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
    "signer_removed": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
    "threshold_changed": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
}


def _expand_allowed_event_types(allowed_types: list[str] | None) -> set[str]:
    """Expand legacy webhook event-type filters to include grouped successors.

    Cheap forward-compat shim so adding a new event type to an existing
    UI grouping doesn't silently strand pre-existing webhook filters.
    """
    if not allowed_types:
        return set()
    expanded: set[str] = set(allowed_types)
    for seed in allowed_types:
        expanded |= _FILTER_GROUP_EXPANSIONS.get(seed, set())
    return expanded


def notify_protocol_events(session: Session, events: list[MonitoredEvent]) -> None:
    """Send Discord notifications for detected governance/monitoring events.

    Groups events by protocol_id, loads ProtocolSubscription rows, filters
    by event_filter (if set), and sends Discord embeds.
    """
    if not events:
        return

    # Group events by protocol_id
    events_by_protocol: dict[int, list[MonitoredEvent]] = {}
    for event in events:
        mc = event.monitored_contract
        if mc and mc.protocol_id:
            events_by_protocol.setdefault(mc.protocol_id, []).append(event)

    if not events_by_protocol:
        return

    # Load subscriptions
    protocol_ids = list(events_by_protocol.keys())
    subs = (
        session.execute(
            select(ProtocolSubscription).where(
                ProtocolSubscription.protocol_id.in_(protocol_ids),
                ProtocolSubscription.discord_webhook_url.isnot(None),
            )
        )
        .scalars()
        .all()
    )

    if not subs:
        return

    subs_by_protocol: dict[int, list[ProtocolSubscription]] = {}
    for sub in subs:
        subs_by_protocol.setdefault(sub.protocol_id, []).append(sub)

    sent = 0
    for protocol_id, proto_events in events_by_protocol.items():
        proto_subs = subs_by_protocol.get(protocol_id, [])
        if not proto_subs:
            continue

        for event in proto_events:
            embed = _format_governance_embed(event, session)
            for sub in proto_subs:
                # Check event filter. Legacy "Signers" filter only listed
                # signer_added/removed/threshold_changed; expand the
                # allowed set on the fly so a historic webhook still
                # picks up the related Safe execution events that were
                # added later under the same UI grouping.
                if sub.event_filter and isinstance(sub.event_filter, dict):
                    allowed_types = sub.event_filter.get("event_types")
                    if allowed_types and event.event_type not in _expand_allowed_event_types(allowed_types):
                        continue

                try:
                    _send_discord(sub.discord_webhook_url, embed)  # type: ignore[arg-type]
                    sent += 1
                except Exception as exc:
                    logger.warning(
                        "Discord notification failed for protocol subscription %s: %s",
                        sub.id,
                        exc,
                        extra={"exc_type": type(exc).__name__},
                    )

    if sent:
        logger.info(
            "Sent %d protocol notification(s) for %d event(s)",
            sent,
            len(events),
        )


# ---------------------------------------------------------------------------
# Re-analysis completion notification
# ---------------------------------------------------------------------------


def notify_reanalysis_complete(session: Session, job: "Job") -> None:
    """Send a Discord notification when a re-analysis job finishes.

    Builds a diff summary comparing the pre-reanalysis snapshot (stored in
    ``job.request["reanalysis_snapshot"]``) with the current DB state, then
    dispatches the embed to all protocol subscriptions for this job's protocol.

    The embed references the original reanalysis Job ID so recipients can
    correlate it with the initial event notification.
    """
    request = job.request if isinstance(job.request, dict) else {}
    trigger = request.get("reanalysis_trigger", "unknown")
    protocol_id = job.protocol_id
    if not protocol_id:
        return

    # Load subscriptions
    subs = (
        session.execute(
            select(ProtocolSubscription).where(
                ProtocolSubscription.protocol_id == protocol_id,
                ProtocolSubscription.discord_webhook_url.isnot(None),
            )
        )
        .scalars()
        .all()
    )
    if not subs:
        return

    # Build diff
    from services.monitoring.reanalysis import build_reanalysis_diff

    changes = build_reanalysis_diff(session, job)

    # Resolve names
    protocol_name = None
    proto = session.get(Protocol, protocol_id)
    if proto:
        protocol_name = proto.name

    contract_name = None
    if job.address:
        job_chain_id = require_supported_chain_id(
            chain_id=job.chain_id,
            context=f"notification contract lookup for job {job.id}",
        )
        contract_row = session.execute(
            select(Contract)
            .where(
                Contract.address == job.address.lower(),
                Contract.chain_id == job_chain_id,
            )
            .limit(1)
        ).scalar_one_or_none()
        if contract_row:
            contract_name = contract_row.contract_name

    # Build title
    label = contract_name or f"{(job.address or '?')[:10]}...{(job.address or '?')[-4:]}"
    if protocol_name:
        title = f"{protocol_name}: Re-analysis complete — {label}"
    else:
        title = f"Re-analysis complete — {label}"

    short_id = str(job.id)[:8]

    fields: list[dict] = [
        {"name": "Trigger", "value": trigger.replace("_", " "), "inline": True},
        {"name": "Job", "value": f"`{short_id}`", "inline": True},
    ]
    if job.address:
        fields.append({"name": "Contract", "value": f"`{job.address}`", "inline": False})

    if changes:
        fields.append(
            {
                "name": "Changes detected",
                "value": "\n".join(f"• {c}" for c in changes),
                "inline": False,
            }
        )
    else:
        fields.append(
            {
                "name": "Changes detected",
                "value": "No significant differences from previous analysis.",
                "inline": False,
            }
        )

    embed = {
        "title": title,
        "color": 0x2ECC71,  # green
        "fields": fields,
    }

    sent = 0
    for sub in subs:
        try:
            _send_discord(sub.discord_webhook_url, embed)  # type: ignore[arg-type]
            sent += 1
        except Exception as exc:
            logger.warning(
                "Reanalysis completion notification failed for subscription %s: %s",
                sub.id,
                exc,
                extra={"exc_type": type(exc).__name__},
            )

    if sent:
        logger.info(
            "Sent %d reanalysis-complete notification(s) for job %s",
            sent,
            job.id,
        )
