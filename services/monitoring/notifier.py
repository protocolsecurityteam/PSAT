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

logger = logging.getLogger(__name__)

DISCORD_TIMEOUT = 10


def _format_embed(event: ProxyUpgradeEvent) -> dict:
    """Build a Discord embed dict for a single upgrade event."""
    proxy = event.watched_proxy
    label = proxy.label or proxy.proxy_address
    fields = [
        {"name": "Proxy", "value": f"`{proxy.proxy_address}`", "inline": True},
        {"name": "Chain", "value": proxy.chain, "inline": True},
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

# Color mapping by severity
_EVENT_COLORS = {
    "ownership_transferred": 0xFF0000,  # red
    "ownership_transfer_started": 0xFF9900,  # orange (intent, not commit)
    "authority_updated": 0xFF0000,  # red — full access-control regime swap
    "paused": 0xFF0000,
    "unpaused": 0xFF0000,
    "upgraded": 0xFF9900,  # orange
    "admin_changed": 0xFF9900,
    "beacon_upgraded": 0xFF9900,
    "timelock_executed": 0xFF9900,
    "timelock_scheduled": 0x3498DB,  # blue
    "signer_added": 0x3498DB,
    "signer_removed": 0x3498DB,
    "safe_tx_executed": 0x2ECC71,  # green — successful Safe tx execution
    "safe_tx_failed": 0xE74C3C,  # red — Safe tx execution reverted
    "safe_module_executed": 0x2ECC71,
    "safe_module_failed": 0xE74C3C,
    "role_granted": 0xF39C12,  # amber
    "role_revoked": 0xF39C12,
    "threshold_changed": 0xF39C12,
    "delay_changed": 0xF39C12,
    "state_changed_poll": 0x9B59B6,  # purple
}


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
        {"name": "Chain", "value": mc.chain, "inline": True},
        {"name": "Event", "value": event.event_type, "inline": True},
    ]
    if contract_name:
        fields.insert(0, {"name": "Name", "value": contract_name, "inline": True})

    # Add event-specific fields
    if event.event_type in ("ownership_transferred", "ownership_transfer_started"):
        if data.get("old_owner"):
            fields.append({"name": "Old Owner", "value": f"`{data['old_owner']}`", "inline": False})
        if data.get("new_owner"):
            fields.append({"name": "New Owner", "value": f"`{data['new_owner']}`", "inline": False})
    elif event.event_type == "authority_updated":
        if data.get("old_authority"):
            fields.append({"name": "Old Authority", "value": f"`{data['old_authority']}`", "inline": False})
        if data.get("new_authority"):
            fields.append({"name": "New Authority", "value": f"`{data['new_authority']}`", "inline": False})
    elif event.event_type in ("upgraded", "new_implementation", "changed_master_copy", "target_updated"):
        if data.get("implementation"):
            fields.append({"name": "New Implementation", "value": f"`{data['implementation']}`", "inline": False})
    elif event.event_type == "admin_changed":
        if data.get("previous_admin"):
            fields.append({"name": "Old Admin", "value": f"`{data['previous_admin']}`", "inline": False})
        if data.get("new_admin"):
            fields.append({"name": "New Admin", "value": f"`{data['new_admin']}`", "inline": False})
    elif event.event_type == "beacon_upgraded":
        if data.get("beacon"):
            fields.append({"name": "Beacon", "value": f"`{data['beacon']}`", "inline": False})
    elif event.event_type in ("paused", "unpaused"):
        if data.get("account"):
            fields.append({"name": "Account", "value": f"`{data['account']}`", "inline": False})
    elif event.event_type in ("role_granted", "role_revoked"):
        if data.get("role"):
            fields.append({"name": "Role", "value": f"`{data['role']}`", "inline": False})
        if data.get("account"):
            fields.append({"name": "Account", "value": f"`{data['account']}`", "inline": True})
        if data.get("sender"):
            fields.append({"name": "Sender", "value": f"`{data['sender']}`", "inline": True})
    elif event.event_type in ("signer_added", "signer_removed"):
        if data.get("owner"):
            fields.append({"name": "Signer", "value": f"`{data['owner']}`", "inline": False})
    elif event.event_type == "threshold_changed":
        if data.get("threshold"):
            fields.append({"name": "New Threshold", "value": str(data["threshold"]), "inline": True})
    elif event.event_type == "delay_changed":
        if data.get("old_delay") is not None:
            fields.append({"name": "Old Delay", "value": str(data["old_delay"]), "inline": True})
        if data.get("new_delay") is not None:
            fields.append({"name": "New Delay", "value": str(data["new_delay"]), "inline": True})
    elif event.event_type == "state_changed_poll":
        if data.get("field"):
            fields.append({"name": "Field", "value": data["field"], "inline": True})
        if data.get("old_value"):
            fields.append({"name": "Old", "value": f"`{data['old_value']}`", "inline": True})
        if data.get("new_value"):
            fields.append({"name": "New", "value": f"`{data['new_value']}`", "inline": True})

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

    color = _EVENT_COLORS.get(event.event_type, 0x95A5A6)

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
        contract_row = session.execute(
            select(Contract)
            .where(
                Contract.address == job.address.lower(),
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
