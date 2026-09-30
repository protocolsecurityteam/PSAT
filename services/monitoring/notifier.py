"""Discord notification dispatch for proxy upgrade and governance events."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import (
    Contract,
    Job,
    MonitoredEvent,
    Protocol,
    ProtocolSubscription,
)
from services.monitoring.event_topics import (
    _HANDROLLED_EVENT_TYPE_TO_TAGS,
    WITNESS_TIER_ACTIVITY,
    WITNESS_TIER_HINT,
    value_changed_event_type,
)
from services.monitoring.salience import (
    SALIENCE_ALERT,
    SALIENCE_NOT_DETERMINED,
    SALIENCE_NOTABLE,
    SALIENCE_ROUTINE,
)
from utils.egress import UnsafeUrlError, connect_host

logger = logging.getLogger(__name__)

DISCORD_TIMEOUT = 10

# Webhook URLs are user-supplied; without this gate they are an SSRF sink.
_DISCORD_WEBHOOK_HOSTS = frozenset({"discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"})


def _is_discord_webhook(webhook_url: str) -> bool:
    # Same host parser as the SSRF guard, so backslash/userinfo tricks can't make them disagree.
    parsed = urlparse(webhook_url)
    if parsed.scheme != "https":
        return False
    try:
        host = connect_host(webhook_url)
    except UnsafeUrlError:
        return False
    return host.lower() in _DISCORD_WEBHOOK_HOSTS


def _send_discord(webhook_url: str, embed: dict) -> bool:
    """Post one embed; ``True`` iff the webhook accepted it, so rejected posts don't count as sent."""
    if not _is_discord_webhook(webhook_url):
        logger.warning(
            "Skipping non-Discord webhook target",
            extra={"host": urlparse(webhook_url).hostname},
        )
        return False
    resp = requests.post(
        webhook_url,
        json={"embeds": [embed]},
        timeout=DISCORD_TIMEOUT,
    )
    if not resp.ok:
        logger.warning(
            "Discord webhook rejected the post",
            extra={"status_code": resp.status_code, "response": resp.text[:200]},
        )
        return False
    return True


# Colors come from the write target (``pendingOwner`` intent is orange, ``owner`` commit red), with event_type overrides
# for outcome- or phase-paired events whose tags collide (Safe success/failure, timelock scheduled/executed).

_DEFAULT_EMBED_COLOR = 0x95A5A6  # neutral grey for unrecognized events

_WRITE_TARGET_TO_COLOR: dict[str, int] = {
    # RED: committed control-graph changes
    "owner": 0xFF0000,
    "authority": 0xFF0000,
    "paused": 0xFF0000,
    # ORANGE: upgrades and intent-phase ownership
    "pendingOwner": 0xFF9900,
    "pendingImplementation": 0xFF9900,
    "implementation": 0xFF9900,
    "beacon": 0xFF9900,
    "facets": 0xFF9900,
    "admin": 0xFF9900,
    # BLUE: Safe signer set
    "owners": 0x3498DB,
    # AMBER: operational parameters
    "_roles": 0xF39C12,
    "threshold": 0xF39C12,
    "min_delay": 0xF39C12,
}

# When an event writes several targets, the first in this order wins.
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
    "safe_tx_executed": 0x2ECC71,  # green — success
    "safe_module_executed": 0x2ECC71,
    "safe_tx_failed": 0xE74C3C,  # red — reverted
    "safe_module_failed": 0xE74C3C,
    "timelock_scheduled": 0x3498DB,  # blue — queued
    "timelock_executed": 0xFF9900,  # orange — applied
    # Synthetic poll event: no tags, no decoder
    "state_changed_poll": 0x9B59B6,  # purple
}


def _resolve_embed_color(event_type: str, data: dict | None) -> int:
    """Embed color: event_type override, else the first write target in priority order.

    Untagged legacy events synthesize tags.
    """
    override = _EVENT_TYPE_COLOR_OVERRIDES.get(event_type)
    if override is not None:
        return override
    if event_type.startswith("value_changed"):
        # The read proves which slot moved, not the emitter's write set.
        field = (data or {}).get("field")
        if isinstance(field, str) and field in _WRITE_TARGET_TO_COLOR:
            return _WRITE_TARGET_TO_COLOR[field]
        return _EVENT_TYPE_COLOR_OVERRIDES["state_changed_poll"]
    tags = (data or {}).get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = set(tags.get("writes") or [])
    for write_target in _COLOR_PRIORITY:
        if write_target in writes:
            return _WRITE_TARGET_TO_COLOR[write_target]
    return _DEFAULT_EMBED_COLOR


# Write target -> ``(label, data_key, inline)`` Discord fields, deduped by ``data_key`` (Ownable2Step writes owner and
# pendingOwner to one arg). Labels are user-facing, not slot names; underscore targets are activity markers that surface
# their args.
_WRITE_TARGET_TO_RENDER: dict[str, list[tuple[str, str, bool]]] = {
    "owner": [
        ("Old Owner", "old_owner", False),
        ("New Owner", "new_owner", False),
    ],
    # Ownable2Step intent; semantic aliases land in old_owner/new_owner.
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
        # Diamond cuts store the first facet under ``implementation``.
        ("New Implementation", "implementation", False),
    ],
    "admin": [
        ("Old Admin", "previous_admin", False),
        ("New Admin", "new_admin", False),
    ],
    "paused": [
        # paused/unpaused share a target; show the account that flipped it.
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
    """Hex strings (addresses, roles) in backticks; everything else as str."""
    if isinstance(value, str) and value.startswith("0x"):
        return f"`{value}`"
    return str(value)


def _generic_render_fallback(
    write_target: str,
    data: dict,
    seen_keys: set[str],
) -> list[dict]:
    """Fields for a write target with no render spec: ``data["new<Cap>"]`` or ``data[write_target]`` as "New <Cap>".

    Underscore targets are skipped.
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


def _safe_exec_fields(safe_exec: dict) -> list[dict]:
    """Render a decoded Safe execution ("Safe executed setFee(uint256) on 0x7a4…e7 (call)").

    Undecoded outcomes render their reason so "called nobody" and "not decoded" look different.
    """
    status = safe_exec.get("status")
    if status != "decoded":
        reason = {
            "not_top_level_call": (
                "the observed transaction was not this Safe's own execTransaction "
                "(relayer, nested Safe, or wrapper) — the inner call is not witnessed"
            ),
            "over_budget": "not decoded this pass (per-pass transaction budget)",
            "args_undecodable": "execTransaction arguments did not decode",
            "ambiguous_attribution": (
                "this Safe executed more than once in this transaction; which call these "
                "arguments describe is not witnessed, so none is published"
            ),
        }.get(str(status), f"not decoded ({status})")
        return [{"name": "Safe call", "value": reason, "inline": False}]

    fields: list[dict] = []
    target = safe_exec.get("to")
    if target:
        fields.append({"name": "Target", "value": f"`{target}`", "inline": True})

    target_function = safe_exec.get("target_function") or {}
    # Resolved signature from the target's verified source, else the raw selector.
    label = target_function.get("signature") or safe_exec.get("selector")
    if label:
        fields.append({"name": "Function", "value": f"`{label}`", "inline": True})

    value = safe_exec.get("value")
    if value is not None:
        fields.append({"name": "Value", "value": f"{value} wei", "inline": True})

    operation_label = safe_exec.get("operation_label")
    if operation_label:
        recognized = safe_exec.get("multisend_recognized")
        suffix = (
            ""
            if operation_label != "delegatecall"
            else (" (pinned MultiSend)" if recognized else " (target NOT a pinned MultiSend)")
        )
        fields.append({"name": "Operation", "value": f"{operation_label}{suffix}", "inline": True})

    batch = safe_exec.get("batch")
    if isinstance(batch, list):
        summary = ", ".join(
            str(call.get("signature") or call.get("selector") or "?") for call in batch[:4] if isinstance(call, dict)
        )
        if len(batch) > 4:
            summary = f"{summary}, …"
        fields.append(
            {
                "name": "Batch",
                "value": f"{len(batch)} call(s){f': {summary}' if summary else ''}",
                "inline": False,
            }
        )
    elif safe_exec.get("batch_status") == "undecodable":
        # No partial list; name which layer failed.
        why = {
            "malformed_payload": "the MultiSend payload did not decode",
            "nested_payload_undecodable": "a nested MultiSend payload did not decode",
            "nested_depth_exceeded": "the batch nests deeper than this decoder expands",
        }.get(str(safe_exec.get("batch_status_reason")), "the MultiSend payload did not decode")
        fields.append({"name": "Batch", "value": f"{why} — contents not listed", "inline": False})
    return fields


def _format_governance_embed(event: MonitoredEvent, session: Session) -> dict:
    """Build a Discord embed for a governance/monitoring event."""
    mc = event.monitored_contract
    data = event.data or {}

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

    # ``state_changed_poll`` renders its (field, old, new) directly; everything else goes through the tag-driven render
    # table.
    if event.event_type == "state_changed_poll":
        if data.get("field"):
            fields.append({"name": "Field", "value": data["field"], "inline": True})
        if data.get("old_value"):
            fields.append({"name": "Old", "value": f"`{data['old_value']}`", "inline": True})
        if data.get("new_value"):
            fields.append({"name": "New", "value": f"`{data['new_value']}`", "inline": True})
    elif event.event_type.startswith("value_changed"):
        # Read-verified diff: old -> new is the witness.
        if data.get("field"):
            fields.append({"name": "Field", "value": data["field"], "inline": True})
        if data.get("old") is not None:
            fields.append({"name": "Old", "value": _render_event_value(data["old"]), "inline": True})
        if data.get("new") is not None:
            fields.append({"name": "New", "value": _render_event_value(data["new"]), "inline": True})
        fields.append({"name": "Witness", "value": "verification read", "inline": True})
    elif isinstance(data.get("safe_exec"), dict):
        # The decoded execution is the embed's content; ``_safe_op`` has no render spec.
        fields.extend(_safe_exec_fields(data["safe_exec"]))
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

    # Timelock families publish their resolved signature in their own namespaced block.
    target_function = data.get("target_function")
    if isinstance(target_function, dict):
        label = target_function.get("signature") or target_function.get("selector")
        if label:
            fields.append({"name": "Function", "value": f"`{label}`", "inline": True})

    if event.block_number:
        fields.append({"name": "Block", "value": str(event.block_number), "inline": True})
    if event.tx_hash:
        fields.append({"name": "Tx", "value": f"`{event.tx_hash}`", "inline": False})

    # Tell the recipient the watch-list came from a plan that couldn't be re-read; what it missed is invisible.
    plan_stale_since = data.get("plan_stale_since")
    if plan_stale_since:
        fields.append(
            {
                "name": "Watch-list",
                "value": f"from a tracking plan last read {plan_stale_since} — coverage may be incomplete",
                "inline": False,
            }
        )

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


# Legacy "Signers" filters listed only three signer events; saved filters with only those also get the Safe execution
# types added to the group later. Kept after ``safe_exec`` split out of ``signers`` (``site/src/surface/meta.js``):
# muting executions on old filters would assume the subscriber's intent. See ``_FILTER_GROUPS_KEY``.
_FILTER_GROUP_EXPANSIONS: dict[str, set[str]] = {
    "signer_added": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
    "signer_removed": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
    "threshold_changed": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
}

# The analyzer's three controller_id spellings.
_CONTROLLER_ID_PREFIXES = ("", "state_variable:", "external_contract:")


def _value_changed_forms(write_target: str) -> set[str]:
    return {value_changed_event_type(f"{prefix}{write_target}") for prefix in _CONTROLLER_ID_PREFIXES}


# Seeds meaning any read-witnessed field diff. A verification read advances ``last_known_state`` and pre-empts the poll,
# so without this a "State polling" subscriber would hear about a rotation from neither path. A stem rule, since
# per-contract ids can't be enumerated.
_READ_WITNESSED_WILDCARD_SEEDS = frozenset({"state_changed_poll"})


# ``event_filter`` key naming the UI alert groups a filter was saved against. Present, the filter is taken at its word;
# absent, it predates the split and keeps the legacy expansion. Pre- and post-split saves otherwise enumerate identical
# ``event_types``, so the key had to land with the split. Inert today: the UI always passes every group.
_FILTER_GROUPS_KEY = "groups"

# Mirrors ``MONITOR_ALERT_GROUPS`` in ``site/src/surface/meta.js``; pinned by
# ``tests/monitoring/test_witness_notifier_gating.py``.
_KNOWN_FILTER_GROUPS = frozenset(
    {"upgrades", "ownership", "pause", "roles", "signers", "safe_exec", "timelock", "state"}
)


def _stated_filter_groups(event_filter: object) -> list[str] | None:
    """The known group keys a filter states, or ``None``.

    Unknown names aren't statements: the token suppresses the legacy expansion, so an unknown word must not mute
    anything.
    """
    if not isinstance(event_filter, dict):
        return None
    groups = event_filter.get(_FILTER_GROUPS_KEY)
    if not isinstance(groups, list) or not groups:
        return None
    if not all(isinstance(g, str) for g in groups):
        return None
    # Unknown names are dropped; known ones still count.
    known = [g for g in groups if g in _KNOWN_FILTER_GROUPS]
    return known or None


def _expand_allowed_event_types(allowed_types: list[str] | None, *, filter_groups: list[str] | None = None) -> set[str]:
    """Expand saved event-type filters to their successors.

    Two expansions: the historical UI groupings (skipped when *filter_groups* states its own groups), and,
    unconditionally, the witness taxonomy's ``value_changed:<controller_id>`` for filters on the legacy owner events or
    ``state_changed:<id>``. ``member_changed:<mapping_var>`` is never expanded: no legacy filter covered those.
    """
    if not allowed_types:
        return set()
    expanded: set[str] = set(allowed_types)
    for seed in allowed_types:
        if not filter_groups:
            expanded |= _FILTER_GROUP_EXPANSIONS.get(seed, set())
        stem, sep, controller_id = seed.partition(":")
        if sep and stem in ("state_changed", "controller_changed") and controller_id:
            expanded.add(f"value_changed:{controller_id}")
            continue
        for write_target in (_HANDROLLED_EVENT_TYPE_TO_TAGS.get(seed) or {}).get("writes") or []:
            if isinstance(write_target, str) and not write_target.startswith("_"):
                expanded |= _value_changed_forms(write_target)
    return expanded


def _filter_allows(
    allowed_types: list[str] | None,
    event_type: str,
    *,
    filter_groups: list[str] | None = None,
) -> bool:
    """Whether a saved filter covers *event_type*; an empty filter covers everything.

    Wildcard seeds admit any read-witnessed type.
    """
    if not allowed_types:
        return True
    if event_type in _expand_allowed_event_types(allowed_types, filter_groups=filter_groups):
        return True
    if event_type.startswith("value_changed"):
        return any(seed in _READ_WITNESSED_WILDCARD_SEEDS for seed in allowed_types)
    return False


# Hint/activity tiers only prove a writer ran; refuse them here too, not just in the scanner.
_NON_NOTIFYING_TIERS = frozenset({WITNESS_TIER_HINT, WITNESS_TIER_ACTIVITY})


def _may_notify(event: MonitoredEvent) -> bool:
    data = event.data if isinstance(event.data, dict) else {}
    return data.get("witness_tier") not in _NON_NOTIFYING_TIERS


# Mirror of ``salience.SALIENCE_ORDER``: unrated events rank with ``notable``.
_SALIENCE_ORDER = {
    SALIENCE_ROUTINE: 0,
    SALIENCE_NOT_DETERMINED: 1,
    SALIENCE_NOTABLE: 1,
    SALIENCE_ALERT: 2,
}


def _salience_allows(subscription: ProtocolSubscription, event: MonitoredEvent) -> bool:
    """Whether *subscription*'s opt-in ``min_salience`` admits *event*.

    Absent means no change in behaviour; an unrecognized threshold admits everything rather than mute on our misreading.
    """
    event_filter = subscription.event_filter if isinstance(subscription.event_filter, dict) else {}
    minimum = event_filter.get("min_salience")
    if not isinstance(minimum, str) or minimum not in _SALIENCE_ORDER:
        return True
    data = event.data if isinstance(event.data, dict) else {}
    level = data.get("salience")
    if level not in _SALIENCE_ORDER:
        # Unrated is not routine.
        level = SALIENCE_NOT_DETERMINED
    return _SALIENCE_ORDER[level] >= _SALIENCE_ORDER[minimum]


def notify_protocol_events(session: Session, events: list[MonitoredEvent]) -> None:
    """Send Discord notifications for governance/monitoring events to each protocol's subscriptions, honouring their
    filters.
    """
    if not events:
        return

    # Occurrences that only prove a writer ran never page, whatever route delivered them.
    events_by_protocol: dict[int, list[MonitoredEvent]] = {}
    for event in events:
        if not _may_notify(event):
            continue
        mc = event.monitored_contract
        if mc and mc.protocol_id:
            events_by_protocol.setdefault(mc.protocol_id, []).append(event)

    if not events_by_protocol:
        return

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
    failed = 0
    for protocol_id, proto_events in events_by_protocol.items():
        proto_subs = subs_by_protocol.get(protocol_id, [])
        if not proto_subs:
            continue

        for event in proto_events:
            embed = _format_governance_embed(event, session)
            for sub in proto_subs:
                # Expanded so old "Signers" webhooks still get later Safe execution types, unless the filter states its
                # groups.
                if sub.event_filter and isinstance(sub.event_filter, dict):
                    if not _filter_allows(
                        sub.event_filter.get("event_types"),
                        event.event_type,
                        filter_groups=_stated_filter_groups(sub.event_filter),
                    ):
                        continue
                # Both filters must pass; absent ``min_salience`` is a no-op.
                if not _salience_allows(sub, event):
                    continue

                try:
                    if _send_discord(sub.discord_webhook_url, embed):  # pyright: ignore[reportArgumentType]
                        sent += 1
                    else:
                        failed += 1
                except Exception as exc:
                    failed += 1
                    logger.warning(
                        "Discord notification failed for a protocol subscription",
                        extra={
                            "subscription_id": str(sub.id),
                            "protocol_id": protocol_id,
                            "exc_type": type(exc).__name__,
                            "error": str(exc),
                        },
                    )

    if sent or failed:
        logger.info(
            "Sent %d protocol notification(s) for %d event(s), %d failed",
            sent,
            len(events),
            failed,
            extra={"sent": sent, "failed": failed, "events": len(events)},
        )


def notify_reanalysis_complete(session: Session, job: "Job") -> None:
    """Notify a finished re-analysis: a diff against ``job.request["reanalysis_snapshot"]``, sent to the protocol's
    subscriptions and citing the job id.
    """
    request = job.request if isinstance(job.request, dict) else {}
    trigger = request.get("reanalysis_trigger", "unknown")
    protocol_id = job.protocol_id
    if not protocol_id:
        return

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

    from services.monitoring.reanalysis import build_reanalysis_diff

    changes = build_reanalysis_diff(session, job)

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
    failed = 0
    for sub in subs:
        try:
            if _send_discord(sub.discord_webhook_url, embed):  # pyright: ignore[reportArgumentType]
                sent += 1
            else:
                failed += 1
        except Exception as exc:
            failed += 1
            logger.warning(
                "Reanalysis completion notification failed for a subscription",
                extra={
                    "subscription_id": str(sub.id),
                    "job_id": str(job.id),
                    "exc_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

    if sent or failed:
        logger.info(
            "Sent %d reanalysis-complete notification(s) for job %s, %d failed",
            sent,
            job.id,
            failed,
            extra={"sent": sent, "failed": failed, "job_id": str(job.id)},
        )
