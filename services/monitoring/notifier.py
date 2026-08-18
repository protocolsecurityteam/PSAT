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

logger = logging.getLogger(__name__)

DISCORD_TIMEOUT = 10


def _send_discord(webhook_url: str, embed: dict) -> bool:
    """Post one embed. ``True`` iff the webhook accepted it.

    The return value is the point: a non-ok response used to be logged here and
    then discarded, so a revoked or rate-limited webhook counted toward the
    caller's "sent" total exactly like a delivered post.
    """
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
    if event_type.startswith("value_changed"):
        # The proven field, not the emitter's donated write set: the read is
        # what says which slot moved.
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


def _safe_exec_fields(safe_exec: dict) -> list[dict]:
    """Render a decoded Safe execution — the difference between "safe_tx_executed
    on 0x41df…6ae" and "Safe executed setFee(uint256) on 0x7a4…e7 (call)".

    Every undecoded outcome renders its OWN reason instead of nothing: a
    recipient who sees no target must be able to tell "the Safe called nobody"
    from "we did not decode this", and an embed that renders identically in
    both cases cannot.
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
    # The signature when one was RESOLVED from the target's own verified
    # source; the raw selector otherwise. A selector renders fine and is true.
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
        # No partial list, and the embed says so: a truncated batch would
        # understate what the Safe did. The reason names WHICH layer failed.
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
    elif event.event_type.startswith("value_changed"):
        # Read-verified diff: the old→new pair IS the witness, so it renders
        # from the event's own data rather than through the emitter's donated
        # write set (which is what the tag-driven path below reads).
        if data.get("field"):
            fields.append({"name": "Field", "value": data["field"], "inline": True})
        if data.get("old") is not None:
            fields.append({"name": "Old", "value": _render_event_value(data["old"]), "inline": True})
        if data.get("new") is not None:
            fields.append({"name": "New", "value": _render_event_value(data["new"]), "inline": True})
        fields.append({"name": "Witness", "value": "verification read", "inline": True})
    elif isinstance(data.get("safe_exec"), dict):
        # The decoded execution IS the content of a Safe embed; the tag-driven
        # path below has no render spec for the ``_safe_op`` marker (it names no
        # single slot), so before enrichment these embeds carried nothing but
        # the address and the block.
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

    # The timelock families publish their resolved signature in a namespaced
    # block of their own (their ``target``/``selector`` are keys the taxonomy
    # owns). Rendered here rather than in a branch above so the row keeps
    # whatever its own family already renders.
    target_function = data.get("target_function")
    if isinstance(target_function, dict):
        label = target_function.get("signature") or target_function.get("selector")
        if label:
            fields.append({"name": "Function", "value": f"`{label}`", "inline": True})

    if event.block_number:
        fields.append({"name": "Block", "value": str(event.block_number), "inline": True})
    if event.tx_hash:
        fields.append({"name": "Tx", "value": f"`{event.tx_hash}`", "inline": False})

    # The event is real; the watch-list that caught it was built from a plan
    # that could not be re-read at the last enrollment. Saying so is the
    # difference between "we are watching this contract" and "we are watching
    # it on a plan last read at T" — the recipient cannot infer the second
    # from an embed that looks exactly like a fresh-plan one, and what the
    # stale plan may have MISSED is invisible by construction.
    plan_stale_since = data.get("plan_stale_since")
    if plan_stale_since:
        fields.append(
            {
                "name": "Watch-list",
                "value": f"from a tracking plan last read {plan_stale_since} — coverage may be incomplete",
                "inline": False,
            }
        )

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
#
# These stay after the `safe_exec` group was split out of `signers` in
# ``site/src/surface/meta.js``: the split changes what a NEW subscription
# enumerates, and a filter saved before it says nothing about whether its owner
# wanted executions — the only reading we can witness is the one the UI gave it
# at the time, which included them. Muting them on the split would be a claim
# about a subscriber's intent, exactly what this shim exists to refuse. See
# ``_FILTER_GROUPS_KEY`` for how a filter states the newer vocabulary instead of
# being assumed into it.
_FILTER_GROUP_EXPANSIONS: dict[str, set[str]] = {
    "signer_added": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
    "signer_removed": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
    "threshold_changed": {"safe_tx_executed", "safe_tx_failed", "safe_module_executed", "safe_module_failed"},
}

# The three controller_id spellings the analyzer emits, so a seed naming a
# write target expands to whichever form the tracking plan actually used.
_CONTROLLER_ID_PREFIXES = ("", "state_variable:", "external_contract:")


def _value_changed_forms(write_target: str) -> set[str]:
    return {value_changed_event_type(f"{prefix}{write_target}") for prefix in _CONTROLLER_ID_PREFIXES}


# Seeds that ask for read-witnessed field diffs in general rather than for one
# named slot. ``state_changed_poll`` is the only one today: it is what the
# "State polling" UI category writes, and a subscriber who picked it asked to
# hear when a polled field's value moves. A verification read is that same
# fact observed by the same machinery one tick earlier — and because the read
# advances ``last_known_state``, the poll that would otherwise have raised
# ``state_changed_poll`` finds no diff and never fires. Without this rule such
# a subscriber hears about the rotation from neither path.
#
# Per-contract controller ids cannot be enumerated into a static set, so this
# is a stem rule rather than an expansion.
_READ_WITNESSED_WILDCARD_SEEDS = frozenset({"state_changed_poll"})


# ``event_filter`` key naming the alert-group vocabulary a filter was saved
# against (``site/src/surface/sidebar/activity/helpers.js``'s group keys). It is
# a POSITIVE token, and the only thing that will distinguish a post-split
# "signers, and I mean only signers" save from a pre-split "signers" save —
# the two enumerate byte-identical ``event_types``. Absent, the filter predates
# the vocabulary and keeps the legacy grouping expansion, so no saved
# subscription is ever muted by a split it was not written against; present, the
# save enumerated its own groups and is taken at its word, so no subscription
# will be force-fed a group it did not name.
#
# The discriminator is inert on the notification plane TODAY: the only producer
# is ``ActivityPanel.attachWebhook``, and the Alerts control passes it the whole
# offered group set, so no save the UI can currently produce says "signers
# without executions". It is written now because a filter saved before this key
# existed and one saved after it are otherwise indistinguishable forever — the
# discriminator has to land with the split or not at all. A per-group selector
# is what would make it bite.
_FILTER_GROUPS_KEY = "groups"

# The group keys the UI can state — mirror of ``MONITOR_ALERT_GROUPS`` in
# ``site/src/surface/meta.js``. Pinned by
# ``tests/test_witness_notifier_gating.py`` against that table.
_KNOWN_FILTER_GROUPS = frozenset(
    {"upgrades", "ownership", "pause", "roles", "signers", "safe_exec", "timelock", "state"}
)


def _stated_filter_groups(event_filter: object) -> list[str] | None:
    """The group keys a filter positively states, or ``None`` if it states none.

    An unreadable token is not a statement, and a name from no vocabulary we
    have is unreadable in exactly the same way a non-list is: both are treated
    as absent rather than as a claim of coverage. This matters because the token
    SUPPRESSES the legacy grouping expansion — reading ``["banana"]`` as a
    statement would mute a subscription's Safe executions on the strength of a
    word this system has never defined.
    """
    if not isinstance(event_filter, dict):
        return None
    groups = event_filter.get(_FILTER_GROUPS_KEY)
    if not isinstance(groups, list) or not groups:
        return None
    if not all(isinstance(g, str) for g in groups):
        return None
    # An unknown name is dropped rather than fatal — a filter naming a group we
    # do know still states that one. A token that names nothing we know states
    # nothing at all.
    known = [g for g in groups if g in _KNOWN_FILTER_GROUPS]
    return known or None


def _expand_allowed_event_types(allowed_types: list[str] | None, *, filter_groups: list[str] | None = None) -> set[str]:
    """Expand legacy webhook event-type filters to include grouped successors.

    Cheap forward-compat shim so adding a new event type to an existing
    UI grouping doesn't silently strand pre-existing webhook filters.

    Two expansions:

      * the historical UI groupings above;
      * the witness taxonomy's read-verified vocabulary. A filter saved
        against ``ownership_transferred`` (or against the neutral
        ``state_changed:<controller_id>`` the terminal fallback used to mint)
        is asking to hear about the owner slot moving, so the
        ``value_changed:<controller_id>`` that now carries that fact is
        allowed alongside it. Without this the taxonomy would silently mute
        every pre-existing subscription for exactly the events it strengthened.

    ``member_changed:<mapping_var>`` is deliberately NOT expanded from any
    seed: no legacy filter ever covered those mappings (their occurrences
    published under a neutral ``state_changed`` type or not at all), so
    inventing coverage for them would be a claim about the subscriber's
    intent rather than a reading of it.

    ``filter_groups`` is the filter's own statement of which alert groups it
    covers (see ``_FILTER_GROUPS_KEY``). When it states them, the historical
    UI-grouping expansion is not applied — the save already enumerated the
    groups it wanted, so folding a neighbouring group in would override it. The
    taxonomy expansion below is unconditional either way: it is not a grouping
    guess but the same fact under the name the taxonomy now gives it.
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
    """Does a saved webhook filter cover *event_type*?

    An empty / absent filter covers everything (the existing contract). Beyond
    the enumerable expansion, a wildcard seed admits any read-witnessed type —
    see ``_READ_WITNESSED_WILDCARD_SEEDS``.
    """
    if not allowed_types:
        return True
    if event_type in _expand_allowed_event_types(allowed_types, filter_groups=filter_groups):
        return True
    if event_type.startswith("value_changed"):
        return any(seed in _READ_WITNESSED_WILDCARD_SEEDS for seed in allowed_types)
    return False


# Tiers whose occurrences prove only that a writer ran. They never reach the
# notify list from the scanner (no row is inserted at all), so this is the
# second lock on the same door: any caller handing the notifier a hint- or
# activity-tier row is refused rather than trusted.
_NON_NOTIFYING_TIERS = frozenset({WITNESS_TIER_HINT, WITNESS_TIER_ACTIVITY})


def _may_notify(event: MonitoredEvent) -> bool:
    data = event.data if isinstance(event.data, dict) else {}
    return data.get("witness_tier") not in _NON_NOTIFYING_TIERS


# Mirror of ``services.monitoring.salience.SALIENCE_ORDER``. ``not_determined``
# sorts WITH ``notable`` so an unclassified event is never filtered out by a
# threshold the classifier never rated it against.
_SALIENCE_ORDER = {
    SALIENCE_ROUTINE: 0,
    SALIENCE_NOT_DETERMINED: 1,
    SALIENCE_NOTABLE: 1,
    SALIENCE_ALERT: 2,
}


def _salience_allows(subscription: ProtocolSubscription, event: MonitoredEvent) -> bool:
    """Does *subscription*'s ``min_salience`` admit *event*?

    **Opt-in, and only opt-in** (invariant 7). A subscription without
    ``min_salience`` receives exactly what it receives today — this is the same
    no-default-change contract ``_expand_allowed_event_types`` keeps for saved
    event-type filters, and it is why the threshold rides inside the existing
    ``event_filter`` JSONB rather than in a new column.

    An unrecognized threshold admits everything: a filter value nothing in the
    vocabulary matches is a filter we cannot honour, and declining to deliver
    on that basis would mute a subscriber over our own misreading.
    """
    event_filter = subscription.event_filter if isinstance(subscription.event_filter, dict) else {}
    minimum = event_filter.get("min_salience")
    if not isinstance(minimum, str) or minimum not in _SALIENCE_ORDER:
        return True
    data = event.data if isinstance(event.data, dict) else {}
    level = data.get("salience")
    if level not in _SALIENCE_ORDER:
        # A row minted before salience landed, or one no rule rated. Unrated is
        # not routine (invariant 5), so it is measured at the not_determined
        # rank rather than dropped.
        level = SALIENCE_NOT_DETERMINED
    return _SALIENCE_ORDER[level] >= _SALIENCE_ORDER[minimum]


def notify_protocol_events(session: Session, events: list[MonitoredEvent]) -> None:
    """Send Discord notifications for detected governance/monitoring events.

    Groups events by protocol_id, loads ProtocolSubscription rows, filters
    by event_filter (if set), and sends Discord embeds.
    """
    if not events:
        return

    # Group events by protocol_id. Side effects follow claim strength
    # (invariant 5): an occurrence that only proves a writer ran never pages
    # anyone, whatever route handed it to this function.
    events_by_protocol: dict[int, list[MonitoredEvent]] = {}
    for event in events:
        if not _may_notify(event):
            continue
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
    failed = 0
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
                # added later under the same UI grouping — unless the filter
                # states its own groups, which only a post-split save does.
                if sub.event_filter and isinstance(sub.event_filter, dict):
                    if not _filter_allows(
                        sub.event_filter.get("event_types"),
                        event.event_type,
                        filter_groups=_stated_filter_groups(sub.event_filter),
                    ):
                        continue
                # Composes with the type filter: both must pass. Absent
                # ``min_salience`` is a no-op, so no existing subscription
                # changes behaviour.
                if not _salience_allows(sub, event):
                    continue

                try:
                    if _send_discord(sub.discord_webhook_url, embed):  # type: ignore[arg-type]
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
    failed = 0
    for sub in subs:
        try:
            if _send_discord(sub.discord_webhook_url, embed):  # type: ignore[arg-type]
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
