"""Event -> monitoring-state dispatch: watch-filter gates, per-write-target
state extractors, and the shared new-value resolution chain.

Lifted verbatim from ``services.monitoring.unified_watcher`` (which
re-exports the names tests import). Pure dispatch + session-local writes;
nothing here touches the RPC layer, so no ``unified_watcher`` patch target
is involved.
"""

from __future__ import annotations

from typing import Callable

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from db.models import MonitoredContract, ProxyUpgradeEvent, WatchedProxy
from services.monitoring.event_topics import (
    _HANDROLLED_EVENT_TYPE_TO_TAGS,
    is_member_changed_event_type,
)

# Per-write-target → monitoring_config flag gates. Tag-driven dispatch
# routes each ``effect_tags.writes`` entry through this map; if any of
# the resulting flags is enabled the event passes the watch filter.
#
# ``admin``-family writes route to both watch_upgrades (EIP-1967 proxy
# admin slot is the upgrader role) AND watch_ownership (Compound/Aave/
# Curve "admin" is the principal owner) because the underlying mutation
# is "the privileged controller changed" — the monitoring intent depends
# on what the contract IS, not what the event is named.
_WRITE_TARGET_TO_CONFIG_KEYS: dict[str, tuple[str, ...]] = {
    # Ownership
    "owner": ("watch_ownership",),
    "_owner": ("watch_ownership",),
    "pendingOwner": ("watch_ownership",),
    "_pendingOwner": ("watch_ownership",),
    # Admin family — both upgrade- and ownership-gated
    "admin": ("watch_upgrades", "watch_ownership"),
    "_admin": ("watch_upgrades", "watch_ownership"),
    "pendingAdmin": ("watch_upgrades", "watch_ownership"),
    "future_admin": ("watch_upgrades", "watch_ownership"),
    # Upgrade-relevant slot writes (also any delegates=True event)
    "implementation": ("watch_upgrades",),
    "beacon": ("watch_upgrades",),
    "facets": ("watch_upgrades",),
    "pendingImplementation": ("watch_upgrades",),
    "_initialized": ("watch_upgrades",),
    "_initializing": ("watch_upgrades",),
    # Authority
    "authority": ("watch_authority",),
    # Pause
    "paused": ("watch_pause",),
    # Roles
    "_roles": ("watch_roles",),
    # Safe signers / Safe + Timelock activity
    "owners": ("watch_safe_signers",),
    "threshold": ("watch_safe_signers",),
    "_safe_op": ("watch_safe_signers",),
    "_safe_module_op": ("watch_safe_signers",),
    "_safe_modules": ("watch_safe_modules",),
    "_safe_guard": ("watch_safe_modules",),
    "_timelock_op": ("watch_timelock",),
    "min_delay": ("watch_timelock",),
}


def _should_watch(mc: MonitoredContract, parsed: dict) -> bool:
    """Check if the monitoring config allows this event.

    Tag-driven: derive the set of monitoring_config flags this event is
    gated on from ``effect_tags.writes`` + ``effect_tags.delegates``,
    then pass if any flag is enabled (or defaults on). Legacy events
    without tags synthesize them from event_type via
    ``_HANDROLLED_EVENT_TYPE_TO_TAGS``.
    """
    config = mc.monitoring_config or {}
    event_type = parsed.get("event_type", "")

    tags = parsed.get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = tags.get("writes") or []
    delegates = bool(tags.get("delegates"))

    config_keys: set[str] = set()
    if delegates:
        config_keys.add("watch_upgrades")
    for write_target in writes:
        if not isinstance(write_target, str):
            continue
        keys = _WRITE_TARGET_TO_CONFIG_KEYS.get(write_target)
        if keys:
            config_keys.update(keys)

    if not config_keys:
        return True  # Unrecognized event — allow rather than silently drop.

    # Legacy alias: ``watch_signers`` predates the rename to
    # ``watch_safe_signers``. Accept either flag so historic
    # MonitoredContract rows written before the rename keep working
    # without a migration. Only kicks in when the event's gating
    # reduces to watch_safe_signers alone — multi-gate events
    # (admin_changed) flow through the general path.
    if config_keys == {"watch_safe_signers"}:
        if config.get("watch_safe_signers") or config.get("watch_signers"):
            return True
        if "watch_safe_signers" in config or "watch_signers" in config:
            return False
        # Neither key set — default-on, fall through to the general path.

    # Allow if ANY relevant flag is set (or defaults to True via .get()).
    return any(config.get(key, True) for key in config_keys)


def _write_through_proxy_event(
    session: Session,
    mc: MonitoredContract,
    parsed: dict,
) -> None:
    """Write a ProxyUpgradeEvent for backward compatibility."""
    new_impl = parsed.get("implementation") or parsed.get("beacon") or parsed.get("new_admin")
    if not new_impl:
        return

    # Load the WatchedProxy to get old implementation
    wp = session.get(WatchedProxy, mc.watched_proxy_id)
    if not wp:
        return

    upgrade_event = ProxyUpgradeEvent(
        watched_proxy_id=wp.id,
        block_number=parsed["block_number"],
        tx_hash=parsed.get("tx_hash", ""),
        old_implementation=wp.last_known_implementation,
        new_implementation=new_impl,
        event_type=parsed["event_type"],
    )
    session.add(upgrade_event)

    wp.last_known_implementation = new_impl
    if parsed["block_number"] > wp.last_scanned_block:
        wp.last_scanned_block = parsed["block_number"]


def _extract_new_owner(parsed: dict) -> object:
    return parsed.get("new_owner")


def _extract_new_authority(parsed: dict) -> object:
    return parsed.get("new_authority")


def _extract_paused_bool(parsed: dict) -> object:
    # paused/unpaused share writes=["paused"]; the event_type discriminates
    # the new state. The arg on the wire is the account that flipped the
    # flag, not the flag value — so we ignore parsed["account"] and read
    # the semantic from event_type.
    et = parsed.get("event_type")
    if et == "paused":
        return True
    if et == "unpaused":
        return False
    return None


def _extract_threshold(parsed: dict) -> object:
    # GnosisSafe ChangedThreshold(uint256 threshold) decodes to ``threshold``.
    # Tracked Safe-shaped ABIs may use new_threshold via semantic-key aliasing.
    val = parsed.get("threshold")
    if val is None:
        val = parsed.get("new_threshold")
    return val


def _extract_implementation(parsed: dict) -> object:
    return parsed.get("implementation")


def _extract_new_admin(parsed: dict) -> object:
    return parsed.get("new_admin")


def _extract_beacon(parsed: dict) -> object:
    return parsed.get("beacon")


def _extract_new_delay(parsed: dict) -> object:
    return parsed.get("new_delay")


def _extract_initialized_version(parsed: dict) -> object:
    # OZ Initializable Initialized(uint64 version). Canonical ABI names
    # the arg ``version``; some forks use ``initVersion``. Either way the
    # value goes into last_known_state so reanalysis can compare against
    # the next observation.
    version = parsed.get("version")
    if version is None:
        version = parsed.get("initVersion")
    return version


_StateExtractor = Callable[[dict], object]

# Per-write-target dispatch for ``_update_state_from_event``. Maps a tag
# write target → (state_key, extractor). The state_key may differ from
# the write target (``_initialized`` writes to ``initialized_version``);
# the extractor pulls the right value out of the decoded event. Targets
# absent here fall through to the generic name-match reflection so
# custom slots (e.g. ``protocolAdmin``) work without per-slot code.
_WRITE_TARGET_TO_STATE: dict[str, tuple[str, _StateExtractor]] = {
    "owner": ("owner", _extract_new_owner),
    "authority": ("authority", _extract_new_authority),
    "paused": ("paused", _extract_paused_bool),
    "threshold": ("threshold", _extract_threshold),
    "implementation": ("implementation", _extract_implementation),
    "admin": ("admin", _extract_new_admin),
    "beacon": ("beacon", _extract_beacon),
    "min_delay": ("min_delay", _extract_new_delay),
    "_initialized": ("initialized_version", _extract_initialized_version),
}


def _resolve_value_for_write_target(parsed: dict, write_target: str) -> object | None:
    """Pull the new value an event reports for *write_target* using the
    most specific signal available, falling back to ABI conventions
    when the analyzer's tag is the only structural pin.

    Resolution order:

      1. **Bare-name match** — ``parsed[write_target]`` works for
         single-arg events whose only arg is the new value
         (DSAuth ``LogSetOwner(address indexed owner)`` with
         write_target ``owner``).
      2. **OZ ``new<Cap>`` convention** — ``parsed[f"new{Cap}"]`` covers
         the OZ family (``newOwner``, ``newAdmin``, ``newImplementation``).
      3. **Tag-pinned ``new*`` arg from the ABI inputs spec** — when the
         analyzer attached ``_inputs`` (per-contract tracked events via
         ``parse_tracked_log``), find any input whose name starts with
         "new" (case-insensitive) and return its value. Catches
         Compound-shape ``NewAdmin(address newAdmin)`` /
         ``ProtocolAdminChanged(previousAdmin, newAdmin)`` for a
         write_target like ``protocolAdmin`` where neither the bare
         name nor the OZ ``new<Cap>`` convention applies.
      4. **Positional last-arg fallback** — for single-write events the
         "new value" is conventionally the last arg even when no naming
         convention applies (Solady, custom ABIs that just name the
         arg ``account`` or ``to``). Only fires when ``_inputs`` is
         present and (3) didn't match.

    Underscore-prefixed write_targets (``_roles``, ``_timelock_op``,
    ``_safe_op``, ``_safe_module_op``) are synthetic activity markers
    not real slots; they short-circuit to ``None`` so the fallback
    doesn't false-positive on the third-arg ``sender`` of a RoleGranted
    event (which has no canonical extractor and would otherwise hit
    pass (4) and overwrite ``state["_roles"]`` with a sender address).
    """
    if write_target.startswith("_"):
        return None

    candidate = parsed.get(write_target)
    if candidate is not None:
        return candidate

    cap = write_target[:1].upper() + write_target[1:]
    candidate = parsed.get(f"new{cap}")
    if candidate is not None:
        return candidate

    inputs = parsed.get("_inputs")
    if not isinstance(inputs, list) or not inputs:
        return None

    # Pass 3: any input whose name starts with "new" (case-insensitive).
    # First match wins; the analyzer's tag tells us there's a single
    # write target here, so the convention "the new value of THAT slot
    # is named new<something>" is reliable.
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = inp.get("name") or ""
        if name.lower().startswith("new") and name in parsed:
            return parsed[name]

    # Pass 4: positional last-arg. The analyzer's tag pins this event
    # as writing exactly one slot, so the last arg is the conventional
    # location of the new value across every governance ABI we've seen
    # (Solady, custom). Skipped when (3) matched.
    last = inputs[-1]
    if isinstance(last, dict):
        name = last.get("name") or ""
        if name and name in parsed:
            return parsed[name]
    return None


def _update_state_from_event(mc: MonitoredContract, parsed: dict) -> None:
    """Reflect the event's mutations into ``last_known_state``.

    Tag-driven: each ``effect_tags.writes`` target either resolves to a
    canonical (state_key, extractor) in ``_WRITE_TARGET_TO_STATE`` or
    falls back to generic name-match reflection so custom slots like
    ``protocolAdmin`` flow through without per-slot code.

    Legacy events without ``effect_tags`` synthesize them from event_type
    via ``_HANDROLLED_EVENT_TYPE_TO_TAGS`` — covers monitoring_config
    rows persisted before tag synthesis landed.
    """
    event_type = parsed["event_type"]
    # A qualified member change proves one ENTRY moved. The reflection below
    # resolves a single "new value" per write target and would store this
    # entry's key or value as the whole mapping's — a value the mapping does
    # not have and nothing observed.
    if is_member_changed_event_type(event_type):
        return

    state = dict(mc.last_known_state or {})
    tags = parsed.get("effect_tags") or _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type) or {}
    writes = tags.get("writes") or []

    for write_target in writes:
        if not isinstance(write_target, str):
            continue
        mapping = _WRITE_TARGET_TO_STATE.get(write_target)
        if mapping is not None:
            state_key, extractor = mapping
            value = extractor(parsed)
            if value is not None:
                state[state_key] = value
            continue
        # Generic resolution for custom slots — uses bare-name match,
        # OZ ``new<Cap>`` convention, ABI-pinned ``new*`` arg, and last-
        # arg positional fallback. Unlike the canonical branch we DO
        # overwrite an existing state entry — this path is the only one
        # that updates custom slots, so a subsequent observation must
        # take precedence.
        candidate = _resolve_value_for_write_target(parsed, write_target)
        if candidate is not None:
            state[write_target] = candidate

    mc.last_known_state = state
    flag_modified(mc, "last_known_state")


def _new_value_for_write_target(write_target: str, parsed: dict) -> object | None:
    """Pull the new value for *write_target* out of a parsed event.

    Tries the canonical extractor in ``_WRITE_TARGET_TO_STATE`` first,
    then defers to ``_resolve_value_for_write_target`` for custom slots
    so the event-side relational sync and the state-update sync share
    one resolution chain.
    """
    mapping = _WRITE_TARGET_TO_STATE.get(write_target)
    if mapping is not None:
        _, extractor = mapping
        return extractor(parsed)
    return _resolve_value_for_write_target(parsed, write_target)
