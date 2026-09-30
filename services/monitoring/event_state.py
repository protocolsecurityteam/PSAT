"""Event to monitoring-state dispatch: watch filters, per-write-target state extractors, new-value resolution."""

from __future__ import annotations

from typing import Callable

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from db.models import MonitoredContract, ProxyUpgradeEvent, WatchedProxy
from services.monitoring.event_topics import (
    _HANDROLLED_EVENT_TYPE_TO_TAGS,
    is_member_changed_event_type,
)

# Write target -> monitoring_config flags gating it. ``admin`` writes gate on both upgrades (EIP-1967 admin is the
# upgrader) and ownership (Compound/Aave/Curve admin is the owner).
_WRITE_TARGET_TO_CONFIG_KEYS: dict[str, tuple[str, ...]] = {
    "owner": ("watch_ownership",),
    "_owner": ("watch_ownership",),
    "pendingOwner": ("watch_ownership",),
    "_pendingOwner": ("watch_ownership",),
    "admin": ("watch_upgrades", "watch_ownership"),
    "_admin": ("watch_upgrades", "watch_ownership"),
    "pendingAdmin": ("watch_upgrades", "watch_ownership"),
    "future_admin": ("watch_upgrades", "watch_ownership"),
    "implementation": ("watch_upgrades",),
    "beacon": ("watch_upgrades",),
    "facets": ("watch_upgrades",),
    "pendingImplementation": ("watch_upgrades",),
    "_initialized": ("watch_upgrades",),
    "_initializing": ("watch_upgrades",),
    "authority": ("watch_authority",),
    "paused": ("watch_pause",),
    "_roles": ("watch_roles",),
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
    """Whether the monitoring config allows this event: any flag gated by its ``effect_tags`` is enabled (flags default
    on).
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

    # Legacy alias ``watch_signers`` still honored on rows written before the rename.
    if config_keys == {"watch_safe_signers"}:
        if config.get("watch_safe_signers") or config.get("watch_signers"):
            return True
        if "watch_safe_signers" in config or "watch_signers" in config:
            return False

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
    # paused/unpaused share writes=["paused"]; the wire arg is the account, so the state comes from event_type.
    et = parsed.get("event_type")
    if et == "paused":
        return True
    if et == "unpaused":
        return False
    return None


def _extract_threshold(parsed: dict) -> object:
    # Safe ABIs decode ``threshold``; tracked Safe-shaped ABIs may alias to ``new_threshold``.
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
    # OZ ``Initialized(uint64 version)``; some forks name it ``initVersion``.
    version = parsed.get("version")
    if version is None:
        version = parsed.get("initVersion")
    return version


_StateExtractor = Callable[[dict], object]

# Write target -> (state_key, extractor). Unlisted targets fall back to generic name-match so custom slots need no code.
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
    """The new value an event reports for *write_target*, most specific signal first:

    1. bare name (``parsed[write_target]``);
    2. OZ ``new<Cap>``;
    3. any ABI input named ``new*`` (Compound ``NewAdmin(newAdmin)`` for ``protocolAdmin``);
    4. the last input (Solady and custom ABIs).

    Underscore targets (``_roles``, ``_safe_op``...) are activity markers, not slots, and return ``None``; otherwise
    pass 4 would store a RoleGranted ``sender`` as the role state.
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

    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = inp.get("name") or ""
        if name.lower().startswith("new") and name in parsed:
            return parsed[name]

    # The tag pins a single written slot, so the last arg is the conventional new value.
    last = inputs[-1]
    if isinstance(last, dict):
        name = last.get("name") or ""
        if name and name in parsed:
            return parsed[name]
    return None


def _update_state_from_event(mc: MonitoredContract, parsed: dict) -> None:
    """Reflect the event's writes into ``last_known_state``.

    Canonical extractors first, generic name-match for custom slots. Untagged legacy events synthesize tags from
    event_type.
    """
    event_type = parsed["event_type"]
    # A member change moves one entry; the single-value reflection below would store that entry as the whole mapping's
    # value.
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
        # Unlike the canonical branch this overwrites: it is the only path that updates custom slots.
        candidate = _resolve_value_for_write_target(parsed, write_target)
        if candidate is not None:
            state[write_target] = candidate

    mc.last_known_state = state
    flag_modified(mc, "last_known_state")


def _new_value_for_write_target(write_target: str, parsed: dict) -> object | None:
    """Canonical extractor first, then the custom-slot chain, so event sync and state sync resolve alike."""
    mapping = _WRITE_TARGET_TO_STATE.get(write_target)
    if mapping is not None:
        _, extractor = mapping
        return extractor(parsed)
    return _resolve_value_for_write_target(parsed, write_target)
