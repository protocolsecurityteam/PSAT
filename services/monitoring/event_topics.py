"""Unified event topic constants and parsers for governance + proxy events."""

from __future__ import annotations

from eth_utils.crypto import keccak

from services.discovery.upgrade_history import (
    EVENT_TOPICS as PROXY_EVENT_TOPICS,
)
from services.discovery.upgrade_history import (
    _data_to_addresses,
    _hex_to_int,
    _topic_to_address,
    parse_upgrade_log,
)

# ---------------------------------------------------------------------------
# Governance event topic0 hashes
# ---------------------------------------------------------------------------

# OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
OWNERSHIP_TRANSFERRED_TOPIC0 = "0x" + keccak(text="OwnershipTransferred(address,address)").hex()

# Paused(address account)
PAUSED_TOPIC0 = "0x" + keccak(text="Paused(address)").hex()

# Unpaused(address account)
UNPAUSED_TOPIC0 = "0x" + keccak(text="Unpaused(address)").hex()

# RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)
ROLE_GRANTED_TOPIC0 = "0x" + keccak(text="RoleGranted(bytes32,address,address)").hex()

# RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)
ROLE_REVOKED_TOPIC0 = "0x" + keccak(text="RoleRevoked(bytes32,address,address)").hex()

# GnosisSafe AddedOwner(address owner)
ADDED_OWNER_TOPIC0 = "0x" + keccak(text="AddedOwner(address)").hex()

# GnosisSafe RemovedOwner(address owner)
REMOVED_OWNER_TOPIC0 = "0x" + keccak(text="RemovedOwner(address)").hex()

# GnosisSafe ChangedThreshold(uint256 threshold)
CHANGED_THRESHOLD_TOPIC0 = "0x" + keccak(text="ChangedThreshold(uint256)").hex()

# OZ TimelockController CallScheduled — exact v5 signature (7 params)
CALL_SCHEDULED_TOPIC0 = "0x" + keccak(text="CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)").hex()

# OZ TimelockController CallExecuted — exact v5 signature (5 params)
CALL_EXECUTED_TOPIC0 = "0x" + keccak(text="CallExecuted(bytes32,uint256,address,uint256,bytes)").hex()

# MinDelayChange(uint256 oldDuration, uint256 newDuration)
MIN_DELAY_CHANGE_TOPIC0 = "0x" + keccak(text="MinDelayChange(uint256,uint256)").hex()

# GnosisSafe ExecutionSuccess(bytes32 txHash, uint256 payment) —
# emitted when a Safe tx executes successfully on-chain.
EXECUTION_SUCCESS_TOPIC0 = "0x" + keccak(text="ExecutionSuccess(bytes32,uint256)").hex()

# GnosisSafe ExecutionFailure(bytes32 txHash, uint256 payment) —
# emitted when a Safe tx execution reverts (the wrapper still records).
EXECUTION_FAILURE_TOPIC0 = "0x" + keccak(text="ExecutionFailure(bytes32,uint256)").hex()

# GnosisSafe module-triggered execution (no signer threshold needed —
# the module is pre-authorized via enableModule). The module address is
# indexed in topics[1]. There's no SafeTx hash on these events because
# the call doesn't go through the SafeTx wrapping path.
EXECUTION_FROM_MODULE_SUCCESS_TOPIC0 = "0x" + keccak(text="ExecutionFromModuleSuccess(address)").hex()
EXECUTION_FROM_MODULE_FAILURE_TOPIC0 = "0x" + keccak(text="ExecutionFromModuleFailure(address)").hex()

# ---------------------------------------------------------------------------
# Topic -> event_type mapping
# ---------------------------------------------------------------------------

GOVERNANCE_EVENT_TOPICS: dict[str, str] = {
    OWNERSHIP_TRANSFERRED_TOPIC0: "ownership_transferred",
    PAUSED_TOPIC0: "paused",
    UNPAUSED_TOPIC0: "unpaused",
    ROLE_GRANTED_TOPIC0: "role_granted",
    ROLE_REVOKED_TOPIC0: "role_revoked",
    ADDED_OWNER_TOPIC0: "signer_added",
    REMOVED_OWNER_TOPIC0: "signer_removed",
    CHANGED_THRESHOLD_TOPIC0: "threshold_changed",
    CALL_SCHEDULED_TOPIC0: "timelock_scheduled",
    CALL_EXECUTED_TOPIC0: "timelock_executed",
    MIN_DELAY_CHANGE_TOPIC0: "delay_changed",
    EXECUTION_SUCCESS_TOPIC0: "safe_tx_executed",
    EXECUTION_FAILURE_TOPIC0: "safe_tx_failed",
    EXECUTION_FROM_MODULE_SUCCESS_TOPIC0: "safe_module_executed",
    EXECUTION_FROM_MODULE_FAILURE_TOPIC0: "safe_module_failed",
}

ALL_EVENT_TOPICS: dict[str, str] = {**PROXY_EVENT_TOPICS, **GOVERNANCE_EVENT_TOPICS}

# ---------------------------------------------------------------------------
# Synthetic effect_tags for hand-rolled events
# ---------------------------------------------------------------------------

# Synthesizes ``effect_tags`` from a canonical event_type. Two consumers:
#
#   1. ``parse_governance_log`` / ``parse_any_log`` attach tags to every
#      hand-rolled event so downstream sees the same shape ``parse_tracked_log``
#      produces from the static analysis tracking_plan.
#   2. ``_update_state_from_event`` / ``_should_watch`` /
#      ``_sync_relational_tables`` / ``should_trigger_reanalysis`` fall
#      back to this map when ``parsed["effect_tags"]`` is missing —
#      catches legacy monitoring_config specs persisted before tags
#      landed in the spec shape, and bare-event_type callers.
#
# Tag-driven dispatch unifies hand-rolled and per-contract event handling
# under one shape; the previous parallel event_type → config_keys maps
# in unified_watcher and reanalysis collapse into a single source of
# truth.
#
# Conventions:
#   - Real state-variable names ("owner", "admin", "implementation",
#     "paused", "owners", "threshold", "min_delay", "beacon", "facets")
#     match what the static analyzer emits for those slots.
#   - Underscore-prefixed names are synthetic markers for events that
#     don't mutate a single named slot — used so the watcher's config
#     gating still has something to key off:
#       ``_roles``        — RoleGranted / RoleRevoked (AccessControl
#                            doesn't expose a single state-var name)
#       ``_timelock_op``  — CallScheduled / CallExecuted (activity,
#                            no persistent state change)
#       ``_safe_op``      — ExecutionSuccess / ExecutionFailure (Safe
#                            tx wrapper activity)
#       ``_safe_module_op`` — ExecutionFromModule[Success|Failure]
#                            (Safe module call activity)
#   - ``delegates: True`` marks events that signal a delegate-target swap.
#     Set on every proxy-impl event (Upgraded, NewImplementation,
#     BeaconUpgraded, DiamondCut, etc.) so the upgrade-triggered paths
#     (reanalysis, coverage refresh, UpgradeEvent insert) fire uniformly.
_HANDROLLED_EVENT_TYPE_TO_TAGS: dict[str, dict] = {
    # Proxy / upgrade events — see services/discovery/upgrade_history.py
    "upgraded": {"writes": ["implementation"], "delegates": True},
    "admin_changed": {"writes": ["admin"]},
    "beacon_upgraded": {"writes": ["beacon"], "delegates": True},
    "changed_master_copy": {"writes": ["implementation"], "delegates": True},
    "new_implementation": {"writes": ["implementation"], "delegates": True},
    "new_pending_implementation": {"writes": ["pendingImplementation"]},
    "target_updated": {"writes": ["implementation"], "delegates": True},
    "upgraded_revision": {"writes": ["implementation"], "delegates": True},
    "diamond_cut": {"writes": ["facets"], "delegates": True},
    # Governance events
    "ownership_transferred": {"writes": ["owner"]},
    "paused": {"writes": ["paused"]},
    "unpaused": {"writes": ["paused"]},
    "role_granted": {"writes": ["_roles"]},
    "role_revoked": {"writes": ["_roles"]},
    "signer_added": {"writes": ["owners"]},
    "signer_removed": {"writes": ["owners"]},
    "threshold_changed": {"writes": ["threshold"]},
    "timelock_scheduled": {"writes": ["_timelock_op"]},
    "timelock_executed": {"writes": ["_timelock_op"]},
    "delay_changed": {"writes": ["min_delay"]},
    "safe_tx_executed": {"writes": ["_safe_op"]},
    "safe_tx_failed": {"writes": ["_safe_op"]},
    "safe_module_executed": {"writes": ["_safe_module_op"]},
    "safe_module_failed": {"writes": ["_safe_module_op"]},
    # Per-contract canonical types from ``parse_tracked_log``. Events
    # produced through that path already carry tags from the spec; the
    # entries here are the synthesis fallback for callers that pass only
    # an event_type (legacy specs without tags, bare reanalysis checks).
    "ownership_transfer_started": {"writes": ["pendingOwner"]},
    "authority_updated": {"writes": ["authority"]},
    "initialized": {"writes": ["_initialized"], "is_initializer": True},
    "signer_updated": {"writes": ["owners"]},
}


def _attach_effect_tags(event: dict | None) -> dict | None:
    """If *event* carries a canonical hand-rolled event_type, attach the
    matching ``effect_tags`` (in place) so the watcher's tag-driven
    dispatch sees the same shape it gets from ``parse_tracked_log``.

    No-op when event_type isn't in the synthesis map — e.g. an unknown
    or per-contract event with tags already in its spec.
    """
    if not event:
        return event
    event_type = event.get("event_type")
    if not isinstance(event_type, str):
        return event
    tags = _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type)
    if tags is None:
        return event
    # Copy so the module-level dict is never mutated by callers.
    event["effect_tags"] = {k: (list(v) if isinstance(v, list) else v) for k, v in tags.items()}
    return event


# ---------------------------------------------------------------------------
# Governance log parser
# ---------------------------------------------------------------------------


def parse_governance_log(log: dict) -> dict | None:
    """Parse a governance event log entry.

    Returns a dict with event_type, block_number, tx_hash, and parsed fields,
    or None if the log is not a recognised governance event.
    """
    topics = log.get("topics", [])
    if not topics:
        return None

    topic0 = topics[0].lower()
    event_type = GOVERNANCE_EVENT_TOPICS.get(topic0)
    if not event_type:
        return None

    event: dict = {
        "event_type": event_type,
        "block_number": _hex_to_int(log.get("blockNumber", "0x0")),
        "tx_hash": log.get("transactionHash"),
        # log_index disambiguates multiple events in the same tx (e.g.
        # OZ TimelockController ``scheduleBatch`` / ``executeBatch`` emit
        # one CallScheduled / CallExecuted per call in the batch). Drives
        # the dedupe key in unified_watcher so batch ops aren't collapsed.
        "log_index": _hex_to_int(log.get("logIndex", "0x0")),
    }

    data = log.get("data", "0x")

    if event_type == "ownership_transferred":
        # topics[1] = old owner, topics[2] = new owner (both indexed)
        if len(topics) >= 3:
            event["old_owner"] = _topic_to_address(topics[1])
            event["new_owner"] = _topic_to_address(topics[2])

    elif event_type == "paused":
        # data = address account (non-indexed)
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["account"] = addrs[0]

    elif event_type == "unpaused":
        # data = address account (non-indexed)
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["account"] = addrs[0]

    elif event_type == "role_granted":
        # topics[1] = role (bytes32), topics[2] = account, topics[3] = sender
        if len(topics) >= 4:
            event["role"] = topics[1]
            event["account"] = _topic_to_address(topics[2])
            event["sender"] = _topic_to_address(topics[3])

    elif event_type == "role_revoked":
        # topics[1] = role (bytes32), topics[2] = account, topics[3] = sender
        if len(topics) >= 4:
            event["role"] = topics[1]
            event["account"] = _topic_to_address(topics[2])
            event["sender"] = _topic_to_address(topics[3])

    elif event_type == "signer_added":
        # data = address owner (non-indexed)
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["owner"] = addrs[0]

    elif event_type == "signer_removed":
        # data = address owner (non-indexed)
        if data and data != "0x" and len(data.replace("0x", "")) >= 40:
            addrs = _data_to_addresses(data, 1)
            event["owner"] = addrs[0]

    elif event_type == "threshold_changed":
        # data = uint256 threshold (non-indexed)
        if data and data != "0x":
            event["threshold"] = _hex_to_int(data)

    elif event_type == "timelock_scheduled":
        # topics[1] = id (bytes32), topics[2] = index (uint256)
        # data = (address target, uint256 value, bytes data, bytes32 predecessor, uint256 delay)
        # ABI layout: 5 head words (32B each) then dynamic bytes at the
        # offset stored in word 3. We read the static fields (target,
        # value, predecessor, delay) and the calldata's first 4-byte
        # selector — enough to render "setX on AuctionManager (delay 3d)"
        # without having to fully decode the call args, which would
        # require the target's ABI.
        if len(topics) >= 3:
            event["operation_id"] = topics[1]
            event["index"] = _hex_to_int(topics[2])
            raw = (data or "").replace("0x", "")
            if len(raw) >= 5 * 64:
                event["target"] = "0x" + raw[24:64]  # right-most 20 bytes of word 0
                event["value"] = int(raw[64:128], 16)
                # word 2: offset to the bytes data (relative to start of data region)
                bytes_offset = int(raw[128:192], 16) * 2  # bytes → hex chars
                event["predecessor"] = "0x" + raw[192:256]
                event["delay"] = int(raw[256:320], 16)
                # Selector + calldata length, when present
                if bytes_offset and bytes_offset + 64 <= len(raw):
                    cd_len = int(raw[bytes_offset : bytes_offset + 64], 16)
                    event["calldata_length"] = cd_len
                    if cd_len >= 4 and bytes_offset + 64 + 8 <= len(raw):
                        event["selector"] = "0x" + raw[bytes_offset + 64 : bytes_offset + 64 + 8]

    elif event_type == "timelock_executed":
        # topics[1] = id (bytes32), topics[2] = index (uint256)
        # data = (address target, uint256 value, bytes data)
        # ABI layout: 3 head words (32B each), bytes follows at the
        # offset stored in word 2. Decode the same static fields as
        # CallScheduled minus predecessor/delay (those aren't emitted
        # on execution).
        if len(topics) >= 3:
            event["operation_id"] = topics[1]
            event["index"] = _hex_to_int(topics[2])
            raw = (data or "").replace("0x", "")
            if len(raw) >= 3 * 64:
                event["target"] = "0x" + raw[24:64]
                event["value"] = int(raw[64:128], 16)
                bytes_offset = int(raw[128:192], 16) * 2
                if bytes_offset and bytes_offset + 64 <= len(raw):
                    cd_len = int(raw[bytes_offset : bytes_offset + 64], 16)
                    event["calldata_length"] = cd_len
                    if cd_len >= 4 and bytes_offset + 64 + 8 <= len(raw):
                        event["selector"] = "0x" + raw[bytes_offset + 64 : bytes_offset + 64 + 8]

    elif event_type == "delay_changed":
        # data = (uint256 oldDuration, uint256 newDuration) — both non-indexed
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            raw = data.replace("0x", "").zfill(128)
            event["old_delay"] = int(raw[:64], 16)
            event["new_delay"] = int(raw[64:128], 16)

    elif event_type in ("safe_tx_executed", "safe_tx_failed"):
        # data = (bytes32 txHash, uint256 payment) — both non-indexed.
        # txHash here is the Safe-internal transaction hash (the EIP-712
        # hash of the SafeTx, not the on-chain tx_hash) — useful as a
        # stable id to correlate execution against the Safe Transaction
        # Service's pending queue if we ever integrate that.
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            raw = data.replace("0x", "")
            event["safe_tx_hash"] = "0x" + raw[:64]
            event["payment"] = int(raw[64:128], 16)

    elif event_type in ("safe_module_executed", "safe_module_failed"):
        # ExecutionFromModule[Success|Failure](address indexed module).
        # No SafeTx hash + no payment — the call bypasses the SafeTx
        # wrapping path because the module is pre-authorised. Just the
        # module address in topics[1].
        if len(topics) >= 2 and topics[1]:
            event["module"] = _topic_to_address(topics[1])

    _attach_effect_tags(event)
    return event


def parse_any_log(log: dict) -> dict | None:
    """Try to parse a log as a proxy upgrade event first, then governance.

    Returns the parsed event dict or None.
    """
    result = parse_upgrade_log(log)
    if result is not None:
        # ``parse_upgrade_log`` lives in services/discovery/upgrade_history.py
        # — importing the tag synthesizer there would create a circular
        # import. Attach tags here at the consolidated entry point so the
        # watcher always sees tagged events regardless of which decoder
        # produced them.
        return _attach_effect_tags(result)
    return parse_governance_log(log)


# ---------------------------------------------------------------------------
# Per-contract topic extraction from the analysis tracking_plan
# ---------------------------------------------------------------------------

# Map canonical event_type → ``(old_key, new_key)`` semantic-key pair.
# Drives the name-aware arg fill in ``_assign_semantic_keys`` so that
# downstream state/relational sync can read ``parsed["new_owner"]``
# regardless of whether the ABI named the input ``newOwner``,
# ``new_owner``, ``user``, or nothing at all.
_EVENT_TYPE_TO_SEMANTIC_KEYS: dict[str, tuple[str, str]] = {
    "ownership_transferred": ("old_owner", "new_owner"),
    "ownership_transfer_started": ("old_owner", "new_owner"),
    "authority_updated": ("old_authority", "new_authority"),
    "admin_changed": ("previous_admin", "new_admin"),
    "threshold_changed": ("old_threshold", "new_threshold"),
}


# Legacy controller_id → event_type map. Preserved only for monitoring_config
# rows persisted before effect_tags landed in the spec shape — once those rows
# get re-enrolled (every protocol re-analysis), this can be deleted.
_CONTROLLER_ID_TO_EVENT_TYPE: dict[str, str] = {
    "owner": "ownership_transferred",
    "_owner": "ownership_transferred",
    "state_variable:owner": "ownership_transferred",
    "state_variable:_owner": "ownership_transferred",
    "state_variable:pendingOwner": "ownership_transfer_started",
    "external_contract:authority": "authority_updated",
    "state_variable:authority": "authority_updated",
}


def _classify_from_writes(writes: list[str] | set[str] | None) -> str | None:
    """Derive a canonical event_type from the state vars an event's emitter
    writes. Returns None when no canonical type matches — caller falls
    back to controller_id or ``controller_changed:<id>``.

    Priority order resolves multi-write emitters:
      1. ``owner`` / ``_owner`` — commit-phase ownership transfer wins
         over the started-phase even when both are written (OZ
         Ownable2Step ``acceptOwnership``).
      2. ``pendingOwner`` — start-phase only when ``owner`` is untouched
         (OZ Ownable2Step ``transferOwnership``).
      3. ``authority`` — Solmate Auth / DSAuth registry swap.
      4. ``admin`` family — Compound, Aave, Curve admin slots.
      5. Initializer slots — OZ Initializable ``_initialized`` /
         ``_initializing``.
      6. Safe-shaped — ``owners`` array, ``threshold``.
    """
    if not writes:
        return None
    write_set = set(writes)
    # Explicit priority — owner wins over pendingOwner so Ownable2Step
    # commit phase classifies correctly when both are written.
    for canonical, candidates in (
        ("ownership_transferred", ("owner", "_owner")),
        ("ownership_transfer_started", ("pendingOwner", "_pendingOwner")),
        ("authority_updated", ("authority",)),
        ("admin_changed", ("admin", "_admin", "pendingAdmin", "future_admin")),
        ("initialized", ("_initialized", "_initializing")),
        ("signer_updated", ("owners",)),
        ("threshold_changed", ("threshold",)),
    ):
        if write_set & set(candidates):
            return canonical
    return None


def _classify_from_tags(effect_tags: dict | None) -> str | None:
    """Tag-driven event_type derivation. Tries writes first, then falls
    back to the is_initializer flag for cases where the slot isn't named
    ``_initialized`` (rare but possible in OZ forks)."""
    if not isinstance(effect_tags, dict):
        return None
    by_writes = _classify_from_writes(effect_tags.get("writes"))
    if by_writes:
        return by_writes
    if effect_tags.get("is_initializer"):
        return "initialized"
    if effect_tags.get("delegates"):
        # Bare delegatecall in the emitter body (not just storing an
        # impl slot) means the function pivots delegate execution
        # itself — proxy fallback patterns, custom upgrade choreography.
        return "upgraded"
    return None


def _assign_semantic_keys(
    event: dict,
    event_type: str,
    inputs: list[dict],
    args_in_order: list[object],
) -> None:
    """Fill ``old_*`` / ``new_*`` semantic-key aliases on *event*.

    Resolution order picks the right answer across every governance
    ABI we've seen:

      1. **Name-aware** — input names beginning ``new*`` claim the new
         slot; ``previous*`` / ``old*`` claim the old slot. Wins for
         OZ ``previousOwner`` / ``newOwner`` and Compound ``newAdmin``.
      2. **Positional remainder for 2-arg events** — if exactly one
         slot was filled by name, the *other* arg fills the other
         slot. This is the Solmate ``user`` / ``newOwner`` case:
         ``user`` doesn't name-match, but for a two-arg event whose
         second arg already claimed ``new``, the first arg is the
         old value. (Solmate's ``setOwner`` is gated by ``onlyOwner``
         so ``msg.sender == currentOwner`` at emission, making the
         ``user`` arg effectively the previous owner.)
      3. **Two anonymous args** — neither name matches, positional
         (old, new) by convention.
      4. **Single arg event** — convention is "this is the new value",
         no old recorded. DSAuth ``LogSetOwner(address indexed owner)``
         and Compound ``NewAdmin(address newAdmin)`` both fall here
         when name match misses.
    """
    keys = _EVENT_TYPE_TO_SEMANTIC_KEYS.get(event_type)
    if not keys:
        return
    old_key, new_key = keys

    new_idx: int | None = None
    old_idx: int | None = None
    for i, inp in enumerate(inputs):
        name = (inp.get("name") or "").lower()
        if name.startswith("new") and new_idx is None:
            new_idx = i
        elif (name.startswith("previous") or name.startswith("old")) and old_idx is None:
            old_idx = i

    n = len(args_in_order)
    if n == 2:
        if old_idx is None and new_idx is not None:
            old_idx = 1 - new_idx
        elif new_idx is None and old_idx is not None:
            new_idx = 1 - old_idx
        elif old_idx is None and new_idx is None:
            old_idx, new_idx = 0, 1
    elif n == 1 and new_idx is None:
        new_idx = 0

    if old_idx is not None and old_idx < n:
        event[old_key] = args_in_order[old_idx]
    if new_idx is not None and new_idx < n:
        event[new_key] = args_in_order[new_idx]


def _resolve_event_type(
    controller_id: str | None,
    effect_tags: dict | None = None,
) -> str:
    """Pick the canonical event_type for a tracked event.

    Resolution order:
      1. ``effect_tags`` — primary signal. The emitter's state writes are
         deterministic and ABI-independent, so e.g. Compound's
         ``NewAdmin`` and OZ's ``OwnershipTransferred`` classify
         correctly without per-ABI rules once their emitters are tagged.
      2. ``_CONTROLLER_ID_TO_EVENT_TYPE`` — back-compat path for legacy
         specs without effect_tags (older monitoring_config rows). Falls
         away once everything re-enrolls.
      3. ``controller_changed:<id>`` — terminal fallback. Persisted but
         not semantically classified.
    """
    by_tags = _classify_from_tags(effect_tags)
    if by_tags:
        return by_tags
    cid = (controller_id or "").strip()
    if not cid:
        return "controller_changed"
    if cid in _CONTROLLER_ID_TO_EVENT_TYPE:
        return _CONTROLLER_ID_TO_EVENT_TYPE[cid]
    return f"controller_changed:{cid}"


def extract_governance_topics(tracking_plan: dict | None) -> list[dict]:
    """Walk a ``ControlTrackingPlan`` and return per-contract topic specs.

    Each entry has shape ``{topic0, signature, event_type, controller_id,
    inputs, effect_tags}``. Topic0s already in ``ALL_EVENT_TOPICS`` are
    skipped so the hand-rolled decoders keep ownership of OZ / Safe /
    Timelock / proxy events. Returns ``[]`` when *tracking_plan* is None
    or has no events.

    ``effect_tags`` flows through from the static analysis pipeline
    (``services/static/contract_analysis_pipeline/tracking.py``). The
    watcher reads them to classify and route events without falling
    back on a hand-curated event-name list.
    """
    if not tracking_plan:
        return []
    seen: set[str] = set()
    out: list[dict] = []
    for tc in tracking_plan.get("tracked_controllers") or []:
        ew = tc.get("event_watch")
        if not ew:
            continue
        controller_id = tc.get("controller_id")
        for ev in ew.get("events") or []:
            topic0 = (ev.get("topic0") or "").lower()
            if not topic0 or not topic0.startswith("0x"):
                continue
            # Hand-rolled registry wins for OZ/Safe/Timelock/proxy events —
            # those decoders carry semantics (batch indexing, calldata
            # selectors, etc.) the generic path can't reproduce.
            if topic0 in ALL_EVENT_TOPICS:
                continue
            if topic0 in seen:
                continue
            seen.add(topic0)
            effect_tags = ev.get("effect_tags") if isinstance(ev.get("effect_tags"), dict) else None
            spec: dict = {
                "topic0": topic0,
                "signature": ev.get("signature"),
                "event_type": _resolve_event_type(controller_id, effect_tags),
                "controller_id": controller_id,
                "inputs": list(ev.get("inputs") or []),
            }
            if effect_tags:
                spec["effect_tags"] = effect_tags
            out.append(spec)
    return out


def parse_tracked_log(log: dict, spec: dict) -> dict | None:
    """Generic per-contract event decoder driven by an ABI input list.

    *spec* is one entry from ``extract_governance_topics``. Walks the
    inputs splitting indexed (topics[1:]) from non-indexed (data) and
    decodes each by type via ``eth_abi``. Outputs:

      - ``event_type``, ``block_number``, ``tx_hash``, ``log_index``
      - one key per input under its ABI name (``user``, ``newOwner``, …)
      - semantic-key aliases (``old_owner``/``new_owner``, ``old_authority``/
        ``new_authority``) when the event_type has a registered mapping, so
        existing state/relational sync paths keep working.

    Returns None when the log shape doesn't match the spec (wrong topic
    count, undecodable non-indexed data, etc.) — caller treats None the
    same as an unparseable hand-rolled log.
    """
    # Local import: eth_abi pulls in a chunk of typing/cython init on first
    # use; keeping it lazy avoids paying the cost when no contract has any
    # tracked_topics (the common case for pre-tracking-plan rows).
    from eth_abi.abi import decode as eth_abi_decode

    inputs = spec.get("inputs") or []
    topics = log.get("topics") or []
    data = log.get("data") or "0x"

    indexed_inputs = [i for i in inputs if i.get("indexed")]
    non_indexed_inputs = [i for i in inputs if not i.get("indexed")]

    # topics[0] is the event sig; indexed args live in topics[1:].
    if len(topics) < 1 + len(indexed_inputs):
        return None

    event: dict = {
        "event_type": spec.get("event_type", "controller_changed"),
        "block_number": _hex_to_int(log.get("blockNumber", "0x0")),
        "tx_hash": log.get("transactionHash"),
        "log_index": _hex_to_int(log.get("logIndex", "0x0")),
    }
    # Effect tags ride along on the parsed event so the watcher can
    # branch on them (state sync, relational sync, reanalysis trigger)
    # without re-deriving from event_type. Absent on hand-rolled
    # events (parse_governance_log path), present on every per-contract
    # event whose tracking_plan carries them.
    spec_tags = spec.get("effect_tags")
    if isinstance(spec_tags, dict) and spec_tags:
        event["effect_tags"] = spec_tags

    # Decode indexed args from topics.
    args_in_order: list[object] = []
    for i, spec_in in enumerate(indexed_inputs):
        topic = topics[1 + i]
        sol_type = (spec_in.get("type") or "").strip()
        decoded: object
        if sol_type in ("address", "address payable"):
            decoded = _topic_to_address(topic)
        elif sol_type.startswith("uint") or sol_type.startswith("int"):
            decoded = _hex_to_int(topic)
        elif sol_type.startswith("bytes") and sol_type != "bytes":
            decoded = topic  # fixed-size bytes ride as the raw 32-byte topic
        else:
            # Dynamic types (string, bytes, arrays) are stored as the
            # keccak of the value when indexed — we can't recover the
            # original, just preserve the hash.
            decoded = topic
        name = spec_in.get("name") or f"arg{i}"
        event[name] = decoded
        args_in_order.append(decoded)

    # Decode non-indexed args from data.
    if non_indexed_inputs:
        try:
            raw = bytes.fromhex((data or "0x").removeprefix("0x"))
            sol_types = [str(i.get("type") or "") for i in non_indexed_inputs]
            decoded_tuple = eth_abi_decode(sol_types, raw)
        except Exception:
            return None
        for i, spec_in in enumerate(non_indexed_inputs):
            val = decoded_tuple[i]
            # Normalize bytes → 0x-hex so JSONB-serializability is preserved.
            if isinstance(val, (bytes, bytearray)):
                val = "0x" + bytes(val).hex()
            name = spec_in.get("name") or f"arg{len(indexed_inputs) + i}"
            event[name] = val
            args_in_order.append(val)

    # Semantic-key aliases (``old_owner`` / ``new_owner``, etc.) keyed
    # off event_type. Name-aware fill so single-arg events
    # (``LogSetOwner(address indexed owner)``,
    # ``NewAdmin(address newAdmin)``) and two-arg variants with
    # non-standard ABI names (Solmate's ``user`` / ``newOwner``) all
    # surface the canonical sync keys.
    _assign_semantic_keys(event, event["event_type"], inputs, args_in_order)

    return event
