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

# Safe module enable/disable and guard swap. An enabled module can move the
# Safe's assets WITHOUT meeting the k/n signer threshold, so these are the
# events that decide whether k/n bounds protection at all; the pipeline could
# already see a module EXECUTE (above) but not one being ENABLED.
#
# Indexing differs by release and the topic0 does not: the ``address`` argument
# is indexed from 1.4.1 and non-indexed on 1.1.1/1.3.0, so the same topic0
# carries the module in ``topics[1]`` on some Safes and in the data word on
# others. A decoder that reads only topics silently returns nothing on a 1.3.0
# Safe — see the topics-or-data read in ``parse_governance_log``.
ENABLED_MODULE_TOPIC0 = "0x" + keccak(text="EnabledModule(address)").hex()
DISABLED_MODULE_TOPIC0 = "0x" + keccak(text="DisabledModule(address)").hex()
CHANGED_GUARD_TOPIC0 = "0x" + keccak(text="ChangedGuard(address)").hex()

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
    ENABLED_MODULE_TOPIC0: "safe_module_enabled",
    DISABLED_MODULE_TOPIC0: "safe_module_disabled",
    CHANGED_GUARD_TOPIC0: "safe_guard_changed",
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
#       ``_safe_modules``   — EnabledModule / DisabledModule (the module
#                            SET changed; the Safe exposes no named
#                            state var for the linked list)
#       ``_safe_guard``     — ChangedGuard (guard slot swap)
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
    "safe_module_enabled": {"writes": ["_safe_modules"]},
    "safe_module_disabled": {"writes": ["_safe_modules"]},
    "safe_guard_changed": {"writes": ["_safe_guard"]},
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
# Strict word decoding (Safe module/guard addresses)
# ---------------------------------------------------------------------------


def _strict_word(raw: object, index: int = 0) -> str | None:
    """Word *index* of a ``0x``-prefixed ABI body, lowercased, or ``None``.

    Strict for the same reason ``restaking_reads.decode_word`` is. ``"0x"`` is
    not a zero word, and the ``.replace("0x", "").zfill(64)`` shape used by the
    older decoders left-pads an empty topic into the zero address and strips a
    ``0x`` occurring anywhere in the body, leaving a short string that slices to
    a wrong address. ``bytes.fromhex`` rather than ``int(..., 16)`` because
    ``int`` accepts ``_`` separators and surrounding whitespace; it ignores
    ASCII whitespace itself, hence the explicit byte-length check after it.
    """
    if not isinstance(raw, str) or not raw.startswith("0x"):
        return None
    body = raw[2:]
    if not body or len(body) % 64 or len(body) < (index + 1) * 64:
        return None
    word = body[index * 64 : (index + 1) * 64]
    try:
        data = bytes.fromhex(word)
    except ValueError:
        return None
    if len(data) != 32:
        return None
    return word.lower()


def _strict_word_address(raw: object, index: int = 0) -> str | None:
    """The address held by word *index*, or ``None``.

    ``None`` when the word is malformed (see :func:`_strict_word`) or when its
    top 12 bytes are set — an ABI-encoded address is left-padded with zeros, so
    a word that is not is not an address and publishing its low 20 bytes would
    invent one. An event that does not decode publishes no address at all.
    """
    word = _strict_word(raw, index)
    if word is None or word[:24] != "0" * 24:
        return None
    return "0x" + word[24:]


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
        # module address in topics[1], published only when that topic is a
        # whole, well-formed word — an undecodable log names no module.
        module = _strict_word_address(topics[1]) if len(topics) >= 2 else None
        if module is not None:
            event["module"] = module

    elif event_type in ("safe_module_enabled", "safe_module_disabled", "safe_guard_changed"):
        # EnabledModule/DisabledModule/ChangedGuard(address). Indexed from Safe
        # 1.4.1, non-indexed on 1.1.1/1.3.0 — same topic0 either way. Read
        # topics[1] when the emitter indexed it, else the single data word;
        # topics-only would decode 1.3.0 as "no address" and 1.3.0 is 9 of the
        # 19 Safes on this corpus.
        #
        # Either source must decode as a whole word before anything is
        # published: an empty topic left-padded to width is the ZERO ADDRESS,
        # which on ``safe_guard_changed`` is the word for "guard removed" — a
        # protection-withdrawal fact minted from a log that carried no address.
        # A body that does not decode yields no key at all, not a zero.
        key = "guard" if event_type == "safe_guard_changed" else "module"
        if len(topics) >= 2 and topics[1]:
            decoded = _strict_word_address(topics[1])
        else:
            decoded = _strict_word_address(data)
        if decoded is not None:
            event[key] = decoded

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


# Per-canonical-family corroboration vocabulary. A canonical event_type is
# a semantic claim about what THIS event announces — so the event's own ABI
# must corroborate the family before the type may be minted. The emitter's
# write set alone is not that evidence: a multi-write emitter (an
# ``initialize()`` that seeds ``_owner``, ``_paused`` and four config slots)
# donates its whole slot set to every event it emits, so writes-only
# classification stamps ``ownership_transferred`` on ``Initialized(uint8)``
# and ``initialized`` on ``EEthSet(address)``.
#
# ``name`` hints are lowercase substrings of the event name; the arg-shape
# check requires the signature's parameter list to carry the family's
# payload type (the semantic-key fill for the address families reads an
# address arg — a family claim over a signature with no address arg would
# alias a non-address value into ``old_owner``/``new_owner``).
_CANONICAL_NAME_HINTS: dict[str, tuple[str, ...]] = {
    "ownership_transferred": ("owner",),
    "ownership_transfer_started": ("owner",),
    "authority_updated": ("auth",),
    # Curve/Vyper's 2-step admin transfer announces the ``future_admin`` /
    # ``admin`` write as CommitOwnership/ApplyOwnership — ownership
    # vocabulary corroborates the admin family too.
    "admin_changed": ("admin", "owner"),
    "initialized": ("initial",),
    "signer_updated": ("owner", "signer"),
    "threshold_changed": ("threshold",),
    "upgraded": ("upgrad", "implementation", "beacon"),
}

# Families whose parsed payload is an address (semantic keys / delegate
# target). ``initialized`` carries a version uint (or nothing) and
# ``threshold_changed`` a uint — no address required.
_CANONICAL_ADDRESS_ARG_FAMILIES = frozenset(
    {
        "ownership_transferred",
        "ownership_transfer_started",
        "authority_updated",
        "admin_changed",
        "signer_updated",
        "upgraded",
    }
)
_CANONICAL_UINT_ARG_FAMILIES = frozenset({"threshold_changed"})


def _event_corroborates(event_type: str, signature: str | None) -> bool:
    """True when the event's own signature corroborates the canonical
    family claim *event_type*: name hint present AND the parameter list
    carries the family's payload type.

    An absent/empty signature is the not-determined state — it cannot
    corroborate anything, so no canonical type is minted from it.
    """
    hints = _CANONICAL_NAME_HINTS.get(event_type)
    if hints is None:
        return False
    sig = signature or ""
    name, _, params = sig.partition("(")
    name = name.strip().lower()
    if not name:
        return False
    if not any(h in name for h in hints):
        return False
    params = params.lower()
    if event_type in _CANONICAL_ADDRESS_ARG_FAMILIES:
        return "address" in params
    if event_type in _CANONICAL_UINT_ARG_FAMILIES:
        return "int" in params  # matches uint*/int*
    return True


def _classify_from_writes(writes: list[str] | set[str] | None, signature: str | None = None) -> str | None:
    """Derive a canonical event_type from the state vars an event's emitter
    writes, corroborated by the event's own signature. Returns None when
    no corroborated canonical type matches — caller falls back to the
    terminal ``<stem>:<id>`` form (see :func:`_resolve_event_type`).

    A family is minted only when BOTH hold: the emitter writes one of the
    family's slots AND the event's own name/arg-shape corroborate the
    family (:func:`_event_corroborates`). The write set alone is donated
    by the emitter to every event it emits, so on its own it is not
    evidence of what this event announces.

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
    # commit phase classifies correctly when both are written. A family
    # the signature does not corroborate is skipped, so a multi-write
    # emitter's event lands on the family it actually announces
    # (``Initialized(uint8)`` from an owner-seeding initializer passes
    # over ``ownership_transferred`` and classifies ``initialized``).
    for canonical, candidates in (
        ("ownership_transferred", ("owner", "_owner")),
        ("ownership_transfer_started", ("pendingOwner", "_pendingOwner")),
        ("authority_updated", ("authority",)),
        ("admin_changed", ("admin", "_admin", "pendingAdmin", "future_admin")),
        ("initialized", ("_initialized", "_initializing")),
        ("signer_updated", ("owners",)),
        ("threshold_changed", ("threshold",)),
    ):
        if write_set & set(candidates) and _event_corroborates(canonical, signature):
            return canonical
    return None


def _classify_from_tags(effect_tags: dict | None, signature: str | None = None) -> str | None:
    """Tag-driven event_type derivation. Tries writes first, then falls
    back to the is_initializer flag for cases where the slot isn't named
    ``_initialized`` (rare but possible in OZ forks). Every canonical
    outcome requires the event's own signature to corroborate the family
    (:func:`_event_corroborates`)."""
    if not isinstance(effect_tags, dict):
        return None
    by_writes = _classify_from_writes(effect_tags.get("writes"), signature)
    if by_writes:
        return by_writes
    if effect_tags.get("is_initializer") and _event_corroborates("initialized", signature):
        return "initialized"
    if effect_tags.get("delegates") and _event_corroborates("upgraded", signature):
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


# The one ``authority_provenance`` value that PROVES a tracked write target
# is a controller: a lowered predicate leaf requires the caller to equal / be
# a member of it (schemas/contract_analysis.py ``ControllerProvenance``).
# ``call_target`` — "called, and no gate was proven" — is not that proof, and
# an absent key is the third state, not determined. Only the proven value may
# mint the ``controller_changed`` claim.
_PROVEN_CONTROLLER_PROVENANCE = "caller_gate"


def _resolve_event_type(
    controller_id: str | None,
    effect_tags: dict | None = None,
    *,
    authority_provenance: str | None = None,
    signature: str | None = None,
) -> str:
    """Pick the canonical event_type for a tracked event.

    Resolution order:
      1. ``effect_tags`` — primary signal, corroborated by *signature*.
         The emitter's state writes say which slots the surrounding
         function touches; the event's own name/arg-shape say what THIS
         event announces. A canonical family type is minted only when
         both agree (:func:`_classify_from_tags`) — a write set alone is
         donated by a multi-write emitter to every event it emits and is
         not evidence of the event's meaning.
      2. ``_CONTROLLER_ID_TO_EVENT_TYPE`` — back-compat path for legacy
         specs without effect_tags (older monitoring_config rows). Falls
         away once everything re-enrolls. Same corroboration bar: the
         controller_id names the tracked slot, not the event, so the
         canonical family it maps to must also be corroborated by the
         event's own signature.
      3. Terminal fallback — the event is recorded but not semantically
         classified, so the published type says only what is earned:

           * ``controller_changed:<id>`` when *authority_provenance*
             proves the write target gates callers. This is a positive
             claim that an authority binding moved.
           * ``state_changed:<id>`` for every other input — a proven
             ``call_target``, and a not-determined (absent) provenance
             alike. It claims only "this tracked slot was written",
             which is true whether or not the slot controls anything;
             it is not a claim that the slot is *not* a controller.

         Both non-proven inputs collapse onto the neutral form on
         purpose: the neutral form asserts nothing about control in
         either direction, so nothing downstream can read the
         not-determined state as a proven one. The discriminator itself
         stays in the tracking plan for anyone who needs the three
         states apart.
    """
    by_tags = _classify_from_tags(effect_tags, signature)
    if by_tags:
        return by_tags
    stem = "controller_changed" if authority_provenance == _PROVEN_CONTROLLER_PROVENANCE else "state_changed"
    cid = (controller_id or "").strip()
    if not cid:
        return stem
    legacy = _CONTROLLER_ID_TO_EVENT_TYPE.get(cid)
    if legacy is not None and _event_corroborates(legacy, signature):
        return legacy
    return f"{stem}:{cid}"


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
                # ``authority_provenance`` is absent on a plan whose target
                # never earned the gate proof — pass it through as-is so the
                # resolver sees the same three states the plan carries.
                "event_type": _resolve_event_type(
                    controller_id,
                    effect_tags,
                    authority_provenance=tc.get("authority_provenance"),
                    signature=ev.get("signature"),
                ),
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
        # A spec with no event_type was never classified at all, so the
        # neutral stem is the only earned answer here too.
        "event_type": spec.get("event_type") or "state_changed",
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
    # Attach the ABI input list (declaration order, not topic order) so
    # downstream write-target resolution can do positional / name-prefix
    # heuristics for non-OZ ABIs. Compound's ``NewAdmin(address newAdmin)``
    # and similar shapes need this to map a custom write_target like
    # ``protocolAdmin`` to the ``newAdmin`` arg.
    event["_inputs"] = list(inputs)

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
