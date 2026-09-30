"""Unified event topic constants and parsers for governance + proxy events."""

from __future__ import annotations

from eth_utils.crypto import keccak
from typing_extensions import TypeGuard

from schemas.contract_analysis import ControllerProvenance
from services.discovery.upgrade_history import (
    EVENT_TOPICS as PROXY_EVENT_TOPICS,
)
from services.discovery.upgrade_history import (
    _data_to_addresses,
    _hex_to_int,
    _topic_to_address,
    parse_upgrade_log,
)
from utils.scoring_status import (
    OPENNESS_NOT_DETERMINED,
    OPENNESS_RESTRICTED,
    OPENNESS_VALUES,
)

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

# OZ TimelockController CallScheduled, exact v5 signature (7 params)
CALL_SCHEDULED_TOPIC0 = "0x" + keccak(text="CallScheduled(bytes32,uint256,address,uint256,bytes,bytes32,uint256)").hex()

# OZ TimelockController CallExecuted, exact v5 signature (5 params)
CALL_EXECUTED_TOPIC0 = "0x" + keccak(text="CallExecuted(bytes32,uint256,address,uint256,bytes)").hex()

# MinDelayChange(uint256 oldDuration, uint256 newDuration)
MIN_DELAY_CHANGE_TOPIC0 = "0x" + keccak(text="MinDelayChange(uint256,uint256)").hex()

# GnosisSafe ExecutionSuccess(bytes32 txHash, uint256 payment)
EXECUTION_SUCCESS_TOPIC0 = "0x" + keccak(text="ExecutionSuccess(bytes32,uint256)").hex()

# GnosisSafe ExecutionFailure(bytes32 txHash, uint256 payment); the wrapper still records
EXECUTION_FAILURE_TOPIC0 = "0x" + keccak(text="ExecutionFailure(bytes32,uint256)").hex()

# Module executions skip the signer threshold; the module is in topics[1] and there is no SafeTx hash.
EXECUTION_FROM_MODULE_SUCCESS_TOPIC0 = "0x" + keccak(text="ExecutionFromModuleSuccess(address)").hex()
EXECUTION_FROM_MODULE_FAILURE_TOPIC0 = "0x" + keccak(text="ExecutionFromModuleFailure(address)").hex()

# Module enable/disable and guard swaps decide whether k/n bounds protection at all. The address is indexed from Safe
# 1.4.1 but in the data word on 1.1.1/1.3.0 with the same topic0, so decoding reads topics or data.
ENABLED_MODULE_TOPIC0 = "0x" + keccak(text="EnabledModule(address)").hex()
DISABLED_MODULE_TOPIC0 = "0x" + keccak(text="DisabledModule(address)").hex()
CHANGED_GUARD_TOPIC0 = "0x" + keccak(text="ChangedGuard(address)").hex()


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


# Synthesized ``effect_tags`` per canonical hand-rolled event_type, so hand-rolled events get the same shape
# ``parse_tracked_log`` produces, and untagged legacy specs or bare event_types still dispatch.
#
# Real slot names match the analyzer's. Underscore names are markers for events with no single named slot: ``_roles``
# (AccessControl), ``_timelock_op``, ``_safe_op``, ``_safe_module_op``, ``_safe_modules`` (module set) and
# ``_safe_guard``. ``delegates: True`` marks delegate-target swaps so every upgrade path fires uniformly.
_HANDROLLED_EVENT_TYPE_TO_TAGS: dict[str, dict] = {
    # Proxy / upgrade events (see services/discovery/upgrade_history.py)
    "upgraded": {"writes": ["implementation"], "delegates": True},
    "admin_changed": {"writes": ["admin"]},
    "beacon_upgraded": {"writes": ["beacon"], "delegates": True},
    "changed_master_copy": {"writes": ["implementation"], "delegates": True},
    "new_implementation": {"writes": ["implementation"], "delegates": True},
    "new_pending_implementation": {"writes": ["pendingImplementation"]},
    "target_updated": {"writes": ["implementation"], "delegates": True},
    "upgraded_revision": {"writes": ["implementation"], "delegates": True},
    "diamond_cut": {"writes": ["facets"], "delegates": True},
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
    # Per-contract types from ``parse_tracked_log`` already carry spec tags; these are the fallback for bare
    # event_types.
    "ownership_transfer_started": {"writes": ["pendingOwner"]},
    "authority_updated": {"writes": ["authority"]},
    "initialized": {"writes": ["_initialized"], "is_initializer": True},
    "signer_updated": {"writes": ["owners"]},
}


def _attach_effect_tags(event: dict | None) -> dict | None:
    """Attach synthesized ``effect_tags`` in place for a canonical hand-rolled event_type; no-op otherwise."""
    if not event:
        return event
    event_type = event.get("event_type")
    if not isinstance(event_type, str):
        return event
    tags = _HANDROLLED_EVENT_TYPE_TO_TAGS.get(event_type)
    if tags is None:
        return event
    # Copy so callers can't mutate the module dict.
    event["effect_tags"] = {k: (list(v) if isinstance(v, list) else v) for k, v in tags.items()}
    return event


def _strict_word(raw: object, index: int = 0) -> str | None:
    """Word *index* of a ``0x``-prefixed ABI body, lowercased, or ``None``.

    Strict like ``restaking_reads.decode_word``: ``"0x"`` is not a zero word, and ``replace("0x", "").zfill(64)`` turned
    empty topics into the zero address. ``bytes.fromhex`` plus a length check, since ``int(..., 16)`` accepts ``_`` and
    whitespace.
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
    """The address in word *index*, or ``None`` if malformed or its top 12 bytes are set (not an ABI address)."""
    word = _strict_word(raw, index)
    if word is None or word[:24] != "0" * 24:
        return None
    return "0x" + word[24:]


def parse_governance_log(log: dict) -> dict | None:
    """Parse a governance log into event_type, block_number, tx_hash and fields; ``None`` if unrecognised."""
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
        # Batch timelock ops emit one event per call in one tx; log_index keeps the watcher's dedupe from collapsing
        # them.
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
        # topics[1] = id, topics[2] = index; data = (target, value, bytes data, predecessor, delay). Read the static
        # words plus the calldata selector, enough to render "setX on AuctionManager (delay 3d)" without the target's
        # ABI.
        if len(topics) >= 3:
            event["operation_id"] = topics[1]
            event["index"] = _hex_to_int(topics[2])
            raw = (data or "").replace("0x", "")
            if len(raw) >= 5 * 64:
                event["target"] = "0x" + raw[24:64]  # right-most 20 bytes of word 0
                event["value"] = int(raw[64:128], 16)
                # word 2: offset to the bytes data
                bytes_offset = int(raw[128:192], 16) * 2  # bytes → hex chars
                event["predecessor"] = "0x" + raw[192:256]
                event["delay"] = int(raw[256:320], 16)
                if bytes_offset and bytes_offset + 64 <= len(raw):
                    cd_len = int(raw[bytes_offset : bytes_offset + 64], 16)
                    event["calldata_length"] = cd_len
                    if cd_len >= 4 and bytes_offset + 64 + 8 <= len(raw):
                        event["selector"] = "0x" + raw[bytes_offset + 64 : bytes_offset + 64 + 8]

    elif event_type == "timelock_executed":
        # topics[1] = id, topics[2] = index; data = (target, value, bytes data), same static fields minus
        # predecessor/delay.
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
        # data = (uint256 oldDuration, uint256 newDuration)
        if data and data != "0x" and len(data.replace("0x", "")) >= 128:
            raw = data.replace("0x", "").zfill(128)
            event["old_delay"] = int(raw[:64], 16)
            event["new_delay"] = int(raw[64:128], 16)

    elif event_type in ("safe_tx_executed", "safe_tx_failed"):
        # Execution[Success|Failure](bytes32 txHash, uint256 payment); txHash is the Safe's EIP-712 hash. Safe 1.4.1
        # indexes txHash (one-word body), 1.3.0 doesn't (two-word body), same topic0. Decode by the layout the log
        # proves; a body matching neither publishes nothing rather than minting ``payment: 0``.
        body = data[2:] if isinstance(data, str) and data.startswith("0x") else ""
        if len(topics) >= 2:
            hash_word = _strict_word(topics[1])
            if hash_word is not None:
                event["safe_tx_hash"] = "0x" + hash_word
            payment_word = _strict_word(data) if len(body) == 64 else None
            if payment_word is not None:
                event["payment"] = int(payment_word, 16)
        elif len(body) >= 128:
            raw = data.replace("0x", "")
            event["safe_tx_hash"] = "0x" + raw[:64]
            event["payment"] = int(raw[64:128], 16)

    elif event_type in ("safe_module_executed", "safe_module_failed"):
        # ExecutionFromModule[Success|Failure](address indexed module): only published from a well-formed topic.
        module = _strict_word_address(topics[1]) if len(topics) >= 2 else None
        if module is not None:
            event["module"] = module

    elif event_type in ("safe_module_enabled", "safe_module_disabled", "safe_guard_changed"):
        # Enabled/DisabledModule and ChangedGuard: topics[1] when indexed (1.4.1), else the data word (1.3.0, about half
        # our Safes). Must decode as a whole word: a padded empty topic is the zero address, which for a guard means
        # "guard removed".
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
    """Parse a log as a proxy upgrade event first, then governance; ``None`` if neither."""
    result = parse_upgrade_log(log)
    if result is not None:
        # Tags are attached here because ``upgrade_history`` can't import the synthesizer (cycle). Rebuilt as a plain
        # dict since the watcher adds keys.
        return _attach_effect_tags(dict(result))
    return parse_governance_log(log)


# event_type -> (old_key, new_key), so sync can read ``parsed["new_owner"]`` whatever the ABI named the argument.
_EVENT_TYPE_TO_SEMANTIC_KEYS: dict[str, tuple[str, str]] = {
    "ownership_transferred": ("old_owner", "new_owner"),
    "ownership_transfer_started": ("old_owner", "new_owner"),
    "authority_updated": ("old_authority", "new_authority"),
    "admin_changed": ("previous_admin", "new_admin"),
    "threshold_changed": ("old_threshold", "new_threshold"),
}


# Legacy controller_id -> event_type for configs predating effect_tags; deletable once everything re-enrolls.
_CONTROLLER_ID_TO_EVENT_TYPE: dict[str, str] = {
    "owner": "ownership_transferred",
    "_owner": "ownership_transferred",
    "state_variable:owner": "ownership_transferred",
    "state_variable:_owner": "ownership_transferred",
    "state_variable:pendingOwner": "ownership_transfer_started",
    "external_contract:authority": "authority_updated",
    "state_variable:authority": "authority_updated",
}


# Per-family corroboration: the event's own ABI must support the family before its canonical type is minted. The
# emitter's write set alone isn't evidence (an ``initialize()`` that seeds ``_owner`` would stamp
# ``ownership_transferred`` on ``Initialized(uint8)``). ``name`` hints are lowercase substrings; address families also
# need an address argument.
_CANONICAL_NAME_HINTS: dict[str, tuple[str, ...]] = {
    "ownership_transferred": ("owner",),
    "ownership_transfer_started": ("owner",),
    "authority_updated": ("auth",),
    # Curve/Vyper announce admin transfers as CommitOwnership/ApplyOwnership.
    "admin_changed": ("admin", "owner"),
    "initialized": ("initial",),
    "signer_updated": ("owner", "signer"),
    "threshold_changed": ("threshold",),
    "upgraded": ("upgrad", "implementation", "beacon"),
}

# Families whose payload is an address; ``initialized`` and ``threshold_changed`` carry uints.
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
    """True when the signature corroborates *event_type*: a name hint and the family's payload type.

    A missing signature corroborates nothing.
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
    """A canonical event_type from the emitter's writes, corroborated by the event's signature; ``None`` falls back
    to the terminal ``<stem>:<id>`` form.

    Priority for multi-write emitters: ``owner`` (Ownable2Step commit beats start), ``pendingOwner``, ``authority``, the
    admin family, initializer slots, then Safe-shaped ``owners``/``threshold``.
    """
    if not writes:
        return None
    write_set = set(writes)
    # Uncorroborated families are skipped, so ``Initialized(uint8)`` from an owner-seeding initializer lands on
    # ``initialized``.
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
    """Classify from writes, falling back to ``is_initializer`` for forks that don't name the slot ``_initialized``;
    always corroborated.
    """
    if not isinstance(effect_tags, dict):
        return None
    by_writes = _classify_from_writes(effect_tags.get("writes"), signature)
    if by_writes:
        return by_writes
    if effect_tags.get("is_initializer") and _event_corroborates("initialized", signature):
        return "initialized"
    if effect_tags.get("delegates") and _event_corroborates("upgraded", signature):
        # A bare delegatecall in the emitter means it pivots delegate execution itself.
        return "upgraded"
    return None


def _assign_semantic_keys(
    event: dict,
    event_type: str,
    inputs: list[dict],
    args_in_order: list[object],
) -> None:
    """Fill ``old_*``/``new_*`` semantic-key aliases on *event*.

    In order: names (``new*``, ``previous*``/``old*``); for two-arg events with one name match, the other arg takes the
    other slot (Solmate ``user``/``newOwner``, where ``user`` is the owner by the onlyOwner gate); two unnamed args are
    (old, new); a single arg is the new value.
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


# Only ``caller_gate`` proves a tracked write target is a controller; ``call_target`` or absence may not mint
# ``controller_changed``.
_PROVEN_CONTROLLER_PROVENANCE: ControllerProvenance = "caller_gate"


def _resolve_event_type(
    controller_id: str | None,
    effect_tags: dict | None = None,
    *,
    authority_provenance: str | None = None,
    signature: str | None = None,
) -> str:
    """Pick the canonical event_type for a tracked event.

    1. ``effect_tags`` corroborated by *signature* (:func:`_classify_from_tags`).
    2. ``_CONTROLLER_ID_TO_EVENT_TYPE`` for legacy untagged specs, same corroboration bar.
    3. Otherwise ``controller_changed:<id>`` when *authority_provenance* proves a caller gate, else the neutral
    ``state_changed:<id>`` (for both ``call_target`` and absent provenance), which claims only that the slot was
    written.
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


# What an occurrence may claim. ``self_describing``: the decoded args qualify as the change; publishes directly.
# ``hint``: the spec only exists via the write set, so an occurrence triggers a verification read whose diff is the
# witness. ``activity``: nothing can be read or qualified; publishes and notifies nothing.
WITNESS_TIER_SELF_DESCRIBING = "self_describing"
WITNESS_TIER_HINT = "hint"
WITNESS_TIER_ACTIVITY = "activity"
WITNESS_TIERS = frozenset({WITNESS_TIER_SELF_DESCRIBING, WITNESS_TIER_HINT, WITNESS_TIER_ACTIVITY})

# Emitting functions' openness (utils.scoring_status). Absent is a third state that can only demote a tier.

# varchar(100): an overflowing type is demoted, never truncated (a truncated id names a different slot).
MAX_EVENT_TYPE_LENGTH = 100

VALUE_CHANGED_STEM = "value_changed"
MEMBER_CHANGED_STEM = "member_changed"

# Signal classes shared by the classifier, salience and the polling planner.
SIGNAL_CLASS_CONFIG = "config"
SIGNAL_CLASS_METRIC = "metric"


def value_changed_event_type(controller_id: str | None) -> str:
    """Event type for a read-verified old→new diff on *controller_id*."""
    cid = (controller_id or "").strip()
    return f"{VALUE_CHANGED_STEM}:{cid}" if cid else VALUE_CHANGED_STEM


def member_changed_event_type(mapping_var: str | None) -> str:
    """Event type for a member change on *mapping_var*; key, value and direction ride in ``data`` so each entry
    doesn't become its own type.
    """
    var = (mapping_var or "").strip()
    return f"{MEMBER_CHANGED_STEM}:{var}" if var else MEMBER_CHANGED_STEM


# Resolves a topic0 donated to several controllers by evidence, not label order.
_TIER_STRENGTH = {
    WITNESS_TIER_ACTIVITY: 0,
    WITNESS_TIER_HINT: 1,
    WITNESS_TIER_SELF_DESCRIBING: 2,
}


def _member_key_is_extractable(member_witness: object, inputs: list[dict]) -> bool:
    """Whether the proven key position lies within the event's parameters; without the entry key the spec doesn't
    qualify.
    """
    if not is_member_witness(member_witness):
        return False
    key_position = member_witness.get("key_position")
    if not isinstance(key_position, int) or isinstance(key_position, bool):
        return False
    return 0 <= key_position < len(inputs)


def is_member_changed_event_type(event_type: object) -> bool:
    """True for member-change types: one entry moved, not the variable's value, so slot-shaped consumers must not
    read it as one.
    """
    return isinstance(event_type, str) and event_type.startswith(f"{MEMBER_CHANGED_STEM}:")


def member_witness_mapping_var(raw: object) -> str:
    """The mapping/struct variable a correspondence record testifies about, or ``""``."""
    if not is_member_witness(raw):
        return ""
    name = raw.get("mapping_name") if isinstance(raw, dict) else None
    return name.strip() if isinstance(name, str) else ""


def normalized_writer_openness(raw: object) -> str:
    """``writer_openness`` in the three-state vocabulary; anything unrecognized is ``not_determined``."""
    if isinstance(raw, str) and raw.strip().lower() in OPENNESS_VALUES:
        return raw.strip().lower()
    return OPENNESS_NOT_DETERMINED


def is_member_witness(raw: object) -> TypeGuard[dict]:
    """True only for a populated dict.

    This gate lets a mapping write publish directly, so truthy non-dicts (a serialization bug) must not pass.
    """
    return isinstance(raw, dict) and bool(raw)


def _is_canonical_family(event_type: str | None) -> bool:
    """True for canonical family names, which were only minted with signature corroboration."""
    if not isinstance(event_type, str) or not event_type:
        return False
    if ":" in event_type:
        return False
    return event_type not in ("state_changed", "controller_changed")


def _controller_state_var(controller_id: str | None) -> str:
    cid = (controller_id or "").strip()
    if not cid:
        return ""
    return cid.split(":", 1)[1] if ":" in cid else cid


def _event_states_the_change(
    inputs: list[dict] | None,
    effect_tags: dict | None,
    controller_id: str | None,
) -> bool:
    """True when the event's ABI has a ``new*`` and an ``old*``/``previous*`` argument and the emitter writes exactly
    this one controller, so the pair can only be about it.
    """
    if not isinstance(inputs, list) or len(inputs) < 2:
        return False
    if not isinstance(effect_tags, dict):
        return False
    writes = effect_tags.get("writes")
    if not isinstance(writes, list) or len(writes) != 1:
        return False
    state_var = _controller_state_var(controller_id)
    if not state_var or writes[0] != state_var:
        return False
    has_new = False
    has_old = False
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        name = (inp.get("name") or "").strip().lower()
        if not name:
            continue
        if name.startswith("new"):
            has_new = True
        elif name.startswith(("old", "previous")):
            has_old = True
    return has_new and has_old


# Single-cell shapes; a pair on a mapping, array or struct names no particular value.
_SCALAR_SLOT_TYPE_KINDS = frozenset({"address", "contract", "primitive"})


def read_spec_is_scalar_slot(read_spec: object) -> bool:
    """True only when the slot is proven to hold one value; unknown ``type_kind`` refuses."""
    if not isinstance(read_spec, dict):
        return False
    return str(read_spec.get("type_kind") or "").strip().lower() in _SCALAR_SLOT_TYPE_KINDS


def classify_witness_tier(
    *,
    event_type: str | None,
    controller_id: str | None,
    inputs: list[dict] | None = None,
    effect_tags: dict | None = None,
    member_witness: object = None,
    writer_openness: object = None,
    poll_decodable: bool = False,
    controller_scalar_proven: bool = False,
) -> str:
    """Assign the witness tier for one enrolled event spec.

    Inputs can only demote, never promote, so the least-informed spec lands on ``activity``. *poll_decodable* proves the
    controller can be read back; *controller_scalar_proven* gates the old/new arm and defaults to refusal.
    """
    if is_member_witness(member_witness) and normalized_writer_openness(writer_openness) == OPENNESS_RESTRICTED:
        if len(event_type or "") <= MAX_EVENT_TYPE_LENGTH:
            return WITNESS_TIER_SELF_DESCRIBING

    if _is_canonical_family(event_type):
        return WITNESS_TIER_SELF_DESCRIBING

    # The old/new arm also needs a single-cell slot: on a mapping, a keyless pair like
    # ``TokenMaxPositionWeightLimitUpdated(oldLimit, newLimit)`` would publish one entry's limit as the whole mapping's
    # value. Member-witness specs returned above.
    if controller_scalar_proven and _event_states_the_change(inputs, effect_tags, controller_id):
        if len(event_type or "") <= MAX_EVENT_TYPE_LENGTH:
            return WITNESS_TIER_SELF_DESCRIBING

    if poll_decodable and len(value_changed_event_type(controller_id)) <= MAX_EVENT_TYPE_LENGTH:
        return WITNESS_TIER_HINT

    return WITNESS_TIER_ACTIVITY


def extract_governance_topics(tracking_plan: dict | None) -> list[dict]:
    """Per-contract topic specs from a ``ControlTrackingPlan``; ``[]`` without one.

    Each entry: ``{topic0, signature, event_type, controller_id, inputs, effect_tags, witness_tier, writer_openness}``
    plus optional ``member_witness``. Topic0s in ``ALL_EVENT_TOPICS`` are skipped so hand-rolled decoders keep
    OZ/Safe/Timelock/proxy events. ``witness_tier`` decides at runtime whether an occurrence may publish
    (:func:`classify_witness_tier`).
    """
    if not tracking_plan:
        return []
    # Local import to keep the modules acyclic.
    from services.monitoring.polling_plan import _is_poll_decodable

    by_topic: dict[str, dict] = {}
    order: list[str] = []
    for tc in tracking_plan.get("tracked_controllers") or []:
        ew = tc.get("event_watch")
        if not ew:
            continue
        controller_id = tc.get("controller_id")
        read_spec = tc.get("read_spec")
        poll_decodable = _is_poll_decodable(read_spec) if isinstance(read_spec, dict) else False
        controller_scalar_proven = read_spec_is_scalar_slot(read_spec)
        for ev in ew.get("events") or []:
            topic0 = (ev.get("topic0") or "").lower()
            if not topic0 or not topic0.startswith("0x"):
                continue
            # Hand-rolled decoders carry semantics (batch indexing, selectors) the generic path can't.
            if topic0 in ALL_EVENT_TOPICS:
                continue
            effect_tags = ev.get("effect_tags") if isinstance(ev.get("effect_tags"), dict) else None
            inputs = list(ev.get("inputs") or [])
            event_type = _resolve_event_type(
                controller_id,
                effect_tags,
                # Passed through as-is so the resolver sees all three states.
                authority_provenance=tc.get("authority_provenance"),
                signature=ev.get("signature"),
            )
            member_witness = ev.get("member_witness")
            writer_openness = normalized_writer_openness(ev.get("writer_openness"))
            # A qualified member change publishes under the mapping whose entry moved, with key/value/direction in
            # ``data``. Canonical families keep their own claim.
            mapping_var = member_witness_mapping_var(member_witness)
            qualified = (
                bool(mapping_var)
                and writer_openness == OPENNESS_RESTRICTED
                and not _is_canonical_family(event_type)
                and len(member_changed_event_type(mapping_var)) <= MAX_EVENT_TYPE_LENGTH
                and _member_key_is_extractable(member_witness, inputs)
            )
            if qualified:
                event_type = member_changed_event_type(mapping_var)
            # A qualification that can't be published is dropped so it can't promote a slot-stem spec.
            witness_for_tier = member_witness if qualified else None
            spec: dict = {
                "topic0": topic0,
                "signature": ev.get("signature"),
                "event_type": event_type,
                "controller_id": controller_id,
                "inputs": inputs,
                "witness_tier": classify_witness_tier(
                    event_type=event_type,
                    controller_id=controller_id,
                    inputs=inputs,
                    effect_tags=effect_tags,
                    member_witness=witness_for_tier,
                    writer_openness=writer_openness,
                    poll_decodable=poll_decodable,
                    controller_scalar_proven=controller_scalar_proven,
                ),
                # Published even when not determined, so the third state is visible.
                "writer_openness": writer_openness,
            }
            if effect_tags:
                spec["effect_tags"] = effect_tags
            if is_member_witness(witness_for_tier):
                spec["member_witness"] = witness_for_tier
            if topic0 in by_topic:
                # Resolve a topic0 donated to several controllers by strongest tier, first-seen on a tie (not
                # alphabetical label).
                if _TIER_STRENGTH[spec["witness_tier"]] <= _TIER_STRENGTH[by_topic[topic0]["witness_tier"]]:
                    continue
            else:
                order.append(topic0)
            by_topic[topic0] = spec
    return [by_topic[topic0] for topic0 in order]


def parse_tracked_log(log: dict, spec: dict) -> dict | None:
    """Decode a per-contract event from *spec*'s ABI inputs, or ``None`` if the log doesn't match.

    Outputs event_type, block_number, tx_hash, log_index, one key per input name, and semantic-key aliases
    (``old_owner``/``new_owner``...) for registered event_types.
    """
    # Lazy: eth_abi's first import is slow and most contracts have no tracked topics.
    from eth_abi.abi import decode as eth_abi_decode

    inputs = spec.get("inputs") or []
    topics = log.get("topics") or []
    data = log.get("data") or "0x"

    # Keep declaration indexes: member-witness positions refer to declared order, not the topic/data split.
    indexed_inputs = [(idx, i) for idx, i in enumerate(inputs) if i.get("indexed")]
    non_indexed_inputs = [(idx, i) for idx, i in enumerate(inputs) if not i.get("indexed")]

    if len(topics) < 1 + len(indexed_inputs):
        return None

    event: dict = {
        # An unclassified spec only earns the neutral stem.
        "event_type": spec.get("event_type") or "state_changed",
        "block_number": _hex_to_int(log.get("blockNumber", "0x0")),
        "tx_hash": log.get("transactionHash"),
        "log_index": _hex_to_int(log.get("logIndex", "0x0")),
    }
    # Tags ride on the event so the watcher needn't re-derive from event_type.
    spec_tags = spec.get("effect_tags")
    if isinstance(spec_tags, dict) and spec_tags:
        event["effect_tags"] = spec_tags
    # ABI inputs in declaration order, for write-target resolution on non-OZ ABIs (``NewAdmin(newAdmin)`` for
    # ``protocolAdmin``).
    event["_inputs"] = list(inputs)

    args_in_order: list[object] = []
    by_declaration: dict[int, object] = {}
    for i, (decl_index, spec_in) in enumerate(indexed_inputs):
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
            # Indexed dynamic types are stored as their keccak; keep the hash.
            decoded = topic
        name = spec_in.get("name") or f"arg{i}"
        event[name] = decoded
        args_in_order.append(decoded)
        by_declaration[decl_index] = decoded

    if non_indexed_inputs:
        try:
            raw = bytes.fromhex((data or "0x").removeprefix("0x"))
            sol_types = [str(i.get("type") or "") for _idx, i in non_indexed_inputs]
            decoded_tuple = eth_abi_decode(sol_types, raw)
        except Exception:
            return None
        for i, (decl_index, spec_in) in enumerate(non_indexed_inputs):
            val = decoded_tuple[i]
            # Bytes to 0x-hex for JSONB.
            if isinstance(val, (bytes, bytearray)):
                val = "0x" + bytes(val).hex()
            name = spec_in.get("name") or f"arg{len(indexed_inputs) + i}"
            event[name] = val
            args_in_order.append(val)
            by_declaration[decl_index] = val

    _assign_semantic_keys(event, event["event_type"], inputs, args_in_order)
    if not _assign_member_witness_keys(event, spec, by_declaration):
        return None

    return event


# A member-change payload; these are witnessed values, so same-named ABI params must not survive underneath.
_MEMBER_PAYLOAD_KEYS = ("key", "value", "direction")


def _assign_member_witness_keys(event: dict, spec: dict, by_declaration: dict[int, object]) -> bool:
    """Fill ``key``/``value``/``direction`` on a member change; False if the log can't carry its type's claim.

    Gated on the type stem. Each key is cleared before filling, only from what the record proves: otherwise
    ``WardAdded(address indexed usr, uint256 value)`` would publish an unrelated amount as the entry's new value.
    """
    event_type = event.get("event_type")
    if not isinstance(event_type, str) or not event_type.startswith(f"{MEMBER_CHANGED_STEM}:"):
        return True
    witness = spec.get("member_witness")
    if not is_member_witness(witness):
        return True
    for payload_key in _MEMBER_PAYLOAD_KEYS:
        event.pop(payload_key, None)
    key_position = witness.get("key_position")
    if not isinstance(key_position, int) or isinstance(key_position, bool) or key_position not in by_declaration:
        # Without ``data.key`` the row can't say which entry moved.
        return False
    event["key"] = by_declaration[key_position]
    value_position = witness.get("value_position")
    if isinstance(value_position, int) and not isinstance(value_position, bool) and value_position in by_declaration:
        event["value"] = by_declaration[value_position]
    direction = witness.get("direction")
    if isinstance(direction, str) and direction:
        event["direction"] = direction
    return True
