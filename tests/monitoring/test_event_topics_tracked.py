"""Unit tests for the per-contract tracked-topic extractor + decoder.

Covers ``extract_governance_topics`` (consumes a tracking_plan and produces
per-contract topic specs) and ``parse_tracked_log`` (generic ABI-driven
decoder for events not in the hand-rolled global registry).

Pure unit tests — no DB, no Anvil, no RPC.
"""

from __future__ import annotations

from eth_abi.abi import encode as eth_abi_encode
from eth_utils.crypto import keccak

from services.discovery.upgrade_history import (
    ADMIN_CHANGED_TOPIC0,
    DIAMOND_CUT_TOPIC0,
    UPGRADED_TOPIC0,
)
from services.monitoring.event_topics import (
    ADDED_OWNER_TOPIC0,
    ALL_EVENT_TOPICS,
    CALL_SCHEDULED_TOPIC0,
    OWNERSHIP_TRANSFERRED_TOPIC0,
    PAUSED_TOPIC0,
    ROLE_GRANTED_TOPIC0,
    extract_governance_topics,
    parse_any_log,
    parse_governance_log,
    parse_tracked_log,
)


def _topic_addr(addr: str) -> str:
    return "0x" + "0" * 24 + addr.lower().removeprefix("0x")


def _topic0(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


# ---------------------------------------------------------------------------
# extract_governance_topics
# ---------------------------------------------------------------------------


def test_extract_governance_topics_solmate_owned():
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:owner",
                "event_watch": {
                    "events": [
                        {
                            "name": "OwnerUpdated",
                            "signature": "OwnerUpdated(address,address)",
                            "topic0": _topic0("OwnerUpdated(address,address)"),
                            "inputs": [
                                {"name": "user", "type": "address", "indexed": True},
                                {"name": "newOwner", "type": "address", "indexed": True},
                            ],
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1
    spec = topics[0]
    assert spec["topic0"] == _topic0("OwnerUpdated(address,address)")
    assert spec["event_type"] == "ownership_transferred"
    assert spec["controller_id"] == "state_variable:owner"
    assert len(spec["inputs"]) == 2


def test_extract_governance_topics_solmate_authority():
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "external_contract:authority",
                "event_watch": {
                    "events": [
                        {
                            "name": "AuthorityUpdated",
                            "signature": "AuthorityUpdated(address,address)",
                            "topic0": _topic0("AuthorityUpdated(address,address)"),
                            "inputs": [
                                {"name": "user", "type": "address", "indexed": True},
                                {"name": "newAuthority", "type": "address", "indexed": True},
                            ],
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1
    assert topics[0]["event_type"] == "authority_updated"


def test_extract_governance_topics_skips_hand_rolled_oz():
    """OZ OwnershipTransferred is already in ALL_EVENT_TOPICS — the
    extractor must not duplicate it in the per-contract list. Hand-rolled
    decoder wins for OZ-shaped events because it encodes semantics
    (state sync, sync paths) the generic path doesn't reproduce."""
    oz_topic0 = _topic0("OwnershipTransferred(address,address)")
    assert oz_topic0 in ALL_EVENT_TOPICS  # sanity

    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:owner",
                "event_watch": {
                    "events": [
                        {
                            "name": "OwnershipTransferred",
                            "signature": "OwnershipTransferred(address,address)",
                            "topic0": oz_topic0,
                            "inputs": [
                                {"name": "previousOwner", "type": "address", "indexed": True},
                                {"name": "newOwner", "type": "address", "indexed": True},
                            ],
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert topics == []


def test_extract_governance_topics_unknown_controller_id_falls_through():
    """A controller_id we don't have a semantic mapping for still produces
    a tracked-topic entry — under the neutral ``state_changed:<id>``
    event_type, because this plan proves nothing about the target gating
    callers. The scanner records the event; no specific sync handler
    fires and no control claim is published.
    """
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:guardian",
                "event_watch": {
                    "events": [
                        {
                            "name": "GuardianSet",
                            "signature": "GuardianSet(address,address)",
                            "topic0": _topic0("GuardianSet(address,address)"),
                            "inputs": [
                                {"name": "previousGuardian", "type": "address", "indexed": True},
                                {"name": "newGuardian", "type": "address", "indexed": True},
                            ],
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1
    assert topics[0]["event_type"] == "state_changed:state_variable:guardian"


def test_extract_governance_topics_unknown_controller_id_with_gate_proof():
    """Same plan, plus the tracking plan's proof that a lowered predicate
    leaf gates callers on ``guardian`` — now the controller claim IS
    earned and the terminal fallback publishes it."""
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:guardian",
                "authority_provenance": "caller_gate",
                "event_watch": {
                    "events": [
                        {
                            "name": "GuardianSet",
                            "signature": "GuardianSet(address,address)",
                            "topic0": _topic0("GuardianSet(address,address)"),
                            "inputs": [
                                {"name": "previousGuardian", "type": "address", "indexed": True},
                                {"name": "newGuardian", "type": "address", "indexed": True},
                            ],
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1
    assert topics[0]["event_type"] == "controller_changed:state_variable:guardian"


def test_extract_governance_topics_handles_null_plan():
    assert extract_governance_topics(None) == []
    assert extract_governance_topics({}) == []
    assert extract_governance_topics({"tracked_controllers": []}) == []


def test_extract_governance_topics_dedups_across_controllers():
    """If two controllers reference the same event, the topic0 is emitted
    exactly once — the dispatcher map is topic0-keyed."""
    sig = "SomeEvent(address,address)"
    topic = _topic0(sig)
    event_dict = {
        "name": "SomeEvent",
        "signature": sig,
        "topic0": topic,
        "inputs": [
            {"name": "a", "type": "address", "indexed": True},
            {"name": "b", "type": "address", "indexed": True},
        ],
    }
    plan = {
        "tracked_controllers": [
            {"controller_id": "state_variable:owner", "event_watch": {"events": [event_dict]}},
            {"controller_id": "state_variable:_owner", "event_watch": {"events": [event_dict]}},
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1


# ---------------------------------------------------------------------------
# parse_tracked_log
# ---------------------------------------------------------------------------


def test_parse_tracked_log_two_indexed_addresses_with_semantic_keys():
    """Solmate OwnerUpdated shape: both args indexed addresses. The decoder
    must surface ABI-name keys (``user``, ``newOwner``) AND semantic-key
    aliases (``old_owner``, ``new_owner``) so the existing
    ``_update_state_from_event`` / ``_sync_relational_tables`` paths
    keep working without modification."""
    sig = "OwnerUpdated(address,address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "ownership_transferred",
        "controller_id": "state_variable:owner",
        "inputs": [
            {"name": "user", "type": "address", "indexed": True},
            {"name": "newOwner", "type": "address", "indexed": True},
        ],
    }
    old = "0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"
    new = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    log = {
        "topics": [spec["topic0"], _topic_addr(old), _topic_addr(new)],
        "data": "0x",
        "blockNumber": "0x123",
        "logIndex": "0x4",
        "transactionHash": "0xdeadbeef",
    }

    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["event_type"] == "ownership_transferred"
    # ABI-name keys preserved
    assert parsed["user"].lower() == old.lower()
    assert parsed["newOwner"].lower() == new.lower()
    # Semantic-key aliases populated positionally
    assert parsed["old_owner"].lower() == old.lower()
    assert parsed["new_owner"].lower() == new.lower()
    # Standard envelope
    assert parsed["block_number"] == 0x123
    assert parsed["log_index"] == 0x4
    assert parsed["tx_hash"] == "0xdeadbeef"


def test_parse_tracked_log_authority_semantic_keys():
    sig = "AuthorityUpdated(address,address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "authority_updated",
        "controller_id": "external_contract:authority",
        "inputs": [
            {"name": "user", "type": "address", "indexed": True},
            {"name": "newAuthority", "type": "address", "indexed": True},
        ],
    }
    caller = "0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"
    new_auth = "0x3994741a5b29c60d0Ab318dE1024F9256Fe959dc"
    log = {
        "topics": [spec["topic0"], _topic_addr(caller), _topic_addr(new_auth)],
        "data": "0x",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0xfeed",
    }

    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["event_type"] == "authority_updated"
    assert parsed["old_authority"].lower() == caller.lower()
    assert parsed["new_authority"].lower() == new_auth.lower()


def test_parse_tracked_log_non_indexed_data():
    """Validates the eth_abi decode path: signature with a single
    non-indexed address packed into ``data`` (DSAuth ``LogSetOwner`` is
    the real-world example)."""
    sig = "LogSetOwner(address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "controller_changed:state_variable:owner",
        "controller_id": "state_variable:owner",
        "inputs": [{"name": "newOwner", "type": "address", "indexed": False}],
    }
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    data = "0x" + eth_abi_encode(["address"], [new_owner]).hex()
    log = {
        "topics": [spec["topic0"]],
        "data": data,
        "blockNumber": "0xa",
        "logIndex": "0x0",
        "transactionHash": "0xab",
    }

    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["newOwner"].lower() == new_owner.lower()


def test_parse_tracked_log_dsauth_single_indexed_owner():
    """DSAuth-style ``LogSetOwner(address indexed owner)``: one indexed
    address, name does not start with ``new``. Single-arg fallback
    treats the value as the new owner; no old_owner recorded (none to
    record from a one-arg event)."""
    sig = "LogSetOwner(address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "ownership_transferred",
        "controller_id": "state_variable:owner",
        "inputs": [{"name": "owner", "type": "address", "indexed": True}],
    }
    new_owner = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    log = {
        "topics": [spec["topic0"], _topic_addr(new_owner)],
        "data": "0x",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0xab",
    }

    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["new_owner"].lower() == new_owner.lower()
    assert "old_owner" not in parsed


def test_parse_tracked_log_compound_new_admin_non_indexed():
    """Compound-style ``NewAdmin(address newAdmin)``: single non-indexed
    address packed in data, name starts with ``new``. Name match alone
    fills new_admin; admin_changed leaves previous_admin unset (Compound's
    NewAdmin only carries the new value)."""
    sig = "NewAdmin(address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "admin_changed",
        "controller_id": "state_variable:admin",
        "inputs": [{"name": "newAdmin", "type": "address", "indexed": False}],
    }
    new_admin = "0x3994741a5b29c60D0AB318dE1024F9256fe959dc"
    data = "0x" + eth_abi_encode(["address"], [new_admin]).hex()
    log = {
        "topics": [spec["topic0"]],
        "data": data,
        "blockNumber": "0x2",
        "logIndex": "0x0",
        "transactionHash": "0xcd",
    }

    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["new_admin"].lower() == new_admin.lower()
    assert "previous_admin" not in parsed


def test_parse_tracked_log_anonymous_args_positional_fallback():
    """Two-arg event whose ABI input names match neither ``new*`` nor
    ``previous*`` — convention falls back to positional ``(old, new)``."""
    sig = "GovernorChanged(address,address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "ownership_transferred",
        "controller_id": "state_variable:owner",
        "inputs": [
            {"name": "from_", "type": "address", "indexed": True},
            {"name": "to_", "type": "address", "indexed": True},
        ],
    }
    old = "0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"
    new = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    log = {
        "topics": [spec["topic0"], _topic_addr(old), _topic_addr(new)],
        "data": "0x",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0xef",
    }
    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["old_owner"].lower() == old.lower()
    assert parsed["new_owner"].lower() == new.lower()


def test_parse_tracked_log_ozownable2step_oz_naming():
    """Ownable2Step ``OwnershipTransferStarted(previousOwner, newOwner)``
    — both names match OZ convention exactly, both slots fill via name
    pass alone."""
    sig = "OwnershipTransferStarted(address,address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "ownership_transfer_started",
        "controller_id": "state_variable:pendingOwner",
        "inputs": [
            {"name": "previousOwner", "type": "address", "indexed": True},
            {"name": "newOwner", "type": "address", "indexed": True},
        ],
    }
    old = "0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"
    new = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
    log = {
        "topics": [spec["topic0"], _topic_addr(old), _topic_addr(new)],
        "data": "0x",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0xff",
    }
    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["event_type"] == "ownership_transfer_started"
    assert parsed["old_owner"].lower() == old.lower()
    assert parsed["new_owner"].lower() == new.lower()


# ---------------------------------------------------------------------------
# Tag-driven classification (effect_tags)
# ---------------------------------------------------------------------------


def test_extract_governance_topics_tags_drive_admin_changed():
    """Compound NewAdmin via the tag-driven path: even though
    ``state_variable:admin`` isn't in the legacy controller_id map,
    effect_tags.writes containing ``admin`` classifies the event as
    ``admin_changed``. This is the general fix — no per-ABI table edit
    needed to pick up the Compound family."""
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:admin",
                "event_watch": {
                    "events": [
                        {
                            "name": "NewAdmin",
                            "signature": "NewAdmin(address)",
                            "topic0": _topic0("NewAdmin(address)"),
                            "inputs": [{"name": "newAdmin", "type": "address", "indexed": False}],
                            "effect_tags": {"writes": ["admin"]},
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1
    spec = topics[0]
    assert spec["event_type"] == "admin_changed"
    assert spec["effect_tags"] == {"writes": ["admin"]}


def test_extract_governance_topics_tags_curve_commit_ownership():
    """Curve / Vyper 2-step admin pattern: ``CommitOwnership`` is emitted
    by a function writing ``future_admin``. Tag-driven classification
    routes it through ``admin_changed`` without a controller_id mapping."""
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:future_admin",
                "event_watch": {
                    "events": [
                        {
                            "name": "CommitOwnership",
                            "signature": "CommitOwnership(address)",
                            "topic0": _topic0("CommitOwnership(address)"),
                            "inputs": [{"name": "admin", "type": "address", "indexed": False}],
                            "effect_tags": {"writes": ["future_admin"]},
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1
    assert topics[0]["event_type"] == "admin_changed"


def test_extract_governance_topics_tags_ownable2step_commit_phase():
    """OZ Ownable2Step ``acceptOwnership`` writes BOTH ``owner`` and
    ``pendingOwner``. The classifier must pick ``ownership_transferred``
    (commit phase), not ``ownership_transfer_started``."""
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:owner",
                "event_watch": {
                    "events": [
                        {
                            "name": "OwnershipTransferred",
                            "signature": "OwnershipTransferred2(address,address)",
                            "topic0": _topic0("OwnershipTransferred2(address,address)"),
                            "inputs": [
                                {"name": "previousOwner", "type": "address", "indexed": True},
                                {"name": "newOwner", "type": "address", "indexed": True},
                            ],
                            "effect_tags": {"writes": ["owner", "pendingOwner"]},
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert topics[0]["event_type"] == "ownership_transferred"


def test_extract_governance_topics_tags_initializer():
    """OZ Initializable ``Initialized(uint64 version)`` — tagged via
    ``is_initializer`` since the slot is named ``_initialized``."""
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:_initialized",
                "event_watch": {
                    "events": [
                        {
                            "name": "Initialized",
                            "signature": "Initialized(uint64)",
                            "topic0": _topic0("Initialized(uint64)"),
                            "inputs": [{"name": "version", "type": "uint64", "indexed": False}],
                            "effect_tags": {"writes": ["_initialized"], "is_initializer": True},
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert topics[0]["event_type"] == "initialized"


def test_extract_governance_topics_tags_fall_through_when_no_match():
    """When effect_tags don't match any canonical write target, the
    classifier falls back to controller_id and ultimately to the terminal
    form — neutral here, since this plan carries no gate proof for
    ``guardian``."""
    plan = {
        "tracked_controllers": [
            {
                "controller_id": "state_variable:guardian",
                "event_watch": {
                    "events": [
                        {
                            "name": "GuardianSet",
                            "signature": "GuardianSet(address)",
                            "topic0": _topic0("GuardianSet(address)"),
                            "inputs": [{"name": "guardian", "type": "address", "indexed": True}],
                            "effect_tags": {"writes": ["guardian"]},
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert topics[0]["event_type"] == "state_changed:state_variable:guardian"
    # Tags still ride along even when classification fell back.
    assert topics[0]["effect_tags"] == {"writes": ["guardian"]}


def test_extract_governance_topics_tags_outrank_controller_id():
    """If the controller_id mapping disagrees with effect_tags, tags win
    — tags reflect what the emitter ACTUALLY mutates, which is more
    accurate than the controller's name."""
    plan = {
        "tracked_controllers": [
            {
                # Misleading controller_id (would map to ownership_transferred)
                "controller_id": "state_variable:owner",
                "event_watch": {
                    "events": [
                        {
                            "name": "AdminSet",
                            "signature": "AdminSet(address)",
                            "topic0": _topic0("AdminSet(address)"),
                            "inputs": [{"name": "newAdmin", "type": "address", "indexed": True}],
                            # ...but the emitter actually writes admin, not owner
                            "effect_tags": {"writes": ["admin"]},
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert topics[0]["event_type"] == "admin_changed"


def test_parse_tracked_log_carries_effect_tags_through():
    """The decoder propagates effect_tags from the spec onto the parsed
    event so the watcher's downstream sync paths can branch on them."""
    sig = "NewAdmin(address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "admin_changed",
        "controller_id": "state_variable:admin",
        "inputs": [{"name": "newAdmin", "type": "address", "indexed": False}],
        "effect_tags": {"writes": ["admin"]},
    }
    new_admin = "0x3994741a5b29c60D0AB318dE1024F9256fe959dc"
    data = "0x" + eth_abi_encode(["address"], [new_admin]).hex()
    log = {
        "topics": [spec["topic0"]],
        "data": data,
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0xfe",
    }
    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["effect_tags"] == {"writes": ["admin"]}
    assert parsed["new_admin"].lower() == new_admin.lower()


def test_parse_tracked_log_returns_none_on_short_topics():
    """If the log's topic count doesn't match the spec's indexed inputs
    (corrupt log, wrong topic0 routed by mistake), the decoder declines
    rather than emitting a partial event."""
    sig = "OwnerUpdated(address,address)"
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": "ownership_transferred",
        "controller_id": "state_variable:owner",
        "inputs": [
            {"name": "user", "type": "address", "indexed": True},
            {"name": "newOwner", "type": "address", "indexed": True},
        ],
    }
    # Only one of the two indexed addresses present.
    log = {
        "topics": [spec["topic0"], _topic_addr("0x1111111111111111111111111111111111111111")],
        "data": "0x",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0xab",
    }
    assert parse_tracked_log(log, spec) is None


# ---------------------------------------------------------------------------
# Hand-rolled decoders attach synthesized effect_tags
# ---------------------------------------------------------------------------
#
# These tests pin the canonical event_type → effect_tags map. Downstream
# consumers (``_should_watch``, ``_update_state_from_event``,
# ``_sync_relational_tables``, ``should_trigger_reanalysis``) all branch
# on tags, so a regression here would silently drop hand-rolled events
# from the dispatch.


def test_parse_governance_log_ownership_transferred_attaches_tags():
    log = {
        "topics": [
            OWNERSHIP_TRANSFERRED_TOPIC0,
            _topic_addr("0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"),
            _topic_addr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ],
        "data": "0x",
        "blockNumber": "0x10",
        "transactionHash": "0xdeadbeef",
    }
    ev = parse_governance_log(log)
    assert ev is not None
    assert ev["event_type"] == "ownership_transferred"
    assert ev["effect_tags"] == {"writes": ["owner"]}


def test_parse_governance_log_paused_attaches_tags():
    log = {
        "topics": [PAUSED_TOPIC0],
        "data": "0x" + "00" * 12 + "ab" * 20,
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev = parse_governance_log(log)
    assert ev is not None
    assert ev["event_type"] == "paused"
    assert ev["effect_tags"] == {"writes": ["paused"]}


def test_parse_governance_log_role_granted_attaches_tags():
    log = {
        "topics": [
            ROLE_GRANTED_TOPIC0,
            "0x" + "00" * 32,  # role
            _topic_addr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),  # account
            _topic_addr("0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"),  # sender
        ],
        "data": "0x",
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev = parse_governance_log(log)
    assert ev is not None
    assert ev["event_type"] == "role_granted"
    assert ev["effect_tags"] == {"writes": ["_roles"]}


def test_parse_governance_log_added_owner_attaches_tags():
    log = {
        "topics": [ADDED_OWNER_TOPIC0],
        "data": "0x" + "00" * 12 + "cd" * 20,
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev = parse_governance_log(log)
    assert ev is not None
    assert ev["event_type"] == "signer_added"
    assert ev["effect_tags"] == {"writes": ["owners"]}


def test_parse_governance_log_call_scheduled_attaches_tags():
    target_word = "0" * 24 + "0" * 38 + "01"
    value_word = "0" * 64
    bytes_offset = format(160, "x").zfill(64)
    predecessor_word = "0" * 64
    delay_word = format(3600, "x").zfill(64)
    data_hex = "0x" + target_word + value_word + bytes_offset + predecessor_word + delay_word
    log = {
        "topics": [
            CALL_SCHEDULED_TOPIC0,
            "0x" + "ab" * 32,
            "0x" + format(0, "x").zfill(64),
        ],
        "data": data_hex,
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev = parse_governance_log(log)
    assert ev is not None
    assert ev["event_type"] == "timelock_scheduled"
    # Synthetic ``_timelock_op`` marker — activity events don't mutate a
    # named state slot, but ``_should_watch`` still needs a tag to gate
    # them against ``watch_timelock``.
    assert ev["effect_tags"] == {"writes": ["_timelock_op"]}


def test_parse_any_log_upgraded_attaches_tags():
    """parse_upgrade_log lives in services/discovery/upgrade_history.py
    and can't import the synthesizer without a circular dependency.
    parse_any_log attaches tags at the consolidated entry point — verify
    they actually land there."""
    log = {
        "topics": [
            UPGRADED_TOPIC0,
            _topic_addr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ],
        "data": "0x",
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev = parse_any_log(log)
    assert ev is not None
    assert ev["event_type"] == "upgraded"
    # ``delegates: True`` is the canonical marker for delegate-target
    # swaps — drives the upgrade path in _sync_relational_tables.
    assert ev["effect_tags"] == {"writes": ["implementation"], "delegates": True}


def test_parse_any_log_admin_changed_attaches_tags():
    data = (
        "0x"
        + "00" * 12
        + "ab" * 20  # previous admin
        + "00" * 12
        + "cd" * 20  # new admin
    )
    log = {
        "topics": [ADMIN_CHANGED_TOPIC0],
        "data": data,
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev = parse_any_log(log)
    assert ev is not None
    assert ev["event_type"] == "admin_changed"
    assert ev["effect_tags"] == {"writes": ["admin"]}


def test_parse_any_log_diamond_cut_attaches_tags():
    """EIP-2535 DiamondCut signals a facet swap — equivalent to an
    implementation upgrade for a proxy. Tags must include both
    ``delegates: True`` (to trigger reanalysis) and ``facets`` (to
    route through the upgrade path)."""
    # Minimal DiamondCut data: one Add action with one facet, zero init.
    facet = "00" * 12 + "01" * 20
    # ABI: offset to FacetCut[], _init, _calldata offset
    array_off = format(96, "x").zfill(64)
    init_word = "0" * 64
    calldata_off = format(160, "x").zfill(64)
    # Array starts here: count=1, entry_offset=32
    array_count = format(1, "x").zfill(64)
    entry_off = format(32, "x").zfill(64)
    # Entry: facet, action=0 (Add), selectors array (empty)
    entry = facet + format(0, "x").zfill(64) + format(96, "x").zfill(64) + format(0, "x").zfill(64)
    calldata_len = "0" * 64
    data_hex = "0x" + array_off + init_word + calldata_off + array_count + entry_off + entry + calldata_len

    log = {
        "topics": [DIAMOND_CUT_TOPIC0],
        "data": data_hex,
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev = parse_any_log(log)
    assert ev is not None
    assert ev["event_type"] == "diamond_cut"
    assert ev["effect_tags"] == {"writes": ["facets"], "delegates": True}


def test_parse_any_log_handrolled_tags_isolated_from_module_state():
    """``_attach_effect_tags`` must deep-copy the writes list so a
    consumer mutating ``ev["effect_tags"]["writes"]`` doesn't poison
    the module-level synthesis map for future events."""
    log = {
        "topics": [
            OWNERSHIP_TRANSFERRED_TOPIC0,
            _topic_addr("0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"),
            _topic_addr("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
        ],
        "data": "0x",
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }
    ev1 = parse_governance_log(log)
    assert ev1 is not None
    ev1["effect_tags"]["writes"].append("__poisoned__")

    ev2 = parse_governance_log(log)
    assert ev2 is not None
    assert ev2["effect_tags"]["writes"] == ["owner"], (
        "module-level synthesis map was mutated by a consumer — _attach_effect_tags must copy the writes list"
    )
