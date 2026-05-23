"""Unit tests for the per-contract tracked-topic extractor + decoder.

Covers ``extract_governance_topics`` (consumes a tracking_plan and produces
per-contract topic specs) and ``parse_tracked_log`` (generic ABI-driven
decoder for events not in the hand-rolled global registry).

Pure unit tests — no DB, no Anvil, no RPC.
"""

from __future__ import annotations

import sys
from pathlib import Path

from eth_abi.abi import encode as eth_abi_encode
from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.monitoring.event_topics import (
    ALL_EVENT_TOPICS,
    extract_governance_topics,
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
    a tracked-topic entry — just under a ``controller_changed:<id>``
    event_type so the scanner records the event but no specific sync
    handler fires.
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
