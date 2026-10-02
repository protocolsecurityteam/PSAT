from __future__ import annotations

import pytest
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


@pytest.mark.parametrize(
    ("controller_id", "name", "new_input", "expected_event_type"),
    [
        pytest.param("state_variable:owner", "OwnerUpdated", "newOwner", "ownership_transferred", id="solmate-owned"),
        pytest.param(
            "external_contract:authority",
            "AuthorityUpdated",
            "newAuthority",
            "authority_updated",
            id="solmate-authority",
        ),
    ],
)
def test_extract_governance_topics_solmate(controller_id, name, new_input, expected_event_type):
    signature = f"{name}(address,address)"
    plan = {
        "tracked_controllers": [
            {
                "controller_id": controller_id,
                "event_watch": {
                    "events": [
                        {
                            "name": name,
                            "signature": signature,
                            "topic0": _topic0(signature),
                            "inputs": [
                                {"name": "user", "type": "address", "indexed": True},
                                {"name": new_input, "type": "address", "indexed": True},
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
    assert spec["topic0"] == _topic0(signature)
    assert spec["event_type"] == expected_event_type
    assert spec["controller_id"] == controller_id
    assert len(spec["inputs"]) == 2


def test_extract_governance_topics_skips_hand_rolled_oz():
    """The hand-rolled OZ decoder carries semantics the generic path doesn't."""
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
    """The plan proves nothing about gating callers, so no control claim is published."""
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
    """The dispatcher is topic0-keyed."""
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


_OLD = "0xf39fd6e51aad88f6f4ce6ab8827279cffFb92266"
_NEW = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
_NEW_ADMIN = "0x3994741a5b29c60D0AB318dE1024F9256fe959dc"


def _in(name: str, indexed: bool, typ: str = "address") -> dict:
    return {"name": name, "type": typ, "indexed": indexed}


@pytest.mark.parametrize(
    ("sig", "event_type", "controller_id", "inputs", "indexed_args", "data_args", "expected", "absent"),
    [
        # ABI-name keys and semantic aliases, so existing sync paths keep working.
        pytest.param(
            "OwnerUpdated(address,address)",
            "ownership_transferred",
            "state_variable:owner",
            [_in("user", True), _in("newOwner", True)],
            [_OLD, _NEW],
            [],
            {"user": _OLD, "newOwner": _NEW, "old_owner": _OLD, "new_owner": _NEW},
            (),
            id="two-indexed-addresses-with-semantic-keys",
        ),
        pytest.param(
            "AuthorityUpdated(address,address)",
            "authority_updated",
            "external_contract:authority",
            [_in("user", True), _in("newAuthority", True)],
            [_OLD, "0x3994741a5b29c60d0Ab318dE1024F9256Fe959dc"],
            [],
            {"old_authority": _OLD, "new_authority": "0x3994741a5b29c60d0Ab318dE1024F9256Fe959dc"},
            (),
            id="authority-semantic-keys",
        ),
        pytest.param(
            "LogSetOwner(address)",
            "controller_changed:state_variable:owner",
            "state_variable:owner",
            [_in("newOwner", False)],
            [],
            [_NEW],
            {"newOwner": _NEW},
            (),
            id="non-indexed-data",
        ),
        pytest.param(
            "LogSetOwner(address)",
            "ownership_transferred",
            "state_variable:owner",
            [_in("owner", True)],
            [_NEW],
            [],
            {"new_owner": _NEW},
            ("old_owner",),
            id="dsauth-single-indexed-owner",
        ),
        pytest.param(
            "NewAdmin(address)",
            "admin_changed",
            "state_variable:admin",
            [_in("newAdmin", False)],
            [],
            [_NEW_ADMIN],
            {"new_admin": _NEW_ADMIN},
            ("previous_admin",),
            id="compound-new-admin-non-indexed",
        ),
        pytest.param(
            "GovernorChanged(address,address)",
            "ownership_transferred",
            "state_variable:owner",
            [_in("from_", True), _in("to_", True)],
            [_OLD, _NEW],
            [],
            {"old_owner": _OLD, "new_owner": _NEW},
            (),
            id="anonymous-args-positional-fallback",
        ),
        pytest.param(
            "OwnershipTransferStarted(address,address)",
            "ownership_transfer_started",
            "state_variable:pendingOwner",
            [_in("previousOwner", True), _in("newOwner", True)],
            [_OLD, _NEW],
            [],
            {"old_owner": _OLD, "new_owner": _NEW},
            (),
            id="ownable2step-oz-naming",
        ),
    ],
)
def test_parse_tracked_log_shapes(sig, event_type, controller_id, inputs, indexed_args, data_args, expected, absent):
    spec = {
        "topic0": _topic0(sig),
        "signature": sig,
        "event_type": event_type,
        "controller_id": controller_id,
        "inputs": inputs,
    }
    log = {
        "topics": [spec["topic0"], *(_topic_addr(a) for a in indexed_args)],
        "data": "0x" + eth_abi_encode(["address"] * len(data_args), data_args).hex(),
        "blockNumber": "0x123",
        "logIndex": "0x4",
        "transactionHash": "0xdeadbeef",
    }

    parsed = parse_tracked_log(log, spec)
    assert parsed is not None
    assert parsed["event_type"] == event_type
    for key, value in expected.items():
        assert parsed[key].lower() == value.lower()
    for key in absent:
        assert key not in parsed
    assert parsed["block_number"] == 0x123
    assert parsed["log_index"] == 0x4
    assert parsed["tx_hash"] == "0xdeadbeef"


@pytest.mark.parametrize(
    ("controller_id", "name", "signature", "inputs", "effect_tags", "expected_event_type"),
    [
        # ``admin`` in effect_tags.writes classifies it with no per-ABI edit.
        pytest.param(
            "state_variable:admin",
            "NewAdmin",
            "NewAdmin(address)",
            [_in("newAdmin", False)],
            {"writes": ["admin"]},
            "admin_changed",
            id="tags-drive-admin-changed",
        ),
        pytest.param(
            "state_variable:future_admin",
            "CommitOwnership",
            "CommitOwnership(address)",
            [_in("admin", False)],
            {"writes": ["future_admin"]},
            "admin_changed",
            id="curve-commit-ownership",
        ),
        # ``acceptOwnership`` writes both slots, and the commit phase wins.
        pytest.param(
            "state_variable:owner",
            "OwnershipTransferred",
            "OwnershipTransferred2(address,address)",
            [_in("previousOwner", True), _in("newOwner", True)],
            {"writes": ["owner", "pendingOwner"]},
            "ownership_transferred",
            id="ownable2step-commit-phase",
        ),
        pytest.param(
            "state_variable:_initialized",
            "Initialized",
            "Initialized(uint64)",
            [_in("version", False, "uint64")],
            {"writes": ["_initialized"], "is_initializer": True},
            "initialized",
            id="initializer",
        ),
        # No canonical write target, so it falls back to controller_id then the neutral form.
        pytest.param(
            "state_variable:guardian",
            "GuardianSet",
            "GuardianSet(address)",
            [_in("guardian", True)],
            {"writes": ["guardian"]},
            "state_changed:state_variable:guardian",
            id="fall-through-when-no-match",
        ),
        # Tags reflect what the emitter actually mutates, so they beat controller_id.
        pytest.param(
            "state_variable:owner",
            "AdminSet",
            "AdminSet(address)",
            [_in("newAdmin", True)],
            {"writes": ["admin"]},
            "admin_changed",
            id="tags-outrank-controller-id",
        ),
    ],
)
def test_extract_governance_topics_tag_classification(
    controller_id, name, signature, inputs, effect_tags, expected_event_type
):
    plan = {
        "tracked_controllers": [
            {
                "controller_id": controller_id,
                "event_watch": {
                    "events": [
                        {
                            "name": name,
                            "signature": signature,
                            "topic0": _topic0(signature),
                            "inputs": inputs,
                            "effect_tags": effect_tags,
                        }
                    ]
                },
            }
        ]
    }
    topics = extract_governance_topics(plan)
    assert len(topics) == 1
    assert topics[0]["event_type"] == expected_event_type
    assert topics[0]["effect_tags"] == effect_tags


def test_parse_tracked_log_carries_effect_tags_through():
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
    """A partial event from a corrupt or misrouted log is worse than none."""
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
    log = {
        "topics": [spec["topic0"], _topic_addr("0x1111111111111111111111111111111111111111")],
        "data": "0x",
        "blockNumber": "0x1",
        "logIndex": "0x0",
        "transactionHash": "0xab",
    }
    assert parse_tracked_log(log, spec) is None


# Downstream consumers branch on these tags, so a regression silently drops events.


def _call_scheduled_log() -> dict:
    target_word = "0" * 24 + "0" * 38 + "01"
    value_word = "0" * 64
    bytes_offset = format(160, "x").zfill(64)
    predecessor_word = "0" * 64
    delay_word = format(3600, "x").zfill(64)
    return {
        "topics": [CALL_SCHEDULED_TOPIC0, "0x" + "ab" * 32, "0x" + format(0, "x").zfill(64)],
        "data": "0x" + target_word + value_word + bytes_offset + predecessor_word + delay_word,
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }


def _diamond_cut_log() -> dict:
    facet = "00" * 12 + "01" * 20
    array_off = format(96, "x").zfill(64)
    init_word = "0" * 64
    calldata_off = format(160, "x").zfill(64)
    array_count = format(1, "x").zfill(64)
    entry_off = format(32, "x").zfill(64)
    entry = facet + format(0, "x").zfill(64) + format(96, "x").zfill(64) + format(0, "x").zfill(64)
    calldata_len = "0" * 64
    return {
        "topics": [DIAMOND_CUT_TOPIC0],
        "data": "0x" + array_off + init_word + calldata_off + array_count + entry_off + entry + calldata_len,
        "blockNumber": "0x10",
        "transactionHash": "0xdead",
    }


def _governance_log(topics: list[str], data: str = "0x", block: str = "0x10", tx: str = "0xdead") -> dict:
    return {"topics": topics, "data": data, "blockNumber": block, "transactionHash": tx}


# ``parse_upgrade_log`` can't import the synthesizer (circular), so tags attach in ``parse_any_log``.
@pytest.mark.parametrize(
    ("parser", "log", "event_type", "effect_tags"),
    [
        pytest.param(
            parse_governance_log,
            _governance_log(
                [OWNERSHIP_TRANSFERRED_TOPIC0, _topic_addr(_OLD), _topic_addr(_NEW)], block="0x10", tx="0xdeadbeef"
            ),
            "ownership_transferred",
            {"writes": ["owner"]},
            id="ownership-transferred",
        ),
        pytest.param(
            parse_governance_log,
            _governance_log([PAUSED_TOPIC0], "0x" + "00" * 12 + "ab" * 20),
            "paused",
            {"writes": ["paused"]},
            id="paused",
        ),
        pytest.param(
            parse_governance_log,
            _governance_log(
                [
                    ROLE_GRANTED_TOPIC0,
                    "0x" + "00" * 32,  # role
                    _topic_addr(_NEW),  # account
                    _topic_addr(_OLD),  # sender
                ]
            ),
            "role_granted",
            {"writes": ["_roles"]},
            id="role-granted",
        ),
        pytest.param(
            parse_governance_log,
            _governance_log([ADDED_OWNER_TOPIC0], "0x" + "00" * 12 + "cd" * 20),
            "signer_added",
            {"writes": ["owners"]},
            id="added-owner",
        ),
        # ``_should_watch`` needs a tag to gate activity events against ``watch_timelock``.
        pytest.param(
            parse_governance_log,
            _call_scheduled_log(),
            "timelock_scheduled",
            {"writes": ["_timelock_op"]},
            id="call-scheduled",
        ),
        pytest.param(
            parse_any_log,
            _governance_log([UPGRADED_TOPIC0, _topic_addr(_NEW)]),
            "upgraded",
            {"writes": ["implementation"], "delegates": True},
            id="any-log-upgraded",
        ),
        pytest.param(
            parse_any_log,
            _governance_log(
                [ADMIN_CHANGED_TOPIC0],
                "0x" + "00" * 12 + "ab" * 20 + "00" * 12 + "cd" * 20,  # previous admin, new admin
            ),
            "admin_changed",
            {"writes": ["admin"]},
            id="any-log-admin-changed",
        ),
        pytest.param(
            parse_any_log,
            _diamond_cut_log(),
            "diamond_cut",
            {"writes": ["facets"], "delegates": True},
            id="any-log-diamond-cut",
        ),
    ],
)
def test_hand_rolled_decoders_attach_synthesized_tags(parser, log, event_type, effect_tags):
    ev = parser(log)
    assert ev is not None
    assert ev["event_type"] == event_type
    assert ev["effect_tags"] == effect_tags


def test_parse_any_log_handrolled_tags_isolated_from_module_state():
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


class TestTimelockEventDecode:
    def test_call_scheduled_decodes_static_fields(self):
        from services.monitoring.event_topics import CALL_SCHEDULED_TOPIC0, parse_governance_log

        target_word = "0" * 24 + "0" * 38 + "01"
        value_word = "0" * 64
        bytes_offset = format(160, "x").zfill(64)  # 5 head words * 32B
        predecessor_word = "0" * 64
        delay_word = format(3600, "x").zfill(64)
        calldata = "12345678abcd"  # selector 0x12345678 + 2-byte tail
        cd_len = format(6, "x").zfill(64)
        cd_padded = calldata + "0" * (64 - len(calldata))
        data_hex = "0x" + target_word + value_word + bytes_offset + predecessor_word + delay_word + cd_len + cd_padded

        log = {
            "topics": [CALL_SCHEDULED_TOPIC0, "0x" + "ab" * 32, "0x" + format(0, "x").zfill(64)],
            "data": data_hex,
            "blockNumber": "0x100",
            "transactionHash": "0xfeed",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "timelock_scheduled"
        assert ev["operation_id"] == "0x" + "ab" * 32
        assert ev["index"] == 0
        assert ev["target"] == "0x" + "00" * 19 + "01"
        assert ev["value"] == 0
        assert ev["predecessor"] == "0x" + "00" * 32
        assert ev["delay"] == 3600
        assert ev["calldata_length"] == 6
        assert ev["selector"] == "0x12345678"

    def test_call_executed_decodes_static_fields(self):
        from services.monitoring.event_topics import CALL_EXECUTED_TOPIC0, parse_governance_log

        target_word = "0" * 24 + "0" * 38 + "02"
        value_word = format(1000000000000000000, "x").zfill(64)  # 1 ETH
        bytes_offset = format(96, "x").zfill(64)  # 3 head words
        cd_len = format(4, "x").zfill(64)
        selector_word = "deadbeef" + "0" * 56
        data_hex = "0x" + target_word + value_word + bytes_offset + cd_len + selector_word

        log = {
            "topics": [CALL_EXECUTED_TOPIC0, "0x" + "cd" * 32, "0x" + format(7, "x").zfill(64)],
            "data": data_hex,
            "blockNumber": "0x200",
            "transactionHash": "0xbabe",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "timelock_executed"
        assert ev["operation_id"] == "0x" + "cd" * 32
        assert ev["index"] == 7
        assert ev["target"] == "0x" + "00" * 19 + "02"
        assert ev["value"] == 10**18
        assert ev["calldata_length"] == 4
        assert ev["selector"] == "0xdeadbeef"

    def test_short_data_field_does_not_crash(self):
        """RPCs occasionally truncate before the body."""
        from services.monitoring.event_topics import CALL_SCHEDULED_TOPIC0, parse_governance_log

        log = {
            "topics": [CALL_SCHEDULED_TOPIC0, "0x" + "ab" * 32, "0x" + format(0, "x").zfill(64)],
            "data": "0x" + "00" * 32,  # only 1 word — way too short
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["operation_id"] == "0x" + "ab" * 32
        assert ev["index"] == 0
        assert "target" not in ev
        assert "delay" not in ev
