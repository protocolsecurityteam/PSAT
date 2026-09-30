"""C1 monitor half: module and guard change events plus the Safe slot poll entries.

The poll observes change only; membership is decided in tests/resolution/test_classify_safe_modules_guard.py.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from services.monitoring.event_topics import (
    ALL_EVENT_TOPICS,
    CHANGED_GUARD_TOPIC0,
    DISABLED_MODULE_TOPIC0,
    ENABLED_MODULE_TOPIC0,
    EXECUTION_FAILURE_TOPIC0,
    EXECUTION_FROM_MODULE_FAILURE_TOPIC0,
    EXECUTION_FROM_MODULE_SUCCESS_TOPIC0,
    EXECUTION_SUCCESS_TOPIC0,
    GOVERNANCE_EVENT_TOPICS,
    parse_any_log,
    parse_governance_log,
)
from services.monitoring.polling_plan import (
    SAFE_GUARD_SLOT,
    SAFE_MODULES_HEAD_SLOT,
    build_polling_plan,
)
from services.monitoring.unified_watcher import _should_watch

MODULE = "0x2e1b5a40edc922bce489668b11749b8eabd67f6b"
SAFE = "0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca"


def test_topics_are_registered_and_therefore_scanned():
    """Registration is what enrolls every active Safe."""
    assert GOVERNANCE_EVENT_TOPICS[ENABLED_MODULE_TOPIC0] == "safe_module_enabled"
    assert GOVERNANCE_EVENT_TOPICS[DISABLED_MODULE_TOPIC0] == "safe_module_disabled"
    assert GOVERNANCE_EVENT_TOPICS[CHANGED_GUARD_TOPIC0] == "safe_guard_changed"
    for topic in (ENABLED_MODULE_TOPIC0, DISABLED_MODULE_TOPIC0, CHANGED_GUARD_TOPIC0):
        assert topic in ALL_EVENT_TOPICS


def _log(topic0: str, *, indexed: bool):
    if indexed:
        return {
            "address": SAFE,
            "topics": [topic0, "0x" + "0" * 24 + MODULE[2:]],
            "data": "0x",
            "blockNumber": hex(25643300),
            "transactionHash": "0x" + "ab" * 32,
            "logIndex": "0x0",
        }
    return {
        "address": SAFE,
        "topics": [topic0],
        "data": "0x" + "0" * 24 + MODULE[2:],
        "blockNumber": hex(25643300),
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x0",
    }


def _parsed(log: dict) -> dict[str, Any]:
    out = parse_governance_log(log)
    assert out is not None
    return out


def test_enabled_module_decodes_on_both_indexing_conventions():
    """1.3.0 is 9 of the 19 Safe principals here, and it doesn't index the address."""
    for indexed in (True, False):
        parsed = _parsed(_log(ENABLED_MODULE_TOPIC0, indexed=indexed))
        assert parsed["event_type"] == "safe_module_enabled"
        assert parsed["module"] == MODULE
        assert parsed["effect_tags"]["writes"] == ["_safe_modules"]


def test_disabled_module_and_changed_guard_decode():
    parsed = _parsed(_log(DISABLED_MODULE_TOPIC0, indexed=False))
    assert parsed["event_type"] == "safe_module_disabled"
    assert parsed["module"] == MODULE

    parsed = cast(dict, parse_any_log(_log(CHANGED_GUARD_TOPIC0, indexed=True)))
    assert parsed["event_type"] == "safe_guard_changed"
    assert parsed["guard"] == MODULE
    assert parsed["effect_tags"]["writes"] == ["_safe_guard"]


# The published address is the fact. A slot or body that is not a whole 32-byte word decodes to nothing; padding it
# would mint an address, and on ``safe_guard_changed`` the zero address reads as "guard removed".


def _log_with(topic0: str, *, topics_tail: list[str], data: str) -> dict:
    return {
        "address": SAFE,
        "topics": [topic0, *topics_tail],
        "data": data,
        "blockNumber": hex(25643300),
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x0",
    }


_WORD = "0" * 24 + MODULE[2:]


@pytest.mark.parametrize(
    ("topic0", "topics_tail", "data", "event_type", "key"),
    [
        pytest.param(ENABLED_MODULE_TOPIC0, [], "0x", "safe_module_enabled", "module", id="empty-data-and-no-topic"),
        # Padding ``"0x"`` would mint the zero address, which reads as "guard removed".
        pytest.param(ENABLED_MODULE_TOPIC0, ["0x"], "0x", "safe_module_enabled", "module", id="empty-topic-enabled"),
        pytest.param(DISABLED_MODULE_TOPIC0, ["0x"], "0x", "safe_module_disabled", "module", id="empty-topic-disabled"),
        pytest.param(CHANGED_GUARD_TOPIC0, ["0x"], "0x", "safe_guard_changed", "guard", id="empty-topic-guard"),
        pytest.param(
            EXECUTION_FROM_MODULE_SUCCESS_TOPIC0,
            ["0x"],
            "0x",
            "safe_module_executed",
            "module",
            id="empty-topic-module-execution-success",
        ),
        pytest.param(
            EXECUTION_FROM_MODULE_FAILURE_TOPIC0,
            ["0x"],
            "0x",
            "safe_module_failed",
            "module",
            id="empty-topic-module-execution-failure",
        ),
        # ``"0X"`` survives a ``"0x"`` strip and yields a different, plausible address.
        pytest.param(
            ENABLED_MODULE_TOPIC0, [], "0X" + _WORD, "safe_module_enabled", "module", id="uppercase-0x-data-body"
        ),
        # ``bytes.fromhex`` ignores whitespace, so the byte-length check rejects these.
        pytest.param(ENABLED_MODULE_TOPIC0, [], "0x" + " " * 64, "safe_module_enabled", "module", id="whitespace-body"),
        pytest.param(
            ENABLED_MODULE_TOPIC0,
            [],
            "0x" + "0" * 62 + "  ",
            "safe_module_enabled",
            "module",
            id="trailing-whitespace-body",
        ),
        pytest.param(
            ENABLED_MODULE_TOPIC0,
            [],
            "0x" + "1_" + "0" * 62,
            "safe_module_enabled",
            "module",
            id="underscore-body",
        ),
        pytest.param(ENABLED_MODULE_TOPIC0, [], "0x", "safe_module_enabled", "module", id="partial-word-empty-body"),
        pytest.param(ENABLED_MODULE_TOPIC0, [], "0x00", "safe_module_enabled", "module", id="partial-word-one-byte"),
        pytest.param(
            ENABLED_MODULE_TOPIC0, [], "0x" + "0" * 63, "safe_module_enabled", "module", id="partial-word-63-nibbles"
        ),
        pytest.param(
            ENABLED_MODULE_TOPIC0, [], "0x" + "0" * 65, "safe_module_enabled", "module", id="partial-word-65-nibbles"
        ),
        pytest.param(
            ENABLED_MODULE_TOPIC0,
            ["0x" + "ff" * 32],
            "0x",
            "safe_module_enabled",
            "module",
            id="dirty-top-twelve-bytes",
        ),
    ],
)
def test_malformed_topic_or_data_publishes_no_address(topic0, topics_tail, data, event_type, key):
    parsed = _parsed(_log_with(topic0, topics_tail=topics_tail, data=data))
    assert parsed["event_type"] == event_type
    assert key not in parsed


def test_well_formed_logs_decode_byte_identically():
    for topic0, key in (
        (ENABLED_MODULE_TOPIC0, "module"),
        (DISABLED_MODULE_TOPIC0, "module"),
        (CHANGED_GUARD_TOPIC0, "guard"),
    ):
        for indexed in (True, False):
            parsed = _parsed(_log(topic0, indexed=indexed))
            assert parsed[key] == MODULE
    # "Guard removed" is a real event.
    parsed = _parsed(_log_with(CHANGED_GUARD_TOPIC0, topics_tail=["0x" + "0" * 64], data="0x"))
    assert parsed["guard"] == "0x" + "0" * 40


def test_should_watch_respects_the_flag():
    class _MC:
        def __init__(self, config):
            self.monitoring_config = config

    parsed = _parsed(_log(ENABLED_MODULE_TOPIC0, indexed=True))
    assert _should_watch(cast(Any, _MC({"watch_safe_modules": True})), parsed) is True
    assert _should_watch(cast(Any, _MC({"watch_safe_modules": False})), parsed) is False
    # Rows enrolled before the flag existed default on.
    assert _should_watch(cast(Any, _MC({"watch_ownership": True})), parsed) is True


def test_safe_polling_plan_carries_both_storage_slots():
    plan = {entry["field"]: entry for entry in build_polling_plan(contract_type="safe")}
    assert plan["modules_head"]["kind"] == "storage_slot"
    assert plan["modules_head"]["slot"] == SAFE_MODULES_HEAD_SLOT
    assert plan["modules_head"]["suppress_when_scan_event_types"] == [
        "safe_module_enabled",
        "safe_module_disabled",
    ]
    assert plan["guard"]["kind"] == "storage_slot"
    assert plan["guard"]["slot"] == SAFE_GUARD_SLOT
    assert plan["guard"]["suppress_when_scan_event_types"] == ["safe_guard_changed"]
    assert plan["threshold"]["target"] == "getThreshold"


def test_non_safe_types_get_no_safe_slot_entries():
    fields = {entry["field"] for entry in build_polling_plan(contract_type="timelock")}
    assert "modules_head" not in fields
    assert "guard" not in fields


class TestSafeExecutionEvents:
    """Emitted for every executed Safe tx."""

    @pytest.mark.parametrize(
        ("topic0", "hash_byte", "payment", "tx", "log_index", "event_type"),
        [
            pytest.param(EXECUTION_SUCCESS_TOPIC0, "ab", 123456, "0xfeed", 3, "safe_tx_executed", id="success"),
            pytest.param(EXECUTION_FAILURE_TOPIC0, "cd", 0, "0xbabe", 0, "safe_tx_failed", id="failure"),
        ],
    )
    def test_execution_decodes(self, topic0, hash_byte, payment, tx, log_index, event_type):
        log = {
            "topics": [topic0],
            "data": "0x" + hash_byte * 32 + format(payment, "x").zfill(64),
            "blockNumber": "0x100",
            "transactionHash": tx,
            "logIndex": hex(log_index),
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == event_type
        assert ev["safe_tx_hash"] == "0x" + hash_byte * 32
        assert ev["payment"] == payment
        assert ev["log_index"] == log_index

    def test_short_data_does_not_crash(self):
        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0],
            "data": "0x" + "ab" * 8,  # well under the 64+64 hex chars expected
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == "safe_tx_executed"
        assert "safe_tx_hash" not in ev
        assert "payment" not in ev

    @pytest.mark.parametrize(
        ("topic0", "address", "safe_tx_hash", "data", "block", "tx", "log_index", "event_type", "payment"),
        [
            # Byte-for-byte log 414 of mainnet tx 0xf047c068…, which decoded to neither field before this arm.
            pytest.param(
                EXECUTION_SUCCESS_TOPIC0,
                "0x607d0c7e3578802eb46d388cb86cfba8ff657306",
                "0x557306e1acffe8fbc5eeed5d3c7f67aae3713431d50c9224fec4ec51efc2a7b2",
                "0x" + "0" * 64,
                hex(25683190),
                "0xf047c068b4d7311344adfb02fc56310d7200d12799a9894675b3b66ff5f2b431",
                hex(414),
                "safe_tx_executed",
                0,
                id="success-mainnet",
            ),
            pytest.param(
                EXECUTION_FAILURE_TOPIC0,
                SAFE,
                "0x" + "cd" * 32,
                "0x" + format(4200, "x").zfill(64),
                "0x100",
                "0xbabe",
                "0x0",
                "safe_tx_failed",
                4200,
                id="failure",
            ),
        ],
    )
    def test_indexed_txhash_variant_decodes(
        self, topic0, address, safe_tx_hash, data, block, tx, log_index, event_type, payment
    ):
        log = {
            "address": address,
            "topics": [topic0, safe_tx_hash],
            "data": data,
            "blockNumber": block,
            "transactionHash": tx,
            "logIndex": log_index,
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == event_type
        assert ev["safe_tx_hash"] == safe_tx_hash
        assert ev["payment"] == payment

    # A body that isn't payment alone means an unreadable layout; the hash still decodes, and no payment is invented.
    @pytest.mark.parametrize(
        "data",
        [
            pytest.param("0x" + "11" * 32 + "22" * 32, id="two-word-body"),
            pytest.param("0x", id="empty-body"),
        ],
    )
    def test_indexed_variant_with_unreadable_body_publishes_no_payment(self, data):
        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0, "0x" + "ab" * 32],
            "data": data,
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["safe_tx_hash"] == "0x" + "ab" * 32
        assert "payment" not in ev

    def test_indexed_variant_with_malformed_topic_publishes_no_hash(self):
        log = {
            "topics": [EXECUTION_SUCCESS_TOPIC0, "0xabcd"],
            "data": "0x" + format(7, "x").zfill(64),
            "blockNumber": "0x1",
            "transactionHash": "0xa",
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert "safe_tx_hash" not in ev
        assert ev["payment"] == 7

    @pytest.mark.parametrize(
        ("topic0", "module_byte", "tx", "event_type"),
        [
            pytest.param(EXECUTION_FROM_MODULE_SUCCESS_TOPIC0, "ee", "0xfeed", "safe_module_executed", id="success"),
            pytest.param(EXECUTION_FROM_MODULE_FAILURE_TOPIC0, "ff", "0xbeef", "safe_module_failed", id="failure"),
        ],
    )
    def test_execution_from_module_decodes(self, topic0, module_byte, tx, event_type):
        log = {
            "topics": [topic0, "0x" + "0" * 24 + module_byte * 20],  # padded module address in topic
            "data": "0x",
            "blockNumber": "0x10",
            "transactionHash": tx,
        }
        ev = parse_governance_log(log)
        assert ev is not None
        assert ev["event_type"] == event_type
        assert ev["module"] == "0x" + module_byte * 20
