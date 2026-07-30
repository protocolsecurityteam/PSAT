"""C1 monitor half: EnabledModule / DisabledModule / ChangedGuard topics and the
two Safe storage-slot poll entries.

Before this, the pipeline could see a module EXECUTE
(``ExecutionFromModule[Success|Failure]``) but not one being ENABLED, and no Safe
address had a cursor on any of the three topics. The poll entries observe CHANGE
in the head/guard words; membership itself is decided in the resolution plane
(see tests/test_classify_safe_modules_guard.py), never here.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.monitoring.event_topics import (  # noqa: E402
    ALL_EVENT_TOPICS,
    CHANGED_GUARD_TOPIC0,
    DISABLED_MODULE_TOPIC0,
    ENABLED_MODULE_TOPIC0,
    GOVERNANCE_EVENT_TOPICS,
    parse_any_log,
    parse_governance_log,
)
from services.monitoring.polling_plan import (  # noqa: E402
    SAFE_GUARD_SLOT,
    SAFE_MODULES_HEAD_SLOT,
    build_polling_plan,
)
from services.monitoring.unified_watcher import _WRITE_TARGET_TO_CONFIG_KEYS, _should_watch  # noqa: E402

MODULE = "0x2e1b5a40edc922bce489668b11749b8eabd67f6b"
SAFE = "0x21f73d42eb58ba49ddb685dc29d3bf5c0f0373ca"


def test_topic0s_match_the_recomputed_signature_hashes():
    assert ENABLED_MODULE_TOPIC0 == "0x" + keccak(text="EnabledModule(address)").hex()
    assert DISABLED_MODULE_TOPIC0 == "0x" + keccak(text="DisabledModule(address)").hex()
    assert CHANGED_GUARD_TOPIC0 == "0x" + keccak(text="ChangedGuard(address)").hex()
    assert ENABLED_MODULE_TOPIC0 == "0xecdf3a3effea5783a3c4c2140e677577666428d44ed9d474a0b3a4c9943f8440"
    assert DISABLED_MODULE_TOPIC0 == "0xaab4fa2b463f581b2b32cb3b7e3b704b9ce37cc209b5fb4d77e593ace4054276"
    assert CHANGED_GUARD_TOPIC0 == "0x1151116914515bc0891ff9047a6cb32cf902546f83066499bcf8ba33d2353fa2"


def test_topics_are_registered_and_therefore_scanned():
    """``_scan_topics_union`` is the registry ∪ per-contract tracked topics, so
    registration is what enrolls every active Safe."""
    assert GOVERNANCE_EVENT_TOPICS[ENABLED_MODULE_TOPIC0] == "safe_module_enabled"
    assert GOVERNANCE_EVENT_TOPICS[DISABLED_MODULE_TOPIC0] == "safe_module_disabled"
    assert GOVERNANCE_EVENT_TOPICS[CHANGED_GUARD_TOPIC0] == "safe_guard_changed"
    for topic in (ENABLED_MODULE_TOPIC0, DISABLED_MODULE_TOPIC0, CHANGED_GUARD_TOPIC0):
        assert topic in ALL_EVENT_TOPICS


def _log(topic0: str, *, indexed: bool):
    """The same event as emitted by an indexing (1.4.1) and a non-indexing
    (1.1.1 / 1.3.0) singleton. Same topic0 either way."""
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
    """A topics-only decoder returns nothing on a 1.3.0 Safe, and 1.3.0 is 8 of
    the 19 Safe principals on this corpus."""
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


def test_empty_data_and_no_topic_yields_no_address():
    """No address anywhere ⇒ the key is absent, not the zero address."""
    log = {
        "address": SAFE,
        "topics": [ENABLED_MODULE_TOPIC0],
        "data": "0x",
        "blockNumber": hex(1),
        "transactionHash": "0x" + "ab" * 32,
        "logIndex": "0x0",
    }
    parsed = _parsed(log)
    assert parsed["event_type"] == "safe_module_enabled"
    assert "module" not in parsed


def test_write_targets_gate_on_watch_safe_modules():
    assert _WRITE_TARGET_TO_CONFIG_KEYS["_safe_modules"] == ("watch_safe_modules",)
    assert _WRITE_TARGET_TO_CONFIG_KEYS["_safe_guard"] == ("watch_safe_modules",)


def test_should_watch_respects_the_flag():
    class _MC:
        def __init__(self, config):
            self.monitoring_config = config

    parsed = _parsed(_log(ENABLED_MODULE_TOPIC0, indexed=True))
    assert _should_watch(cast(Any, _MC({"watch_safe_modules": True})), parsed) is True
    assert _should_watch(cast(Any, _MC({"watch_safe_modules": False})), parsed) is False
    # Rows enrolled before the flag existed default on rather than silently
    # dropping the event.
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
    # The pre-existing entry is untouched.
    assert plan["threshold"]["target"] == "getThreshold"


def test_slot_constants_equal_their_preimages():
    assert SAFE_MODULES_HEAD_SLOT == "0x" + keccak((1).to_bytes(32, "big") + (1).to_bytes(32, "big")).hex()
    assert SAFE_GUARD_SLOT == "0x" + keccak(text="guard_manager.guard.address").hex()


def test_non_safe_types_get_no_safe_slot_entries():
    fields = {entry["field"] for entry in build_polling_plan(contract_type="timelock")}
    assert "modules_head" not in fields
    assert "guard" not in fields


def test_poll_entries_translate_to_pinned_storage_reads():
    from services.monitoring.unified_watcher import _rpc_call_for_entry

    plan = {entry["field"]: entry for entry in build_polling_plan(contract_type="safe")}
    method, params = cast(tuple, _rpc_call_for_entry(SAFE, plan["modules_head"]))
    assert method == "eth_getStorageAt"
    assert params[:2] == [SAFE, SAFE_MODULES_HEAD_SLOT]
