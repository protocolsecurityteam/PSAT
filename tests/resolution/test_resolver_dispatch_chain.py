"""Dispatch-chain tests for semantic event-indexed resolution."""

from __future__ import annotations

from services.resolution.adapters import AdapterRegistry, EvaluationContext  # noqa: E402
from services.resolution.adapters.event_indexed import EventIndexedAdapter  # noqa: E402


def _registry() -> AdapterRegistry:
    reg = AdapterRegistry()
    reg.register(EventIndexedAdapter)
    return reg


def test_event_hint_routes_to_event_indexed():
    desc = {
        "kind": "mapping_membership",
        "storage_var": "owners",
        "key_sources": [{"source": "msg_sender"}],
        "enumeration_hint": [
            {
                "topic0": "0x" + "ab" * 32,
                "direction": "add",
                "topics_to_keys": {1: 0},
            }
        ],
    }
    chosen = _registry().pick(desc, EvaluationContext(chain_id=1, contract_address="0x" + "cc" * 20))
    assert chosen is EventIndexedAdapter


def test_no_event_hint_no_match():
    desc = {
        "kind": "mapping_membership",
        "storage_var": "owners",
        "key_sources": [{"source": "msg_sender"}],
    }
    assert _registry().pick(desc, EvaluationContext(chain_id=1, contract_address="0x" + "cc" * 20)) is None


def test_value_predicate_set_hint_routes_to_event_indexed():
    desc = {
        "kind": "mapping_membership",
        "storage_var": "owners",
        "key_sources": [{"source": "msg_sender"}],
        "value_predicate": {"op": "eq", "rhs_values": ["10"], "value_type": "uint256"},
        "enumeration_hint": [
            {
                "topic0": "0x" + "ab" * 32,
                "direction": "set",
                "value_position": 1,
                "key_position": 0,
                "event_signature": "OwnerSet(address,uint256)",
                "indexed_positions": [0],
            }
        ],
    }
    chosen = _registry().pick(desc, EvaluationContext(chain_id=1, contract_address="0x" + "cc" * 20))
    assert chosen is EventIndexedAdapter
