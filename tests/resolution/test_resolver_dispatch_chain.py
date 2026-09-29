"""Dispatch-chain tests for semantic event-indexed resolution."""

from __future__ import annotations

import pytest

from services.resolution.adapters import AdapterRegistry, EvaluationContext
from services.resolution.adapters.event_indexed import EventIndexedAdapter


def _registry() -> AdapterRegistry:
    reg = AdapterRegistry()
    reg.register(EventIndexedAdapter)
    return reg


_KEY_SOURCES = [{"source": "msg_sender"}]

_DISPATCH_CASES = [
    pytest.param(
        {
            "kind": "mapping_membership",
            "storage_var": "owners",
            "key_sources": _KEY_SOURCES,
            "enumeration_hint": [{"topic0": "0x" + "ab" * 32, "direction": "add", "topics_to_keys": {1: 0}}],
        },
        EventIndexedAdapter,
        id="event-hint-routes-to-event-indexed",
    ),
    # Fail-closed: no enumeration hint means no adapter.
    pytest.param(
        {"kind": "mapping_membership", "storage_var": "owners", "key_sources": _KEY_SOURCES},
        None,
        id="no-event-hint-no-match",
    ),
    pytest.param(
        {
            "kind": "mapping_membership",
            "storage_var": "owners",
            "key_sources": _KEY_SOURCES,
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
        },
        EventIndexedAdapter,
        id="value-predicate-set-hint-routes-to-event-indexed",
    ),
]


@pytest.mark.parametrize("desc, expected", _DISPATCH_CASES)
def test_adapter_dispatch(desc, expected):
    chosen = _registry().pick(desc, EvaluationContext(chain_id=1, contract_address="0x" + "cc" * 20))
    assert chosen is expected
