"""Job / snapshot / graph builders for the policy worker.

Extracted verbatim from ``test_policy_worker_integration``, which
``test_effects_stage`` imported these from cross-module.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
AUTH_ADDRESS = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TARGET_ADDRESS = "0x1111111111111111111111111111111111111111"


def _job(**overrides: Any) -> SimpleNamespace:
    payload: dict[str, Any] = {
        "id": uuid.uuid4(),
        "address": TARGET_ADDRESS,
        "name": "TestContract",
        "company": None,
        "protocol_id": None,
        "request": {"rpc_url": "https://rpc.example", "chain_id": 1},
    }
    payload.update(overrides)
    return SimpleNamespace(**payload)


def _minimal_snapshot(controller_values: dict | None = None) -> dict:
    """Return a minimal control_snapshot dict."""
    return {
        "contract_address": TARGET_ADDRESS,
        "controller_values": controller_values or {},
    }


def _graph_with_nodes(nodes: list[dict]) -> dict:
    return {"nodes": nodes, "edges": []}


def _minimal_contract_analysis() -> dict:
    return {
        "contract_address": TARGET_ADDRESS,
        "contract_name": "TestContract",
        "functions": [],
    }


def _authority_bundle(snapshot: dict | None = None) -> dict:
    return {
        "analysis": {
            "subject": {"address": AUTH_ADDRESS, "name": "Authority"},
        },
        "tracking_plan": {
            "schema_version": "0.1",
            "contract_address": AUTH_ADDRESS,
            "contract_name": "Authority",
            "tracking_strategy": "event_first_with_polling_fallback",
            "tracked_controllers": [],
        },
        "snapshot": snapshot or {"contract_address": AUTH_ADDRESS, "controller_values": {}},
    }
