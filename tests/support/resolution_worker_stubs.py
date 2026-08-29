"""Job factory and dependency stubs for ``ResolutionWorker.process`` tests.

Shared by ``tests/resolution/test_resolution_worker.py`` and ``tests/resolution/test_flow_asset_plane.py``
so the two exercise the worker against one stub surface.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest

TARGET_ADDRESS = "0x1111111111111111111111111111111111111111"
PROXY_ADDRESS = "0x2222222222222222222222222222222222222222"
CHILD_ADDRESS = "0x3333333333333333333333333333333333333333"


def _job(**overrides: Any) -> SimpleNamespace:
    payload: dict[str, Any] = {
        "id": uuid.uuid4(),
        "address": TARGET_ADDRESS,
        "name": "TestContract",
        "company": None,
        "protocol_id": None,
        "request": {"rpc_url": "https://rpc.example"},
    }
    payload.update(overrides)
    req = payload.get("request")
    if isinstance(req, dict) and "chain" not in req and "chain_id" not in req:
        payload["request"] = {**req, "chain": "ethereum"}
    return SimpleNamespace(**payload)


def _minimal_tracking_plan() -> dict:
    return {
        "schema_version": "1",
        "contract_address": TARGET_ADDRESS,
        "contract_name": "TestContract",
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [],
    }


def _minimal_contract_analysis(address: str = TARGET_ADDRESS, name: str = "TestContract") -> dict:
    """A schema-complete ``ContractAnalysis`` carrying no findings."""
    return {
        "schema_version": "2",
        "subject": {
            "address": address,
            "name": name,
            "compiler_version": "unknown",
            "source_verified": None,
        },
        "analysis_status": {"static_analysis_completed": True, "errors": []},
        "summary": {
            "control_model": "unknown",
            "is_upgradeable": False,
            "is_pausable": None,
            "has_timelock": None,
            "standards": None,
            "is_factory": None,
            "is_nft": None,
        },
        "contract_classification": {
            "standards": [],
            "is_erc20": False,
            "is_erc721": False,
            "is_erc1155": False,
            "is_nft": False,
            "is_factory": False,
            "factory_functions": None,
            "evidence": [],
        },
        "semantic_control": {
            "pattern": "unknown",
            "owner_variables": [],
            "admin_variables": [],
            "role_definitions": [],
            "semantic_functions": [],
            "current_holders": {"status": "unknown_static_only"},
        },
        "upgradeability": {
            "is_upgradeable": False,
            "is_upgradeable_proxy": False,
            "pattern": "none",
            "upgradeable_version": None,
            "implementation_slots": [],
            "admin_paths": [],
            "evidence": [],
        },
        "pausability": {
            "is_pausable": None,
            "pause_functions": [],
            "unpause_functions": [],
            "gating_modifiers": [],
            "pause_variables": [],
            "authorized_roles": [],
            "evidence": [],
        },
        "timelock": {
            "has_timelock": None,
            "pattern": "none",
            "delay": None,
            "delay_source": "not_read",
            "delay_variables": [],
            "queue_execute_functions": [],
            "authorized_roles": [],
            "evidence": [],
        },
        "audit_alignment": {"status": "not_checked", "bytecode_match": "unknown", "notes": []},
        "tracking_hints": [],
        "controller_tracking": [],
    }


def _minimal_snapshot() -> dict:
    return {
        "schema_version": "1",
        "contract_address": TARGET_ADDRESS,
        "contract_name": "TestContract",
        "block_number": 12345,
        "controller_values": {},
    }


def _resolved_graph(nodes: list[dict] | None = None, edges: list[dict] | None = None) -> dict:
    return {
        "root_contract_address": TARGET_ADDRESS,
        "nodes": nodes or [],
        "edges": edges or [],
    }


def _patch_all(monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> dict[str, Any]:
    """Patch all external dependencies for ResolutionWorker and return tracking dicts."""
    tracking_plan = overrides.get("tracking_plan", _minimal_tracking_plan())
    contract_analysis = overrides.get("contract_analysis", _minimal_contract_analysis())
    snapshot = overrides.get("snapshot", _minimal_snapshot())
    resolved_graph = overrides.get("resolved_graph", _resolved_graph())
    dependencies = overrides.get("dependencies", None)  # None = no artifact

    artifact_store: dict[str, Any] = {}

    def fake_get_artifact(_session: Any, _job_id: Any, name: str) -> Any:
        lookup: dict[str, Any] = {
            "control_tracking_plan": tracking_plan,
            "contract_analysis": contract_analysis,
            "dependencies": dependencies,
        }
        return lookup.get(name)

    store_calls: list[tuple[str, Any]] = []

    def fake_store_artifact(_session: Any, _job_id: Any, name: str, data: Any = None, text_data: Any = None) -> None:
        store_calls.append((name, data))
        artifact_store[name] = data

    create_job_calls: list[dict] = []

    def fake_create_job(_session: Any, request_dict: dict, initial_stage: Any = None) -> Any:
        create_job_calls.append(request_dict)
        return SimpleNamespace(id=uuid.uuid4(), company=None)

    def fake_build_control_snapshot(plan: Any, rpc_url: str, **_kw: Any) -> dict:
        return snapshot

    def fake_resolve_control_graph(
        *,
        root_artifacts: Any = None,
        rpc_url: str = "",
        max_depth: int = 6,
        workspace_prefix: str = "",
        nested_artifacts_override: Any = None,
        **_kw: Any,  # absorb classify_cache, initial_graph, future kwargs
    ) -> tuple[dict, dict]:
        return resolved_graph, {}

    monkeypatch.setattr("workers.resolution_worker.get_artifact", fake_get_artifact)
    monkeypatch.setattr("workers.resolution_worker.store_artifact", fake_store_artifact)
    monkeypatch.setattr("workers.resolution_worker.create_job", fake_create_job)
    # The perimeter walk moved to services/discovery/perimeter; the resolution
    # worker still imports create_job for its dependency-provider spawn, so both
    # bindings are stubbed and the assertions below are unchanged.
    monkeypatch.setattr("services.discovery.perimeter.create_job", fake_create_job)
    monkeypatch.setattr("workers.resolution_worker.build_control_snapshot", fake_build_control_snapshot)
    monkeypatch.setattr("workers.resolution_worker.resolve_control_graph", fake_resolve_control_graph)
    monkeypatch.setattr("workers.base.update_job_detail", lambda *a, **kw: None)

    return {
        "store_calls": store_calls,
        "create_job_calls": create_job_calls,
        "artifact_store": artifact_store,
    }
