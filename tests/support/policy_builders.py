"""Minimal schema-complete artifact fixtures for policy tests.

Every builder produces a document that passes the typed artifact loaders
(``db.queue.typed``) — partial dicts used to slip through because reads were
untyped; validation is now fail-closed, so fixtures carry every required
field, populated with the schema's own "nothing determined" values.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

from schemas.assessment import Assessment

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


def _snapshot_value(**overrides: Any) -> dict:
    """One ``ControlSnapshotValue`` entry; callers override any field."""
    entry: dict[str, Any] = {
        "source": "state_variable:test",
        "value": None,
        "block_number": 1,
        "observed_via": "eth_call",
        "resolved_type": "unknown",
        "details": {},
    }
    entry.update(overrides)
    return entry


def _minimal_snapshot(controller_values: dict | None = None, address: str = TARGET_ADDRESS) -> dict:
    """A minimal ``control_snapshot`` document. Partial per-controller dicts
    are completed with the schema defaults (a bare ``{"value": ...}`` entry
    becomes a complete value read)."""
    values: dict[str, Any] = {}
    for controller_id, cv in (controller_values or {}).items():
        complete = {"source", "value", "block_number", "observed_via", "resolved_type", "details"}
        values[controller_id] = cv if set(cv) >= complete else _snapshot_value(**cv)
    return {
        "schema_version": "1",
        "contract_address": address,
        "contract_name": "TestContract",
        "block_number": 1,
        "controller_values": values,
    }


def _graph_with_nodes(nodes: list[dict], address: str = TARGET_ADDRESS) -> dict:
    return {
        "schema_version": "1",
        "root_contract_address": address,
        "max_depth": 6,
        "nodes": nodes,
        "edges": [],
    }


def _minimal_contract_analysis(address: str = TARGET_ADDRESS, name: str = "TestContract") -> dict:
    """A ``ContractAnalysis`` document carrying no findings: every analysis
    section reports its schema's nothing-determined shape."""
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


def _tracking_plan(address: str = TARGET_ADDRESS, name: str = "TestContract") -> dict:
    return {
        "schema_version": "1",
        "contract_address": address,
        "contract_name": name,
        "tracking_strategy": "event_first_with_polling_fallback",
        "tracked_controllers": [],
    }


def _assessment(
    *,
    analysis: dict | None = None,
    snapshot: dict | None = None,
    graph: dict | None = None,
    chain_id: int = 1,
) -> Assessment:
    """Canonical worker handoff fixture built from the old algorithm inputs."""

    from services.assessment import add_observations, add_resolution, build_static_assessment

    facts = analysis or _minimal_contract_analysis()
    snapshot = snapshot or _minimal_snapshot()
    if snapshot.get("controller_values"):
        facts = {**facts, "controller_tracking": list(facts.get("controller_tracking") or [])}
        known = {item.get("controller_id") for item in facts["controller_tracking"]}
        for key, value in snapshot["controller_values"].items():
            if key in known:
                continue
            facts["controller_tracking"].append(
                {
                    "controller_id": key,
                    "label": key,
                    "source": value.get("source") or key,
                    "kind": "state_variable",
                    "read_spec": {"strategy": "getter_call", "target": key},
                    "confidence": "exact",
                    "tracking_mode": "state_only",
                    "writer_functions": [],
                    "associated_events": [],
                    "polling_sources": [],
                    "notes": [],
                }
            )
    subject = facts["subject"]
    result = build_static_assessment(
        chain_id=chain_id,
        address=subject["address"],
        contract_name=subject["name"],
        code_hash=None,
        source_hash="test-source",
        analysis=facts,
        effects={
            "schema_version": "semantic-3",
            "contract_name": subject["name"],
            "functions": {},
            "claims_schema_version": "claims/1",
            "claim_analyses": {},
            "claim_diagnostics": [],
        },
        predicate_trees={"schema_version": "semantic", "trees": {}},
    )
    result = add_observations(result, snapshot)
    if graph is not None:
        result = add_resolution(result, graph, chain_id=chain_id)
    return result


def _authority_bundle(snapshot: dict | None = None) -> dict:
    """A nested ``LoadedArtifacts`` bundle for the authority contract."""
    analysis = _minimal_contract_analysis(address=AUTH_ADDRESS, name="Authority")
    return {
        "analysis": analysis,
        "tracking_plan": _tracking_plan(address=AUTH_ADDRESS, name="Authority"),
        "snapshot": snapshot or _minimal_snapshot({}, address=AUTH_ADDRESS),
    }
