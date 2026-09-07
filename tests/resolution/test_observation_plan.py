import json
from pathlib import Path
from typing import cast

from schemas.observations import ControllerInstruction, ObservationPlan
from schemas.static_facts import StaticFacts
from services.resolution.observation_plan import build_observation_plan
from services.static import collect_static_inputs

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "contracts"


def _write_project(tmp_path: Path, contract_name: str, source_code: str) -> Path:
    project_dir = tmp_path / contract_name
    (project_dir / "src").mkdir(parents=True)
    (project_dir / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = ["lib"]\nsolc_version = "0.8.19"\n'
    )
    (project_dir / "src" / f"{contract_name}.sol").write_text(source_code)
    (project_dir / "contract_meta.json").write_text(
        json.dumps(
            {
                "address": "0x1111111111111111111111111111111111111111",
                "contract_name": contract_name,
                "compiler_version": "v0.8.19+commit.7dd6d404",
            }
        )
        + "\n"
    )
    return project_dir


def _fixture_source(relative_path: str) -> str:
    return (FIXTURES_DIR / relative_path).read_text()


def _tracked_controller(plan: ObservationPlan, label: str) -> ControllerInstruction:
    for controller in plan["tracked_controllers"]:
        if controller["label"] == label:
            return controller
    raise AssertionError(f"Tracked controller {label} not found")


def test_build_observation_plan_uses_event_watch_when_available(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "AuthModifierController",
        _fixture_source("composed/auth_modifier_controller.sol"),
    )
    analysis = collect_static_inputs(project_dir)[0]

    plan = build_observation_plan(analysis)

    owner = _tracked_controller(plan, "owner")
    assert owner["tracking_mode"] == "event_plus_state"
    assert owner["event_watch"] == {
        "transport": "wss_logs",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "events": [
            {
                "name": "OwnershipTransferred",
                "signature": "OwnershipTransferred(address,address)",
                "topic0": "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
                "inputs": [
                    {"name": "user", "type": "address", "indexed": True},
                    {"name": "newOwner", "type": "address", "indexed": True},
                ],
                "effect_tags": {"writes": ["owner"]},
            }
        ],
        "writer_functions": ["transferOwnership(address)"],
    }
    assert owner["polling_fallback"]["cadence"] == "realtime_confirm"

    authority = _tracked_controller(plan, "authority")
    assert authority["event_watch"] == {
        "transport": "wss_logs",
        "contract_address": "0x1111111111111111111111111111111111111111",
        "events": [
            {
                "name": "AuthorityUpdated",
                "signature": "AuthorityUpdated(address,address)",
                "topic0": "0xa3396fd7f6e0a21b50e5089d2da70d5ac0a3bbbd1f617a93f134b76389980198",
                "inputs": [
                    {"name": "user", "type": "address", "indexed": True},
                    {"name": "newAuthority", "type": "address", "indexed": True},
                ],
                "effect_tags": {"writes": ["authority"]},
            }
        ],
        "writer_functions": ["setAuthority(AuthorityLike)"],
    }


def test_build_observation_plan_falls_back_to_state_only(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "OwnerNoEvent",
        _fixture_source("tracking/owner_update_no_event.sol"),
    )
    analysis = collect_static_inputs(project_dir)[0]

    plan = build_observation_plan(analysis)

    owner = _tracked_controller(plan, "owner")
    assert owner["tracking_mode"] == "state_only"
    assert owner["event_watch"] is None
    assert owner["polling_fallback"]["cadence"] == "state_only"
    assert owner["polling_fallback"]["polling_sources"] == ["owner"]


def test_build_observation_plan_from_dict_matches_fixture():
    """Analysis dict -> plan produces the documented event_first shape."""
    analysis = {
        "schema_version": "0.1",
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Example",
            "compiler_version": "v0.8.19",
            "source_verified": True,
        },
        "controller_tracking": [
            {
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "owner",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "owner",
                    "kind": "state_variable",
                    "state_variable_name": "owner",
                    "type": "address",
                },
                "tracking_mode": "event_plus_state",
                "writer_functions": [
                    {
                        "contract": "OwnableLike",
                        "function": "transferOwnership(address)",
                        "visibility": "public",
                        "writes": ["owner"],
                        "associated_events": [
                            {
                                "name": "OwnershipTransferred",
                                "signature": "OwnershipTransferred(address,address)",
                                "topic0": "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
                                "inputs": [
                                    {"name": "user", "type": "address", "indexed": True},
                                    {"name": "newOwner", "type": "address", "indexed": True},
                                ],
                            }
                        ],
                        "evidence": [],
                    }
                ],
                "associated_events": [
                    {
                        "name": "OwnershipTransferred",
                        "signature": "OwnershipTransferred(address,address)",
                        "topic0": "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0",
                        "inputs": [
                            {"name": "user", "type": "address", "indexed": True},
                            {"name": "newOwner", "type": "address", "indexed": True},
                        ],
                    }
                ],
                "polling_sources": ["owner"],
                "notes": ["Monitor associated events for low-latency detection and confirm state via RPC."],
            }
        ],
    }

    plan = build_observation_plan(cast(StaticFacts, analysis))

    assert plan["tracking_strategy"] == "event_first_with_polling_fallback"
    event_watch = plan["tracked_controllers"][0]["event_watch"]
    assert event_watch is not None
    assert event_watch["events"][0]["name"] == "OwnershipTransferred"


def test_build_observation_plan_filters_non_controller_runtime_reads():
    """Only address-like state and role identifiers should reach runtime resolution."""
    base_target = {
        "tracking_mode": "state_only",
        "writer_functions": [],
        "associated_events": [],
        "polling_sources": [],
        "notes": [],
    }
    analysis = {
        "schema_version": "0.1",
        "subject": {
            "address": "0x1111111111111111111111111111111111111111",
            "name": "Example",
            "compiler_version": "v0.8.19",
            "source_verified": True,
        },
        "controller_tracking": [
            {
                **base_target,
                "controller_id": "state_variable:owner",
                "label": "owner",
                "source": "owner",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "owner",
                    "kind": "state_variable",
                    "state_variable_name": "owner",
                    "type": "address",
                },
            },
            {
                **base_target,
                "controller_id": "state_variable:paused",
                "label": "paused",
                "source": "paused",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "paused",
                    "kind": "state_variable",
                    "state_variable_name": "paused",
                    "type": "bool",
                },
            },
            {
                **base_target,
                "controller_id": "state_variable:redemptionManager",
                "label": "redemptionManager",
                "source": "redemptionManager",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "redemptionManager",
                    "kind": "state_variable",
                    "state_variable_name": "redemptionManager",
                    "type": "IRedemptionManager",
                },
            },
            {
                **base_target,
                "controller_id": "state_variable:minters",
                "label": "minters",
                "source": "minters",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "minters",
                    "kind": "state_variable",
                    "state_variable_name": "minters",
                    "type": "mapping(address => bool)",
                },
            },
            {
                **base_target,
                "controller_id": "state_variable:accountantState",
                "label": "accountantState",
                "source": "accountantState",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "accountantState",
                    "kind": "state_variable",
                    "state_variable_name": "accountantState",
                    "type": "Example.AccountantState",
                    "type_kind": "struct",
                    "components": [
                        {
                            "name": "payoutAddress",
                            "type": "address",
                            "abi_type": "address",
                            "type_kind": "address",
                        }
                    ],
                },
            },
            {
                **base_target,
                "controller_id": "state_variable:accountantState.payoutAddress",
                "label": "accountantState.payoutAddress",
                "source": "accountantState.payoutAddress",
                "kind": "state_variable",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "accountantState",
                    "kind": "state_variable",
                    "state_variable_name": "accountantState",
                    "type": "address",
                    "type_kind": "address",
                    "parent_type": "Example.AccountantState",
                    "member_path": ["payoutAddress"],
                    "components": [
                        {
                            "name": "payoutAddress",
                            "type": "address",
                            "abi_type": "address",
                            "type_kind": "address",
                        }
                    ],
                },
            },
            {
                **base_target,
                "controller_id": "external_contract:name",
                "label": "name",
                "source": "name",
                "kind": "external_contract",
                "read_spec": {
                    "strategy": "getter_call",
                    "target": "name",
                    "kind": "state_variable",
                    "state_variable_name": "name",
                    "type": "string",
                },
            },
            {
                **base_target,
                "controller_id": "role_identifier:PAUSER_ROLE",
                "label": "PAUSER_ROLE",
                "source": "PAUSER_ROLE",
                "kind": "role_identifier",
                "read_spec": {"strategy": "getter_call", "target": "PAUSER_ROLE"},
            },
        ],
    }

    plan = build_observation_plan(cast(StaticFacts, analysis))

    assert [target["controller_id"] for target in plan["tracked_controllers"]] == [
        "role_identifier:PAUSER_ROLE",
        "state_variable:accountantState.payoutAddress",
        "state_variable:owner",
        "state_variable:redemptionManager",
    ]
