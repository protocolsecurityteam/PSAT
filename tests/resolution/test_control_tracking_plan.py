import json
from pathlib import Path
from typing import cast

from schemas.contract_analysis import ContractAnalysis
from schemas.control_tracking import ControlTrackingPlan, TrackedController
from services.resolution.tracking_plan import build_control_tracking_plan
from services.static import collect_contract_analysis

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


def _tracked_controller(plan: ControlTrackingPlan, label: str) -> TrackedController:
    for controller in plan["tracked_controllers"]:
        if controller["label"] == label:
            return controller
    raise AssertionError(f"Tracked controller {label} not found")


def test_build_control_tracking_plan_falls_back_to_state_only(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "OwnerNoEvent",
        _fixture_source("tracking/owner_update_no_event.sol"),
    )
    analysis = collect_contract_analysis(project_dir)

    plan = build_control_tracking_plan(analysis)

    owner = _tracked_controller(plan, "owner")
    assert owner["tracking_mode"] == "state_only"
    assert owner["event_watch"] is None
    assert owner["polling_fallback"]["cadence"] == "state_only"
    assert owner["polling_fallback"]["polling_sources"] == ["owner"]


def test_build_control_tracking_plan_filters_non_controller_runtime_reads():
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

    plan = build_control_tracking_plan(cast(ContractAnalysis, analysis))

    assert [target["controller_id"] for target in plan["tracked_controllers"]] == [
        "role_identifier:PAUSER_ROLE",
        "state_variable:accountantState.payoutAddress",
        "state_variable:owner",
        "state_variable:redemptionManager",
    ]
