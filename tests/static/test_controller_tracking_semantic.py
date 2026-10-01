from __future__ import annotations

import pytest

slither = pytest.importorskip("slither")

from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts,
)
from services.static.contract_analysis_pipeline.summaries import (  # noqa: E402
    _build_semantic_control_summary,
)
from services.static.contract_analysis_pipeline.tracking import (  # noqa: E402
    build_controller_tracking,
)
from tests.support.slither_compile import _compile_contract  # noqa: E402


def _build(tmp_path, source, contract_name="C"):
    contract = _compile_contract(tmp_path, source, contract_name)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    targets = build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)
    return targets


def test_authority_state_var_promoted_to_external_contract(tmp_path):
    source = """
    pragma solidity ^0.8.19;
    interface IRoleRegistry {
        function hasRole(bytes32 role, address account) external view returns (bool);
    }
    contract C {
        IRoleRegistry public roleRegistry;
        bool public paused;
        bytes32 public constant PAUSER_ROLE = keccak256("PAUSER");
        constructor(address rr) { roleRegistry = IRoleRegistry(rr); }
        function pauseContract() external {
            require(roleRegistry.hasRole(PAUSER_ROLE, msg.sender), "no");
            paused = true;
        }
    }
    """
    targets = _build(tmp_path, source)
    by_id = {t["controller_id"]: t for t in targets}
    assert "external_contract:roleRegistry" in by_id, list(by_id.keys())
    assert by_id["external_contract:roleRegistry"]["kind"] == "external_contract"


def test_struct_state_var_read_spec_preserves_field_components(tmp_path):
    source = """
    pragma solidity ^0.8.19;
    contract C {
        struct AccountantState {
            address payoutAddress;
            uint96 highwaterMark;
            bool isPaused;
        }

        AccountantState public accountantState;

        function sweep() external view {
            require(msg.sender == accountantState.payoutAddress, "not payout");
        }
    }
    """
    contract = _compile_contract(tmp_path, source)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    targets = build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)
    by_id = {t["controller_id"]: t for t in targets}

    assert "state_variable:accountantState" not in by_id, list(by_id.keys())
    assert "state_variable:accountantState.payoutAddress" in by_id, list(by_id.keys())
    leaf = predicate_trees["trees"]["sweep()"]["leaf"]
    projected_operand = next(operand for operand in leaf["operands"] if operand.get("source") == "state_variable")
    assert projected_operand["state_variable_name"] == "accountantState"
    assert projected_operand["member_path"] == ["payoutAddress"]

    projected_spec = by_id["state_variable:accountantState.payoutAddress"]["read_spec"]
    assert isinstance(projected_spec, dict)
    assert projected_spec["target"] == "accountantState"
    assert projected_spec.get("parent_type") == "C.AccountantState"
    assert projected_spec.get("type") == "address"
    assert projected_spec.get("type_kind") == "address"
    assert projected_spec.get("member_path") == ["payoutAddress"]
    assert projected_spec.get("components") == [
        {
            "name": "payoutAddress",
            "type": "address",
            "abi_type": "address",
            "type_kind": "address",
        },
        {
            "name": "highwaterMark",
            "type": "uint96",
            "abi_type": "uint96",
            "type_kind": "primitive",
        },
        {
            "name": "isPaused",
            "type": "bool",
            "abi_type": "bool",
            "type_kind": "primitive",
        },
    ]


def test_private_var_without_getter_gets_unknown_strategy_and_no_poll_entry(tmp_path):
    """``getter_call`` would mint ``keccak('_admin()')`` for a function that doesn't exist."""
    from services.monitoring.polling_plan import build_polling_plan

    source = """
    pragma solidity ^0.8.19;
    contract Admined {
        address private _admin;
        modifier onlyAdmin() {
            require(msg.sender == _admin, "no");
            _;
        }
    }
    contract C is Admined {
        uint256 public value;
        function setValue(uint256 v) external onlyAdmin {
            value = v;
        }
    }
    """
    targets = _build(tmp_path, source)
    by_id = {t["controller_id"]: t for t in targets}
    assert "state_variable:_admin" in by_id, list(by_id.keys())
    read_spec = by_id["state_variable:_admin"]["read_spec"]
    assert isinstance(read_spec, dict)
    assert read_spec["strategy"] == "unknown"
    assert read_spec.get("state_variable_name") == "_admin"
    assert read_spec.get("type_kind") == "address"

    plan = build_polling_plan(
        contract_type="regular",
        proxy_type=None,
        tracking_plan={"tracked_controllers": targets},
        tracked_topics=None,
    )
    assert not any(e.get("field") == "_admin" or e.get("target") == "_admin" for e in plan)


def test_private_var_with_getter_stays_pollable_through_the_getter(tmp_path):
    from services.monitoring.polling_plan import build_polling_plan, selector_for

    source = """
    pragma solidity ^0.8.19;
    contract Ownable {
        address private _owner;
        modifier onlyOwner() {
            require(msg.sender == _owner, "not owner");
            _;
        }
        function owner() public view returns (address) {
            return _owner;
        }
    }
    contract C is Ownable {
        uint256 public value;
        function setValue(uint256 v) external onlyOwner {
            value = v;
        }
    }
    """
    targets = _build(tmp_path, source)
    by_id = {t["controller_id"]: t for t in targets}
    read_spec = by_id["state_variable:_owner"]["read_spec"]
    assert isinstance(read_spec, dict)
    assert read_spec["strategy"] == "getter_call"
    assert read_spec["target"] == "owner"

    plan = build_polling_plan(
        contract_type="regular",
        proxy_type=None,
        tracking_plan={"tracked_controllers": targets},
        tracked_topics=None,
    )
    entry = next(e for e in plan if e.get("field") == "_owner")
    assert entry["target"] == "owner"
    assert entry["selector"] == selector_for("owner")


def test_public_underscore_var_keeps_its_auto_getter(tmp_path):
    """The underscore prefix isn't the discriminator."""
    from services.monitoring.polling_plan import build_polling_plan, selector_for

    source = """
    pragma solidity ^0.8.19;
    contract C {
        address public _roleRegistry;
        uint256 public value;
        constructor(address rr) { _roleRegistry = rr; }
        function setValue(uint256 v) external {
            require(msg.sender == _roleRegistry, "no");
            value = v;
        }
    }
    """
    targets = _build(tmp_path, source)
    by_id = {t["controller_id"]: t for t in targets}
    assert "state_variable:_roleRegistry" in by_id, list(by_id.keys())
    read_spec = by_id["state_variable:_roleRegistry"]["read_spec"]
    assert isinstance(read_spec, dict)
    assert read_spec["strategy"] == "getter_call"
    assert read_spec["target"] == "_roleRegistry"

    plan = build_polling_plan(
        contract_type="regular",
        proxy_type=None,
        tracking_plan={"tracked_controllers": targets},
        tracked_topics=None,
    )
    entry = next(e for e in plan if e.get("field") == "_roleRegistry")
    assert entry["selector"] == selector_for("_roleRegistry")
