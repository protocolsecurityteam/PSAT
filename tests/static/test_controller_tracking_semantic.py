"""``build_controller_tracking`` semantic behavior.

Validates the predicate-tree + effects-driven builder covers the old
controller-tracking shapes and that:

* Inherited Ownable's ``_owner`` private state-var gets emitted as
  ``state_variable:_owner`` directly from leaves.
* External authority registries (``set_descriptor.authority_contract.
  address_source``) get promoted to ``external_contract`` kind.
* External authority calls promote their registry state variable without
  inventing role identifiers from standard ABI/event names.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

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


def _compile(tmp_path: Path, source: str, contract_name: str = "C"):
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == contract_name)


def _build(tmp_path, source, contract_name="C"):
    contract = _compile(tmp_path, source, contract_name)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    targets = build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)
    return targets


def test_inherited_owner_caught_from_predicate_tree(tmp_path):
    """Ownable's private ``_owner`` is the canonical inherited-owner shape.

    The semantic builder should emit it directly from the leaf operand
    walk."""
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
    assert "state_variable:_owner" in by_id, list(by_id.keys())
    target = by_id["state_variable:_owner"]
    assert target["kind"] == "state_variable"
    # Private state-var with same-name getter ``owner()`` → read_spec
    # points at the GETTER, not the var.
    read_spec = target.get("read_spec")
    assert isinstance(read_spec, dict)
    assert read_spec["target"] == "owner"


def test_authority_state_var_promoted_to_external_contract(tmp_path):
    """A state var carrying a registry address (used as
    ``set_descriptor.authority_contract.address_source``) gets the
    ``external_contract`` kind."""
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
    contract = _compile(tmp_path, source)
    predicate_trees = build_predicate_artifacts(contract)
    effects = build_effects(contract)
    semantic_control = _build_semantic_control_summary(contract, tmp_path, predicate_trees, effects)
    targets = build_controller_tracking(contract, tmp_path, predicate_trees, effects, semantic_control)
    by_id = {t["controller_id"]: t for t in targets}

    # The bare struct has no single storable address value, so it is not a
    # controller; only the projected address member is.
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
    # The projected member spec preserves the full struct field component list.
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


def test_role_identifier_does_not_infer_authority_contract_source(tmp_path):
    """A local bytes32 constant can be tracked without a standard-specific
    registry-source assumption."""
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
    assert "role_identifier:PAUSER_ROLE" in by_id
    spec = by_id["role_identifier:PAUSER_ROLE"]["read_spec"]
    assert isinstance(spec, dict)
    assert spec["target"] == "PAUSER_ROLE"
    assert "contract_source" not in spec


def test_writer_functions_from_effects(tmp_path):
    """Writer attribution comes from ``effects.functions[*].sinks``
    filtered to ``state_write`` — not from ``permission_graph`` sinks."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        constructor() { owner = msg.sender; }
        function transferOwnership(address newOwner) external {
            require(msg.sender == owner, "not owner");
            owner = newOwner;
        }
    }
    """
    targets = _build(tmp_path, source)
    by_id = {t["controller_id"]: t for t in targets}
    target = by_id["state_variable:owner"]
    assert {w["function"] for w in target["writer_functions"]} == {"transferOwnership(address)"}


def test_external_role_getter_name_does_not_create_role_identifier(tmp_path):
    """A getter name on an external authority is not enough to create a
    local role identifier."""
    source = """
    pragma solidity ^0.8.19;
    interface IRoleRegistry {
        function hasRole(bytes32 role, address account) external view returns (bool);
        function BREAK_GLASS() external view returns (bytes32);
    }
    contract C {
        IRoleRegistry public roleRegistry;
        bool public paused;
        constructor(IRoleRegistry r) { roleRegistry = r; }
        function pauseContract() external {
            require(
                roleRegistry.hasRole(roleRegistry.BREAK_GLASS(), msg.sender),
                "no"
            );
            paused = true;
        }
    }
    """
    targets = _build(tmp_path, source)
    by_id = {t["controller_id"]: t for t in targets}
    assert "external_contract:roleRegistry" in by_id, list(by_id.keys())
    assert "role_identifier:BREAK_GLASS" not in by_id


def test_writer_emits_event_promotes_tracking_mode(tmp_path):
    """When a writer emits an event tied to the tracked state var, the
    target's ``tracking_mode`` becomes ``event_plus_state``."""
    source = """
    pragma solidity ^0.8.19;
    contract C {
        address public owner;
        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
        constructor() { owner = msg.sender; }
        function transferOwnership(address newOwner) external {
            require(msg.sender == owner);
            emit OwnershipTransferred(owner, newOwner);
            owner = newOwner;
        }
    }
    """
    targets = _build(tmp_path, source)
    by_id = {t["controller_id"]: t for t in targets}
    target = by_id["state_variable:owner"]
    assert target["tracking_mode"] == "event_plus_state"
    assert any(e["name"] == "OwnershipTransferred" for e in target["associated_events"])


# ---------------------------------------------------------------------------
# read_spec getter honesty — a getter_call claim requires an actual getter
# ---------------------------------------------------------------------------


def test_private_var_without_getter_gets_unknown_strategy_and_no_poll_entry(tmp_path):
    """A private state var with no public getter cannot be read by any
    function call. Its read_spec must not claim ``getter_call`` (which
    would mint ``keccak('_admin()')`` — a selector of a function that
    does not exist), and it must produce no polling-plan entry."""
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
    # Type info survives so type-shape guards downstream keep their inputs.
    assert read_spec.get("type_kind") == "address"

    plan = build_polling_plan(
        contract_type="regular",
        proxy_type=None,
        tracking_plan={"tracked_controllers": targets},
        tracked_topics=None,
    )
    assert not any(e.get("field") == "_admin" or e.get("target") == "_admin" for e in plan)


def test_private_var_with_getter_stays_pollable_through_the_getter(tmp_path):
    """POSITIVE ARM: a private var whose same-contract view getter was
    discovered keeps ``getter_call`` — pointed at the getter, never the
    var."""
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
    """DISCRIMINATING CONTROL: the underscore prefix is not the
    discriminator — a PUBLIC ``_roleRegistry`` has a compiled auto-getter
    named after itself and stays pollable through it."""
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
