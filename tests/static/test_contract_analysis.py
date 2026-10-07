import json
from pathlib import Path

import pytest

from schemas.contract_analysis import (
    ContractAnalysis,
    ControllerTrackingTarget,
    SemanticFunctionSummary,
)
from services.static import collect_contract_analysis

pytestmark = pytest.mark.compile

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


_CLASSIFICATION_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract C {
    address public owner;
    uint256 public value;
    function poke(uint256 v) external { require(msg.sender == owner, "no"); value = v; }
}
"""


def _fixture_source(relative_path: str) -> str:
    return (FIXTURES_DIR / relative_path).read_text()


def _semantic_function(analysis: ContractAnalysis, signature: str) -> SemanticFunctionSummary:
    for function in analysis["semantic_control"]["semantic_functions"]:
        if function["function"] == signature:
            return function
    raise AssertionError(f"Semantic function {signature} not found")


def _tracked_controller(analysis: ContractAnalysis, label: str) -> ControllerTrackingTarget:
    for controller in analysis["controller_tracking"]:
        if controller["label"] == label:
            return controller
    raise AssertionError(f"Tracked controller {label} not found")


@pytest.mark.parametrize("failing_matcher", [False, True])
def test_collect_contract_analysis_uses_semantic_factory_without_upgrade_timelock_name_guessing(
    tmp_path, monkeypatch, failing_matcher
):
    if failing_matcher:
        from dataclasses import replace

        from services.static.claims import builder

        builder.discover()
        registry = builder.registry

        def fail(_ctx, _signature):
            raise RuntimeError("injected matcher failure")

        entry = replace(registry()["contract_deployment"], claim_id="test.failure", trigger=fail)
        monkeypatch.setattr(builder, "registry", lambda: {**registry(), entry.claim_id: entry})
    project_dir = _write_project(
        tmp_path,
        "UpgradeFactory",
        _fixture_source("composed/upgrade_factory_uups.sol"),
    )

    analysis = collect_contract_analysis(project_dir)
    assert bool(analysis["analysis_status"]["errors"]) is failing_matcher
    if failing_matcher:
        assert any("test.failure" in message for message in analysis["analysis_status"]["errors"])

    # Recovered from the UUPS standard via ``implementation_update``, not the ``upgradeTo`` name.
    assert analysis["summary"]["is_upgradeable"] is True
    assert analysis["upgradeability"]["pattern"] == "custom"
    # Bespoke ``schedule``/``execute`` carry no OZ-timelock standard gate.
    assert analysis["timelock"]["has_timelock"] is False
    assert analysis["timelock"]["pattern"] == "none"
    assert analysis["contract_classification"]["is_factory"] is True
    factory_functions = analysis["contract_classification"]["factory_functions"]
    assert factory_functions is not None, "None means the effects artifact was degraded, not that there are none"
    assert "createChild()" in factory_functions
    assert analysis["upgradeability"]["implementation_slots"] == []
    create_child = _semantic_function(analysis, "createChild()")
    assert any(sink_id.endswith(":contract_creation:Child") for sink_id in create_child["sink_ids"])
    assert "owner" in create_child["controller_refs"]


def test_collect_contract_analysis_detects_erc721_as_nft(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "Collectible",
        _fixture_source("nft/collectible_erc721.sol"),
    )

    analysis = collect_contract_analysis(project_dir)

    assert "ERC721" in analysis["contract_classification"]["standards"]
    assert analysis["contract_classification"]["is_nft"] is True
    assert analysis["summary"]["is_nft"] is True


def test_contract_creation_sink_classified(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "UpgradeFactory",
        _fixture_source("composed/upgrade_factory_uups.sol"),
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "createChild()")
    assert semantic["effect_labels"] == ["contract_deployment"]
    assert semantic["action_summary"] == "Deploys a new contract instance."


def test_modifier_helper_auth_structure_recovered(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "AuthModifierController",
        _fixture_source("composed/auth_modifier_controller.sol"),
    )

    analysis = collect_contract_analysis(project_dir)

    for signature in ("setHook(address)", "manage(PingTarget,uint256)", "transferOwnership(address)"):
        semantic = _semantic_function(analysis, signature)
        assert {"owner", "authority"}.issubset(set(semantic["controller_refs"]))

    semantic_signatures = {item["function"] for item in analysis["semantic_control"]["semantic_functions"]}
    assert not any(sig.startswith("constructor(") for sig in semantic_signatures)

    owner_tracking = _tracked_controller(analysis, "owner")
    assert owner_tracking["tracking_mode"] == "event_plus_state"
    assert owner_tracking["associated_events"] == [
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
    ]
    assert {writer["function"] for writer in owner_tracking["writer_functions"]} == {"transferOwnership(address)"}

    authority_tracking = _tracked_controller(analysis, "authority")
    assert authority_tracking["tracking_mode"] == "event_plus_state"
    assert authority_tracking["associated_events"] == [
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
    ]
    assert {writer["function"] for writer in authority_tracking["writer_functions"]} == {"setAuthority(AuthorityLike)"}

    manage = _semantic_function(analysis, "manage(PingTarget,uint256)")
    assert manage["effect_labels"] == ["external_contract_call"]
    # The guard-origin ``auth.canCall`` is excluded from effect_targets but stays in ``sinks``.
    assert "target.ping" in manage["effect_targets"]
    assert not any("canCall" in target for target in manage["effect_targets"])
    assert manage["action_summary"] == "Calls an external contract from the contract context."

    set_hook = _semantic_function(analysis, "setHook(address)")
    # No sibling invokes ``hook``, so the rotate doesn't fire; the retired fallback mislabelled this ``hook_update``.
    assert set_hook["effect_labels"] == []
    assert set_hook["effect_targets"] == ["hook"]
    assert set_hook["action_summary"] == "Writes or calls into: hook."

    transfer_ownership = _semantic_function(analysis, "transferOwnership(address)")
    assert transfer_ownership["effect_labels"] == ["ownership_transfer"]
    assert transfer_ownership["action_summary"] == "Transfers contract ownership."


def test_semantic_function_semantics_detect_pause_and_asset_flow(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "Token",
        _fixture_source("token/token_erc20_ownable_pausable.sol"),
    )

    analysis = collect_contract_analysis(project_dir)

    pause = _semantic_function(analysis, "pause()")
    assert "pause_toggle" in pause["effect_labels"]
    assert pause["action_summary"] == "Changes the contract pause state."


def test_void_role_registry_upgrader_is_controller_ref(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "RoleRegistryUpgradeTarget",
        """
        pragma solidity ^0.8.19;

        contract RoleRegistryLike {
            function onlyProtocolUpgrader(address) external view {}
        }

        contract RoleRegistryUpgradeTarget {
            RoleRegistryLike public roleRegistry;

            constructor(RoleRegistryLike registry) {
                roleRegistry = registry;
            }

            function upgradeTo(address newImplementation) external {
                roleRegistry.onlyProtocolUpgrader(msg.sender);
                (bool ok,) = newImplementation.delegatecall("");
                require(ok, "delegatecall failed");
            }
        }
        """,
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "upgradeTo(address)")

    assert "roleRegistry" in semantic["controller_refs"]
    assert "delegatecall_execution" in semantic["effect_labels"]


def test_modifier_helper_preserves_opaque_role_identifier(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "OpaqueRoleModifierPause",
        """
        pragma solidity ^0.8.19;

        interface IAuth {
            function q(bytes32 role, address who) external view returns (bool);
        }

        contract OpaqueRoleModifierPause {
            bytes32 public constant BREAK_GLASS = keccak256("x");
            IAuth public auth;
            bool public paused;

            constructor(IAuth auth_) {
                auth = auth_;
            }

            modifier gate(bytes32 x) {
                _check(x);
                _;
            }

            function _check(bytes32 x) internal view {
                require(auth.q(x, msg.sender), "bad");
            }

            function pause() external gate(BREAK_GLASS) {
                paused = true;
            }
        }
        """,
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "pause()")

    assert "BREAK_GLASS" in semantic["controller_refs"]

    tracked = _tracked_controller(analysis, "BREAK_GLASS")
    assert tracked["controller_id"] == "role_identifier:BREAK_GLASS"
    assert tracked["kind"] == "role_identifier"


@pytest.mark.parametrize(
    ("project_name", "source", "function", "controller_ref"),
    [
        pytest.param(
            "OpaqueExternalGuard",
            """
        pragma solidity ^0.8.19;

        interface IGate {
            function x(address who) external view;
        }

        contract OpaqueGate is IGate {
            address public owner;
            error Denied();

            constructor(address owner_) {
                owner = owner_;
            }

            function x(address who) external view {
                if (who != owner) revert Denied();
            }
        }

        contract OpaqueExternalGuard {
            IGate public gate;
            bool public paused;

            constructor(IGate gate_) {
                gate = gate_;
            }

            function pause() external {
                gate.x(msg.sender);
                paused = true;
            }
        }
        """,
            "pause()",
            "gate",
            id="void_helper_guard",
        ),
        pytest.param(
            "OpaqueExternalRoleGuard",
            """
        pragma solidity ^0.8.19;

        interface IAuth {
            function z(address who) external view;
        }

        contract OpaqueRoleAuth is IAuth {
            bytes32 public constant BREAK_GLASS = keccak256("x");
            mapping(bytes32 => mapping(address => bool)) internal roles;
            error Denied();

            constructor(address pauser) {
                roles[BREAK_GLASS][pauser] = true;
            }

            function z(address who) external view {
                if (!roles[BREAK_GLASS][who]) revert Denied();
            }
        }

        contract OpaqueExternalRoleGuard {
            IAuth public auth;
            bool public paused;

            constructor(IAuth auth_) {
                auth = auth_;
            }

            function pause() external {
                auth.z(msg.sender);
                paused = true;
            }
        }
        """,
            "pause()",
            "auth",
            id="role_helper",
        ),
        pytest.param(
            "OpaqueExternalPolicyGuard",
            """
        pragma solidity ^0.8.19;

        interface IPolicy {
            function q(address who, address target, bytes4 sig) external view;
        }

        contract OpaquePolicy is IPolicy {
            mapping(address => mapping(bytes4 => mapping(address => bool))) internal can;
            error Denied();

            constructor(address admin) {
                can[address(this)][this.guard.selector][admin] = true;
            }

            function guard() external {}

            function q(address who, address target, bytes4 sig) external view {
                if (!can[target][sig][who]) revert Denied();
            }
        }

        contract OpaqueExternalPolicyGuard {
            IPolicy public policy;
            bool public executed;

            constructor(IPolicy policy_) {
                policy = policy_;
            }

            function execute() external {
                policy.q(msg.sender, address(this), this.execute.selector);
                executed = true;
            }
        }
        """,
            "execute()",
            "policy",
            id="policy_helper",
        ),
    ],
)
def test_opaque_external_helper_is_controller_ref(tmp_path, project_name, source, function, controller_ref):
    project_dir = _write_project(tmp_path, project_name, source)

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, function)
    assert controller_ref in semantic["controller_refs"]
    assert "external_contract_call" in semantic["effect_labels"]


def test_is_factory_is_not_determined_without_the_effects_artifact(tmp_path):
    """The only non-IR field; ``core`` substitutes an error sentinel when ``build_effects`` raises, and ``false``
    would claim it deploys nothing without looking.
    """
    from slither import Slither

    from services.static.contract_analysis_pipeline.summaries import (
        _detect_contract_classification,
    )
    from tests.support.foundry_project import write_foundry_project

    project = write_foundry_project(tmp_path, "C", _CLASSIFICATION_SOURCE)
    contract = next(c for c in Slither(str(project)).contracts if c.name == "C")

    degraded = _detect_contract_classification(contract, tmp_path, {"schema_version": "semantic", "error": "boom"})
    assert degraded["is_factory"] is None
    assert degraded["factory_functions"] is None
    assert degraded["standards"] == []
    assert degraded["is_nft"] is False

    ran = _detect_contract_classification(contract, tmp_path, {"functions": {}})
    assert ran["is_factory"] is False, "an effects artifact that ran and found no creation sink is a PROVEN absence"
    assert ran["factory_functions"] == []


def test_standards_absence_is_measured_not_missing(tmp_path):
    """Nulling ``standards`` was rejected: it's IR-derived and non-empty on 31 of 88 local contracts, every real
    token among them.
    """
    from slither import Slither

    from services.static.contract_analysis_pipeline.summaries import (
        _detect_contract_classification,
    )
    from tests.support.foundry_project import write_foundry_project

    erc20 = """
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.19;
    contract C {
        mapping(address => uint256) public balanceOf;
        mapping(address => mapping(address => uint256)) public allowance;
        uint256 public totalSupply;
        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
        function transfer(address to, uint256 v) external returns (bool) { balanceOf[to] += v; return true; }
        function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; return true; }
        function transferFrom(address f, address t, uint256 v) external returns (bool) {
            balanceOf[f] -= v; balanceOf[t] += v; return true;
        }
    }
    """
    project = write_foundry_project(tmp_path, "C", erc20)
    contract = next(c for c in Slither(str(project)).contracts if c.name == "C")
    classification = _detect_contract_classification(contract, tmp_path, None)
    assert "ERC20" in classification["standards"]
    assert classification["is_factory"] is None
