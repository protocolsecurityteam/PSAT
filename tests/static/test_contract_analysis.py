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


def test_collect_contract_analysis_with_artifacts_returns_semantic_artifacts(tmp_path):
    from services.static.contract_analysis_pipeline import collect_contract_analysis_with_artifacts

    project_dir = _write_project(
        tmp_path,
        "Token",
        _fixture_source("token/token_erc20_ownable_pausable.sol"),
    )

    analysis, predicate_trees, effects = collect_contract_analysis_with_artifacts(project_dir)

    assert analysis["schema_version"] == "0.1"
    assert predicate_trees is not None
    assert predicate_trees.get("schema_version") == "semantic"
    assert "trees" in predicate_trees or "error" in predicate_trees
    assert effects is not None
    assert effects.get("schema_version") == "semantic-3"
    assert "functions" in effects or "error" in effects


def test_collect_contract_analysis_uses_semantic_factory_without_upgrade_timelock_name_guessing(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "UpgradeFactory",
        _fixture_source("composed/upgrade_factory_uups.sol"),
    )

    analysis = collect_contract_analysis(project_dir)

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


def test_state_write_in_internal_helper_surfaces_on_caller(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "IndirectOwnerPause",
        _fixture_source("pause/indirect_owner_pause.sol"),
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "pause()")
    assert "owner" in semantic["controller_refs"]
    assert any(sink_id.endswith(":state_write:paused") for sink_id in semantic["sink_ids"])


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


@pytest.mark.parametrize(
    ("contract_name", "fixture_name", "signature", "target", "sink_kind"),
    [
        (
            "ExternalCallControl",
            "calls/external_call_control.sol",
            "pingTarget(uint256)",
            "target.ping",
            "external_call",
        ),
        (
            "DelegateCallControl",
            "calls/delegatecall_control.sol",
            "execute(bytes)",
            "implementation",
            "delegatecall",
        ),
        (
            "SelfDestructControl",
            "calls/selfdestruct_control.sol",
            "destroy()",
            "selfdestruct",
            "selfdestruct",
        ),
    ],
)
def test_additional_semantic_sink_kinds_surface_on_semantic_summary(
    tmp_path, contract_name, fixture_name, signature, target, sink_kind
):
    project_dir = _write_project(
        tmp_path,
        contract_name,
        _fixture_source(fixture_name),
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, signature)
    assert any(sink_id.endswith(f":{sink_kind}:{target}") for sink_id in semantic["sink_ids"])
    assert "owner" in semantic["controller_refs"]


def test_external_call_in_internal_helper_surfaces_on_caller(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "IndirectExternalCallControl",
        _fixture_source("calls/indirect_external_call_control.sol"),
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "pingTarget(uint256)")
    assert "owner" in semantic["controller_refs"]
    assert any(sink_id.endswith(":external_call:target.ping") for sink_id in semantic["sink_ids"])


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


def test_controller_tracking_falls_back_to_state_only_without_events(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "OwnerNoEvent",
        _fixture_source("tracking/owner_update_no_event.sol"),
    )

    analysis = collect_contract_analysis(project_dir)

    owner_tracking = _tracked_controller(analysis, "owner")
    assert owner_tracking["tracking_mode"] == "state_only"
    assert owner_tracking["associated_events"] == []
    assert {writer["function"] for writer in owner_tracking["writer_functions"]} == {"transferOwnership(address)"}


def test_non_authority_external_calls_with_caller_args_not_classified_as_authority(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "NonAuthorityExternalCallGuard",
        """
        pragma solidity ^0.8.19;

        interface TokenLike {
            function balanceOf(address account) external view returns (uint256);
        }

        interface PingTarget {
            function ping(uint256 value) external;
        }

        contract NonAuthorityExternalCallGuard {
            address public owner;
            TokenLike public token;

            constructor(TokenLike token_) {
                owner = msg.sender;
                token = token_;
            }

            function manage(PingTarget target, uint256 value) external {
                require(msg.sender == owner, "not owner");
                require(token.balanceOf(msg.sender) > 0, "no balance");
                target.ping(value);
            }
        }
        """,
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "manage(PingTarget,uint256)")

    assert "owner" in semantic["controller_refs"]
    assert "token" not in semantic["controller_refs"]
    assert "external_authority_check" not in semantic["guard_kinds"]


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


def test_external_role_getter_name_is_not_tracked_as_role_identifier(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "OpaqueRolePause",
        """
        pragma solidity ^0.8.19;

        interface IRoleRegistry {
            function hasRole(bytes32 role, address account) external view returns (bool);
            function BREAK_GLASS() external view returns (bytes32);
        }

        contract OpaqueRolePause {
            IRoleRegistry public roleRegistry;
            bool public paused;

            constructor(IRoleRegistry registry) {
                roleRegistry = registry;
            }

            function pauseContract() external {
                require(roleRegistry.hasRole(roleRegistry.BREAK_GLASS(), msg.sender), "bad role");
                paused = true;
            }
        }
        """,
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "pauseContract()")

    assert "roleRegistry" in semantic["controller_refs"]
    assert "BREAK_GLASS" not in semantic["controller_refs"]

    tracked_ids = {target["controller_id"] for target in analysis["controller_tracking"]}
    assert "external_contract:roleRegistry" in tracked_ids
    assert "role_identifier:BREAK_GLASS" not in tracked_ids


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
