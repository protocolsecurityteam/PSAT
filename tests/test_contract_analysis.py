import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from schemas.contract_analysis import (
    ContractAnalysis,
    ControllerTrackingTarget,
    SemanticFunctionSummary,
)
from services.static import collect_contract_analysis

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "contracts"
FIXTURE_INDEX_PATH = FIXTURES_DIR / "index.json"


def _write_project(tmp_path: Path, contract_name: str, source_code: str, slither_output: dict | None = None) -> Path:
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
    (project_dir / "slither_results.json").write_text(
        json.dumps(
            slither_output
            or {
                "results": {
                    "detectors": [
                        {
                            "check": "reentrancy-events",
                            "impact": "Medium",
                            "confidence": "Medium",
                            "description": "Sample finding",
                        }
                    ]
                }
            }
        )
        + "\n"
    )
    return project_dir


def _fixture_source(relative_path: str) -> str:
    return (FIXTURES_DIR / relative_path).read_text()


def _fixture_index() -> list[dict]:
    return json.loads(FIXTURE_INDEX_PATH.read_text())["fixtures"]


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


def test_fixture_index_covers_all_solidity_contract_fixtures():
    indexed_paths = {entry["path"] for entry in _fixture_index()}
    # The detection-pattern index catalogs the hand-authored single-file fixtures.
    # ``label_corpus/`` holds the effect-labels golden-gate sources (synthetic
    # single-file .sol + one Foundry project); their own manifest is the source of
    # truth, so they are not indexed here.
    fixture_paths = {
        str(path.relative_to(FIXTURES_DIR))
        for path in FIXTURES_DIR.rglob("*.sol")
        if "label_corpus" not in path.relative_to(FIXTURES_DIR).parts
    }

    assert indexed_paths == fixture_paths

    for entry in _fixture_index():
        assert entry["category"]
        assert entry["contract_name"]
        assert entry["description"]
        assert entry["detection_patterns"]
        assert (FIXTURES_DIR / entry["path"]).exists()


def test_collect_contract_analysis_with_artifacts_returns_semantic_artifacts(tmp_path):
    """The worker-facing entrypoint
    ``collect_contract_analysis_with_artifacts`` returns the semantic
    ``predicate_trees`` and ``effects`` artifacts alongside the
    analysis dict, off a single Slither parse."""
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
    # Successful emit produces a `trees` dict; an error path would
    # set `error` instead.
    assert "trees" in predicate_trees or "error" in predicate_trees
    assert effects is not None
    assert effects.get("schema_version") == "semantic-3"
    assert "functions" in effects or "error" in effects


def test_collect_contract_analysis_uses_semantic_factory_without_upgrade_timelock_name_guessing(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "UpgradeFactory",
        _fixture_source("composed/upgrade_factory_uups.sol"),
        slither_output={"results": {"detectors": []}},
    )

    analysis = collect_contract_analysis(project_dir)

    # Upgradeability is recovered from the UUPS *standard* (``proxiableUUID`` +
    # ``upgradeTo`` selector), not by guessing on the ``upgradeTo`` name — the
    # ``upgrade.implementation`` claim projects to ``implementation_update``,
    # which ``_detect_upgradeability`` consumes. The empty ``upgradeTo`` body
    # writes no slot, so no implementation slot is inferred.
    assert analysis["summary"]["is_upgradeable"] is True
    assert analysis["upgradeability"]["pattern"] == "custom"
    # Timelock still is NOT name-guessed: bespoke ``schedule``/``execute`` carry
    # no OZ-timelock standard gate (no getMinDelay / hashOperation), so no claim.
    assert analysis["timelock"]["has_timelock"] is False
    assert analysis["timelock"]["pattern"] == "none"
    assert analysis["contract_classification"]["is_factory"] is True
    factory_functions = analysis["contract_classification"]["factory_functions"]
    assert factory_functions is not None, "None means the effects artifact was degraded, not that there are none"
    assert "createChild()" in factory_functions
    assert analysis["upgradeability"]["implementation_slots"] == []
    create_child = _semantic_function(analysis, "createChild()")
    # sink_ids come from the semantic effects artifact and end with
    # ``:<kind>:<target>``; the inner segment is the per-function sink index.
    assert any(sink_id.endswith(":contract_creation:Child") for sink_id in create_child["sink_ids"])
    assert "owner" in create_child["controller_refs"]


def test_collect_contract_analysis_detects_erc721_as_nft(tmp_path):
    project_dir = _write_project(
        tmp_path,
        "Collectible",
        _fixture_source("nft/collectible_erc721.sol"),
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
    # ``target.ping`` is the body sink and the sole driver of the label. The
    # modifier ``requiresAuth``'s ``auth.canCall`` is now a guard-origin sink,
    # excluded from effect_targets so it can't dilute the effect (it stays in
    # the raw ``sinks`` list as an ``origin=guard`` fact).
    assert "target.ping" in manage["effect_targets"]
    assert not any("canCall" in target for target in manage["effect_targets"])
    assert manage["action_summary"] == "Calls an external contract from the contract context."

    set_hook = _semantic_function(analysis, "setHook(address)")
    # No sibling entry point invokes ``hook`` at runtime, so ``callee_pointer.rotate``
    # does not fire — the retired unclassified-pointer fallback used to mislabel
    # this bare setter ``hook_update``. It now collapses to silence + fact text
    # (the ``hook`` state write is still the only body sink; the guard-origin
    # ``auth.canCall`` from ``requiresAuth`` is not a target).
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
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
        slither_output={"results": {"detectors": []}},
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "pause()")

    # ``guards`` is no longer populated by the semantic summary.
    assert "BREAK_GLASS" in semantic["controller_refs"]

    tracked = _tracked_controller(analysis, "BREAK_GLASS")
    assert tracked["controller_id"] == "role_identifier:BREAK_GLASS"
    assert tracked["kind"] == "role_identifier"


def test_opaque_external_void_helper_guard_is_controller_ref(tmp_path):
    project_dir = _write_project(
        tmp_path,
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
        slither_output={"results": {"detectors": []}},
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "pause()")
    assert "gate" in semantic["controller_refs"]
    assert "external_contract_call" in semantic["effect_labels"]


def test_opaque_external_role_helper_is_controller_ref(tmp_path):
    project_dir = _write_project(
        tmp_path,
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
        slither_output={"results": {"detectors": []}},
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "pause()")
    assert "auth" in semantic["controller_refs"]
    assert "external_contract_call" in semantic["effect_labels"]


def test_opaque_external_policy_helper_is_controller_ref(tmp_path):
    project_dir = _write_project(
        tmp_path,
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
        slither_output={"results": {"detectors": []}},
    )

    analysis = collect_contract_analysis(project_dir)
    semantic = _semantic_function(analysis, "execute()")
    assert "policy" in semantic["controller_refs"]
    assert "external_contract_call" in semantic["effect_labels"]
