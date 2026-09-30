from __future__ import annotations

import json

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import (  # noqa: E402
    attach_claims_to_effects,
    build_claims,
    project_effect_labels,
)
from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    SCHEMA_VERSION,
    EffectInfo,
    EffectsArtifact,
    build_effects,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)
from tests.support.slither_compile import _compile  # noqa: E402


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _claim_ids(info: EffectInfo) -> set[str]:
    return {claim["claim_id"] for claim in (info.get("claims") or [])}


def _contract(sl: Slither, name: str | None = None):
    if name is None:
        return sl.contracts[0]
    return next(c for c in sl.contracts if c.name == name)


def _info(artifact: EffectsArtifact, signature: str) -> EffectInfo:
    info = artifact["functions"].get(signature)
    assert info is not None, f"expected {signature} in {sorted(artifact['functions'])}"
    return info


def test_basic_state_write_emits_state_write_sink(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function setX(uint256 v) external {
                x = v;
            }
        }
        """,
    )
    artifact = build_effects(_contract(sl))

    assert artifact["schema_version"] == SCHEMA_VERSION
    assert artifact["contract_name"] == "C"

    info = _info(artifact, "setX(uint256)")
    state_writes = [s for s in info["sinks"] if s["kind"] == "state_write"]
    assert len(state_writes) == 1
    assert state_writes[0]["target"] == "x"
    assert "x" in info["effect_targets"]
    assert info["selector"].startswith("0x") and len(info["selector"]) == 10
    assert info["writer_selectors"] == [info["selector"]]


def test_internal_helper_writes_surface_on_caller(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            uint256 public y;
            function _bumpInternally(uint256 v) internal {
                y = v;
            }
            function bump(uint256 v) external {
                x = v;
                _bumpInternally(v + 1);
            }
        }
        """,
    )
    artifact = build_effects(_contract(sl))
    info = _info(artifact, "bump(uint256)")
    targets = {s["target"] for s in info["sinks"] if s["kind"] == "state_write"}
    assert {"x", "y"}.issubset(targets), f"expected x and y, got {targets}"
    assert "_bumpInternally(uint256)" not in artifact["functions"]


def test_external_call_sink_classification(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IToken {
            function mint(address to, uint256 amount) external;
        }
        contract C {
            IToken public token;
            function poke(address to, uint256 amount) external {
                token.mint(to, amount);
            }
        }
        """,
    )
    artifact = build_effects(_contract(sl, "C"))
    info = _info(artifact, "poke(address,uint256)")
    external_calls = [s for s in info["sinks"] if s["kind"] == "external_call"]
    assert any(
        s["target"] == "token.mint" and s["selector"] == _selector("mint(address,uint256)") for s in external_calls
    ), info["sinks"]


def test_effect_label_recognition_pause_toggle(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            bool public stopped;
            modifier whenNotStopped() {
                require(!stopped, "stopped");
                _;
            }
            constructor() {
                owner = msg.sender;
            }
            function trip() external {
                require(msg.sender == owner);
                stopped = true;
            }
            function action() external whenNotStopped {
                // pretends to do work
            }
        }
        """,
    )
    artifact = _pipeline_effects(sl)
    info = _info(artifact, "trip()")
    assert "pause_toggle" in info["effect_labels"], info["effect_labels"]
    assert "pause.set" in _claim_ids(info)


def test_semantic_effects_includes_unguarded_public_function(tmp_path):
    """``predicate_trees`` omits them (no revert path), but consumers need the sink."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            uint256 public x;
            uint256 public y;
            mapping(address => bool) public allowed;

            constructor() {
                owner = msg.sender;
            }

            modifier onlyOwner() {
                require(msg.sender == owner);
                _;
            }

            function setX(uint256 v) external onlyOwner { x = v; }
            function _setYInternally(uint256 v) internal { y = v; }
            function setBoth(uint256 a, uint256 b) external onlyOwner {
                x = a;
                _setYInternally(b);
            }
            function allow(address a) external onlyOwner { allowed[a] = true; }
            function publicSetter(uint256 v) external { x = v; }
        }
        """,
    )
    contract = _contract(sl, "C")
    artifact = build_effects(contract)

    assert "publicSetter(uint256)" in artifact["functions"]
    public_setter = artifact["functions"]["publicSetter(uint256)"]
    sinks = {(s["kind"], s["target"]) for s in public_setter["sinks"]}
    assert ("state_write", "x") in sinks

    set_both_sinks = {(s["kind"], s["target"]) for s in artifact["functions"]["setBoth(uint256,uint256)"]["sinks"]}
    assert ("state_write", "x") in set_both_sinks
    assert ("state_write", "y") in set_both_sinks


def test_artifact_is_json_serializable(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            uint256 public x;
            function setX(uint256 v) external { x = v; }
        }
        """,
    )
    artifact = build_effects(_contract(sl))
    json.dumps(artifact)


def test_fallback_and_receive_included(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public impl;
            uint256 public ethBalance;
            receive() external payable { ethBalance = msg.value; }
            fallback() external {
                (bool ok, ) = impl.delegatecall(msg.data);
                require(ok);
            }
        }
        """,
    )
    artifact = build_effects(_contract(sl))
    fns = set(artifact["functions"].keys())
    assert any("fallback" in f for f in fns), fns
    assert any("receive" in f for f in fns), fns


def test_constructor_skipped(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        contract C {
            address public owner;
            constructor() { owner = msg.sender; }
            function poke() external {}
        }
        """,
    )
    artifact = build_effects(_contract(sl))
    assert not any(name.startswith("constructor") for name in artifact["functions"]), artifact["functions"]


# Authorization labels come from the Plane-1 claims registry via ``project_effect_labels``, as in core.py.


def _pipeline_effects(sl, contract_name=None):
    contract = _contract(sl, contract_name)
    effects = build_effects(contract)
    predicate_trees, _pause = build_predicate_artifacts_with_pause_info(contract)
    claims_artifact = build_claims(contract, effects, predicate_trees)
    attach_claims_to_effects(effects, claims_artifact)
    project_effect_labels(effects)
    return effects


_OZ_OWNABLE = """
pragma solidity ^0.8.20;
abstract contract Context { function _msgSender() internal view virtual returns (address) { return msg.sender; } }
abstract contract Ownable is Context {
    address private _owner;
    event OwnershipTransferred(address indexed p, address indexed n);
    modifier onlyOwner() { _checkOwner(); _; }
    function owner() public view virtual returns (address) { return _owner; }
    function _checkOwner() internal view virtual { require(owner() == _msgSender(), "no"); }
    function transferOwnership(address newOwner) public virtual onlyOwner { _transferOwnership(newOwner); }
    function renounceOwnership() public virtual onlyOwner { _transferOwnership(address(0)); }
    function _transferOwnership(address n) internal virtual { _owner = n; emit OwnershipTransferred(address(0), n); }
}
contract MyToken is Ownable {
    uint256 public x;
    address public treasury;
    address public feeRecipient;
    function setX(uint256 v) external onlyOwner { x = v; }
    function setTreasury(address t) external onlyOwner { treasury = t; }
    // onlyOwner-equivalent that ALSO reads feeRecipient incidentally.
    modifier okFee() { require(msg.sender == owner(), "no"); require(feeRecipient != address(0), "unset"); _; }
    function setFeeRecipient(address r) external okFee { feeRecipient = r; }
}
"""


def test_oz_ownable_checkowner_indirection_is_ownership_transfer(tmp_path):
    """OZ 5.x routes through ``_checkOwner``; the matcher keys on canonical selectors plus the ``owner()`` sibling."""
    artifact = _pipeline_effects(_compile(tmp_path, _OZ_OWNABLE), "MyToken")
    assert "ownership_transfer" in _info(artifact, "transferOwnership(address)")["effect_labels"]
    assert "ownership_transfer" in _info(artifact, "renounceOwnership()")["effect_labels"]
    assert "hook_update" not in _info(artifact, "transferOwnership(address)")["effect_labels"]


def test_incidental_config_read_in_auth_gate_is_not_ownership(tmp_path):
    """The modifier reads ``feeRecipient`` as a business leaf; only ``owner`` is the caller-authority var."""
    artifact = _pipeline_effects(_compile(tmp_path, _OZ_OWNABLE), "MyToken")
    assert "ownership_transfer" not in _info(artifact, "setFeeRecipient(address)")["effect_labels"]
    assert "ownership_transfer" in _info(artifact, "transferOwnership(address)")["effect_labels"]


def test_addr_setter_under_unrelated_owner_gate_is_not_ownership(tmp_path):
    artifact = _pipeline_effects(_compile(tmp_path, _OZ_OWNABLE), "MyToken")
    assert "ownership_transfer" not in _info(artifact, "setTreasury(address)")["effect_labels"]
    assert _info(artifact, "setX(uint256)")["effect_labels"] == []


def test_ownership_detection_is_name_agnostic(tmp_path):
    """``ownership.*`` is standards-gated, so an obfuscated rotation is ``authorized_caller.rotate`` instead."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.20;
        contract Vault {
            address private _g;
            modifier guard() { _verify(); _; }
            function _verify() internal view { require(_g == msg.sender); }
            function rotate(address n) external guard { _g = n; }
        }
        """,
    )
    info = _info(_pipeline_effects(sl, "Vault"), "rotate(address)")
    assert "authorized_caller.rotate" in _claim_ids(info)
    assert "ownership_transfer" not in info["effect_labels"]


def test_oz_accesscontrol_grantrole_is_role_management(tmp_path):
    """Role membership isn't inferred from the predicate post-pass; a caller-keyed data map looks identical."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.20;
        abstract contract Ctx { function _msgSender() internal view returns (address) { return msg.sender; } }
        contract AC is Ctx {
            struct RoleData { mapping(address => bool) members; bytes32 admin; }
            mapping(bytes32 => RoleData) private _roles;
            modifier onlyRole(bytes32 role) { _checkRole(role); _; }
            function hasRole(bytes32 role, address a) public view returns (bool) { return _roles[role].members[a]; }
            function getRoleAdmin(bytes32 role) public view returns (bytes32) { return _roles[role].admin; }
            function _checkRole(bytes32 role) internal view { if (!hasRole(role, _msgSender())) revert("no"); }
            function grantRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
                _roles[role].members[account] = true;
            }
            function revokeRole(bytes32 role, address account) public onlyRole(getRoleAdmin(role)) {
                _roles[role].members[account] = false;
            }
        }
        """,
    )
    artifact = _pipeline_effects(sl, "AC")
    assert "role_management" in _info(artifact, "grantRole(bytes32,address)")["effect_labels"]
    assert "role_management" in _info(artifact, "revokeRole(bytes32,address)")["effect_labels"]


def test_caller_keyed_data_map_is_not_role_management(tmp_path):
    """EndpointV2's ``send`` guards ``q[msg.sender][guid] == 0``, which classifies as a caller_authority membership
    leaf.
    """
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.20;
        contract Endpoint {
            mapping(address => mapping(bytes32 => bytes32)) public q;
            function send(bytes32 guid, bytes32 h) external {
                require(q[msg.sender][guid] == bytes32(0), "exists");
                q[msg.sender][guid] = h;
            }
        }
        """,
    )
    labels = _info(_pipeline_effects(sl, "Endpoint"), "send(bytes32,bytes32)")["effect_labels"]
    assert "role_management" not in labels
    assert "ownership_transfer" not in labels


_SOLMATE_AUTH = """
pragma solidity ^0.8.20;
interface Authority { function canCall(address user, address target, bytes4 sig) external view returns (bool); }
abstract contract Auth {
    address public owner;
    Authority public authority;
    modifier requiresAuth() virtual { require(isAuthorized(msg.sender, msg.sig), "UNAUTH"); _; }
    function isAuthorized(address user, bytes4 sig) internal view virtual returns (bool) {
        Authority a = authority;
        return (address(a) != address(0) && a.canCall(user, address(this), sig)) || user == owner;
    }
    function setAuthority(Authority newAuthority) public virtual {
        require(msg.sender == owner || authority.canCall(msg.sender, address(this), msg.sig));
        authority = newAuthority;
    }
}
contract RolesAuthority is Auth {
    mapping(address => bytes32) public getUserRoles;
    mapping(address => mapping(bytes4 => bool)) public isCapabilityPublic;
    mapping(bytes4 => mapping(address => bytes32)) public getRolesWithCapability;
    function setPublicCapability(address target, bytes4 sig, bool enabled) public virtual requiresAuth {
        isCapabilityPublic[target][sig] = enabled;
    }
    function setRoleCapability(uint8 role, address target, bytes4 sig, bool enabled) public virtual requiresAuth {
        if (enabled) { getRolesWithCapability[sig][target] |= bytes32(uint256(1) << role); }
    }
    function setUserRole(address user, uint8 role, bool enabled) public virtual requiresAuth {
        if (enabled) { getUserRoles[user] |= bytes32(uint256(1) << role); }
    }
}
"""


def test_solmate_rolesauthority_setters_are_role_management(tmp_path):
    """Role state is read through external ``authority.canCall``, so the setters are matched by selector."""
    artifact = build_effects(_contract(_compile(tmp_path, _SOLMATE_AUTH), "RolesAuthority"))
    assert "role_management" in _info(artifact, "setUserRole(address,uint8,bool)")["effect_labels"]
    assert "role_management" in _info(artifact, "setRoleCapability(uint8,address,bytes4,bool)")["effect_labels"]
    assert "role_management" in _info(artifact, "setPublicCapability(address,bytes4,bool)")["effect_labels"]


def test_solmate_setauthority_is_authority_update(tmp_path):
    artifact = build_effects(_contract(_compile(tmp_path, _SOLMATE_AUTH), "RolesAuthority"))
    labels = _info(artifact, "setAuthority(Authority)")["effect_labels"]
    assert "authority_update" in labels
    assert "external_contract_call" not in labels
