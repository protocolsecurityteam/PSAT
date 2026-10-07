from __future__ import annotations

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    EffectInfo,
    EffectsArtifact,
    build_effects,
)
from tests.support.slither_compile import _compile  # noqa: E402


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


def _contract(sl: Slither, name: str | None = None):
    if name is None:
        return sl.contracts[0]
    return next(c for c in sl.contracts if c.name == name)


def _info(artifact: EffectsArtifact, signature: str) -> EffectInfo:
    info = artifact["functions"].get(signature)
    assert info is not None, f"expected {signature} in {sorted(artifact['functions'])}"
    return info


# Authorization labels come from the Plane-1 claims registry via ``project_effect_labels``, as in core.py.


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
    enum Mode { Closed, Open }
    struct Config { Authority delegate; Mode mode; uint256 limit; }
    Mode public mode;
    Config private config;
    function() external private callback;
    function setCallback(function() external next) external { callback = next; }
    function setMode(Mode next) external { mode = next; }
    function setConfig(Config calldata next) external { config = next; }
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


def test_effect_entries_preserve_abi_identity_and_authority_update(tmp_path):
    contract = _contract(_compile(tmp_path, _SOLMATE_AUTH), "RolesAuthority")
    artifact = build_effects(contract)
    labels = _info(artifact, "setAuthority(Authority)")["effect_labels"]
    assert "authority_update" in labels
    assert "external_contract_call" not in labels
    for declared, canonical in [
        ("setAuthority(Authority)", "setAuthority(address)"),
        ("setMode(RolesAuthority.Mode)", "setMode(uint8)"),
        ("setConfig(RolesAuthority.Config)", "setConfig((address,uint8,uint256))"),
        ("setUserRole(address,uint8,bool)", "setUserRole(address,uint8,bool)"),
    ]:
        entry = _info(artifact, declared)
        assert entry["abi_signature"] == canonical
        assert entry["selector"] == _selector(canonical)
        assert entry["writer_selectors"] == [_selector(canonical)]
    # This ABI type is not lowered by the analyzer yet; absence must stay distinct from fallback/receive.
    callback = next(fn for fn in contract.functions if fn.name == "setCallback")
    unknown = _info(artifact, callback.full_name)
    assert unknown["abi_signature"] is None
    assert unknown["selector"] is None
    assert unknown["writer_selectors"] is None
    assert unknown["state_writes"]
