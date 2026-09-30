"""Regression tests for the Plane-0 facts hardening in ``effects/``.

Each test compiles a real Solidity fixture and drives the production
``build_effects`` -> ``build_claims`` -> ``project_effect_labels`` sequence. The
six fixes (FACT records / prerequisites), one section each:
(a) sink ``origin`` body vs guard; (b) keying prefers a concrete body over a 0-node
interface re-declaration; (c) member-level write facts; (d) ``hygiene_class`` and
the hygiene-gated ownership harvest; (e) native ``transfer``/``send`` value sinks;
(f) ``transferFrom`` direction when ``from == address(this)``.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import (  # noqa: E402
    attach_claims_to_effects,
    build_claims,
    project_effect_labels,
)
from services.static.contract_analysis_pipeline.effects import (  # noqa: E402
    build_effects,
)
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    build_predicate_artifacts_with_pause_info,
)


def _compile(tmp_path: Path, source: str, name: str):
    f = tmp_path / f"{name}.sol"
    f.write_text(textwrap.dedent(source).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == name)


def _effects_with_labels(contract):
    predicate_trees, _pause = build_predicate_artifacts_with_pause_info(contract)
    effects = build_effects(contract)
    claims_artifact = build_claims(contract, effects, predicate_trees)
    attach_claims_to_effects(effects, claims_artifact)
    project_effect_labels(effects)
    return effects


def _info(effects, signature):
    info = effects["functions"].get(signature)
    assert info is not None, f"expected {signature} in {sorted(effects['functions'])}"
    return info


def _sink(info, kind, target_contains):
    matches = [s for s in info["sinks"] if s["kind"] == kind and target_contains in s["target"]]
    assert matches, (
        f"no {kind} sink containing {target_contains!r} in {[(s['kind'], s['target']) for s in info['sinks']]}"
    )
    return matches[0]


_GUARD_ORIGIN_SRC = """
pragma solidity ^0.8.20;
interface Authority { function canCall(address u, address t, bytes4 s) external view returns (bool); }
interface Pinger { function ping(uint256 v) external; }
abstract contract Auth {
    address public owner;
    Authority public authority;
    modifier requiresAuth() { require(isAuthorized(msg.sender, msg.sig), "no"); _; }
    function isAuthorized(address u, bytes4 s) internal view returns (bool) {
        Authority a = authority;
        return (address(a) != address(0) && a.canCall(u, address(this), s)) || u == owner;
    }
}
contract Svc is Auth {
    bool public isPaused;
    function pause() external requiresAuth { isPaused = true; }
    function poke(Pinger t, uint256 v) external requiresAuth { t.ping(v); }
}
"""


def test_modifier_auth_call_is_guard_origin_and_never_an_effect(tmp_path):
    contract = _compile(tmp_path, _GUARD_ORIGIN_SRC, "Svc")
    effects = build_effects(contract)

    pause = _info(effects, "pause()")
    assert _sink(pause, "external_call", "canCall")["origin"] == "guard"
    assert _sink(pause, "state_write", "isPaused")["origin"] == "body"
    assert "external_contract_call" not in pause["effect_labels"]

    poke = _info(effects, "poke(Pinger,uint256)")
    assert _sink(poke, "external_call", "ping")["origin"] == "body"
    assert _sink(poke, "external_call", "canCall")["origin"] == "guard"
    assert "external_contract_call" in poke["effect_labels"]


_CLOBBER_SRC = """
pragma solidity ^0.8.20;
interface IPausable {
    function pause(uint256 status) external;
}
abstract contract Pausable is IPausable {
    uint256 internal _paused;
    function pause(uint256 status) public virtual override { _paused = status; }
}
contract Manager is Pausable {
    uint256 public x;
    function setX(uint256 v) external { x = v; }
}
"""


def test_concrete_body_wins_over_zero_node_interface_declaration(tmp_path):
    """Keying by name alone let the 0-node interface clobber the real record."""
    contract = _compile(tmp_path, _CLOBBER_SRC, "Manager")

    pause_fns = [fn for fn in contract.functions if fn.full_name == "pause(uint256)"]
    assert len(pause_fns) >= 2
    assert any(not getattr(fn, "nodes", None) for fn in pause_fns), "expected a 0-node interface re-declaration"

    effects = build_effects(contract)
    pause = _info(effects, "pause(uint256)")
    assert _sink(pause, "state_write", "_paused")["target"] == "_paused"
    assert pause["writer_selectors"] == [pause["selector"]]


_MEMBER_SRC = """
pragma solidity ^0.8.20;
contract Accountant {
    struct State { bool isPaused; address payoutAddress; uint24 delay; }
    State internal s;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function pause() external onlyOwner { s.isPaused = true; }
    function setPayout(address p) external onlyOwner { s.payoutAddress = p; }
    function setDelay(uint24 d) external onlyOwner { s.delay = d; }
}
"""


def test_member_write_facts_carry_member_path_and_declared_type(tmp_path):
    """A pause claim needs to tell the bool member from the address member."""
    contract = _compile(tmp_path, _MEMBER_SRC, "Accountant")
    effects = build_effects(contract)

    def member_fact(signature):
        writes = [sw for sw in _info(effects, signature)["state_writes"] if sw["granularity"] == "member"]
        assert len(writes) == 1, writes
        return writes[0]

    pause_fact = member_fact("pause()")
    assert pause_fact["var"] == "s"
    assert pause_fact["member_path"] == ["isPaused"]
    assert pause_fact["declared_type"] == "bool"

    payout_fact = member_fact("setPayout(address)")
    assert payout_fact["member_path"] == ["payoutAddress"]
    assert payout_fact["declared_type"] == "address"

    delay_fact = member_fact("setDelay(uint24)")
    assert delay_fact["member_path"] == ["delay"]
    assert delay_fact["declared_type"] == "uint24"


# Slither reports the ``OwnableStorageLocation`` constant as written by every function touching the storage, including
# ``owner()``.
_OZ_V5_SRC = """
pragma solidity ^0.8.20;
abstract contract OwnableUpgradeable {
    bytes32 constant OwnableStorageLocation = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;
    struct OwnableStorage { address _owner; }
    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly { $.slot := OwnableStorageLocation }
    }
    function owner() public view returns (address) { return _getOwnableStorage()._owner; }
    modifier onlyOwner() { require(owner() == msg.sender, "no"); _; }
    function transferOwnership(address n) public onlyOwner { _getOwnableStorage()._owner = n; }
}
contract Vault is OwnableUpgradeable {
    address public token;
    function setToken(address t) public onlyOwner { token = t; }
}
"""


def test_oz_v5_slot_constant_ghost_is_not_ownership_and_is_hygiene_tagged(tmp_path):
    """Ghost immunity comes from standards, not write identity."""
    contract = _compile(tmp_path, _OZ_V5_SRC, "Vault")
    effects = _effects_with_labels(contract)

    assert "ownership_transfer" in _info(effects, "transferOwnership(address)")["effect_labels"]
    for signature in ("owner()", "setToken(address)"):
        assert "ownership_transfer" not in _info(effects, signature)["effect_labels"], signature

    owner_write = _sink(_info(effects, "owner()"), "state_write", "OwnableStorageLocation")
    assert owner_write["origin"] == "body"
    owner_fact = next(sw for sw in _info(effects, "owner()")["state_writes"] if sw["var"] == "OwnableStorageLocation")
    assert owner_fact["hygiene_class"] == "view_writer"

    set_token_facts = {sw["var"]: sw for sw in _info(effects, "setToken(address)")["state_writes"]}
    assert set_token_facts["token"]["hygiene_class"] == "normal"
    assert set_token_facts["OwnableStorageLocation"]["hygiene_class"] == "storage_location_pseudo"


_OZ_V4_OWNABLE_SRC = """
pragma solidity ^0.8.20;
abstract contract Ownable {
    address private _owner;
    modifier onlyOwner() { require(owner() == msg.sender, "no"); _; }
    function owner() public view returns (address) { return _owner; }
    function transferOwnership(address n) public onlyOwner { _owner = n; }
}
contract Token is Ownable {
    uint256 public x;
    function setX(uint256 v) external onlyOwner { x = v; }
}
"""


def test_hygiene_gate_keeps_real_address_owner_ownership(tmp_path):
    contract = _compile(tmp_path, _OZ_V4_OWNABLE_SRC, "Token")
    effects = _effects_with_labels(contract)

    assert "ownership_transfer" in _info(effects, "transferOwnership(address)")["effect_labels"]
    owner_fact = next(
        sw for sw in _info(effects, "transferOwnership(address)")["state_writes"] if sw["var"] == "_owner"
    )
    assert owner_fact["hygiene_class"] == "normal"


_REENTRANCY_SRC = """
pragma solidity ^0.8.20;
abstract contract ReentrancyGuard {
    uint256 private _status;
    constructor() { _status = 1; }
    modifier nonReentrant() { require(_status != 2, "reentrant"); _status = 2; _; _status = 1; }
}
contract Pool is ReentrancyGuard {
    uint256 public x;
    function doWork(uint256 v) external nonReentrant { x = v; }
}
"""


def test_reentrancy_guard_write_is_guard_origin_and_hygiene_tagged(tmp_path):
    contract = _compile(tmp_path, _REENTRANCY_SRC, "Pool")
    effects = build_effects(contract)
    facts = {sw["var"]: sw for sw in _info(effects, "doWork(uint256)")["state_writes"]}
    assert facts["_status"]["hygiene_class"] == "reentrancy_guard"
    assert facts["_status"]["origin"] == "guard"
    assert facts["x"]["hygiene_class"] == "normal"
    assert facts["x"]["origin"] == "body"


_NATIVE_TRANSFER_SRC = """
pragma solidity ^0.8.20;
contract W {
    mapping(address => uint256) public balanceOf;
    function deposit() public payable { balanceOf[msg.sender] += msg.value; }
    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
    }
    function withdrawViaSend(uint256 wad) public {
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).send(wad);
    }
}
"""


def test_native_transfer_and_send_become_asset_send(tmp_path):
    """They lower to their own IR op, so the old scan missed them."""
    contract = _compile(tmp_path, _NATIVE_TRANSFER_SRC, "W")
    effects = build_effects(contract)

    withdraw = _info(effects, "withdraw(uint256)")
    flows = withdraw["value_flows"]
    assert any(vf["kind"] == "native_transfer_send" and vf["direction"] == "out" for vf in flows), flows
    assert "asset_send" in withdraw["effect_labels"]
    assert "hook_update" not in withdraw["effect_labels"]

    send = _info(effects, "withdrawViaSend(uint256)")
    assert any(vf["kind"] == "native_transfer_send" for vf in send["value_flows"])
    assert "asset_send" in send["effect_labels"]

    assert not _info(effects, "deposit()")["value_flows"]


_DIRECTION_SRC = """
pragma solidity ^0.8.20;
interface IERC721 {
    function transferFrom(address from, address to, uint256 id) external;
}
contract Rec {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function recover(address token, address to, uint256 id) external onlyOwner {
        IERC721(token).transferFrom(address(this), to, id);
    }
    function pull(address token, address from, uint256 id) external onlyOwner {
        IERC721(token).transferFrom(from, address(this), id);
    }
}
"""


def test_transferfrom_from_self_is_asset_send_not_pull(tmp_path):
    contract = _compile(tmp_path, _DIRECTION_SRC, "Rec")
    effects = build_effects(contract)

    recover = _info(effects, "recover(address,address,uint256)")
    out_flow = next(vf for vf in recover["value_flows"] if vf["kind"] == "callee_erc20_selector")
    assert out_flow["from_is_self"] is True
    assert out_flow["direction"] == "out"
    assert "asset_send" in recover["effect_labels"]
    assert "asset_pull" not in recover["effect_labels"]

    pull = _info(effects, "pull(address,address,uint256)")
    in_flow = next(vf for vf in pull["value_flows"] if vf["kind"] == "callee_erc20_selector")
    assert in_flow["from_is_self"] is False
    assert in_flow["direction"] == "in"
    assert "asset_pull" in pull["effect_labels"]
    assert "asset_send" not in pull["effect_labels"]


_ASSEMBLY_SLOT_SRC = """
pragma solidity ^0.8.20;
contract A {
    function setSlot(uint256 v) external {
        assembly { sstore(0x42, v) }
    }
}
"""


def test_inline_assembly_write_is_assembly_slot_granularity(tmp_path):
    contract = _compile(tmp_path, _ASSEMBLY_SLOT_SRC, "A")
    effects = build_effects(contract)
    facts = _info(effects, "setSlot(uint256)")["state_writes"]
    assembly_facts = [sw for sw in facts if sw["granularity"] == "assembly_slot"]
    assert len(assembly_facts) == 1, facts
    assert assembly_facts[0]["var"].startswith("assembly_storage:")
    assert assembly_facts[0]["hygiene_class"] == "normal"
    assert assembly_facts[0]["member_path"] == []


_PROBE_INPUT_SRC = """
    pragma solidity ^0.8.20;

    contract Redeemer {
        mapping(uint256 => address) public ownerOf;

        // A quantity and a clock value, plus an id-keyed redemption: the three
        // argument roles a prober must tell apart.
        function payOut(address to, uint256 amount, uint256 deadline) external {
            require(block.timestamp <= deadline);
            payable(to).transfer(amount);
        }

        function redeem(uint256 tokenId) external {
            require(ownerOf[tokenId] == msg.sender);
            delete ownerOf[tokenId];
        }

        function deposit() external payable {}
    }
"""


def test_parameter_names_and_payability_are_recorded(tmp_path):
    contract = _compile(tmp_path, _PROBE_INPUT_SRC, "Redeemer")
    effects = build_effects(contract)

    pay = _info(effects, "payOut(address,uint256,uint256)")
    assert pay["parameter_names"] == ["to", "amount", "deadline"]
    assert pay["payable"] is False
    assert _info(effects, "redeem(uint256)")["parameter_names"] == ["tokenId"]
    assert _info(effects, "deposit()")["payable"] is True


def test_value_flow_records_which_parameter_carries_the_amount(tmp_path):
    contract = _compile(tmp_path, _PROBE_INPUT_SRC, "Redeemer")
    effects = build_effects(contract)
    flows = [f for f in _info(effects, "payOut(address,uint256,uint256)")["value_flows"] if f["direction"] == "out"]
    assert flows, "expected a native transfer out"
    assert any(f.get("amount_kind", {}).get("kind") == "param" for f in flows)
    assert {f.get("amount_param_index") for f in flows} == {1}
    assert {f.get("target_param_index") for f in flows} == {0}
