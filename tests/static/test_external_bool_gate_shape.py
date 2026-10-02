"""The external_bool gate-shape discriminator.

A void external call on a state-var-held address that passes ``msg.sender`` is NOT
caller-gate evidence when the callee is effectful: msg.sender is the funds/burn
subject (``permit``, ``transferFrom``, ``burnShares``, ``vault.enter``), not an
authorization subject. On PR-161 this classified wstETH as a *controller* of Lido's
WithdrawalQueueERC721, chain-refuted. The classifier applies the discriminator the
resolution plane proves at ``permissionless_shapes.py``; the tracking harvest
applies it again as belt-and-braces.

Fixtures are faithful to the refuted mainnet shapes and to the load-bearing TRUE
controls (RoleRegistry.only* void view calls, canCall oracles, merkle witness).
"""

from __future__ import annotations

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.contract_analysis_pipeline.predicates import (  # noqa: E402
    build_predicate_tree,
)
from services.static.contract_analysis_pipeline.shared import (  # noqa: E402
    external_bool_leaf_is_gate_shape,
)
from services.static.contract_analysis_pipeline.tracking import (  # noqa: E402
    _collect_authority_state_vars,
    _collect_state_var_authority_roles,
    build_controller_tracking,
)
from tests.support.slither_compile import _compile  # noqa: E402


def _contract(sl: Slither, name: str):
    return next(c for c in sl.contracts if c.name == name)


def _leaves(tree) -> list[dict]:
    if not isinstance(tree, dict):
        return []
    if tree.get("op") == "LEAF":
        leaf = tree.get("leaf")
        return [leaf] if isinstance(leaf, dict) else []
    out: list[dict] = []
    for child in tree.get("children") or []:
        out.extend(_leaves(child))
    return out


def _fn_leaves(contract, full_name: str) -> list[dict]:
    fn = next(f for f in contract.functions if f.full_name == full_name)
    return _leaves(build_predicate_tree(fn))


def test_permit_and_transfer_from_are_not_delegated_authority(tmp_path):
    """The permit authorizes the queue to spend the caller's tokens; it restricts no caller."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IStETH {
            function permit(
                address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s
            ) external;
            function transferFrom(address from, address to, uint256 amount) external returns (bool);
        }
        contract WithdrawalQueue {
            IStETH public STETH;
            function requestWithdrawalsWithPermit(
                uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s
            ) external {
                STETH.permit(msg.sender, address(this), amount, deadline, v, r, s);
                STETH.transferFrom(msg.sender, address(this), amount);
            }
        }
    """,
    )
    contract = _contract(sl, "WithdrawalQueue")
    leaves = _fn_leaves(contract, "requestWithdrawalsWithPermit(uint256,uint256,uint8,bytes32,bytes32)")
    external = [lf for lf in leaves if lf.get("kind") == "external_bool"]
    assert external, "guard: the void permit call must lower to an external_bool leaf"
    for leaf in external:
        assert leaf.get("callee_state_mutability") == "nonview"
        assert leaf.get("authority_role") == "business"
        assert not leaf.get("set_descriptor")


def test_burn_shares_is_not_delegated_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IEETH { function burnShares(address user, uint256 share) external; }
        contract LiquidityPool {
            IEETH public eETH;
            function withdraw(uint256 share) external {
                eETH.burnShares(msg.sender, share);
            }
        }
    """,
    )
    contract = _contract(sl, "LiquidityPool")
    leaves = _fn_leaves(contract, "withdraw(uint256)")
    external = [lf for lf in leaves if lf.get("kind") == "external_bool"]
    assert external, "guard: burnShares must lower to an external_bool leaf"
    for leaf in external:
        assert leaf.get("authority_role") == "business"
        assert not leaf.get("set_descriptor")


def test_result_checked_effectful_transfer_is_not_delegated_authority(tmp_path):
    """Covers the require+nonview arm."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IERC20 { function transferFrom(address from, address to, uint256 amount) external returns (bool); }
        contract Wrapper {
            IERC20 public bEIGEN;
            function wrap(uint256 amount) external {
                require(bEIGEN.transferFrom(msg.sender, address(this), amount), "transfer failed");
            }
        }
    """,
    )
    contract = _contract(sl, "Wrapper")
    leaves = _fn_leaves(contract, "wrap(uint256)")
    external = [lf for lf in leaves if lf.get("kind") == "external_bool"]
    assert external, "guard: the checked transferFrom must lower to an external_bool leaf"
    for leaf in external:
        assert leaf.get("authority_role") == "business"
        assert not leaf.get("set_descriptor")


def test_void_view_role_registry_call_stays_delegated_authority(tmp_path):
    """The largest true family on PR-161 (100 descriptors)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IRoleRegistry { function onlyGuardian(address caller) external view; }
        contract Gated {
            IRoleRegistry public roleRegistry;
            function doThing() external {
                roleRegistry.onlyGuardian(msg.sender);
            }
        }
    """,
    )
    contract = _contract(sl, "Gated")
    leaves = _fn_leaves(contract, "doThing()")
    external = [lf for lf in leaves if lf.get("kind") == "external_bool"]
    assert external
    for leaf in external:
        assert leaf.get("callee_state_mutability") == "view"
        assert leaf.get("authority_role") == "delegated_authority"
        descriptor = leaf.get("set_descriptor") or {}
        address_source = (descriptor.get("authority_contract") or {}).get("address_source") or {}
        assert address_source.get("state_variable_name") == "roleRegistry"


def test_result_checked_can_call_oracle_stays_delegated_authority(tmp_path):
    """The Solmate RolesAuthority family (43 descriptors on PR-161)."""
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IAuthority {
            function canCall(address user, address target, bytes4 sig) external view returns (bool);
        }
        contract Auth {
            IAuthority public authority;
            uint256 public x;
            function admin(uint256 v) external {
                require(authority.canCall(msg.sender, address(this), msg.sig), "UNAUTHORIZED");
                x = v;
            }
        }
    """,
    )
    contract = _contract(sl, "Auth")
    leaves = _fn_leaves(contract, "admin(uint256)")
    external = [lf for lf in leaves if lf.get("kind") == "external_bool"]
    assert external
    assert any(lf.get("authority_role") == "delegated_authority" for lf in external)


def test_merkle_witness_void_call_keeps_delegated_authority(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IVerifier { function verify(bytes32[] calldata proof, address account, uint256 amount) external; }
        contract Claimer {
            IVerifier public verifier;
            function claim(bytes32[] calldata proof, uint256 amount) external {
                verifier.verify(proof, msg.sender, amount);
            }
        }
    """,
    )
    contract = _contract(sl, "Claimer")
    leaves = _fn_leaves(contract, "claim(bytes32[],uint256)")
    external = [lf for lf in leaves if lf.get("kind") == "external_bool"]
    assert external
    assert any(lf.get("authority_role") == "delegated_authority" for lf in external)


def test_const_compare_oracle_view_vs_nonview(tmp_path):
    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IOracle { function status(address who) external view returns (uint256); }
        interface IVault { function join(address who) external returns (uint256); }
        contract O {
            IOracle public oracle;
            IVault public vault;
            uint256 public x;
            function gated(uint256 v) external {
                require(oracle.status(msg.sender) == 2, "no");
                x = v;
            }
            function ungated(uint256 v) external {
                require(vault.join(msg.sender) == 2, "no");
                x = v;
            }
        }
    """,
    )
    contract = _contract(sl, "O")
    gated = [lf for lf in _fn_leaves(contract, "gated(uint256)") if lf.get("kind") == "external_bool"]
    assert gated
    assert all(lf.get("callee_state_mutability") == "view" for lf in gated)
    assert any(lf.get("authority_role") == "delegated_authority" for lf in gated)

    ungated = [lf for lf in _fn_leaves(contract, "ungated(uint256)") if lf.get("kind") == "external_bool"]
    assert ungated
    assert all(lf.get("callee_state_mutability") == "nonview" for lf in ungated)
    assert all(lf.get("authority_role") == "business" for lf in ungated)


def _teller_artifact_and_contract(tmp_path):
    from services.static.contract_analysis_pipeline.predicate_artifacts import (
        build_predicate_artifacts,
    )

    sl = _compile(
        tmp_path,
        """
        pragma solidity ^0.8.19;
        interface IBoringVault {
            function enter(address from, address asset, uint256 assetAmount, address to, uint256 shareAmount) external;
        }
        contract Teller {
            address public owner;
            IBoringVault public vault;
            function deposit(address asset, uint256 amount, uint256 shares) external {
                vault.enter(msg.sender, asset, amount, msg.sender, shares);
            }
            function setOwner(address o) external {
                require(msg.sender == owner, "not owner");
                owner = o;
            }
        }
    """,
    )
    contract = _contract(sl, "Teller")
    return build_predicate_artifacts(contract), contract


def test_tracking_plan_does_not_mint_caller_gate_for_vault_enter(tmp_path):
    """PR-161 published vault + WETH as caller_gate on 8 Teller deployments."""
    artifact, contract = _teller_artifact_and_contract(tmp_path)
    targets = build_controller_tracking(contract, tmp_path, artifact, None)
    by_id = {t["controller_id"]: t for t in targets}
    vault_caller_gates = [
        t for t in targets if "vault" in t["controller_id"] and t.get("authority_provenance") == "caller_gate"
    ]
    assert vault_caller_gates == []
    owner_targets = [t for t in targets if t["label"] == "owner"]
    assert owner_targets, f"guard: owner target must exist, got {sorted(by_id)}"
    assert all(t.get("authority_provenance") == "caller_gate" for t in owner_targets)


def test_harvest_rejects_persisted_nonview_descriptor_tree():
    """The classifier fix alone would leave replayed artifacts poisoned."""

    def leaf_tree(leaf):
        return {"trees": {"f()": {"op": "LEAF", "leaf": leaf}}}

    nonview_leaf = {
        "kind": "external_bool",
        "operator": "truthy",
        "authority_role": "delegated_authority",
        "gate_kind": "external_call_revert",
        "callee_state_mutability": "nonview",
        "callee_signature": "enter(address,address,uint256,address,uint256)",
        "operands": [{"source": "msg_sender"}, {"source": "state_variable", "state_variable_name": "nativeWrapper"}],
        "set_descriptor": {
            "kind": "external_set",
            "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "vault"}},
            "callee_signature": "enter(address,address,uint256,address,uint256)",
        },
    }
    assert _collect_authority_state_vars(leaf_tree(nonview_leaf)) == set()
    roles = _collect_state_var_authority_roles(leaf_tree(nonview_leaf))
    assert "delegated_authority" not in roles.get("nativeWrapper", set())

    view_leaf = dict(nonview_leaf)
    view_leaf["callee_state_mutability"] = "view"
    view_leaf["set_descriptor"] = {
        "kind": "external_set",
        "authority_contract": {"address_source": {"source": "state_variable", "state_variable_name": "roleRegistry"}},
        "callee_signature": "onlyGuardian(address)",
    }
    assert _collect_authority_state_vars(leaf_tree(view_leaf)) == {"roleRegistry"}

    business_leaf = dict(view_leaf)
    business_leaf["authority_role"] = "business"
    assert _collect_authority_state_vars(leaf_tree(business_leaf)) == set()


def test_gate_shape_helper_three_states():
    assert external_bool_leaf_is_gate_shape("view", "external_call_revert", "onlyGuardian(address)")
    assert external_bool_leaf_is_gate_shape("pure", "require", None)
    assert external_bool_leaf_is_gate_shape("nonview_library", "require", "remove(address)")
    assert not external_bool_leaf_is_gate_shape(
        "nonview", "external_call_revert", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
    )
    assert not external_bool_leaf_is_gate_shape("nonview", "require", "transferFrom(address,address,uint256)")
    assert not external_bool_leaf_is_gate_shape(None, "require", "mystery(address)")
    assert not external_bool_leaf_is_gate_shape(None, None, None)
    assert external_bool_leaf_is_gate_shape("nonview", "external_call_revert", "verify(bytes32[],address,uint256)")
    assert external_bool_leaf_is_gate_shape(None, "try_catch_revert", "verify(bytes32[],address)")
    assert not external_bool_leaf_is_gate_shape("nonview", "require", "verify(bytes32[],address,uint256)")
