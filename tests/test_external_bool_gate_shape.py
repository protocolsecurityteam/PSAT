"""The external_bool gate-shape discriminator (Wave 5 B2).

A void external call on a state-var-held address that passes ``msg.sender``
is NOT caller-gate evidence when the callee is effectful: the msg.sender
argument is the funds/burn subject (``permit(msg.sender, …)``,
``transferFrom(msg.sender, …)``, ``burnShares(msg.sender, …)``,
``vault.enter(msg.sender, …)``), not an authorization subject. On PR-161
this classified wstETH as a *controller* of Lido's WithdrawalQueueERC721 —
chain-refuted. The classifier now applies the same discriminator the
resolution plane proves at ``permissionless_shapes.py`` (external_bool arm),
and the tracking harvest applies it again as belt-and-braces.

Fixtures are structurally faithful to the refuted mainnet shapes
(WithdrawalQueueERC721 permit/transferFrom, LiquidityPool burnShares,
TellerWithMultiAssetSupport vault.enter) and to the load-bearing TRUE
controls (RoleRegistry.only* void view calls, canCall oracles, the merkle
bytes32[] witness carve-out).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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


def _compile(tmp_path: Path, source: str) -> Slither:
    src = textwrap.dedent(source).strip() + "\n"
    f = tmp_path / "C.sol"
    f.write_text(src)
    return Slither(str(f))


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


# ---------------------------------------------------------------------------
# Classifier: the refuted FALSE families flip to business / no descriptor
# ---------------------------------------------------------------------------


def test_permit_and_transfer_from_are_not_delegated_authority(tmp_path):
    """WithdrawalQueueERC721 shape: ``STETH.permit(msg.sender, address(this),
    …)`` authorizes the QUEUE to spend the CALLER's tokens; it restricts no
    caller. The leaf must not carry delegated_authority or an
    authority_contract descriptor (which minted STETH/wstETH as controllers)."""
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
    """LiquidityPool shape: ``eETH.burnShares(msg.sender, share)`` is a
    solvency/burn call (msg.sender is the burn subject)."""
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
    """Eigen shape: ``require(bEIGEN.transferFrom(msg.sender, …))`` — the
    result IS checked (gate_kind require) but the callee is effectful and
    msg.sender is the funds subject. Covers the require+nonview arm."""
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


# ---------------------------------------------------------------------------
# Classifier: the load-bearing TRUE families keep delegated_authority
# ---------------------------------------------------------------------------


def test_void_view_role_registry_call_stays_delegated_authority(tmp_path):
    """RoleRegistry.only*(msg.sender) — a void VIEW call whose entire revert
    surface is the gate. The largest true family on PR-161 (100 view
    external_call_revert descriptors) must keep its authority claim."""
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
    """``require(authority.canCall(msg.sender, …))`` — result-checked VIEW
    ACL oracle (the Solmate RolesAuthority family, 43 descriptors on
    PR-161)."""
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
    """The one nonview carve-out the resolution plane proves: a void call
    consuming a caller-supplied ``bytes32[]`` hash-path witness is a merkle
    membership verification against a contract-committed root."""
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
    """The ``call() == constant`` route (``_try_external_auth_oracle``): a
    VIEW status oracle is an authorization predicate; an EFFECTFUL call whose
    result is compared is value movement. Both leaves must now carry the
    mutability so downstream applies the same judgment."""
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


# ---------------------------------------------------------------------------
# Tracking harvest: no caller_gate from a non-gate-shaped leaf
# ---------------------------------------------------------------------------


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
    """End-to-end through ``build_controller_tracking``: the Teller shape
    (PR-161: 8 Teller deployments published vault + WETH as caller_gate
    controllers) yields NO caller_gate target for ``vault``, while the
    direct-equality ``owner`` gate keeps its caller_gate provenance (the
    positive control on the same contract)."""
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
    """Belt-and-braces arm: a tree in which a delegated_authority +
    authority_contract descriptor sits on a NONVIEW external_bool leaf (the
    pre-fix persisted shape) must not contribute to either harvest — the
    classifier fix alone would leave replayed artifacts poisoned."""

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

    # R2 second arm: a descriptor on a NON-authority-role leaf (business)
    # must not mint a caller-gate var either, whatever the mutability.
    business_leaf = dict(view_leaf)
    business_leaf["authority_role"] = "business"
    assert _collect_authority_state_vars(leaf_tree(business_leaf)) == set()


def test_gate_shape_helper_three_states():
    """The discriminator's input→output table, including the two chronic
    failure routes: a not-determined mutability must not reach the proven
    gate state, and the merkle carve-out (the adverse branch) must fire."""
    # Proven gate shapes.
    assert external_bool_leaf_is_gate_shape("view", "external_call_revert", "onlyGuardian(address)")
    assert external_bool_leaf_is_gate_shape("pure", "require", None)
    assert external_bool_leaf_is_gate_shape("nonview_library", "require", "remove(address)")
    # Value movement — not gates.
    assert not external_bool_leaf_is_gate_shape(
        "nonview", "external_call_revert", "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
    )
    assert not external_bool_leaf_is_gate_shape("nonview", "require", "transferFrom(address,address,uint256)")
    # Not determined — must not publish the proven state.
    assert not external_bool_leaf_is_gate_shape(None, "require", "mystery(address)")
    assert not external_bool_leaf_is_gate_shape(None, None, None)
    # Merkle bytes32[] witness carve-out (void call only).
    assert external_bool_leaf_is_gate_shape("nonview", "external_call_revert", "verify(bytes32[],address,uint256)")
    assert external_bool_leaf_is_gate_shape(None, "try_catch_revert", "verify(bytes32[],address)")
    assert not external_bool_leaf_is_gate_shape("nonview", "require", "verify(bytes32[],address,uint256)")
