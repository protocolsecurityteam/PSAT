"""Cross-contract value routing (``value_router`` flows + claim).

A *router* function (``TellerWithMultiAssetSupport.deposit`` /
``bulkWithdraw``) itself neither holds nor sends value: it CALLS an in-unit
contract (``BoringVault.enter`` / ``exit``) whose body moves the value. The
effect walk crosses the resolved ``HighLevelCall`` boundary, rebases its
destination/self classification onto the callee's own contract, and tags the
routed move ``direction: "value_router"`` — kept distinct from the entry's own
``in``/``out`` so it never adds an asset-direction label to the router.

Proven here on a self-contained Router→Vault→SafeTransferLib fixture (the
real Teller/BoringVault shape, no external lib dependency):

  * a routed pull into the vault resolves the destination to ``self`` (the
    money goes INTO the vault, not to the caller);
  * a routed send back out binds the destination to the ROUTER's own caller
    parameter (``target_param_index``) — the provable "caller can name the
    payee" fact, recovered across the boundary WITHOUT over-claiming a wrong
    slot;
  * a SAME-contract library transfer stays ``out`` (never ``value_router``):
    the boundary crossing, not the transfer, is what mints the router flow;
  * the vault, analysed as its OWN entry point, keeps plain ``in``/``out``.

Precedent: ``tests/test_flow_interproc.py`` (same compile-with-Slither harness).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.claims import build_claims  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402

# Router → Vault → token-first library transfer (SafeTransferLib idiom). The
# library body does the real ERC-20 call, so the vault as a direct entry has
# plain in/out flows — routing is the only thing that promotes them to
# value_router on the caller.
_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

library SafeTransferLib {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount), "T");
    }
    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        require(token.transferFrom(from, to, amount), "TF");
    }
}

contract Vault {
    using SafeTransferLib for IERC20;
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function enter(address from, IERC20 asset, uint256 amount, address to, uint256 sh) external {
        asset.safeTransferFrom(from, address(this), amount);
        totalShares += sh;
        shares[to] += sh;
    }

    function exit(address to, IERC20 asset, uint256 amount, address from, uint256 sh) external {
        totalShares -= sh;
        shares[from] -= sh;
        asset.safeTransfer(to, amount);
    }
}

contract Router {
    using SafeTransferLib for IERC20;
    Vault public vault;
    IERC20 public asset;

    function deposit(uint256 amount) external {
        vault.enter(msg.sender, asset, amount, msg.sender, amount);
    }

    function withdraw(uint256 amount, address to) external {
        vault.exit(to, asset, amount, msg.sender, amount);
    }

    function directSend(uint256 amount, address to) external {
        // Same-contract library transfer: stays a plain out-flow, never routed.
        asset.safeTransfer(to, amount);
    }
}
"""


@pytest.fixture(scope="module")
def _unit(tmp_path_factory):
    f = tmp_path_factory.mktemp("value_router") / "router.sol"
    f.write_text(textwrap.dedent(_SRC).strip() + "\n")
    return Slither(str(f))


def _contract(unit, name: str):
    return next(c for c in unit.contracts if c.name == name)


def _effects(unit, name: str):
    return build_effects(_contract(unit, name))["functions"]


def _router_flows(info) -> list[dict[str, Any]]:
    return [f for f in info["value_flows"] if f["direction"] == "value_router"]


# --- routed destination resolution -----------------------------------------


def test_deposit_routes_value_into_the_vault(_unit):
    fns = _effects(_unit, "Router")
    info = fns["deposit(uint256)"]
    routed = _router_flows(info)
    assert len(routed) == 1, routed
    flow = routed[0]
    # The money goes INTO the vault (address(this) of the callee), not the caller.
    assert flow["target_kind"]["kind"] == "self"
    # A destination that is the callee's self is not the entry's own arg slot.
    assert "target_param_index" not in flow
    assert flow["amount_kind"]["kind"] == "param"
    assert flow["amount_param_index"] == 0


def test_withdraw_binds_router_destination_to_the_caller_param(_unit):
    fns = _effects(_unit, "Router")
    info = fns["withdraw(uint256,address)"]
    routed = _router_flows(info)
    assert len(routed) == 1, routed
    flow = routed[0]
    # The vault sends its own asset to a destination the ROUTER's caller named:
    # withdraw's `to`, positional index 1 — recovered across the boundary.
    assert flow["from_is_self"] is True
    assert flow["target_kind"]["kind"] == "param"
    assert flow["target_param_index"] == 1


# --- the crossing, not the transfer, is what mints a router flow ------------


def test_same_contract_library_transfer_is_not_routed(_unit):
    fns = _effects(_unit, "Router")
    info = fns["directSend(uint256,address)"]
    assert _router_flows(info) == []
    # It is a plain out-flow, exactly as before this feature existed.
    assert any(f["direction"] == "out" for f in info["value_flows"])


def test_vault_as_direct_entry_keeps_plain_in_out(_unit):
    fns = _effects(_unit, "Vault")
    enter = fns["enter(address,IERC20,uint256,address,uint256)"]
    exit_ = fns["exit(address,IERC20,uint256,address,uint256)"]
    assert _router_flows(enter) == []
    assert _router_flows(exit_) == []
    assert any(f["direction"] == "in" for f in enter["value_flows"])
    assert any(f["direction"] == "out" for f in exit_["value_flows"])


# --- claim plane ------------------------------------------------------------


def test_value_router_claim_is_minted_for_routers(_unit):
    contract = _contract(_unit, "Router")
    art = build_effects(contract)
    claims = build_claims(contract, art, {})["functions"]

    def _has_router_claim(sig: str) -> bool:
        return any(c["claim_id"] == "value_router" for c in claims[sig])

    assert _has_router_claim("deposit(uint256)")
    assert _has_router_claim("withdraw(uint256,address)")
    # A same-contract transfer is not a routing claim.
    assert not _has_router_claim("directSend(uint256,address)")

    router_claim = next(c for c in claims["withdraw(uint256,address)"] if c["claim_id"] == "value_router")
    assert router_claim["tier"] == "standard_exact"
    witness_flow = router_claim["witness"]["flows"][0]
    assert witness_flow["target_param_index"] == 1
