"""D3: a ``storage_setter`` destination names its variable and in-unit writers, bounded by
``target_writer_scan_complete`` and ``writer_surface_closed`` (always ``not_determined``: one compilation unit
can't see proxies or sibling implementations).
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.contract_analysis_pipeline.effects import build_effects

_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract Router {
    IERC20 public token;
    address public recipientAddress;
    address public otherRecipient;
    address public immutable fixedRecipient;
    address public constant BURN = address(0xdEaD);
    address public deployTimeOnly;
    address public initialisedAtDeclaration = address(0xBEEF);
    mapping(uint256 => address) public routes;

    constructor(address recipient) {
        fixedRecipient = recipient;
        deployTimeOnly = recipient;
    }

    function setRecipientAddress(address recipient) external {
        recipientAddress = recipient;
    }

    function setOtherRecipient(address recipient) external {
        otherRecipient = recipient;
    }

    function sweep(uint256 amount) external {
        token.transfer(recipientAddress, amount);
    }

    // Two sites, one flow key, two different setter-backed destinations.
    function sweepBoth(uint256 amount) external {
        token.transfer(recipientAddress, amount);
        token.transfer(otherRecipient, amount);
    }

    function sweepFixed(uint256 amount) external {
        token.transfer(fixedRecipient, amount);
    }

    function sweepBurn(uint256 amount) external {
        token.transfer(BURN, amount);
    }

    function sweepDeployTime(uint256 amount) external {
        token.transfer(deployTimeOnly, amount);
    }

    // Written only by the declaration-site initialiser Slither synthesises.
    function sweepInitialised(uint256 amount) external {
        token.transfer(initialisedAtDeclaration, amount);
    }

    // A mapping ELEMENT: classified by its base's mutability, but the base is
    // not the destination — there is one destination per key.
    function sweepRoute(uint256 id, uint256 amount) external {
        token.transfer(routes[id], amount);
    }
}

// Two DIFFERENT declarations that share an identifier, each with its own
// setter and its own value. Two routed sites, one flow key.
contract LegA {
    IERC20 public token;
    address public recipient;

    function setOnA(address r) external {
        recipient = r;
    }

    function pay(uint256 amount) external {
        token.transfer(recipient, amount);
    }
}

contract LegB {
    IERC20 public token;
    address public recipient;

    function setOnB(address r) external {
        recipient = r;
    }

    function pay(uint256 amount) external {
        token.transfer(recipient, amount);
    }
}

contract TwoLegs {
    LegA private legA;
    LegB private legB;

    function sweep(uint256 amount) external {
        legA.pay(amount);
        legB.pay(amount);
    }
}

contract AsmRouter {
    IERC20 public token;
    address public recipientAddress;
    address public deployTimeOnly;

    constructor(address recipient) {
        deployTimeOnly = recipient;
    }

    function setRecipientAddress(address recipient) external {
        recipientAddress = recipient;
    }

    // A raw-slot write Slither cannot attribute: the write surface of every
    // variable in this contract stops being enumerable.
    function rawWrite(uint256 slot, uint256 value) external {
        assembly {
            sstore(slot, value)
        }
    }

    function sweep(uint256 amount) external {
        token.transfer(recipientAddress, amount);
    }

    function sweepDeployTime(uint256 amount) external {
        token.transfer(deployTimeOnly, amount);
    }
}
"""


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    path = tmp_path_factory.mktemp("dest") / "Router.sol"
    path.write_text(textwrap.dedent(_SRC).strip() + "\n")
    return {c.name: c for c in Slither(str(path)).contracts}


@pytest.fixture(scope="module")
def effects(compiled):
    return {
        name: build_effects(contract)
        for name, contract in compiled.items()
        if name in ("Router", "AsmRouter", "TwoLegs")
    }


def _flow(effects, contract: str, signature: str) -> dict:
    flows = effects[contract]["functions"][signature]["value_flows"]
    assert len(flows) == 1, flows
    return flows[0]


def _destination(flow: dict) -> dict:
    return {
        key: value
        for key, value in flow.items()
        if key.startswith("target_") and key != "target_param_index" or key == "writer_surface_closed"
    }


def test_single_writer_destination_is_named_with_both_bounds(effects):
    assert _destination(_flow(effects, "Router", "sweep(uint256)")) == {
        "target_kind": {"kind": "storage_setter", "tier": "dispositive_ast"},
        "target_variable": "recipientAddress",
        "target_writer_signatures": ["setRecipientAddress(address)"],
        "target_writer_scan_complete": True,
        "writer_surface_closed": "not_determined",
    }
