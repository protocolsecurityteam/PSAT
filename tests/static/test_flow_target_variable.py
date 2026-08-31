"""D3: a ``storage_setter`` destination must say WHICH variable, WHO writes it
inside this unit, and how far that answer reaches.

``_state_var_target_kind`` was already told the variable's name and already held
the writing function objects; both were discarded, leaving a flow entry that
says the destination is redirectable without saying by what. This publishes
them — and, more importantly, publishes the two bounds that stop the writer list
being read as the closed set:

* ``target_writer_scan_complete`` — the existing assembly/delegatecall/alias
  blind-spot gate, now travelling in the same dict as the payload it qualifies;
* ``writer_surface_closed`` — permanently ``not_determined``, because this stage
  analyses ONE compilation unit while the deployed address may be a proxy or one
  of several implementations, whose writers are outside it.

Everything asserted here comes from a real solc compile through production
``build_effects``.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.static_analysis.effects import build_effects

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


# --- the positive, pinned byte-exactly --------------------------------------


def test_single_writer_destination_is_named_with_both_bounds(effects):
    assert _destination(_flow(effects, "Router", "sweep(uint256)")) == {
        "target_kind": {"kind": "storage_setter", "tier": "dispositive_ast"},
        "target_variable": "recipientAddress",
        "target_writer_signatures": ["setRecipientAddress(address)"],
        "target_writer_scan_complete": True,
        # A floor: "redirectable AT LEAST BY these writers' principals". Never
        # true, and not derivable here — see the module docstring.
        "writer_surface_closed": "not_determined",
    }


def test_writer_surface_is_never_closed(effects):
    """Every row that names a destination variable carries the bound, and no row
    anywhere carries any other value for it."""
    named = 0
    for artifact in effects.values():
        for info in artifact["functions"].values():
            for flow in info["value_flows"]:
                if "target_variable" in flow:
                    named += 1
                    assert flow["writer_surface_closed"] == "not_determined"
                assert flow.get("writer_surface_closed", "not_determined") == "not_determined"
    assert named >= 5


def test_writer_list_never_travels_without_its_gate(effects):
    for artifact in effects.values():
        for info in artifact["functions"].values():
            for flow in info["value_flows"]:
                if "target_writer_signatures" in flow:
                    assert "target_writer_scan_complete" in flow, flow
                    assert "target_variable" in flow, flow


# --- fail-closed arms -------------------------------------------------------


def test_assembly_sstore_leaves_the_no_setter_proof_unavailable(effects):
    """A destination with no attributed setter is a proven "fixed destination"
    ONLY when the write scan was exhaustive. A raw-slot ``sstore`` means it was
    not, so the kind degrades to ``indeterminate`` — never ``storage_no_setter``
    — and nothing about the write surface is published at all."""
    flow = _flow(effects, "AsmRouter", "sweepDeployTime(uint256)")
    assert flow["target_kind"]["kind"] == "indeterminate"
    assert "target_variable" not in flow
    assert "target_writer_signatures" not in flow
    assert "target_writer_scan_complete" not in flow
    assert "writer_surface_closed" not in flow


def test_incomplete_scan_publishes_the_writers_with_the_gate_false(effects):
    """The same contract's named setter still classifies, but the list is
    published under a FALSE completeness gate: these writers are some of them,
    not all of them."""
    assert _destination(_flow(effects, "AsmRouter", "sweep(uint256)")) == {
        "target_kind": {"kind": "storage_setter", "tier": "dispositive_ast"},
        "target_variable": "recipientAddress",
        "target_writer_signatures": ["setRecipientAddress(address)"],
        "target_writer_scan_complete": False,
        "writer_surface_closed": "not_determined",
    }


def test_disagreeing_sites_publish_the_member_list_and_no_scalar(effects):
    """Both sites fold to ``storage_setter``, so agreement on the KIND is not
    agreement on the destination. Publishing either name would let a consumer
    read one of two destinations as the whole."""
    destination = _destination(_flow(effects, "Router", "sweepBoth(uint256)"))
    assert destination == {
        "target_kind": {"kind": "storage_setter", "tier": "dispositive_ast"},
        "target_variables": ["Router.otherRecipient", "Router.recipientAddress"],
    }
    assert "target_variable" not in destination
    assert "target_writer_signatures" not in destination


def test_mapping_element_publishes_no_variable(effects):
    """``routes[id]`` classifies by its base, but the base names one address
    where there is one per key — the shape whose only honest answer is nothing."""
    flow = _flow(effects, "Router", "sweepRoute(uint256,uint256)")
    assert "target_variable" not in flow
    assert "target_variables" not in flow


def test_declaration_initialiser_is_a_writer_for_membership_not_for_publication(effects):
    """Slither's synthetic ``slitherConstructorVariables`` is what makes an
    inline-initialised variable a ``storage_setter``, and it must keep doing so
    — demoting it would mint a "fixed destination" negative that was never
    proven. But it is not callable, so it is not published as a writer, and the
    key is ABSENT rather than an empty list that claims a completed search."""
    destination = _destination(_flow(effects, "Router", "sweepInitialised(uint256)"))
    assert destination["target_kind"]["kind"] == "storage_setter"
    assert destination["target_variable"] == "initialisedAtDeclaration"
    assert "target_writer_signatures" not in destination
    assert "target_writer_scan_complete" not in destination
    assert destination["writer_surface_closed"] == "not_determined"
    # The two absences carry OPPOSITE risk, so they are not the same key being
    # missing: an initialiser-only destination is effectively fixed short of an
    # upgrade, an unattributed storage alias may be redirectable by anyone.
    assert destination["target_writer_absent_reason"] == "declaration_initialiser_only"


def test_empty_writer_list_only_where_the_kind_already_earned_it(effects):
    """``[]`` means "the scan completed and found no writer", which is exactly
    what ``storage_no_setter`` asserts. It appears nowhere else, so it can never
    be confused with "no writer was attributed"."""
    assert _destination(_flow(effects, "Router", "sweepDeployTime(uint256)")) == {
        "target_kind": {"kind": "storage_no_setter", "tier": "dispositive_ast"},
        "target_variable": "deployTimeOnly",
        "target_writer_signatures": [],
        "target_writer_scan_complete": True,
        "writer_surface_closed": "not_determined",
    }
    for artifact in effects.values():
        for info in artifact["functions"].values():
            for flow in info["value_flows"]:
                if flow.get("target_writer_signatures") == []:
                    assert flow["target_kind"]["kind"] == "storage_no_setter", flow


def test_constant_and_immutable_name_a_variable_but_no_writer(effects):
    """A declaration class is not a write-surface finding. Neither publishes a
    writer, and both still carry ``writer_surface_closed`` — behind a proxy an
    immutable is redirectable by upgrade, which is precisely what the bound
    refuses to rule out."""
    for signature, kind, variable in (
        ("sweepFixed(uint256)", "immutable", "fixedRecipient"),
        ("sweepBurn(uint256)", "constant", "BURN"),
    ):
        assert _destination(_flow(effects, "Router", signature)) == {
            "target_kind": {"kind": kind, "tier": "dispositive_ast"},
            "target_variable": variable,
            "writer_surface_closed": "not_determined",
        }


def test_same_named_declarations_are_not_one_destination(effects):
    """``LegA.recipient`` and ``LegB.recipient`` are two declarations with two
    setters and two values. Both routed sites fold to ``storage_setter`` and
    both name "recipient", so agreement on the NAME would publish the scalar —
    whose registered meaning is "every contributing site named the same one" —
    over two different destinations, and skip the member list a consumer is
    instructed to take the worst of. Members are canonical because bare names
    cannot tell them apart."""
    destination = _destination(_flow(effects, "TwoLegs", "sweep(uint256)"))
    assert destination == {
        "target_kind": {"kind": "storage_setter", "tier": "dispositive_ast"},
        "target_variables": ["LegA.recipient", "LegB.recipient"],
    }
    assert "target_variable" not in destination
    # In particular the two setters must not be merged into one floor that
    # reads as the writer set of a single destination.
    assert "target_writer_signatures" not in destination
