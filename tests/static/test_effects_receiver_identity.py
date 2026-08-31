"""D2: an external call's RECEIVER must publish what it structurally is, and
nothing the evidence does not carry.

The sink's ``target`` string has always held the receiver's identifier. A name
is not an identity: it does not say whether the CALLER chose the asset (in which
case there is no single token to price against), whether it is this unit's
storage, or how it could be read. Those are AST facts, dropped one line after
being derived. These tests compile the shapes and drive production
``build_effects`` / the production claims phase — nothing is faked.

The three refusals are the point, and each has its own test:

* ``visibility`` may not decide the binding — a Slither ``LocalVariable``
  answers ``internal`` / ``is_immutable=False`` / ``is_constant=False``
  identically to an internal state variable;
* the auto-getter selector is licensed by the DECLARED TYPE, not the name — a
  parameterised getter's selector is not ``name()``;
* a formal of an internal helper is not an ABI slot of the entry point.

Protocol-agnostic by construction (§0.0.6): the fixture models shapes — a
library-wrapped send, a public immutable, an internal, a constant, a local
copied out of storage, a collection-typed receiver — never a named protocol.
"""

from __future__ import annotations

import textwrap

import pytest

pytest.importorskip("slither")
from eth_utils.crypto import keccak
from slither import Slither

from services.static.static_analysis.effects import build_effects
from tests.support.foundry_project import write_foundry_project

pytestmark = pytest.mark.compile

_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        require(token.transfer(to, amount));
    }
}

// A collection-typed receiver: ``xs.total()`` binds a STORAGE ARRAY as the
// library call's head, which is how a non-address declaration reaches the
// receiver arm at all.
library ArrayLib {
    function total(uint256[] storage xs) internal view returns (uint256) {
        return xs.length;
    }
}

// A library with its OWN public constant receiver. The sink walk recurses into
// library calls, so this declaration reaches the receiver arm — but it belongs
// to the library, not to the analysed contract.
library LConst {
    IERC20 public constant T = IERC20(address(0x3333333333333333333333333333333333333333));

    function go(address to, uint256 amount) internal {
        T.transfer(to, amount);
    }
}

library MapLib {
    function get(mapping(address => uint256) storage m, address key) internal view returns (uint256) {
        return m[key];
    }
}

contract Receivers {
    using SafeERC20 for IERC20;
    using ArrayLib for uint256[];
    using MapLib for mapping(address => uint256);

    IERC20 public immutable immToken;
    IERC20 internal hiddenToken;
    IERC20 public constant CONST_TOKEN = IERC20(address(0x1111111111111111111111111111111111111111));
    uint256[] public amounts;
    mapping(address => uint256) public balances;

    constructor(IERC20 token) {
        immToken = token;
    }

    // The caller names the asset in ABI slot 0.
    function payParam(address token, address to, uint256 amount) external {
        IERC20(token).safeTransfer(to, amount);
    }

    // The send is sited in a helper whose formal occupies no ABI slot here.
    function payHelper(address token, address to, uint256 amount) external {
        _pay(IERC20(token), to, amount);
    }

    function _pay(IERC20 token, address to, uint256 amount) internal {
        token.safeTransfer(to, amount);
    }

    function payImmutable(address to, uint256 amount) external {
        immToken.safeTransfer(to, amount);
    }

    function payInternal(address to, uint256 amount) external {
        hiddenToken.safeTransfer(to, amount);
    }

    function payConstant(address to, uint256 amount) external {
        CONST_TOKEN.safeTransfer(to, amount);
    }

    // The receiver is a LOCAL copied out of storage. The cast walk does not
    // follow assignment edges (a non-SSA assignment names an arbitrary branch's
    // value), so the binding stops here — and ``getToken()`` below is a
    // HAND-WRITTEN getter, not a compiler-minted one, so nothing may pair them.
    function payLocal(address to, uint256 amount) external {
        IERC20 local = hiddenToken;
        local.safeTransfer(to, amount);
    }

    function getToken() public view returns (IERC20) {
        return hiddenToken;
    }

    // Two different assets moved by one function: two sinks, one selector.
    function payTwoTokens(address to, uint256 amount) external {
        immToken.transfer(to, amount);
        hiddenToken.transfer(to, amount);
    }

    // Two sites that fold onto ONE sink record and disagree about the binding.
    function payBothScopes(IERC20 token, address to, uint256 amount) external {
        token.transfer(to, amount);
        _forward(token, to, amount);
    }

    function _forward(IERC20 token, address to, uint256 amount) internal {
        token.transfer(to, amount);
    }

    function readAmounts() external view returns (uint256) {
        return amounts.total();
    }

    function readBalance(address key) external view returns (uint256) {
        return balances.get(key);
    }
}

contract LibConstUser {
    function pay(address to, uint256 amount) external {
        LConst.go(to, amount);
    }
}

// The same identifier declared on BOTH the contract and the library, holding
// two different addresses. Both sites key to the same sink record.
contract Collide {
    IERC20 public constant T = IERC20(address(0x4444444444444444444444444444444444444444));

    function pay(address to, uint256 amount) external {
        T.transfer(to, amount);
        LConst.go(to, amount);
    }
}
"""


def _selector(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    path = tmp_path_factory.mktemp("receivers") / "Receivers.sol"
    path.write_text(textwrap.dedent(_SRC).strip() + "\n")
    return {c.name: c for c in Slither(str(path)).contracts}


@pytest.fixture(scope="module")
def effects(compiled):
    return build_effects(compiled["Receivers"])


@pytest.fixture(scope="module")
def foreign(compiled):
    return {name: build_effects(compiled[name]) for name in ("LibConstUser", "Collide")}


def _receiver(effects, signature: str, target: str) -> dict | None:
    sinks = [s for s in effects["functions"][signature]["sinks"] if s["target"] == target]
    assert len(sinks) == 1, f"{signature} {target}: {sinks}"
    return sinks[0].get("receiver")


# --- the three provable shapes, pinned byte-exactly -------------------------


def test_entry_parameter_receiver_is_caller_named(effects):
    assert _receiver(effects, "payParam(address,address,uint256)", "token.safeTransfer") == {
        "binding": "parameter",
        "param_scope": "entry_point",
        "param_index": 0,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": "token",
        "receiver_provenance": "caller_named",
    }


def test_public_immutable_receiver_carries_its_minted_getter(effects):
    assert _receiver(effects, "payImmutable(address,uint256)", "immToken.safeTransfer") == {
        "binding": "state_variable",
        "param_scope": None,
        "param_index": None,
        # Spelled the long way: an immutable is inlined into the
        # IMPLEMENTATION's bytecode, so behind a proxy it is not an invariant of
        # the address a consumer prices against.
        "mutability": "immutable_in_implementation",
        "visibility": "public",
        "auto_getter_selector": "0x8e0191b5",
        "variable": "immToken",
        "receiver_provenance": "contract_state_unresolved",
    }
    assert _selector("immToken()") == "0x8e0191b5"


def test_internal_state_variable_receiver_mints_no_getter(effects):
    assert _receiver(effects, "payInternal(address,uint256)", "hiddenToken.safeTransfer") == {
        "binding": "state_variable",
        "param_scope": None,
        "param_index": None,
        "mutability": "mutable",
        "visibility": "internal",
        # No accessor exists, so no selector may be published — and the KEY is
        # present with a null value, never an absent key that a consumer could
        # confuse with a shape this plane never examined.
        "auto_getter_selector": None,
        "variable": "hiddenToken",
        "receiver_provenance": "contract_state_unresolved",
    }


def test_constant_receiver_is_a_declaration_class_not_a_writer_finding(effects):
    receiver = _receiver(effects, "payConstant(address,uint256)", "CONST_TOKEN.safeTransfer")
    assert receiver is not None
    assert receiver["mutability"] == "constant"
    # A ``public constant`` still gets a nullary accessor, so the selector is
    # real; the mutability token describes the DECLARATION, not the write
    # surface, which is the value-flow lattice's question and not this one's.
    assert receiver["auto_getter_selector"] == _selector("CONST_TOKEN()")


# --- R3a: the binding is decided by isinstance, never by visibility ---------


def test_local_and_internal_state_variable_are_not_confused(effects):
    """A ``LocalVariable`` and an internal ``StateVariable`` are indistinguishable
    on ``visibility``/``is_immutable``/``is_constant`` — Slither answers
    ``internal``/``False``/``False`` for both. Only the declared kind separates
    them, and getting it wrong publishes a caller's argument as this contract's
    storage."""
    local = _receiver(effects, "payLocal(address,uint256)", "local.safeTransfer")
    internal = _receiver(effects, "payInternal(address,uint256)", "hiddenToken.safeTransfer")
    assert local == {
        "binding": "local",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": "local",
        "receiver_provenance": "not_determined",
    }
    assert internal is not None and internal["binding"] == "state_variable"


def test_hand_written_getter_is_never_paired_with_a_local(effects):
    """``getToken()`` reads exactly what ``local`` holds, and pairing them would
    be a name/behaviour guess, not a compiler fact — solc minted no accessor for
    a local, so there is nothing to publish."""
    local = _receiver(effects, "payLocal(address,uint256)", "local.safeTransfer")
    assert local is not None
    assert local["auto_getter_selector"] is None
    assert local["receiver_provenance"] == "not_determined"


# --- A1: the DECLARED TYPE licenses the selector, not the identifier --------


def test_parameterised_getter_publishes_no_selector(effects):
    """``uint256[] public amounts`` is read by ``amounts(uint256)``; the
    name-derived ``amounts()`` hashes to four bytes that address no function.
    A library call's receiver is its first argument and may be any type, so
    this arm is reachable — and four bytes collide."""
    array = _receiver(effects, "readAmounts()", "amounts.total")
    mapping = _receiver(effects, "readBalance(address)", "balances.get")
    assert array is not None and mapping is not None
    assert array["binding"] == "state_variable" and array["visibility"] == "public"
    assert mapping["binding"] == "state_variable" and mapping["visibility"] == "public"
    assert array["auto_getter_selector"] is None
    assert mapping["auto_getter_selector"] is None
    # The values that must NOT appear, and the real accessors they are not.
    assert _selector("amounts()") != _selector("amounts(uint256)")
    assert array["auto_getter_selector"] not in (_selector("amounts()"), _selector("amounts(uint256)"))
    assert mapping["auto_getter_selector"] not in (_selector("balances()"), _selector("balances(address)"))


# --- fail-closed arms ------------------------------------------------------


def test_internal_helper_formal_is_not_an_abi_slot(effects):
    """The send is sited inside ``_pay``/``SafeERC20``. Its formal is a real
    parameter of the unit being walked, but whether the ENTRY's argument reaches
    it is a dataflow question this walk does not ask — so no index, and no
    ``caller_named``."""
    receiver = _receiver(effects, "payHelper(address,address,uint256)", "token.safeTransfer")
    assert receiver == {
        "binding": "parameter",
        "param_scope": "internal_helper",
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": "token",
        "receiver_provenance": "not_determined",
    }


def test_disagreeing_sites_fold_to_not_determined(effects):
    """Two sites collapse onto one sink record and bind differently. The fold
    runs ONCE over the collected descriptors, so the outcome cannot depend on IR
    order — a later agreeing site cannot restore what a conflict destroyed."""
    assert _receiver(effects, "payBothScopes(IERC20,address,uint256)", "token.transfer") == {
        "binding": "not_determined",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": None,
        "receiver_provenance": "not_determined",
        "not_determined_reason": "fold_disagreement",
    }


def test_non_call_sinks_carry_no_receiver_key(effects):
    """Absent means never computed. A state write has no receiver, and the key
    must not appear holding a null that a consumer could read as an answer."""
    for info in effects["functions"].values():
        for sink in info["sinks"]:
            if sink["kind"] != "external_call":
                assert "receiver" not in sink, sink


def test_no_asset_address_is_ever_published_by_this_plane(effects):
    """This plane resolves no address. Every state-variable receiver therefore
    reads ``contract_state_unresolved`` and carries no address key at all."""
    for info in effects["functions"].values():
        for sink in info["sinks"]:
            receiver = sink.get("receiver")
            if receiver is None:
                continue
            assert "asset_address" not in receiver
            assert receiver["receiver_provenance"] in {
                "caller_named",
                "contract_state_unresolved",
                "not_determined",
            }


# --- the claims projection: keyed by sink id, not listed per flow -----------


def test_witness_joins_each_receiver_to_its_own_sink(tmp_path):
    """Two assets moved by one function share a flow key (same selector, same
    direction). A per-flow list would leave the consumer unable to say which
    receiver carried which move; the map is keyed by sink id so the join is
    exact."""
    from services.static.static_analysis import collect_static_inputs

    project = write_foundry_project(tmp_path, "Receivers", textwrap.dedent(_SRC).strip() + "\n")
    _analysis, _trees, effects = collect_static_inputs(project)
    assert effects is not None

    record = effects["functions"]["payTwoTokens(address,uint256)"]
    flow_claims = [c for c in record["claims"] if c["claim_id"].startswith("flow.")]
    assert flow_claims, record["claims"]
    witness = flow_claims[0]["witness"]
    receivers = witness["sink_receivers"]

    # Every id in the map is one of the ids the same witness published, so the
    # join never dangles.
    assert set(receivers) <= set(witness["sink_ids"])
    variables = {r["variable"] for r in receivers.values()}
    assert {"immToken", "hiddenToken"} <= variables, receivers
    by_variable = {r["variable"]: r for r in receivers.values()}
    assert by_variable["immToken"]["auto_getter_selector"] == "0x8e0191b5"
    assert by_variable["hiddenToken"]["auto_getter_selector"] is None


# --- F1: a declaration this contract does not have --------------------------


def test_library_constant_is_not_this_contract_s_storage(foreign):
    """The sink walk recurses into library calls, so a library's own
    ``public constant`` arrives as a perfectly good ``StateVariable``. It is
    inlined at each call site, it is not this unit's storage, and the accessor
    it would name is NOT in this contract's ABI — a pinned read at the
    deployment address would revert or fall through to a fallback. The
    declaration's owner, not its type, is what refuses it."""
    receiver = _receiver(foreign["LibConstUser"], "pay(address,uint256)", "T.transfer")
    assert receiver is not None
    assert receiver == {
        "binding": "not_determined",
        "param_scope": None,
        "param_index": None,
        "mutability": None,
        "visibility": None,
        "auto_getter_selector": None,
        "variable": None,
        "receiver_provenance": "not_determined",
        "not_determined_reason": "foreign_declaration",
    }
    assert receiver["auto_getter_selector"] is None


def test_same_named_foreign_declaration_does_not_read_as_agreement(foreign):
    """Two ``T``s holding two different addresses — one on the contract, one on
    the library — reach ONE sink record. Described by name alone their
    descriptors are byte-identical (same visibility, same mutability, same
    minted selector), so the fold would publish two distinct assets as one
    agreed receiver. Refusing the foreign declaration is what makes the
    disagreement visible."""
    receiver = _receiver(foreign["Collide"], "pay(address,uint256)", "T.transfer")
    assert receiver is not None
    assert receiver["binding"] == "not_determined"
    assert receiver["not_determined_reason"] == "fold_disagreement"
    assert receiver["variable"] is None
    assert receiver["auto_getter_selector"] is None
