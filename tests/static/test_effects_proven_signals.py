"""The Plane-0 hygiene lattice must rest on the lowered IR, not on identifiers.

Every fixture here is named ADVERSARIALLY: the slot constants carry no
``slot``/``storage`` token and the reentrancy guard carries no ``reentran``/
``locked``/``_status`` token, so a test only passes if the classification came
from the IR shape (an assembly storage-pointer bind, an ``sstore`` to a
constant, a set/restore pair around a modifier's placeholder). The negative
controls are the mirror image: identifiers that LOOK like slots or guards but
whose IR proves they are neither.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("slither")
from slither import Slither

from services.static.static_analysis.effects import build_effects
from services.static.static_analysis.summaries import _extract_value_flows


def _compile(tmp_path: Path, source: str, name: str):
    path = tmp_path / f"{name}.sol"
    path.write_text(textwrap.dedent(source).strip() + "\n")
    return next(c for c in Slither(str(path)).contracts if c.name == name)


def _hygiene(effects, signature: str) -> dict[str, str]:
    info = effects["functions"].get(signature)
    assert info is not None, f"expected {signature} in {sorted(effects['functions'])}"
    return {w["var"]: w["hygiene_class"] for w in info["state_writes"]}


# --- ERC-7201 storage-pointer bind: ``assembly { $.slot := C }`` -------------

_NAMESPACED_SRC = """
pragma solidity ^0.8.20;

contract Vault {
    /// @custom:storage-location erc7201:acme.main
    struct MainData { address controller; bool halted; }

    // ERC-7201 namespaced slot. The identifier deliberately carries no
    // "slot"/"storage" token, so only its assembly USE identifies it.
    bytes32 private constant ACME_MAIN =
        0x0d1c0b3a3e5c1eb8b56b4d9a5e6b2c0bdc1b9e3e1c5c3a8f0d2b6a4c9e7f1300;

    // Same type, same shape of value, never used as a slot: a plain constant.
    bytes32 private constant ACME_DOMAIN = keccak256("acme.domain");

    function _main() private pure returns (MainData storage $) {
        assembly { $.slot := ACME_MAIN }
    }

    function setHalted(bool v) public { _main().halted = v; }
    function domain() public pure returns (bytes32) { return ACME_DOMAIN; }
}
"""


def test_namespaced_slot_constant_is_pseudo_without_a_slot_name(tmp_path):
    """``ACME_MAIN`` is bound to a storage-location local in assembly, so it is a
    slot pseudo-var — proven by the ``Assignment`` to an ``is_storage`` lvalue,
    not by its name (which the old suffix test would have missed entirely)."""
    effects = build_effects(_compile(tmp_path, _NAMESPACED_SRC, "Vault"))
    assert _hygiene(effects, "setHalted(bool)")["ACME_MAIN"] == "storage_location_pseudo"


# --- Solady/EIP-1967 direct slot write: ``assembly { sstore(C, v) }`` --------

_SSTORE_SRC = """
pragma solidity ^0.8.20;

contract Handle {
    // Written through raw sstore; identifier carries no slot/storage token.
    bytes32 internal constant ADMIN_HANDLE =
        0x8b78c6d8000000000000000000000000000000000000000000000000000000ff;

    bytes32 internal constant ADMIN_ROLE = keccak256("acme.role.admin");

    function setAdmin(address v) public {
        assembly { sstore(ADMIN_HANDLE, v) }
    }

    function role() public pure returns (bytes32) { return ADMIN_ROLE; }
}
"""


def test_sstore_target_constant_is_pseudo_and_a_value_constant_is_not(tmp_path):
    """Solidity forbids assigning a constant, so an ``Assignment`` whose lvalue
    IS one (outside the synthetic initializer) can only be ``sstore(C, …)``.
    ``ADMIN_ROLE`` — same type, same declaration site, never a slot — stays a
    plain ``constant``: the negative control that a value-blind name rule
    ('bytes32 constant') could not give."""
    effects = build_effects(_compile(tmp_path, _SSTORE_SRC, "Handle"))
    classes = _hygiene(effects, "setAdmin(address)")
    assert classes["ADMIN_HANDLE"] == "storage_location_pseudo"
    assert classes.get("ADMIN_ROLE") in (None, "constant")


_SLOT_NAMED_VALUE_SRC = """
pragma solidity ^0.8.20;

contract Decoy {
    // Named like a slot locator, but the IR proves it is only ever a VALUE:
    // it is hashed, never bound as a storage pointer and never sstore'd.
    bytes32 public constant OPERATOR_SLOT = keccak256("acme.operator");

    mapping(bytes32 => bool) public flags;

    function flag() public { flags[keccak256(abi.encode(OPERATOR_SLOT))] = true; }
}
"""


def test_slot_named_value_constant_is_not_a_pseudo_slot(tmp_path):
    """The inverse control: a ``*_SLOT`` identifier that the IR never uses as a
    slot must NOT be admitted as a namespaced latch/ownership pseudo-var. Under
    the name rule this was a false hit that fed the pause and namespaced-write
    matchers."""
    effects = build_effects(_compile(tmp_path, _SLOT_NAMED_VALUE_SRC, "Decoy"))
    assert _hygiene(effects, "flag()").get("OPERATOR_SLOT") in (None, "constant")


# --- Reentrancy guard: set/restore around the modifier placeholder ----------

_GUARD_SRC = """
pragma solidity ^0.8.20;

contract Guarded {
    // No "reentran"/"locked"/"_status" token anywhere: only the set/restore
    // shape around ``_;`` identifies this as a guard.
    uint256 private entryFlag = 1;

    address public treasury;

    modifier single() {
        require(entryFlag == 1, "REENTRANCY");
        entryFlag = 2;
        _;
        entryFlag = 1;
    }

    function setTreasury(address t) public single { treasury = t; }
}
"""


def test_guard_var_is_classified_without_a_guard_name(tmp_path):
    """``entryFlag`` is written on both sides of the modifier's placeholder —
    the defining shape of a reentrancy guard, and of nothing else. The real
    state write (``treasury``) is untouched."""
    effects = build_effects(_compile(tmp_path, _GUARD_SRC, "Guarded"))
    classes = _hygiene(effects, "setTreasury(address)")
    assert classes["entryFlag"] == "reentrancy_guard"
    assert classes["treasury"] == "normal"


_HELPER_GUARD_SRC = """
pragma solidity ^0.8.20;

contract HelperGuarded {
    uint256 private gateWord = 1;
    uint256 public counter;

    function _enter() private { require(gateWord == 1, "REENTRANCY"); gateWord = 2; }
    function _leave() private { gateWord = 1; }

    modifier single() { _enter(); _; _leave(); }

    function bump() public single { counter += 1; }
}
"""


def test_guard_split_into_helpers_is_still_classified(tmp_path):
    """The OZ shape: the modifier body is two internal calls, so the set and the
    restore are only visible through the callee walk."""
    effects = build_effects(_compile(tmp_path, _HELPER_GUARD_SRC, "HelperGuarded"))
    classes = _hygiene(effects, "bump()")
    assert classes["gateWord"] == "reentrancy_guard"
    assert classes["counter"] == "normal"


_PAUSE_NOT_GUARD_SRC = """
pragma solidity ^0.8.20;

contract Pausable {
    // Written inside a modifier-guarded flow and read with a revert, but never
    // RESTORED as the call unwinds: a pause latch, not a reentrancy guard.
    bool private halted;
    address public owner;

    modifier live() { require(!halted, "PAUSED"); _; }

    function pause() public { halted = true; }
    function setOwner(address o) public live { owner = o; }
}
"""


def test_pause_latch_is_not_mistaken_for_a_guard(tmp_path):
    """A latch is set and left set; only a guard is restored on the far side of
    the placeholder. The pause flag must stay ``normal`` or the pause matcher
    loses its only write fact."""
    effects = build_effects(_compile(tmp_path, _PAUSE_NOT_GUARD_SRC, "Pausable"))
    assert _hygiene(effects, "pause()")["halted"] == "normal"


# --- token-first routed transfer: the callee's ISSUED selector --------------

_TOKEN_FIRST_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function totalSupply() external view returns (uint256); }

library Mover {
    // Real ERC-20 moves, assembly-only bodies (the Solmate / Solady shape), and
    // names that match nothing: only the selector literal identifies them.
    function push(IERC20 token, address to, uint256 amount) internal {
        bool ok;
        assembly {
            let p := mload(0x40)
            mstore(p, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(p, 4), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 36), amount)
            ok := call(gas(), token, 0, p, 68, 0, 32)
        }
        require(ok, "FAIL");
    }

    function grab(IERC20 token, address from, address to, uint256 amount) internal {
        bool ok;
        assembly {
            let p := mload(0x40)
            mstore(p, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
            mstore(add(p, 4), and(from, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 36), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 68), amount)
            ok := call(gas(), token, 0, p, 100, 0, 32)
        }
        require(ok, "FAIL");
    }

    // Decoy: the canonical name and the canonical trailing types, but the body
    // moves nothing. Under the name rule this minted a value_router flow.
    function safeTransfer(IERC20 token, address to, uint256 amount) internal view {
        require(token.totalSupply() >= amount && to != address(0), "NO");
    }
}

contract Vault {
    using Mover for IERC20;
    uint256 public totalShares;

    function enter(address from, IERC20 asset, uint256 amount, uint256 sh) external {
        asset.grab(from, address(this), amount);
        totalShares += sh;
    }
    function exit(address to, IERC20 asset, uint256 amount, uint256 sh) external {
        totalShares -= sh;
        asset.push(to, amount);
    }
    function decoy(address to, IERC20 asset, uint256 amount) external {
        asset.safeTransfer(to, amount);
    }
}

contract Router {
    Vault public vault;
    IERC20 public asset;

    function deposit(uint256 amount) external { vault.enter(msg.sender, asset, amount, amount); }
    function withdraw(uint256 amount, address to) external { vault.exit(to, asset, amount, amount); }
    function decoyRoute(uint256 amount, address to) external { vault.decoy(to, asset, amount); }
}
"""


@pytest.fixture(scope="module")
def _token_first(tmp_path_factory):
    path = tmp_path_factory.mktemp("token_first") / "mover.sol"
    path.write_text(textwrap.dedent(_TOKEN_FIRST_SRC).strip() + "\n")
    return Slither(str(path))


def _routed(unit, contract_name: str, signature: str) -> list[Any]:
    contract = next(c for c in unit.contracts if c.name == contract_name)
    info = build_effects(contract)["functions"][signature]
    return [f for f in info["value_flows"] if f["direction"] == "value_router"]


def test_routed_send_is_recovered_from_the_issued_selector(_token_first):
    """``Mover.push`` is an assembly-only body: the walk cannot see the call, and
    the name matches no idiom. The ``transfer`` selector literal in its ``mstore``
    is the whole of the evidence, and it also fixes the direction (send)."""
    routed = _routed(_token_first, "Router", "withdraw(uint256,address)")
    assert len(routed) == 1, routed
    assert routed[0]["from_is_self"] is True
    assert routed[0]["target_param_index"] == 1


def test_routed_pull_is_recovered_from_the_issued_selector(_token_first):
    """``Mover.grab`` issues ``transferFrom``, whose ABI tail is
    ``(address,address,uint256)`` — that is what selects the pull shape and the
    shifted operand slots."""
    routed = _routed(_token_first, "Router", "deposit(uint256)")
    assert len(routed) == 1, routed
    assert routed[0]["target_kind"]["kind"] == "self"
    assert routed[0]["amount_param_index"] == 0


def test_canonically_named_helper_that_moves_nothing_is_not_routed(_token_first):
    """The inverse control. ``Mover.safeTransfer`` has the idiom's name and the
    idiom's trailing types; its body issues no ERC-20 move, so there is no flow
    and no ``value_router`` claim to publish."""
    assert _routed(_token_first, "Router", "decoyRoute(uint256,address)") == []


# --- legacy value flows read the IR object, not its repr --------------------

_LEGACY_FLOW_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }

contract Payer {
    function payToken(IERC20 token, address to, uint256 amount) external {
        token.transfer(to, amount);
    }
    function payEth(address payable to, uint256 amount) external {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ETH");
    }
}
"""


def test_value_flows_survive_an_unreadable_ir_repr(tmp_path, monkeypatch):
    """``_extract_value_flows`` used to parse ``str(ir)`` for the destination and
    for the presence of a call value — a debug rendering that can be reformatted
    upstream with no signal that the extraction has gone silent. Blanking every
    IR's ``__str__`` leaves the attributes intact, so the flows must be
    unchanged; under the repr parse this returned nothing at all."""
    from slither.slithir.operations.high_level_call import HighLevelCall
    from slither.slithir.operations.low_level_call import LowLevelCall

    contract = _compile(tmp_path, _LEGACY_FLOW_SRC, "Payer")
    functions = {fn.full_name: fn for fn in contract.functions}
    expected = {
        sig: _extract_value_flows(functions[sig])
        for sig in ("payToken(IERC20,address,uint256)", "payEth(address,uint256)")
    }
    assert expected["payToken(IERC20,address,uint256)"] == [
        {
            "direction": "out",
            "token_var": "token",
            "token_type": "IERC20",
            "method": "transfer(address,uint256)",
            "is_parameter": True,
        }
    ]
    assert expected["payEth(address,uint256)"] == [
        {
            "direction": "eth_out",
            "token_var": "to",
            "token_type": "ETH",
            "method": "call{value}",
            "is_parameter": True,
        }
    ]

    monkeypatch.setattr(HighLevelCall, "__str__", lambda self: "<opaque>")
    monkeypatch.setattr(LowLevelCall, "__str__", lambda self: "<opaque>")
    for sig, flows in expected.items():
        assert _extract_value_flows(functions[sig]) == flows, sig
