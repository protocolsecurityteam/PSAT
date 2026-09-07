"""Real-Slither tests for the static token-slot derivation pass.

Compiles minimal Solidity fixtures with the production Slither toolchain and
drives ``derive_token_slots`` / ``build_effects`` — the exact calls the static
worker makes. Pins the two supported layout standards and the fail-closed
boundary:

  * plain ERC-20: a public-mapping auto-getter and a handwritten getter both
    yield ``storage_layout`` entries at the correct sequential base slots;
  * OZ-v5 ERC-7201 namespaced ERC-20: entries at the folded ``*StorageLocation``
    constant, with ``_allowances`` one slot past ``_balances``;
  * rebasing token: a computed ``balanceOf`` gets NO entry (the read-back anchor
    needs a raw read), while the direct ``sharesOf`` does;
  * negatives: no family getters ⇒ no ``token_slots`` key; an ambiguous getter
    (reads a second mapping) is skipped; a packed struct member before the
    target abandons the namespaced derivation.

Skips only when no compatible solc is installed. No live marker, no RPC.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.static.static_analysis.effects import build_effects  # noqa: E402
from services.static.static_analysis.token_slots import derive_token_slots  # noqa: E402
from tests.support.solc import solc_path_for as _solc_path_for  # noqa: E402

pytestmark = pytest.mark.compile

FLOOR = (0, 8, 20)


_SOLC = _solc_path_for(FLOOR)
_needs_solc = pytest.mark.skipif(_SOLC is None, reason=f"no installed solc satisfies ^{'.'.join(map(str, FLOOR))}")


def _compile(tmp_path: Path, src: str, name: str) -> Any:
    f = tmp_path / f"{name}.sol"
    f.write_text(textwrap.dedent(src))
    sl = Slither(str(f), solc=_SOLC)
    return next(c for c in sl.contracts if c.name == name)


def _by_role(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {e["role"]: e for e in entries}


# ---------------------------------------------------------------------------
# storage_layout: plain ERC-20
# ---------------------------------------------------------------------------

PLAIN_ERC20 = """
    pragma solidity ^0.8.20;
    contract PlainERC20 {
        mapping(address => uint256) public balanceOf;                              // slot 0
        mapping(address => mapping(address => uint256)) private _allowances;       // slot 1
        uint256 public totalSupply;                                                // slot 2
        function allowance(address o, address s) external view returns (uint256) {
            return _allowances[o][s];
        }
    }
"""


@_needs_solc
def test_plain_erc20_auto_getter_and_handwritten(tmp_path: Path) -> None:
    contract = _compile(tmp_path, PLAIN_ERC20, "PlainERC20")
    slots = derive_token_slots(contract)
    assert slots is not None
    by_role = _by_role(slots["entries"])

    bal = by_role["balance"]
    assert bal["getter"] == "balanceOf(address)"
    assert bal["key_kind"] == "address"
    assert bal["derivation"] == "storage_layout"
    assert bal["variable"] == "balanceOf"
    assert bal["base_slot"] == "0x" + "0" * 63 + "0"

    allow = by_role["allowance"]
    assert allow["getter"] == "allowance(address,address)"
    assert allow["key_kind"] == "address_address"
    assert allow["derivation"] == "storage_layout"
    assert allow["variable"] == "_allowances"
    assert allow["base_slot"] == "0x" + "0" * 63 + "1"


# ---------------------------------------------------------------------------
# oz_v5_namespaced: ERC-7201 struct members
# ---------------------------------------------------------------------------

# 0.8's ERC-7201 idiom: a bytes32 *StorageLocation constant is the struct base,
# members follow in declaration order (_balances at +0, _allowances at +1).
OZ_V5_ERC20 = """
    pragma solidity ^0.8.20;
    contract OzV5ERC20 {
        struct ERC20Storage {
            mapping(address => uint256) _balances;
            mapping(address => mapping(address => uint256)) _allowances;
            uint256 _totalSupply;
            string _name;
            string _symbol;
        }
        bytes32 private constant ERC20StorageLocation =
            0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00;
        function _getERC20Storage() private pure returns (ERC20Storage storage $) {
            assembly { $.slot := ERC20StorageLocation }
        }
        function balanceOf(address account) public view returns (uint256) {
            ERC20Storage storage $ = _getERC20Storage();
            return $._balances[account];
        }
        function allowance(address owner, address spender) public view returns (uint256) {
            ERC20Storage storage $ = _getERC20Storage();
            return $._allowances[owner][spender];
        }
    }
"""

_ERC20_BASE = "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00"


@_needs_solc
def test_oz_v5_namespaced_erc20(tmp_path: Path) -> None:
    contract = _compile(tmp_path, OZ_V5_ERC20, "OzV5ERC20")
    slots = derive_token_slots(contract)
    assert slots is not None
    by_role = _by_role(slots["entries"])

    bal = by_role["balance"]
    assert bal["derivation"] == "oz_v5_namespaced"
    assert bal["variable"] == "_balances"
    assert bal["base_slot"] == _ERC20_BASE  # struct base + 0

    allow = by_role["allowance"]
    assert allow["derivation"] == "oz_v5_namespaced"
    assert allow["variable"] == "_allowances"
    assert allow["base_slot"] == _ERC20_BASE[:-2] + "01"  # struct base + 1


# ---------------------------------------------------------------------------
# rebasing: computed balanceOf skipped, direct sharesOf kept
# ---------------------------------------------------------------------------

REBASING = """
    pragma solidity ^0.8.20;
    contract Rebasing {
        mapping(address => uint256) public shares;   // slot 0
        uint256 public rate;                         // slot 1
        function balanceOf(address a) external view returns (uint256) { return shares[a] * rate; }
        function sharesOf(address a) external view returns (uint256) { return shares[a]; }
    }
"""


@_needs_solc
def test_rebasing_excludes_computed_balance_keeps_shares(tmp_path: Path) -> None:
    contract = _compile(tmp_path, REBASING, "Rebasing")
    slots = derive_token_slots(contract)
    assert slots is not None
    by_role = _by_role(slots["entries"])

    assert "balance" not in by_role, "a computed balanceOf must not be a read-back anchor"
    shares = by_role["shares"]
    # ``shares`` is a public mapping, so its auto-getter is the (direct) anchor.
    assert shares["getter"] == "shares(address)"
    assert shares["derivation"] == "storage_layout"
    assert shares["variable"] == "shares"
    assert shares["base_slot"] == "0x" + "0" * 63 + "0"


HANDWRITTEN_SHARES = """
    pragma solidity ^0.8.20;
    contract StEth {
        uint256 public totalSupply;                    // slot 0
        mapping(address => uint256) private _shares;   // slot 1
        function sharesOf(address a) external view returns (uint256) { return _shares[a]; }
    }
"""


@_needs_solc
def test_handwritten_shares_of_private_backing(tmp_path: Path) -> None:
    contract = _compile(tmp_path, HANDWRITTEN_SHARES, "StEth")
    slots = derive_token_slots(contract)
    assert slots is not None
    shares = _by_role(slots["entries"])["shares"]
    assert shares["getter"] == "sharesOf(address)"
    assert shares["derivation"] == "storage_layout"
    assert shares["variable"] == "_shares"
    assert shares["base_slot"] == "0x" + "0" * 63 + "1"


# ---------------------------------------------------------------------------
# ERC-721 ownerOf through a trivial require wrapper
# ---------------------------------------------------------------------------

ERC721 = """
    pragma solidity ^0.8.20;
    contract NFT {
        mapping(uint256 => address) private _owners;   // slot 0
        function ownerOf(uint256 id) public view returns (address) { return _requireOwned(id); }
        function _requireOwned(uint256 id) internal view returns (address) {
            address o = _owners[id];
            if (o == address(0)) revert("nonexistent");
            return o;
        }
    }
"""


@_needs_solc
def test_erc721_owner_of_through_require_wrapper(tmp_path: Path) -> None:
    contract = _compile(tmp_path, ERC721, "NFT")
    slots = derive_token_slots(contract)
    assert slots is not None
    by_role = _by_role(slots["entries"])
    owner = by_role["owner"]
    assert owner["getter"] == "ownerOf(uint256)"
    assert owner["key_kind"] == "uint256"
    assert owner["derivation"] == "storage_layout"
    assert owner["variable"] == "_owners"
    assert owner["base_slot"] == "0x" + "0" * 63 + "0"


# ---------------------------------------------------------------------------
# Negatives
# ---------------------------------------------------------------------------

NO_FAMILY = """
    pragma solidity ^0.8.20;
    contract Counter {
        uint256 public count;
        function increment() external { count += 1; }
    }
"""


@_needs_solc
def test_no_family_getters_omits_key(tmp_path: Path) -> None:
    contract = _compile(tmp_path, NO_FAMILY, "Counter")
    assert derive_token_slots(contract) is None
    assert "token_slots" not in build_effects(contract)


# A getter that reads a second mapping (a freeze check) is not a clean raw read.
AMBIGUOUS = """
    pragma solidity ^0.8.20;
    contract Ambiguous {
        mapping(address => uint256) private _balances;
        mapping(address => bool) private _frozen;
        function balanceOf(address a) external view returns (uint256) {
            require(!_frozen[a], "frozen");
            return _balances[a];
        }
    }
"""


@_needs_solc
def test_ambiguous_getter_reading_second_mapping_skipped(tmp_path: Path) -> None:
    contract = _compile(tmp_path, AMBIGUOUS, "Ambiguous")
    assert derive_token_slots(contract) is None


# A sub-slot scalar before the target makes the namespaced offset unsafe to walk.
PACKED_NAMESPACE = """
    pragma solidity ^0.8.20;
    contract PackedNS {
        struct S {
            uint128 _flag;                              // sub-slot: packing risk
            mapping(address => uint256) _balances;
        }
        bytes32 private constant SLoc =
            0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00;
        function _get() private pure returns (S storage $) { assembly { $.slot := SLoc } }
        function balanceOf(address a) public view returns (uint256) {
            S storage $ = _get();
            return $._balances[a];
        }
    }
"""


@_needs_solc
def test_packed_member_before_target_skips_namespaced(tmp_path: Path) -> None:
    contract = _compile(tmp_path, PACKED_NAMESPACE, "PackedNS")
    assert derive_token_slots(contract) is None


# ---------------------------------------------------------------------------
# Artifact plumbing
# ---------------------------------------------------------------------------


@_needs_solc
def test_build_effects_carries_token_slots(tmp_path: Path) -> None:
    contract = _compile(tmp_path, PLAIN_ERC20, "PlainERC20")
    artifact = build_effects(contract)
    assert "token_slots" in artifact
    roles = {e["role"] for e in artifact["token_slots"]["entries"]}
    assert roles == {"balance", "allowance"}
