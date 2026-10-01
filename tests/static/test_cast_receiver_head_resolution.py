"""G5: a library-wrapped or double-cast token receiver must resolve to the state
variable it aliases, not to the Slither temporary that carries the cast.

A pull like ``IERC20(address(underlying)).safeTransferFrom(...)`` binds the receiver
to ``TMP_n``. Emitting that as the sink head makes every consumer that derives a
getter from it (``input_token_hints``, the cross-contract join, ``effect_targets``)
fabricate ``TMP_n()``, which seeds nothing or the WRONG token. The solc compile and
``build_effects`` are real.

Protocol-agnostic: the fixture models the *shape* (library-wrapped pull,
cast of a state var / parameter / mapping element), never a named protocol.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.effects.calldata import FunctionFacts, input_token_hints  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.summaries import _extract_value_flows  # noqa: E402

# Every reference goes through a cast so the receiver is a temporary.
_SRC = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function shares(address account) external view returns (uint256);
}

library SafeERC20 {
    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        require(token.transferFrom(from, to, amount));
    }
}

contract WrapperVault {
    using SafeERC20 for IERC20;

    address public underlying;          // a token the vault holds, stored as address
    IERC20 public reserveToken;         // ... and one stored already typed
    mapping(uint256 => address) public pool;

    // Double cast of a STATE VAR through the library wrapper -> temporary head.
    function deposit(uint256 amount) external {
        IERC20(address(underlying)).safeTransferFrom(msg.sender, address(this), amount);
    }

    // Direct (non-library) double cast -> a HighLevelCall with a temporary dest.
    function depositDirect(uint256 amount) external {
        IERC20(address(underlying)).transferFrom(msg.sender, address(this), amount);
    }

    // Cast of a PARAMETER -> temporary head resolving to a parameter, no getter.
    function depositParam(address token, uint256 amount) external {
        IERC20(address(token)).safeTransferFrom(msg.sender, address(this), amount);
    }

    // Cast of a MAPPING ELEMENT -> a reference variable, which names no getter.
    function depositIdx(uint256 id, uint256 amount) external {
        IERC20(address(pool[id])).safeTransferFrom(msg.sender, address(this), amount);
    }

    // A share/balance READ names the token in its head without pulling anything.
    function previewShares() external view returns (uint256) {
        return reserveToken.shares(msg.sender);
    }
}
"""


def _compile(tmp_path: Path):
    f = tmp_path / "WrapperVault.sol"
    f.write_text(textwrap.dedent(_SRC).strip() + "\n")
    sl = Slither(str(f))
    return next(c for c in sl.contracts if c.name == "WrapperVault")


def _facts(effects, signature: str) -> FunctionFacts:
    info = effects["functions"][signature]
    return FunctionFacts(
        full_name=signature,
        selector=str(info.get("selector") or ""),
        canonical_signature=str(info.get("abi_signature") or signature),
        effect_info=info,
        tree=None,
        legacy_value_flows=tuple(info.get("value_flows") or ()),
    )


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    return _compile(tmp_path_factory.mktemp("g5"))


@pytest.fixture(scope="module")
def effects(compiled):
    return build_effects(compiled)


def test_input_token_hints_names_the_state_var_getter(effects):
    hints = input_token_hints(_facts(effects, "deposit(uint256)"))
    assert "underlying()" in hints, hints
    assert not any(h.startswith(("TMP_", "REF_", "TUPLE_")) for h in hints), hints


def test_token_read_selector_names_the_token(effects):
    # A read selector must still surface the getter (``_TOKEN_READ_SELECTORS``).
    hints = input_token_hints(_facts(effects, "previewShares()"))
    assert "reserveToken()" in hints, hints


def test_parameter_head_names_no_getter(effects):
    # A parameter's value is in calldata, so it isn't a getter hint.
    hints = input_token_hints(_facts(effects, "depositParam(address,uint256)"))
    assert "token()" not in hints, hints


def test_mapping_element_invents_no_getter_hint(effects):
    hints = input_token_hints(_facts(effects, "depositIdx(uint256,uint256)"))
    assert not any(h.startswith(("TMP_", "REF_", "TUPLE_", "pool")) for h in hints), hints


def test_value_flow_token_var_resolved(compiled):
    fn = next(fu for fu in compiled.functions if fu.name == "depositDirect")
    token_vars = [fl.get("token_var") for fl in _extract_value_flows(fn)]
    assert "underlying" in token_vars, token_vars
    assert not any(str(tv).startswith("TMP_") for tv in token_vars), token_vars
