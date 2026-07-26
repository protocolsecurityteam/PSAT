"""G5: a library-wrapped or double-cast token receiver must resolve to the state
variable it aliases, not to the Slither temporary that carries the cast.

A pull written the real-world way — ``IERC20(address(underlying)).safeTransferFrom(...)``,
a DOUBLE cast through a library — binds the receiver to a temporary whose name is
``TMP_n``. Emitting ``TMP_n`` as the sink head makes every downstream consumer that
derives a getter from it (``input_token_hints``, the cross-contract join, the
persisted ``effect_targets`` display) fabricate ``TMP_n()``, which seeds nothing
and can seed the WRONG token. These tests compile the shape and drive production
``build_effects`` — the only fakes are none; the solc compile is real.

Protocol-agnostic by construction (§0.0.6): the fixture models the *shape* (a
library-wrapped pull, a cast of a state var / a parameter / a mapping element),
never a named protocol's layout.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.effects.calldata import FunctionFacts, input_token_hints  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.summaries import _extract_value_flows  # noqa: E402

# A vault that pulls / reads an ERC-20 it holds, every reference reached through a
# cast so the receiver is a temporary. Names are generic on purpose.
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


def _ext_heads(info) -> list[str]:
    return [s["target"] for s in info["sinks"] if s["kind"] == "external_call"]


@pytest.fixture(scope="module")
def compiled(tmp_path_factory):
    return _compile(tmp_path_factory.mktemp("g5"))


@pytest.fixture(scope="module")
def effects(compiled):
    return build_effects(compiled)


# --- seam 1: the sink head is the state var, not a temporary ---------------


def test_state_var_head_resolved_through_double_cast(effects):
    heads = _ext_heads(effects["functions"]["deposit(uint256)"])
    # The library-wrapped pull now names the state var it aliases.
    assert "underlying.safeTransferFrom" in heads, heads
    # ... and no external-call head is left as a raw Slither temporary.
    assert not any(h.split(".")[0].startswith(("TMP_", "REF_", "TUPLE_")) for h in heads), heads


def test_direct_high_level_call_head_resolved(effects):
    heads = _ext_heads(effects["functions"]["depositDirect(uint256)"])
    assert "underlying.transferFrom" in heads, heads
    assert not any(h.split(".")[0].startswith("TMP_") for h in heads), heads


def test_parameter_cast_head_is_the_parameter(effects):
    heads = _ext_heads(effects["functions"]["depositParam(address,uint256)"])
    # Resolves to the parameter name, not a temporary (a parameter names no
    # getter, which the hint layer enforces separately).
    assert "token.safeTransferFrom" in heads, heads
    assert not any(h.split(".")[0].startswith("TMP_") for h in heads), heads


def test_mapping_element_is_not_resolved_to_a_getter(effects):
    # A reference variable (``pool[id]``) is NOT temporary-rooted through a cast,
    # so it must be left unresolved rather than invented into ``pool()``.
    heads = _ext_heads(effects["functions"]["depositIdx(uint256,uint256)"])
    assert not any(h.startswith("pool.") for h in heads), heads


# --- seam 2: the whole chain, compile -> build_effects -> hints ------------


def test_input_token_hints_names_the_state_var_getter(effects):
    hints = input_token_hints(_facts(effects, "deposit(uint256)"))
    assert "underlying()" in hints, hints
    # No junk temporary getter survives to the hint list.
    assert not any(h.startswith(("TMP_", "REF_", "TUPLE_")) for h in hints), hints


def test_token_read_selector_names_the_token(effects):
    # ``shares(address)`` pulls nothing, but its head names the token, so a read
    # selector must still surface the getter (``_TOKEN_READ_SELECTORS``).
    hints = input_token_hints(_facts(effects, "previewShares()"))
    assert "reserveToken()" in hints, hints


def test_parameter_head_names_no_getter(effects):
    # The head resolved to a parameter; a parameter's value is in calldata, so it
    # must NOT become a getter hint.
    hints = input_token_hints(_facts(effects, "depositParam(address,uint256)"))
    assert "token()" not in hints, hints


def test_mapping_element_invents_no_getter_hint(effects):
    hints = input_token_hints(_facts(effects, "depositIdx(uint256,uint256)"))
    assert not any(h.startswith(("TMP_", "REF_", "TUPLE_", "pool")) for h in hints), hints


# --- summaries value-flow path: token_var resolves too ---------------------


def test_value_flow_token_var_resolved(compiled):
    # The direct high-level call's destination is a temporary; the flow's
    # ``token_var`` must resolve to the state var rather than record ``TMP_n``.
    fn = next(fu for fu in compiled.functions if fu.name == "depositDirect")
    token_vars = [fl.get("token_var") for fl in _extract_value_flows(fn)]
    assert "underlying" in token_vars, token_vars
    assert not any(str(tv).startswith("TMP_") for tv in token_vars), token_vars
