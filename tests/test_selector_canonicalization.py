"""Regression tests for EVM-canonical function-selector derivation.

The predicate trees are keyed on Slither ``full_name`` signatures, which keep
user-defined parameter type names (``addAsset(ERC20)``, ``setMode(Mode)``,
``execute(Order)``). The real EVM selector — and ``effective_functions.selector``
/ the Solmate ``canCall`` fold key — must use the canonical ABI signature, where
contract params lower to ``address``, enums to ``uint8``, and structs to their
tuple form.

The old code re-derived the selector from the ``full_name`` string and mapped
*every* non-elementary type to ``address``. Correct for contract/interface
params, but wrong for enums (should be ``uint8``) and structs (should be a
tuple) — a false-negative on every role-gated enum/struct-param function and a
wrong selector in the effective-permissions artifact.

The fix captures Slither's ``solidity_signature`` at the static stage
(``predicate_artifacts``) into a ``canonical_signatures`` map carried on the
predicate artifact, and the selector consumers prefer it. These tests pin the
whole chain: static map → effective-permissions selector → resolver canCall
selector, on real compiled Solidity.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest
from eth_utils.crypto import keccak

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import (  # noqa: E402
    _abi_signature_and_selector,
    build_effective_permissions,
)
from services.resolution.capability_resolver import _selector_for_signature  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import (  # noqa: E402
    _canonical_signature,
    build_predicate_artifacts,
)


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


# Canonical EVM selectors (keccak of the lowered ABI signature) vs. the wrong
# "collapse every user type to address" selectors the old path produced.
SET_MODE_CANONICAL = _sel("setMode(uint8)")
SET_MODE_ADDRESS_BUG = _sel("setMode(address)")
EXECUTE_CANONICAL = _sel("execute((uint256,address))")
EXECUTE_ADDRESS_BUG = _sel("execute(address)")
SET_FOO_CANONICAL = _sel("setFoo(address)")  # contract param — address IS correct
SET_NUM_CANONICAL = _sel("setNum(uint256)")  # elementary — unchanged

SOURCE = """
pragma solidity ^0.8.19;

interface IFoo {}

contract C {
    enum Mode { Idle, Active, Paused }
    struct Order { uint256 amount; address to; }

    address public owner;
    Mode internal _mode;
    uint256 internal _amount;
    address internal _foo;

    function setMode(Mode m) external {
        require(msg.sender == owner, "auth");
        _mode = m;
    }

    function execute(Order calldata o) external {
        require(msg.sender == owner, "auth");
        _amount = o.amount;
        _foo = o.to;
    }

    function setFoo(IFoo f) external {
        require(msg.sender == owner, "auth");
        _foo = address(f);
    }

    function setNum(uint256 n) external {
        require(msg.sender == owner, "auth");
        _amount = n;
    }
}
"""


@pytest.fixture(scope="module")
def predicate_artifact(tmp_path_factory) -> dict:
    """Compile the fixture with real Slither and run the production artifact
    builder — the same call the static worker makes."""
    tmp = tmp_path_factory.mktemp("sel_canon")
    f = tmp / "C.sol"
    f.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    contract = next(c for c in Slither(str(f)).contracts if c.name == "C")
    return build_predicate_artifacts(contract)


def _lookup(canonical: dict[str, str], func_name: str) -> tuple[str, str]:
    """Return ``(full_name_key, canonical_signature)`` for the entry whose
    function name matches, regardless of how Slither rendered the param name."""
    matches = {k: v for k, v in canonical.items() if k.split("(", 1)[0] == func_name}
    assert len(matches) == 1, f"expected exactly one {func_name}, got {matches}"
    return next(iter(matches.items()))


def test_predicate_artifact_emits_canonical_signatures(predicate_artifact):
    """Static stage: enum→uint8, struct→tuple, contract→address; elementary-only
    functions are omitted (their full_name already canonicalizes)."""
    canonical = predicate_artifact.get("canonical_signatures")
    assert isinstance(canonical, dict) and canonical, "canonical_signatures missing/empty"

    _, set_mode = _lookup(canonical, "setMode")
    _, execute = _lookup(canonical, "execute")
    _, set_foo = _lookup(canonical, "setFoo")

    assert set_mode == "setMode(uint8)"
    assert execute == "execute((uint256,address))"
    assert set_foo == "setFoo(address)"

    # Elementary-only function never needs canonicalization, so it's not carried.
    assert not any(k.split("(", 1)[0] == "setNum" for k in canonical)


def test_canonical_selectors_match_real_evm_and_differ_from_address_collapse(predicate_artifact):
    """The selector keccak'd from each canonical signature equals the real EVM
    selector and — for enum/struct — is NOT the old address-collapsed value."""
    canonical = predicate_artifact["canonical_signatures"]

    _, set_mode = _lookup(canonical, "setMode")
    assert _sel(set_mode) == SET_MODE_CANONICAL
    assert _sel(set_mode) != SET_MODE_ADDRESS_BUG  # revert-proof: catches a regression to the bug

    _, execute = _lookup(canonical, "execute")
    assert _sel(execute) == EXECUTE_CANONICAL
    assert _sel(execute) != EXECUTE_ADDRESS_BUG

    _, set_foo = _lookup(canonical, "setFoo")
    assert _sel(set_foo) == SET_FOO_CANONICAL  # contract param: address collapse is correct here


def test_resolver_selector_uses_artifact_canonical_map(predicate_artifact):
    """Static→resolution handoff: feeding the artifact's canonical map into the
    resolver's selector helper (as ``resolve_contract_capabilities`` now does)
    yields the true ``msg.sig`` for the struct/enum functions, while the no-map
    call reproduces the old address-collapse bug."""
    canonical = predicate_artifact["canonical_signatures"]
    mode_key, _ = _lookup(canonical, "setMode")
    exec_key, _ = _lookup(canonical, "execute")

    assert _selector_for_signature(mode_key, canonical) == SET_MODE_CANONICAL
    assert _selector_for_signature(exec_key, canonical) == EXECUTE_CANONICAL

    # Without the map, the helper falls back to the lossy full_name path.
    assert _selector_for_signature(mode_key) == SET_MODE_ADDRESS_BUG


def test_selector_for_signature_falls_back_for_contracts_without_map():
    """No regression to the #104 contract-type fix: with no canonical map, a
    contract/interface param still lowers to ``address`` via the fallback."""
    assert _selector_for_signature("addAsset(ERC20)") == _sel("addAsset(address)")
    # A bare elementary signature is unaffected with or without a map.
    assert _selector_for_signature("setNum(uint256)") == SET_NUM_CANONICAL
    # Non-signatures return None (guard), with or without a map.
    assert _selector_for_signature(None) is None
    assert _selector_for_signature("notASignature") is None
    assert _selector_for_signature("f(uint8)", {"f(uint8)": "bogus-no-parens"}) == _sel("f(uint8)")


def test_build_effective_permissions_selector_column_is_canonical(predicate_artifact):
    """Policy stage: ``effective_functions.selector`` / ``abi_signature`` come
    from the canonical map, not the address-collapse, for struct/enum params."""
    analysis = {"subject": {"address": "0x" + "11" * 20, "name": "C"}}
    ep = build_effective_permissions(
        analysis,
        predicate_trees=predicate_artifact,
        capability_resolver_output={},  # marks resolver output available
    )
    by_name = {fn["function"].split("(", 1)[0]: fn for fn in ep["functions"]}

    assert by_name["setMode"]["abi_signature"] == "setMode(uint8)"
    assert by_name["setMode"]["selector"] == SET_MODE_CANONICAL
    assert by_name["execute"]["abi_signature"] == "execute((uint256,address))"
    assert by_name["execute"]["selector"] == EXECUTE_CANONICAL
    assert by_name["setFoo"]["selector"] == SET_FOO_CANONICAL


def test_canonical_signature_falls_back_when_slither_cannot_lower():
    """``solidity_signature`` raises for the occasional non-lowerable struct
    param (recursive types). Those drop out of the map so downstream selector
    derivation falls back to the prior full_name path rather than crashing."""

    class _Raises:
        @property
        def solidity_signature(self) -> str:
            raise ValueError("recursive struct cannot be lowered")

    class _NonString:
        solidity_signature = 1234  # not a str

    assert _canonical_signature(_Raises()) is None
    assert _canonical_signature(_NonString()) is None


def test_abi_signature_and_selector_helper_prefers_map():
    """Unit pin on the policy helper: map wins; absent → string fallback."""
    cmap = {"execute(Order)": "execute((uint256,address))"}
    assert _abi_signature_and_selector("execute(Order)", cmap) == (
        "execute((uint256,address))",
        EXECUTE_CANONICAL,
    )
    # Not in the map → lossy fallback (address collapse) — the documented gap.
    assert _abi_signature_and_selector("execute(Order)", {}) == (
        "execute(address)",
        EXECUTE_ADDRESS_BUG,
    )
