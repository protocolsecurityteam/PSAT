"""A function whose types can't be lowered publishes no selector, not a guessed one.

The predicate artifact's ``canonical_signatures`` used to have no way to say "not determined": an absent entry read as
"the spelling is already canonical", and the string fallback lowered any unrecognised type name to ``address``. It now
records ``None``, every selector reader honours it, and an artifact from before (no ``None`` entries) reads an
unlowerable spelling as undetermined. Pinned on real compiled Solidity.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import (  # noqa: E402
    _abi_signature,
    _abi_signature_and_selector,
    _canonical_signature_map,
    recorded_abi_signature,
)
from services.resolution.capability_resolver import _selector_for_signature  # noqa: E402
from services.resolution.predicate_evaluator.binding import _key_dispatch_selector  # noqa: E402
from services.static.claims.context import ClaimContext  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts  # noqa: E402


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


SOURCE = """
pragma solidity ^0.8.19;

enum Mode { Idle, Active }

contract Token {}

library Ledger {
    struct Entry { uint256 amount; }
    function total(uint256[] storage xs) public view returns (uint256) { return xs.length; }
    function credit(Token t, uint256 x) public pure returns (uint256) { return uint160(address(t)) + x; }
    function size(uint256 x) public pure returns (uint256) { return x; }
}

contract C {
    uint256 internal _n;
    function setMode(Mode m) external { _n = uint256(m); }
    function setToken(Token t) external { _n = uint160(address(t)); }
    function setHook(function(uint256) external returns (uint256) hook) external { _n = hook.selector.length; }
    function setNum(uint256 x) external { _n = x; }
}
"""


@pytest.fixture(scope="module")
def compiled(tmp_path_factory) -> dict[str, Any]:
    path = tmp_path_factory.mktemp("undetermined_canonical") / "C.sol"
    path.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    return {c.name: c for c in Slither(str(path)).contracts}


@pytest.fixture(scope="module")
def artifacts(compiled) -> dict[str, dict[str, Any]]:
    return {name: build_predicate_artifacts(compiled[name]) for name in ("C", "Ledger")}


def test_the_artifact_records_undetermined_functions(artifacts):
    contract = artifacts["C"]["canonical_signatures"]
    hook = next(name for name in contract if name.startswith("setHook("))
    assert contract[hook] is None
    assert contract["setMode(Mode)"] == "setMode(uint8)"
    assert contract["setToken(Token)"] == "setToken(address)"
    assert "setNum(uint256)" not in contract
    library = artifacts["Ledger"]["canonical_signatures"]
    assert library["total(uint256[])"] is None
    assert library["credit(Token,uint256)"] is None
    assert "size(uint256)" not in library


@pytest.mark.parametrize(
    ("contract", "function", "selector"),
    [
        ("C", "setMode(Mode)", _sel("setMode(uint8)")),
        ("C", "setToken(Token)", _sel("setToken(address)")),
        ("C", "setNum(uint256)", _sel("setNum(uint256)")),
        # Spelled like a canonical signature; a library hashes the storage location in, so it isn't one.
        ("Ledger", "total(uint256[])", None),
        ("Ledger", "credit(Token,uint256)", None),
        ("Ledger", "size(uint256)", _sel("size(uint256)")),
    ],
)
def test_every_selector_reader_agrees(artifacts, compiled, contract, function, selector):
    artifact = artifacts[contract]
    canonical = artifact.get("canonical_signatures")
    assert _abi_signature_and_selector(function, _canonical_signature_map(artifact))[1] == selector
    assert _selector_for_signature(function, canonical) == selector
    assert _key_dispatch_selector(function, canonical) == selector
    assert ClaimContext(compiled[contract], {}, artifact).canonical_selector(function) == selector


def test_a_hook_parameter_has_no_selector_from_any_reader(artifacts, compiled):
    artifact = artifacts["C"]
    hook = next(name for name in artifact["canonical_signatures"] if name.startswith("setHook("))
    assert _abi_signature_and_selector(hook, _canonical_signature_map(artifact)) == (hook, None)
    assert _selector_for_signature(hook, artifact["canonical_signatures"]) is None
    assert ClaimContext(compiled["C"], {}, artifact).canonical_selector(hook) is None


def test_an_older_artifact_reads_an_unlowerable_spelling_as_undetermined():
    """No ``None`` entries existed: an absent ``setMode(Mode)`` lowered ``Mode`` to ``address`` by name."""
    assert _abi_signature("setMode(Mode)") == "setMode(Mode)"
    assert recorded_abi_signature("setMode(Mode)", {}) is None
    assert _abi_signature_and_selector("setMode(Mode)", {}) == ("setMode(Mode)", None)
    assert _selector_for_signature("setMode(Mode)", {}) is None
    # Sound string lowering still applies: elementary spellings and Vyper's dynamic types.
    assert recorded_abi_signature("f(uint256,bytes32)", {}) == "f(uint256,bytes32)"
    assert recorded_abi_signature("g(DynArray[uint256, 8],String[32])", {}) == "g(uint256[],string)"
