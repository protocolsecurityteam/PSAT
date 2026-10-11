"""The effects record and the predicate trees publish the selector a call actually dispatches on.

Slither spells parameters with their declared types (``setToken(IToken)``), whose hash is a selector no contract
answers. Pinned on real compiled Solidity: interface, contract, enum and struct parameters lower to their ABI types,
and a type the lowering can't express publishes no selector rather than a wrong one.
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest
from eth_utils.crypto import keccak

slither = pytest.importorskip("slither")
from slither import Slither  # noqa: E402

from services.policy.effective_permissions import _mutability_fields  # noqa: E402
from services.static.contract_analysis_pipeline.effects import build_effects  # noqa: E402
from services.static.contract_analysis_pipeline.predicate_artifacts import build_predicate_artifacts  # noqa: E402


def _sel(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()[:8]


SOURCE = """
pragma solidity ^0.8.19;

interface IToken {}
contract Token {}

contract Limits {
    mapping(IToken => uint256) public capOf;
}

type Price is uint128;

library Auth {
    struct Cfg { address owner; uint256 level; }
    function ok(Cfg memory c, address a) public pure returns (bool) { return c.owner == a; }
    function plain(uint256 x) public pure returns (uint256) { return x; }
    function total(uint256[] storage xs) public view returns (uint256) { return xs.length; }
    function quote(Price p, uint256[] memory xs) public pure returns (uint256) { return Price.unwrap(p) + xs.length; }
    function token(IToken t) public pure returns (address) { return address(t); }
}

interface IRegistry {
    function canAct(address who, IToken token) external view returns (bool);
    function rateOf(IToken token) external view returns (uint256);
}

contract C {
    enum Mode { Idle, Active }
    struct Order { uint256 amount; address to; }

    IRegistry public registry;
    Limits public limits;
    IToken public token;
    uint256 internal _n;

    function setToken(IToken t) external { token = t; }
    function setImpl(Token t) external { _n = uint160(address(t)); }
    function setMode(Mode m) external { _n = uint256(m); }
    function execute(Order calldata o) external { _n = o.amount; }
    function setNum(uint256 x) external { _n = x; }
    function setHook(function(uint256) external returns (uint256) hook) external { _n = hook.selector.length; }
    function act() external {
        require(registry.canAct(msg.sender, token), "denied");
        _n = 2;
    }
    function priced() external {
        require(registry.rateOf(token) > 0, "no rate");
        _n = 3;
    }
    function capped() external {
        require(limits.capOf(token) > 0, "no cap");
        _n = 5;
    }
    fallback() external payable { _n = 4; }
    receive() external payable {}
}
"""

CANONICAL = {
    "setToken(IToken)": "setToken(address)",
    "setImpl(Token)": "setImpl(address)",
    "setMode(C.Mode)": "setMode(uint8)",
    "execute(C.Order)": "execute((uint256,address))",
    "setNum(uint256)": "setNum(uint256)",
}


@pytest.fixture(scope="module")
def compiled(tmp_path_factory) -> dict[str, Any]:
    path = tmp_path_factory.mktemp("canonical_selectors") / "C.sol"
    path.write_text(textwrap.dedent(SOURCE).strip() + "\n")
    return {c.name: c for c in Slither(str(path)).contracts}


@pytest.fixture(scope="module")
def contract(compiled) -> Any:
    return compiled["C"]


@pytest.fixture(scope="module")
def effects(contract) -> dict[str, Any]:
    return build_effects(contract)["functions"]


@pytest.fixture(scope="module")
def trees(contract) -> dict[str, Any]:
    return build_predicate_artifacts(contract)["trees"]


@pytest.mark.parametrize(("declared", "canonical"), sorted(CANONICAL.items()))
def test_entry_selector_hashes_the_canonical_signature(effects, declared, canonical):
    record = effects[declared]
    assert record["function"] == declared
    assert record["abi_signature"] == canonical
    assert record["selector"] == _sel(canonical)
    # The write-attribution selector agrees with the entry record.
    assert record["writer_selectors"] == [record["selector"]]


def test_an_unlowerable_parameter_publishes_no_selector(effects):
    """``abi_signature`` lowering doesn't express function types; hashing Slither's spelling would invent one."""
    (declared,) = [name for name in effects if name.startswith("setHook(")]
    record = effects[declared]
    assert record["selector"] is None
    assert record["abi_signature"] is None
    assert record["writer_selectors"] is None
    # ``None`` reaches the column as not determined, never as "writes nothing".
    assert _mutability_fields(record)["writer_selectors"] is None


@pytest.mark.parametrize("name", ["fallback()", "receive()"])
def test_fallback_and_receive_keep_the_no_selector_sentinel(effects, name):
    record = effects[name]
    assert record["selector"] == ""
    assert record["abi_signature"] == name
    assert record["writer_selectors"] == []


def _nodes(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _nodes(child)


def test_a_delegated_gate_descriptor_carries_the_dispatch_selector(trees):
    descriptors = [
        node["set_descriptor"]
        for node in _nodes(trees["act()"])
        if isinstance(node.get("set_descriptor"), dict) and node["set_descriptor"].get("kind") == "external_set"
    ]
    assert descriptors, "act() must lower to a delegated external-set gate"
    for descriptor in descriptors:
        # The spelling stays Slither's: it keys the callee's trees.
        assert descriptor["callee_signature"] == "canAct(address,IToken)"
        assert descriptor["callee_selector"] == _sel("canAct(address,address)")


def test_an_external_call_operand_carries_the_dispatch_selector(trees):
    operands = [
        node
        for node in _nodes(trees["priced()"])
        if node.get("source") == "external_call" and node.get("callee_signature") == "rateOf(IToken)"
    ]
    assert operands
    assert {op["callee_selector"] for op in operands} == {_sel("rateOf(address)")}


class _FakeParam:
    def __init__(self, type_: str) -> None:
        self.type = type_


class _FakeFunction:
    name = "f"

    def __init__(self, *types: str) -> None:
        self.parameters = [_FakeParam(t) for t in types]


def test_dispatch_signature_falls_back_only_to_a_canonical_spelling():
    from services.static.contract_analysis_pipeline.predicate_artifacts import dispatch_selector, dispatch_signature

    assert dispatch_signature(_FakeFunction("uint256"), "f(uint256)") == "f(uint256)"
    # Unresolved callee (``ir.function`` is None): only an elementary spelling is trusted.
    assert dispatch_selector(None, "rateOf(address)") == _sel("rateOf(address)")
    assert dispatch_selector(None, "rateOf(IToken)") is None
    assert dispatch_selector(None, None) is None
    assert dispatch_selector(None, "fallback()") is None


def test_a_public_getter_call_carries_the_getter_dispatch_selector(trees):
    operands = [
        node
        for node in _nodes(trees["capped()"])
        if node.get("source") == "external_call" and node.get("callee") == "capOf"
    ]
    assert operands
    assert {op["callee_selector"] for op in operands} == {_sel("capOf(address)")}


def test_a_library_function_with_a_struct_parameter_has_no_determined_selector(compiled):
    """A library hashes a struct parameter by name (``ok(Auth.Cfg,address)``) and a storage parameter with its
    location (``total(uint256[] storage)``); Slither's spelling and the ABI lowering reproduce neither."""
    from services.static.contract_analysis_pipeline.predicate_artifacts import dispatch_selector

    library = compiled["Auth"]
    by_name = {fn.name: fn for fn in library.functions}
    assert dispatch_selector(by_name["ok"], by_name["ok"].full_name) is None
    assert dispatch_selector(by_name["total"], by_name["total"].full_name) is None
    assert dispatch_selector(by_name["token"], by_name["token"].full_name) is None
    # A value type hashes as its underlying type, in a library as anywhere else.
    assert dispatch_selector(by_name["quote"], by_name["quote"].full_name) == _sel("quote(uint128,uint256[])")
    assert dispatch_selector(by_name["plain"], by_name["plain"].full_name) == _sel("plain(uint256)")
    records = build_effects(library)["functions"]
    assert records["ok(Auth.Cfg,address)"]["selector"] is None
    assert records["total(uint256[])"]["selector"] is None
    assert records["plain(uint256)"]["selector"] == _sel("plain(uint256)")
    # Selector consumers read the same answer from the predicate artifact: recorded as not determined, which an absent
    # entry (the spelling) would not say for ``total(uint256[])``.
    canonical = build_predicate_artifacts(library).get("canonical_signatures", {})
    assert canonical["ok(Auth.Cfg,address)"] is None
    assert canonical["total(uint256[])"] is None
    assert "plain(uint256)" not in canonical
    assert canonical["quote(Price,uint256[])"] == "quote(uint128,uint256[])"
