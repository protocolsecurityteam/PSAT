"""Free-memory addresses must never be represented by a fabricated numeric marker."""

import pytest
from eth_abi import decode

from services.logic.expansion import Selection, expand_formula
from services.logic.formula import compile_function
from services.logic.solver import Translation
from services.logic.terms import CALLER, ORIGIN, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc


@pytest.mark.parametrize(
    "mode,actual_pass",
    [("eq128", True), ("eqSentinel", False), ("store128", True), ("storeSentinel", False), ("afterAlloc", True)],
)
def test_free_memory_marker_is_not_a_numeric_evm_address(anvil, tmp_path, mode, actual_pass):
    body = {
        "eq128": "assembly{p:=mload(64)}require(p==128||msg.sender==owner);",
        "eqSentinel": "assembly{p:=mload(64)}require(p==4294967296||msg.sender==owner);",
        "store128": "uint v;assembly{p:=mload(64)sstore(p,77)v:=sload(128)}require(v==77||msg.sender==owner);",
        "storeSentinel": (
            "uint v;assembly{p:=mload(64)sstore(p,77)v:=sload(4294967296)}require(v==77||msg.sender==owner);"
        ),
        "afterAlloc": "uint[] memory a=new uint[](1);assembly{p:=mload(64)}require(p==192||msg.sender==owner);",
    }[mode]
    source = (
        "pragma solidity 0.8.27;contract C {address owner=msg.sender;uint controlled;"
        "function act()external returns(uint p){" + body + "controlled=9;}}"
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"))
    idx = next(i for i, e in enumerate(f.effects) if e.target[1] == "controlled")
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        f.selector,
        bindings={CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): 0},
    )
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    predicted = tr.truth(f.effects[idx].guard)
    result = expand_formula(f, d.chain(), d.contracts("C"), selection=Selection(False, (idx,))).effects[0]
    raw = rpc(
        d.url,
        "eth_call",
        [{"to": O.hex20(d.at["C"]), "from": O.hex20(O.OWNER), "data": "0x" + O.calldata(fn).hex()}, "latest"],
    )
    free = decode(["uint256"], bytes.fromhex(raw[2:]))[0]
    assert free == (192 if mode == "afterAlloc" else 128)
    assert actual is actual_pass
    assert predicted is None or predicted is actual
    if result.complete:
        assert (result.representation == "cofinite") is actual_pass, result


def test_literal_reserved_arena_offset_is_not_free_memory(anvil, tmp_path):
    source = """pragma solidity 0.8.27;contract C {address owner=msg.sender;uint controlled;
 function act()external{if(msg.sender!=owner){assembly{mstore(4294967296,1)}}controlled=9;}}
 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"))
    idx = next(i for i, e in enumerate(f.effects) if e.target[1] == "controlled")
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        f.selector,
        bindings={CALLER: O.ACCOUNTS[1], ORIGIN: O.ACCOUNTS[1], mk("callvalue"): 0},
    )
    predicted = tr.truth(f.effects[idx].guard)
    try:
        rpc(
            d.url,
            "eth_call",
            [
                {
                    "to": O.hex20(d.at["C"]),
                    "from": O.hex20(O.ACCOUNTS[1]),
                    "gas": rpc(d.url, "eth_getBlockByNumber", ["latest", False])["gasLimit"],
                    "data": "0x" + O.calldata(fn).hex(),
                },
                "latest",
            ],
        )
    except RuntimeError as exc:
        assert "gas" in str(exc).lower() or "oog" in str(exc).lower(), exc
    else:
        raise AssertionError("4GiB expansion should exceed the supplied gas")
    assert O.passes(d, "C", fn, (), sender=O.OWNER)
    assert predicted is not True
