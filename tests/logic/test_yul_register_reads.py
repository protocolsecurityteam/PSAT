"""Assembly reads a Solidity variable's whole register, which need not be the canonical word of its type."""

import pytest
from eth_abi import encode

from services.logic.continuation import generate_function
from services.logic.formula import compile_function
from services.logic.lower import parameter
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

WORD = 2**256 - 1
CLEAN = {
    "uint8 s = x;",
    "uint8 s = x + y;",
    "bool s = x > 3;",
    "small = x; uint8 s = small;",
    "address s = x;",
    "uint8 s = uint8(uint16(x));",
    "uint8 s = small;",
}
CASES = [
    ("uint256 a", "uint8 s = uint8(a);", (0x1FF,)),
    ("uint256 a", "int8 s = int8(int256(a));", (0x1FF,)),
    ("uint256 a", "address s = address(uint160(a));", (WORD,)),
    ("bytes32 a", "bytes4 s = bytes4(a);", (b"\xff" * 32,)),
    ("uint8 x,uint8 y", "uint8 s; unchecked { s = x + y; }", (200, 100)),
    ("uint8 x,uint8 y", "uint8 s; unchecked { s = x * y; }", (200, 100)),
    ("uint8 x,uint8 y", "uint8 s = x << y;", (255, 4)),
    ("uint8 x", "uint8 s = ~x;", (1,)),
    ("int8 x", "int8 s = ~x;", (1,)),
    ("uint8 x", "uint8 s = x;", (200,)),
    ("uint8 x,uint8 y", "uint8 s = x + y;", (100, 100)),
    ("uint8 x", "bool s = x > 3;", (200,)),
    ("uint8 x", "small = x; uint8 s = small;", (200,)),
    ("uint8 x", "uint8 s = uint8(saved);", (200,)),
    ("address x", "address s = x;", (int("ab" * 20, 16),)),
    ("uint8 x", "uint8 s = uint8(uint16(x));", (200,)),
    ("uint8 x", "uint8 s = small;", (200,)),
]


def _saved(anvil, tmp_path, version, source, parameters, args, runtime):
    """The engine's write to ``saved`` (None when undecided) and the chain's."""
    d = O.deployment(anvil[0], tmp_path, source, version=version)
    at = d.deploy("C")
    fn = O.function(d, "C", "act")
    known = d.contracts("C")
    if runtime:
        f = generate_function(d.slither["C"], fn, at, d.chain(), known, own_code=known.get, steps=30000)
        assert isinstance(f, Formula), f
        types = [p.split()[0] for p in parameters.split(",")]
        words = [O.hex20(v) if t == "address" else v for t, v in zip(types, args)]
        inputs = {f.parameters[0]: encode(types, words)}
    else:
        f = compile_function(d.slither["C"], fn, at, d.chain(), known)
        inputs = {parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, args))}
    tr = Translation(d.chain(), known, at, f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0, **inputs})
    assert O.transact_data(d, at, O.calldata(fn, args))
    stored = int(rpc(d.url, "eth_getStorageAt", [O.hex20(at), "0x0", "latest"]), 16)
    values: list[int] = []
    try:
        decided = tr.truth(f.success) is True
        values = [int(str(tr.translate(e.value))) % 2**256 for e in f.effects if tr.truth(e.guard) is True]
    except ValueError:
        decided = False
    if not decided or tr.issues:
        return None, stored, tr.issues
    return (values[-1] if values else 0), stored, tr.issues


@pytest.mark.parametrize("runtime", [False, True])
@pytest.mark.parametrize("version", ["0.5.14", "0.8.27"])
@pytest.mark.parametrize("parameters,body,args", CASES)
def test_assembly_reads_the_register_or_stays_unknown(anvil, tmp_path, runtime, version, parameters, body, args):
    if version.startswith("0.5"):
        body = body.replace("unchecked {", "{")
        body = body.replace("int8(int256(a))", "int8(a)").replace("address(uint160(a))", "address(a)")
    source = (
        f"pragma solidity {version};contract C {{uint256 saved;uint8 small;"
        f"function act({parameters}) external {{{body} uint256 v; assembly {{ v := s }} saved = v;}}}}"
    )
    predicted, stored, issues = _saved(anvil, tmp_path, version, source, parameters, args, runtime)
    if predicted is None:
        # Unknown is sound, but these registers are canonical; 0.5 arithmetic is unchecked, so its sum may not be.
        assert body not in CLEAN or version < "0.8" and "+" in body, (version, body, issues)
        return
    assert predicted == stored, (version, body, hex(stored), predicted)


@pytest.mark.parametrize("runtime", [False, True])
@pytest.mark.parametrize("version", ["0.5.14", "0.8.27"])
@pytest.mark.parametrize("cast", [False, True])
def test_helper_reads_its_argument_register(anvil, tmp_path, runtime, version, cast):
    """An address decoded at entry and passed to an assembly helper stays exact; a narrowed word does not."""
    parameters, argument = ("uint256 a", "address(uint160(a))") if cast else ("address a", "a")
    if version.startswith("0.5"):
        argument = argument.replace("uint160(a)", "a")
    source = (
        f"pragma solidity {version};contract C {{uint256 saved;"
        f"function act({parameters}) external {{_set({argument});}}"
        "function _set(address s) internal {uint256 v; assembly { v := s } saved = v;}}"
    )
    args = (WORD,) if cast else (int("ab" * 20, 16),)
    predicted, stored, issues = _saved(anvil, tmp_path, version, source, parameters, args, runtime)
    if cast:
        assert predicted in (None, stored), (hex(stored), predicted)
    else:
        assert predicted == stored, (hex(stored), predicted, issues)
