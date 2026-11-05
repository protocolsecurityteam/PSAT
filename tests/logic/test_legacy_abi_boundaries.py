"""Compiler-version ABI boundaries checked against independent deployed bytecode."""

import json
import subprocess

import pytest
from crytic_compile.crytic_compile import CryticCompile
from crytic_compile.platform.solc_standard_json import SolcStandardJson
from eth_utils.crypto import keccak
from slither import Slither

from services.logic.abi_values import checked_return_size
from services.logic.continuation import PendingCompilation, generate_function
from services.logic.formula import compile_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk, subterms
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.27"])
@pytest.mark.parametrize("size", [4, 35, 36])
@pytest.mark.parametrize("v2", [False, True])
def test_short_scalar_input(anvil, tmp_path, version, size, v2):
    (tmp_path / "target").mkdir()
    (tmp_path / "root").mkdir()
    source = (
        "pragma solidity "
        + version
        + ";"
        + ("pragma experimental ABIEncoderV2;" if v2 else "")
        + """contract D {
uint public saved;
function set(uint n) public returns(uint){
saved=n+1;
return n;
}
}
"""
    )
    old = O.deployment(anvil[0], tmp_path / "target", source, version)
    target = old.deploy("D")
    payload = keccak(text="set(uint256)")[:4] + bytes([1]) * max(0, size - 4)
    root = O.deployment(
        anvil[0],
        tmp_path / "root",
        """pragma solidity 0.8.27;
contract C{
address target;
uint saved;
constructor(address a){
target=a;
}
function act()external{
(bool ok,)=target.call(hex\""""
        + payload.hex()
        + '");require(ok);saved=7;}}',
    )
    root.deploy("C", ("address",), (target,))
    known = root.contracts("C")
    known[target] = old.slither["D"]
    fn = O.function(root, "C", "act")
    f = generate_function(root.slither["C"], fn, root.at["C"], root.chain(), known, steps=10000)
    assert isinstance(f, Formula), f
    bindings = {
        CALLER: O.OWNER,
        mk("callvalue"): 0,
        **{t: True for t in subterms(f.success, "unknown") if t[1] == "unsupported:raw_call_resources"},
    }
    tr = Translation(root.chain(), known, root.at["C"], f.selector, bindings=bindings)
    actual = O.passes(root, "C", fn, ())
    assert tr.truth(f.success) is actual, (version, size, actual, tr.issues)


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.27"])
@pytest.mark.parametrize("size", [4, 35, 36, 67, 99, 100])
@pytest.mark.parametrize("v2", [False, True])
def test_short_array_input_and_budget(anvil, tmp_path, version, size, v2, monkeypatch):
    (tmp_path / "target").mkdir()
    (tmp_path / "root").mkdir()
    payload = keccak(text="set(uint256[3])")[:4] + bytes([1]) * max(0, size - 4)
    expects = [int.from_bytes(payload[4 + 32 * i : 4 + 32 * (i + 1)].ljust(32, b"\0"), "big") for i in range(3)]
    source = (
        "pragma solidity "
        + version
        + ";"
        + ("pragma experimental ABIEncoderV2;" if v2 else "")
        + """contract D {
uint public saved;
function set(uint[3] memory n) public {
 """
        + "".join("require(n[" + str(i) + "]==" + str(n) + ");" for i, n in enumerate(expects))
        + "saved=7;}}"
    )
    old = O.deployment(anvil[0], tmp_path / "target", source, version)
    target = old.deploy("D")
    root = O.deployment(
        anvil[0],
        tmp_path / "root",
        """pragma solidity 0.8.27;
contract C{
address target;
uint saved;
constructor(address a){
target=a;
}
function act()external{
(bool ok,)=target.call(hex\""""
        + payload.hex()
        + '");require(ok);saved=7;}}',
    )
    root.deploy("C", ("address",), (target,))
    known = root.contracts("C")
    known[target] = old.slither["D"]
    fn = O.function(root, "C", "act")
    from services.logic import calls

    charges = []
    decodes = []
    orig_spent = calls._spent
    orig_decode = calls.decode_static

    def spent(n):
        charges.append(n)
        return orig_spent(n)

    def decode(*a, **kw):
        decodes.append(True)
        return orig_decode(*a, **kw)

    monkeypatch.setattr(calls, "_spent", spent)
    monkeypatch.setattr(calls, "decode_static", decode)
    reads = root.chain()
    f = generate_function(root.slither["C"], fn, root.at["C"], reads, known, steps=10000, value_steps=1)
    if isinstance(f, PendingCompilation):
        assert f.reason == "value_steps", f
        assert charges and all(n > 0 for n in charges), charges
        assert decodes == [], decodes
        f = generate_function(
            root.slither["C"], fn, root.at["C"], reads, known, steps=10000, value_steps=50000, checkpoint=f.checkpoint
        )
    else:
        assert size < 100 and not (version == "0.4.19" and not v2)
    assert isinstance(f, Formula), f
    bindings = {
        CALLER: O.OWNER,
        mk("callvalue"): 0,
        **{t: True for t in subterms(f.success, "unknown") if t[1] == "unsupported:raw_call_resources"},
    }
    tr = Translation(reads, known, root.at["C"], f.selector, bindings=bindings)
    actual = O.passes(root, "C", fn, ())
    assert tr.truth(f.success) is actual, (version, size, actual, tr.issues)


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.27"])
@pytest.mark.parametrize("size", [0, 1, 31, 32])
@pytest.mark.parametrize("v2", [False, True])
def test_return_buffer_by_compiler(anvil, tmp_path, version, size, v2):
    (tmp_path / "target").mkdir()
    (tmp_path / "root").mkdir()
    source = (
        """pragma solidity 0.8.27;
contract D {
fallback() external {
assembly {
mstore(0, 0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00) return(0,"""
        + str(size)
        + ")}}}"
    )
    targetd = O.deployment(anvil[0], tmp_path / "target", source)
    target = targetd.deploy("D")
    src = (
        "pragma solidity "
        + version
        + ";"
        + ("pragma experimental ABIEncoderV2;" if v2 else "")
        + """contract I {
function f() public returns(uint);
 }
 contract C {
function act() public returns(uint) {
return I(address("""
        + str(target)
        + ")).f();}}"
    )
    if version == "0.8.27":
        src = src.replace(
            """contract I {
function f() public returns(uint);
 }
""",
            """interface I {
function f() external returns(uint);
 }
""",
        )
    root = O.deployment(anvil[0], tmp_path / "root", src, version)
    root.deploy("C")
    known = root.contracts("C")
    known[target] = targetd.slither["D"]
    fn = O.function(root, "C", "act")
    f = generate_function(root.slither["C"], fn, root.at["C"], root.chain(), known, steps=10000)
    if version == "0.4.19" and size < 32:
        assert (
            isinstance(f, PendingCompilation) and f.reason == "call" and f.blocker == "unsupported:short_return_buffer"
        ), f
        one = compile_function(root.slither["C"], fn, root.at["C"], root.chain(), known)
        tr = Translation(
            root.chain(), known, root.at["C"], one.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0}
        )
        assert tr.truth(one.success) is None and tr.issues
        assert O.passes(root, "C", fn, ())
        if size == 0:
            returned = rpc(
                root.url,
                "eth_call",
                [
                    {"from": O.hex20(O.OWNER), "to": O.hex20(root.at["C"]), "data": "0x" + O.calldata(fn, ()).hex()},
                    "latest",
                ],
            )
            assert int(returned, 16) == int.from_bytes(keccak(text="f()")[:4], "big") << 224
        return
    assert isinstance(f, Formula), f
    bindings = {CALLER: O.OWNER, mk("callvalue"): 0, **{t: target for t in subterms(f.success, "arg")}}
    tr = Translation(root.chain(), known, root.at["C"], f.selector, bindings=bindings)
    actual = O.passes(root, "C", fn, ())
    result = None
    if actual:
        result = rpc(
            root.url,
            "eth_call",
            [
                {"from": O.hex20(O.OWNER), "to": O.hex20(root.at["C"]), "data": "0x" + O.calldata(fn, ()).hex()},
                "latest",
            ],
        )
        assert len(result) == 66
    assert tr.truth(f.success) is actual


@pytest.mark.parametrize("evm", ["homestead", "byzantium"])
@pytest.mark.parametrize("size", [0, 1, 31, 32])
@pytest.mark.parametrize("v2", [False, True])
def test_return_buffer_by_caller_evm(anvil, tmp_path, evm, size, v2):
    source = (
        "pragma solidity 0.5.14;"
        + ("pragma experimental ABIEncoderV2;" if v2 else "")
        + """interface I{
function f() external returns(uint);
}
 contract T {
function() external {
assembly {
mstore(0,0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00) return(0,SIZE)}
}
}
 contract C {
I t;
constructor(address a)public{
t=I(a);
}
function act()public returns(uint){
return t.f();
}
}
""".replace("SIZE", str(size))
    )
    d = O.deployment(anvil[0], tmp_path, source, version="0.5.14")
    source_path = tmp_path / "target.sol"
    source_path.write_text(source)
    standard = {
        "language": "Solidity",
        "sources": {str(source_path): {"content": source}},
        "settings": {"evmVersion": evm, "outputSelection": {"*": {"*": ["*"], "": ["ast"]}}},
    }
    solc = str(solc_path("0.5.14"))
    result = json.loads(
        subprocess.run(
            [solc, "--standard-json"], input=json.dumps(standard), text=True, capture_output=True, check=True
        ).stdout
    )
    d.compiled = {
        name: {"bin": body["evm"]["bytecode"]["object"], "abi": body["abi"]}
        for name, body in result["contracts"][str(source_path)].items()
    }
    slither = Slither(CryticCompile(SolcStandardJson(standard), solc=solc))
    for unit in slither.compilation_units:
        unit.context["psat_evm_version"] = evm
    d.slither = {c.name: c for c in slither.contracts}
    (tmp_path / "modern").mkdir()
    modern = O.deployment(
        anvil[0],
        tmp_path / "modern",
        """pragma solidity 0.8.27;
contract T{
fallback() external {
assembly {
mstore(0,0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00) return(0,"""
        + str(size)
        + ")}}}",
    )
    target = modern.deploy("T")
    d.deploy("C", ("address",), (target,))
    fn = O.function(d, "C", "act")
    known = d.contracts("C")
    known[target] = modern.slither["T"]
    reads = d.chain()
    assert checked_return_size(d.slither["C"]) is (evm == "byzantium")
    f = generate_function(d.slither["C"], fn, d.at["C"], reads, known, steps=10000)
    actual = O.passes(d, "C", fn, ())
    result = None
    if actual:
        result = rpc(
            d.url,
            "eth_call",
            [{"from": O.hex20(O.OWNER), "to": O.hex20(d.at["C"]), "data": "0x" + O.calldata(fn, ()).hex()}, "latest"],
        )
    if evm == "homestead" and size < 32:
        assert actual
        assert (
            isinstance(f, PendingCompilation) and f.reason == "call" and f.blocker == "unsupported:short_return_buffer"
        ), f
        f = compile_function(d.slither["C"], fn, d.at["C"], reads, known)
        tr = Translation(reads, known, d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
        assert tr.truth(f.success) is None and tr.issues
    else:
        assert isinstance(f, Formula), f
        tr = Translation(reads, known, d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
        assert tr.truth(f.success) is actual


@pytest.mark.parametrize("evm", ["homestead", "byzantium"])
@pytest.mark.parametrize("size", [0, 1, 31, 32])
@pytest.mark.parametrize("v2", [False, True])
def test_return_buffer_with_legacy_assembly_callee(anvil, tmp_path, evm, size, v2):
    source = (
        "pragma solidity 0.5.14;"
        + ("pragma experimental ABIEncoderV2;" if v2 else "")
        + """interface I{
function f() external returns(uint);
}
 contract T {
function() external {
assembly {
mstore(0,0x112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00) return(0,SIZE)}
}
}
 contract C {
I t;
constructor(address a)public{
t=I(a);
}
function act()public returns(uint){
return t.f();
}
}
""".replace("SIZE", str(size))
    )
    d = O.deployment(anvil[0], tmp_path, source, version="0.5.14")
    source_path = tmp_path / "target.sol"
    source_path.write_text(source)
    standard = {
        "language": "Solidity",
        "sources": {str(source_path): {"content": source}},
        "settings": {"evmVersion": evm, "outputSelection": {"*": {"*": ["*"], "": ["ast"]}}},
    }
    solc = str(solc_path("0.5.14"))
    result = json.loads(
        subprocess.run(
            [solc, "--standard-json"], input=json.dumps(standard), text=True, capture_output=True, check=True
        ).stdout
    )
    d.compiled = {
        name: {"bin": body["evm"]["bytecode"]["object"], "abi": body["abi"]}
        for name, body in result["contracts"][str(source_path)].items()
    }
    slither = Slither(CryticCompile(SolcStandardJson(standard), solc=solc))
    for unit in slither.compilation_units:
        unit.context["psat_evm_version"] = evm
    d.slither = {c.name: c for c in slither.contracts}
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    known = d.contracts("C", "T")
    reads = d.chain()
    assert checked_return_size(d.slither["C"]) is (evm == "byzantium")
    f = generate_function(d.slither["C"], fn, d.at["C"], reads, known, steps=10000)
    actual = O.passes(d, "C", fn, ())
    result = None
    if actual:
        result = rpc(
            d.url,
            "eth_call",
            [{"from": O.hex20(O.OWNER), "to": O.hex20(d.at["C"]), "data": "0x" + O.calldata(fn, ()).hex()}, "latest"],
        )
    if evm == "homestead" and size < 32:
        assert actual
        assert (
            isinstance(f, PendingCompilation) and f.reason == "call" and f.blocker == "unsupported:short_return_buffer"
        ), f
        f = compile_function(d.slither["C"], fn, d.at["C"], reads, known)
        tr = Translation(reads, known, d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
        assert tr.truth(f.success) is None and tr.issues
    else:
        assert isinstance(f, Formula), f
        tr = Translation(reads, known, d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0})
        assert tr.truth(f.success) is actual
