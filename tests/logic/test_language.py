"""The lowering's arithmetic, conversions, builtins and encodings, checked against the EVM: each function's lowered
success formula, evaluated by the decision's own evaluator at concrete arguments, says exactly whether ``eth_call``
succeeds on anvil. (What it rejects is named, never answered: ``test_ir_coverage``.)"""

from __future__ import annotations

import pytest
from eth_abi.abi import encode
from eth_utils import keccak

from services.logic.decide import Evaluator, World, converted
from services.logic.lower import Lowerer, parameter
from services.logic.terms import fits, mk, reset_terms, subterms
from tests.fuzz.authority import solc_path
from tests.logic._anvil import Deployment, anvil  # noqa: F401
from tests.support.anvil import ACCOUNT0, rpc

SOURCE = """
pragma solidity 0.8.27;

contract C {
    error Nope(uint256 code);
    enum E { A, B }
    int256 constant NEGATIVE = -5;

    function checkedAdd(uint8 a, uint8 b) external pure returns (uint8) { return a + b; }
    function checkedSub(uint256 a, uint256 b) external pure returns (uint256) { return a - b; }
    function checkedMul(uint128 a, uint128 b) external pure returns (uint128) { return a * b; }
    function checkedPow(uint256 a, uint256 b) external pure returns (uint256) { return a ** b; }
    function signedAdd(int8 a, int8 b) external pure returns (int8) { return a + b; }
    function wrapped(uint8 a, uint8 b, uint8 want) external pure { unchecked { require(a + b == want); } }
    function wrappedShift(uint8 a, uint8 want) external pure { require(a << 4 == want); }
    function divided(uint256 a, uint256 b) external pure returns (uint256) { return a / b; }
    function remainder(uint256 a, uint256 b) external pure returns (uint256) { return a % b; }
    function negative(int256 a) external pure { require(a < 0); }
    function signedDiv(int256 a, int256 b, int256 want) external pure { require(a / b == want); }
    function signedMod(int256 a, int256 b, int256 want) external pure { require(a % b == want); }
    function signedShift(int256 a, uint256 s, int256 want) external pure { require(a >> s == want); }
    function narrowed(uint256 x, uint16 want) external pure { require(uint16(x) == want); }
    function cut(bytes32 h, bytes4 want) external pure { require(bytes4(h) == want); }
    function padded(bytes4 b, bytes32 want) external pure { require(bytes32(b) == want); }
    function unsignedOf(int256 x, uint256 want) external pure { require(uint256(x) == want); }
    function signedOf(uint256 x, int256 want) external pure { require(int256(x) == want); }
    function tiny(int256 x, int8 want) external pure { require(int8(x) == want); }
    function flipped(uint8 x, uint8 want) external pure { require(~x == want); }
    function member(uint256 x) external pure returns (E) { return E(x); }
    function allocated(uint256 n) external pure returns (uint256) { return new uint256[](n).length; }
    function modulus(uint256 m) external pure returns (uint256) { return mulmod(2, 3, m) + addmod(2, 3, m); }
    function yulSigned(int256 a, int256 b, bool less, int256 quotient) external pure {
        bool l;
        int256 q;
        assembly { l := slt(a, b) q := sdiv(a, b) }
        require(l == less && q == quotient);
    }
    function yulBytes(uint256 i, uint256 x, uint256 want, uint256 extended) external pure {
        uint256 b;
        uint256 e;
        assembly { b := byte(i, x) e := signextend(0, x) }
        require(b == want && e == extended);
    }
    function yulDivZero(uint256 a, uint256 want) external pure {
        uint256 q;
        assembly { q := div(a, 0) }
        require(q == want);
    }
    // Hashes of what the code fixes (a hash of what the caller picks is a preimage question, not a value).
    function hashedPacked(bytes32 want) external pure {
        require(keccak256(abi.encode(bytes4(0xabcdef01), uint256(7))) == want);
    }
    function hashedSelector(bytes32 want) external pure {
        require(keccak256(abi.encodeWithSelector(bytes4(0x12345678), uint256(9))) == want);
    }
    function hashedSignature(bytes32 want) external pure {
        require(keccak256(abi.encodeWithSignature("f(uint256)", uint256(9))) == want);
    }
    function enumArgument(E e) external pure returns (E) { return e; }
    function customError(uint256 x) external pure { if (x == 1) revert Nope(x); }
    function requiredError(uint256 x) external pure { require(x != 1, Nope(x)); }
    function _finish(uint256 x) internal pure { if (x == 1) { assembly { return(0, 0) } } }
    function halted(uint256 x) external pure { _finish(x); revert(); }
    function negativeConstant(int256 want) external pure { require(NEGATIVE == want); }
    function deletedItem() external pure {
        uint256[] memory a = new uint256[](2);
        a[0] = 1;
        a[1] = 2;
        delete a[0];
        require(a[0] == 0 && a[1] == 2);
    }
    function sent(uint256 want) external view { _sent(want); }
    function _sent(uint256 want) internal view { require(msg.value == want); }
    function concatenated(bytes32 want) external pure {
        require(keccak256(bytes.concat(bytes2(0x1234), bytes1(0x56))) == want);
    }
}
"""

MAX = 2**256 - 1


def _h(*parts: bytes) -> bytes:
    return keccak(b"".join(parts))


# (function, arguments): arguments as the ABI takes them (ints, bools, bytes for bytesN).
CASES = [
    ("checkedAdd", (200, 55)), ("checkedAdd", (200, 56)), ("checkedSub", (3, 2)), ("checkedSub", (2, 3)),
    ("checkedMul", (2**64, 2**63)), ("checkedMul", (2**64, 2**64)), ("checkedPow", (2, 255)), ("checkedPow", (2, 256)),
    ("checkedPow", (0, 0)), ("signedAdd", (100, 27)), ("signedAdd", (100, 28)), ("signedAdd", (-100, -28)),
    ("signedAdd", (-100, -29)), ("wrapped", (200, 100, 44)), ("wrapped", (200, 100, 300 % 256 + 1)),
    ("wrappedShift", (0x1F, 0xF0)), ("wrappedShift", (0x1F, 0x1F0 % 256 + 1)), ("divided", (7, 2)), ("divided", (7, 0)),
    ("remainder", (7, 0)), ("remainder", (7, 3)), ("negative", (-5,)), ("negative", (3,)), ("signedDiv", (-7, 2, -3)),
    ("signedDiv", (-7, 2, -4)), ("signedMod", (-7, 2, -1)), ("signedMod", (-7, 2, 1)), ("signedShift", (-8, 1, -4)),
    ("signedShift", (-1, 300, -1)), ("signedShift", (-8, 1, 4)), ("narrowed", (70000, 70000 % 65536)),
    ("narrowed", (70000, 70000 % 65536 + 1)), ("cut", (bytes(range(32)), bytes(range(4)))),
    ("cut", (bytes(range(32)), bytes(range(28, 32)))),
    ("padded", (b"\x12\x34\x56\x78", b"\x12\x34\x56\x78" + bytes(28))),
    ("padded", (b"\x12\x34\x56\x78", bytes(28) + b"\x12\x34\x56\x78")), ("unsignedOf", (-1, MAX)),
    ("unsignedOf", (-1, 1)), ("signedOf", (MAX, -1)), ("signedOf", (MAX, 1)), ("tiny", (255, -1)),
    ("tiny", (-129, 127)),
    ("tiny", (255, 127)), ("flipped", (0, 255)), ("flipped", (0, 1)), ("member", (1,)), ("member", (2,)),
    ("allocated", (3,)), ("allocated", (2**64,)), ("modulus", (5,)), ("modulus", (0,)),
    ("yulSigned", (-1, 1, True, -1)), ("yulSigned", (-1, 1, False, -1)), ("yulSigned", (7, -2, False, -3)),
    ("yulBytes", (31, 0x1FF, 0xFF, MAX)), ("yulBytes", (32, 0x1FF, 0, MAX)), ("yulBytes", (31, 0x17F, 0x7F, 0x7F)),
    ("yulDivZero", (5, 0)), ("yulDivZero", (5, 1)),
    ("hashedPacked", (_h(b"\xab\xcd\xef\x01" + bytes(28), (7).to_bytes(32, "big")),)),
    ("hashedPacked", (_h(bytes(28) + b"\xab\xcd\xef\x01", (7).to_bytes(32, "big")),)),
    ("hashedSelector", (_h(b"\x12\x34\x56\x78", (9).to_bytes(32, "big")),)),
    ("hashedSelector", (_h(bytes(28) + b"\x12\x34\x56\x78", (9).to_bytes(32, "big")),)),
    ("hashedSignature", (_h(keccak(text="f(uint256)")[:4], (9).to_bytes(32, "big")),)),
    ("concatenated", (_h(b"\x12\x34\x56"),)), ("concatenated", (_h(b"\x12\x34"),)),
    ("enumArgument", (1,)), ("enumArgument", (2,)), ("negativeConstant", (-5,)), ("negativeConstant", (5,)),
    ("deletedItem", ()), ("sent", (0,)), ("sent", (1,)), ("halted", (1,)), ("halted", (2,)),
    ("customError", (1,)), ("customError", (2,)), ("requiredError", (1,)), ("requiredError", (2,)),
]  # fmt: skip


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    url, root = anvil
    d = Deployment(url, root, SOURCE)
    d.deploy("C")
    return d


def _chain_says(d, fn, values) -> bool:
    types = [parameter(p, i)[2] for i, p in enumerate(fn.parameters)]  # an enum as the ABI sees it
    data = keccak(text=fn.solidity_signature)[:4] + encode(types, list(values))
    call = {"from": ACCOUNT0, "to": "0x%040x" % d.at["C"], "data": "0x" + data.hex()}
    try:
        rpc(d.url, "eth_call", [call, "latest"])
        return True
    except RuntimeError:
        return False


def _engine_says(d, fn, values):
    reset_terms()
    contract = d.slither["C"]
    formula = Lowerer(contract).success(fn)
    world = World(d.chain(), d.at["C"], int.from_bytes(keccak(text=fn.solidity_signature)[:4], "big"), {})
    assignment = {}
    for i, (p, v) in enumerate(zip(fn.parameters, values)):
        term = parameter(p, i)
        assignment[term] = int.from_bytes(v, "big") if isinstance(v, bytes) else v
    caller = int(ACCOUNT0, 16)
    return formula, Evaluator(world, {"caller": caller, "signer": caller}, assignment).truth(formula)


@pytest.mark.parametrize(("name", "values"), CASES, ids=[f"{c[0]}{c[1]}"[:60] for c in CASES])
def test_the_lowered_condition_says_what_the_chain_does(deployed, name, values):
    fn = next(f for f in deployed.slither["C"].functions_entry_points if f.name == name)
    formula, engine = _engine_says(deployed, fn, values)
    # Every construct here is one the lowering handles: a definite answer, the chain's.
    assert engine == _chain_says(deployed, fn, values), (name, values, formula)


def test_conversions_and_ranges_evaluate_as_the_types_say():
    assert converted("uint16", 70000) == 70000 % 65536
    assert converted("int8", 255) == -1 and converted("int8", -129) == 127 and converted("int256", MAX) == -1
    assert converted("uint256", -1) == MAX and converted("address", 2**160 + 5) == 5
    assert converted("bytes4", 0x1234567890) == 0x34567890
    assert fits("add", 200, 55, 8, False) and not fits("add", 200, 56, 8, False)
    assert fits("sub", -100, 28, 8, True) and not fits("sub", -100, 29, 8, True)
    assert fits("pow", 2, 255, 256, False) and not fits("pow", 2, 256, 256, False) and fits("pow", -1, 2**200, 8, True)


CALLS = """
pragma solidity 0.8.27;

contract C {
    function viaCall(address t) external {
        (bool ok, ) = t.call(abi.encodeWithSignature("allow(address)", msg.sender));
        require(ok);
    }
    function viaStatic(address t) external view {
        (bool ok, bytes memory r) = t.staticcall(abi.encodeWithSignature("allowed(address)", msg.sender));
        require(ok && abi.decode(r, (bool)));
    }
    function viaOpaqueStatic(address t, bytes calldata data) external view {
        (bool ok, ) = t.staticcall(data);
        require(ok && msg.sender != address(0));
    }
}
"""

LEGACY = """
pragma solidity 0.4.19;

contract L {
    function guarded(address y) public view {
        address r;
        assembly { if iszero(y) { r := y } }
        require(r == msg.sender);
    }
}
"""


def _compiled(tmp_path_factory, source, version, name):
    solc = solc_path(version)
    if solc is None:
        pytest.skip(f"solc {version} not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("language") / "X.sol"
    path.write_text(source)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == name)


def test_a_low_level_call_is_the_call_its_data_encodes(tmp_path_factory):
    from services.logic.terms import CALLER

    contract = _compiled(tmp_path_factory, CALLS, "0.8.27", "C")
    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "viaCall")
    calls = subterms(Lowerer(contract).success(fn), "call")
    # The action handed the caller, so the callee's own check of who that is counts; not an arranged success.
    assert [(c[2], c[3], c[4]) for c in calls] == [("allow(address)", (CALLER,), False)]
    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "viaStatic")
    formula = Lowerer(contract).success(fn)
    assert {(c[2], c[4]) for c in subterms(formula, "call")} == {("allowed(address)", True)}
    assert subterms(formula, "item") and not subterms(formula, "assumed")  # its answer, decoded: never assumed
    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "viaOpaqueStatic")
    assert "unsupported:staticcall" in {u[1] for u in subterms(Lowerer(contract).success(fn), "unknown")}


def test_legacy_assembly_assigns_nothing_for_sure_past_control_flow(tmp_path_factory):
    contract = _compiled(tmp_path_factory, LEGACY, "0.4.19", "L")
    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == "guarded")
    formula = Lowerer(contract).success(fn)
    # ``r := y`` runs only when ``y`` is zero: never ``r == y`` for sure, so never "open to whoever passes itself".
    assert "asm:r" in {u[1] for u in subterms(formula, "unknown")}
    assert not any(c[1] == "eq" and mk("arg", "y", "address") in c[2:] for c in subterms(formula, "cmp"))
