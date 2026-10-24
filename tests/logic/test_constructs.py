"""Constructs the lowering handles that no other test checked against the EVM: lengths and code sizes, return data,
Yul calls, ``ecrecover``, ``selfdestruct``, balances and code hashes, transient storage, ``msg.sig``/``msg.data``,
``tx.origin``, ``this``, block fields, out-of-range indexes into storage and calldata arrays, ``create``/``create2``,
``sha256``/``ripemd160``, logs, Yul ``stop``/``invalid``/``pop``, a struct built from its fields, and the legacy (< 0.6)
assembly reader's word arithmetic. Each probe requires a value the construct gives to equal ``want``: its lowered
success formula, evaluated by the decision's own evaluator at the arguments of an ``eth_call`` (``msg.data`` as that
call's encoding, its size as sent), must say what the chain does, or, for a construct the lowering rejects, read
unknown under the label naming it (``REJECTED``). Where the lowering answers definitely and wrongly, the case is a
strict ``xfail`` naming the defect, so a fix flips it loudly."""

from __future__ import annotations

import pytest
import rlp
from eth_account import Account
from eth_utils import keccak

from services.logic.decide import UNK, Evaluator, World
from services.logic.lower import Lowerer, parameter
from services.logic.terms import reset_terms, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """
pragma solidity 0.8.27;

contract Other {
    uint256 public stored = 7;
    function answer() external pure returns (uint256) { return 42; }
    function echo(uint256 x, uint256 y) external pure returns (uint256) { return x + y; }
    function nothing() external pure {}
    function fails() external pure { revert(); }
    function setStored(uint256 v) external { stored = v; }
}

contract C {
    struct S { uint128 a; uint64 b; }
    uint256[] arr;
    Other other;
    uint256 slot0Copy;

    constructor(Other o) payable { other = o; arr.push(10); arr.push(20); arr.push(30); }

    function storageLength(uint256 want) external view { require(arr.length == want); }
    function storageItem(uint256 i, uint256 want) external view { require(arr[i] == want); }
    function calldataLength(uint256[] calldata a, uint256 want) external pure { require(a.length == want); }
    function calldataItem(uint256[] calldata a, uint256 i, uint256 want) external pure { require(a[i] == want); }
    function ownCodeLength(uint256 want) external view { require(address(this).code.length == want); }
    function otherCodeLength(uint256 want) external view { require(address(other).code.length == want); }
    function eoaCodeLength(address who, uint256 want) external view { require(who.code.length == want); }
    function yulCodeSize(address who, uint256 want) external view {
        uint256 n;
        assembly { n := extcodesize(who) }
        require(n == want);
    }
    function returnSize(uint256 want) external view {
        address t = address(other);
        uint256 n;
        assembly {
            mstore(0, 0x85bb7d6900000000000000000000000000000000000000000000000000000000)
            let ok := staticcall(gas(), t, 0, 4, 0, 0)
            n := returndatasize()
        }
        require(n == want);
    }
    function returnCopy(uint256 want) external view {
        address t = address(other);
        uint256 v;
        assembly {
            mstore(0, 0x85bb7d6900000000000000000000000000000000000000000000000000000000)
            let ok := staticcall(gas(), t, 0, 4, 0, 0)
            returndatacopy(0, 0, 32)
            v := mload(0)
        }
        require(v == want);
    }
    function yulStaticcall(uint256 want) external view {
        address t = address(other);
        uint256 v;
        assembly {
            mstore(0, 0x85bb7d6900000000000000000000000000000000000000000000000000000000)
            let ok := staticcall(gas(), t, 0, 4, 0, 32)
            v := mload(0)
        }
        require(v == want);
    }
    function yulCall(uint256 want) external {
        address t = address(other);
        uint256 ok;
        assembly { ok := call(gas(), t, 0, 0, 0, 0, 0) }
        require(ok == want);
    }
    function yulCallFails(uint256 want) external {
        address t = address(other);
        uint256 ok;
        assembly {
            mstore(0, 0xce869a6400000000000000000000000000000000000000000000000000000000)
            ok := call(gas(), t, 0, 0, 4, 0, 0)
        }
        require(ok == want);
    }
    function yulDelegatecall(uint256 want) external {
        address t = address(other);
        uint256 ok;
        assembly {
            mstore(0, 0x85bb7d6900000000000000000000000000000000000000000000000000000000)
            ok := delegatecall(gas(), t, 0, 4, 0, 0)
        }
        require(ok == want);
    }
    function recovered(bytes32 h, uint8 v, bytes32 r, bytes32 s, address want) external pure {
        require(ecrecover(h, v, r, s) == want);
    }
    function destroyed(uint256 x) external { if (x == 1) selfdestruct(payable(msg.sender)); revert(); }
    function ownBalance(uint256 want) external view { require(address(this).balance == want); }
    function otherBalance(address who, uint256 want) external view { require(who.balance == want); }
    function yulSelfBalance(uint256 want) external view {
        uint256 b;
        assembly { b := selfbalance() }
        require(b == want);
    }
    function yulBalance(address who, uint256 want) external view {
        uint256 b;
        assembly { b := balance(who) }
        require(b == want);
    }
    function codeHash(address who, bytes32 want) external view { require(who.codehash == want); }
    function yulCodeHash(address who, bytes32 want) external view {
        bytes32 h;
        assembly { h := extcodehash(who) }
        require(h == want);
    }
    function transient(uint256 x, uint256 want) external {
        uint256 v;
        assembly { tstore(1, x) v := tload(1) }
        require(v == want);
    }
    function transientFresh(uint256 want) external view {
        uint256 v;
        assembly { v := tload(7) }
        require(v == want);
    }
    function sig(uint256 want) external pure { require(uint32(msg.sig) == want); }
    function dataLength(uint256 x, uint256 want) external pure { x; require(msg.data.length == want); }
    function dataByte(uint256 i, uint256 want) external pure { require(uint8(msg.data[i]) == want); }
    function origin(uint256 want) external view { require(uint160(tx.origin) == want); }
    function self(uint256 want) external view { require(uint160(address(this)) == want); }
    function yulAddress(uint256 want) external view {
        uint256 a;
        assembly { a := address() }
        require(a == want);
    }
    function timestamp(uint256 want) external view { require(block.timestamp == want); }
    function number(uint256 want) external view { require(block.number == want); }
    function chain(uint256 want) external view { require(block.chainid == want); }
    function created(uint256 want) external {
        Other o = new Other();
        require(uint160(address(o)) == want);
    }
    function createdOk(uint256 x) external { new Other(); require(x == 1); }
    function created2(uint256 want) external {
        Other o = new Other{salt: bytes32(uint256(5))}();
        require(uint160(address(o)) == want);
    }
    function hashed(uint256 x, bytes32 want) external pure { require(sha256(abi.encodePacked(x)) == want); }
    function ripemd(uint256 x, bytes20 want) external pure { require(ripemd160(abi.encodePacked(x)) == want); }
    function yulLogs(uint256 x) external {
        assembly {
            log0(0, 0)
            log1(0, 0, 1)
            log2(0, 0, 1, 2)
            log3(0, 0, 1, 2, 3)
            log4(0, 0, 1, 2, 3, 4)
        }
        require(x == 1);
    }
    function yulStop(uint256 x) external pure {
        assembly { if eq(x, 1) { stop() } }
        revert();
    }
    function yulInvalid(uint256 x) external pure {
        assembly { if eq(x, 1) { invalid() } }
    }
    function yulPop(uint256 x, uint256 want) external pure {
        uint256 v;
        assembly { pop(add(x, 1)) v := add(x, 2) }
        require(v == want);
    }
    function built(uint128 a, uint64 b, uint256 want) external pure {
        S memory s = S(a, b);
        require(uint256(s.a) + s.b == want);
    }
    function returnSizeKnown(uint256 want) external view {
        other.answer();
        uint256 n;
        assembly { n := returndatasize() }
        require(n == want);
    }
    function returnCopyKnown(uint256 want) external view {
        other.answer();
        uint256 v;
        assembly {
            returndatacopy(0, 0, 32)
            v := mload(0)
        }
        require(v == want);
    }
    function yulStaticcallEncoded(uint256 want) external view {
        address t = address(other);
        bytes memory data = abi.encodeCall(Other.echo, (uint256(42), uint256(0)));
        uint256 v;
        assembly {
            let ok := staticcall(gas(), t, add(data, 0x20), mload(data), 0, 32)
            v := mload(0)
        }
        require(v == want);
    }
    function yulCallOk(uint256 want) external {
        address t = address(other);
        uint256 ok;
        assembly {
            mstore(0, 0x448f30a300000000000000000000000000000000000000000000000000000000)
            ok := call(gas(), t, 0, 0, 4, 0, 0)
        }
        require(ok == want);
    }
}"""

LEGACY = """
pragma solidity {version};

contract L {{
{functions}
    // Solidity's own log0..log3 (gone from 0.5's language, kept by the assembler): no effect on success.
    {logs}
}}
"""
_OPS = {
    "add": lambda a, b: (a + b) % 2**256,
    "sub": lambda a, b: (a - b) % 2**256,
    "mul": lambda a, b: (a * b) % 2**256,
    "div": lambda a, b: a // b if b else 0,
    "mod": lambda a, b: a % b if b else 0,
    "exp": lambda a, b: pow(a, b, 2**256),
    "and": lambda a, b: a & b,
    "or": lambda a, b: a | b,
    "xor": lambda a, b: a ^ b,
    "lt": lambda a, b: int(a < b),
    "gt": lambda a, b: int(a > b),
    "eq": lambda a, b: int(a == b),
    "shl": lambda a, b: (b << a) % 2**256 if a < 256 else 0,
    "shr": lambda a, b: b >> a if a < 256 else 0,
}
_UNARY = {"iszero": lambda a: int(a == 0), "not": lambda a: 2**256 - 1 - a}
MAX = 2**256 - 1
_INPUTS = [(MAX, 2), (6, 4), (2, 256), (7, 0)]
# shl/shr arrived with Constantinople: 0.5's assembler knows them, 0.4.19's doesn't.
_LEGACY_OPS = {"0.4.19": [o for o in _OPS if o not in ("shl", "shr")], "0.5.14": list(_OPS)}


def _legacy_source(version: str) -> str:
    functions = [
        f"    function y_{op}(uint256 a, uint256 b, uint256 want) public pure {{ uint256 r; "
        f"assembly {{ r := {op}(a, b) }} require(r == want); }}"
        for op in _LEGACY_OPS[version]
    ] + [
        f"    function y_{op}(uint256 a, uint256 want) public pure {{ uint256 r; "
        f"assembly {{ r := {op}(a) }} require(r == want); }}"
        for op in _UNARY
    ]
    logs = (
        "function solLogs(uint256 x) public { log0(bytes32(x)); log1(bytes32(x), bytes32(1)); "
        "log2(bytes32(x), bytes32(1), bytes32(2)); log3(bytes32(x), bytes32(1), bytes32(2), bytes32(3)); "
        "require(x == 1); }"
        if version == "0.4.19"
        else ""
    )
    return LEGACY.format(version=version, functions="\n".join(functions), logs=logs)


# Constructs the lowering rejects, by the label its formula names (``delegate``: a delegatecall's outcome, the
# target's code run here, which the evaluator leaves unknown).
REJECTED = {
    "returnSize": "unsupported:returndatasize()",  # no call the lowering placed before it
    "returnCopy": "memory",  # copied from a call whose data it couldn't read: memory forgotten
    "yulStaticcall": "memory",
    "yulDelegatecall": "delegate",
    "created": "created",
    "created2": "created",
    "ripemd": "unsupported:ripemd160(bytes)",
}
# (name, case): definite answers that differ from the chain.
WRONG = {
    ("yulCall", 0): "A52: Yul call to a callee that always reverts read as an arranged success",
    ("yulCall", 1): "A52: Yul call to a callee that always reverts read as an arranged success",
    ("yulCallFails", 0): "A52: Yul call to a callee that always reverts read as an arranged success",
    ("yulCallFails", 1): "A52: Yul call to a callee that always reverts read as an arranged success",
    ("recovered", 2): "A53: ecrecover read as the signer identity, whatever digest and signature it is handed",
    ("hashed", 0): "A54: sha256 evaluates unknown, unnamed",
    ("hashed", 1): "A54: sha256 evaluates unknown, unnamed",
}


def _cases(d) -> dict[str, list[tuple[tuple, int]]]:
    """name -> [(arguments, sender)], a passing case first, then failing ones."""
    url, at, other = d.url, d.at["C"], d.at["Other"]
    eoa = O.ACCOUNTS[2]
    balance = int(O.rpc(url, "eth_getBalance", [O.hex20(eoa), "latest"]), 16)
    code = bytes.fromhex(O.rpc(url, "eth_getCode", [O.hex20(other), "latest"])[2:])
    own = bytes.fromhex(O.rpc(url, "eth_getCode", [O.hex20(at), "latest"])[2:])
    block = O.rpc(url, "eth_getBlockByNumber", ["latest", False])
    now, number = int(block["timestamp"], 16), int(block["number"], 16)
    signer = Account.from_key(b"\x11" * 32)
    digest = keccak(b"digest")
    signed = Account.unsafe_sign_hash(digest, signer.key)
    rs = (signed.r.to_bytes(32, "big"), signed.s.to_bytes(32, "big"))
    who = int(signer.address, 16)
    nonce = int(O.rpc(url, "eth_getTransactionCount", [O.hex20(at), "latest"]), 16)
    created = int.from_bytes(keccak(rlp.encode([at.to_bytes(20, "big"), nonce]))[12:], "big")
    init = bytes.fromhex(d.compiled["Other"]["bin"])
    salted = keccak(b"\xff" + at.to_bytes(20, "big") + (5).to_bytes(32, "big") + keccak(init))
    created2 = int.from_bytes(salted[12:], "big")

    def precompile(address: int, x: int) -> bytes:
        call = {"to": O.hex20(address), "data": "0x" + x.to_bytes(32, "big").hex()}
        return bytes.fromhex(O.rpc(url, "eth_call", [call, "latest"])[2:])

    def selector(name: str) -> int:
        return O.selector(O.function(d, "C", name).solidity_signature)

    o = O.OWNER
    return {
        "storageLength": [((3,), o), ((4,), o)],
        "storageItem": [((1, 20), o), ((1, 21), o), ((3, 0), o), ((5, 0), o)],
        "calldataLength": [(([1, 2], 2), o), (([1, 2], 3), o)],
        "calldataItem": [(([5, 6], 1, 6), o), (([5, 6], 1, 7), o), (([5, 6], 2, 0), o)],
        "ownCodeLength": [((len(own),), o), ((len(own) + 1,), o)],
        "otherCodeLength": [((len(code),), o), ((0,), o)],
        "eoaCodeLength": [((eoa, 0), o), ((eoa, 1), o)],
        "yulCodeSize": [((other, len(code)), o), ((other, 0), o)],
        "returnSize": [((32,), o), ((0,), o)],
        "returnCopy": [((42,), o), ((41,), o)],
        "returnSizeKnown": [((32,), o), ((0,), o)],
        "returnCopyKnown": [((42,), o), ((41,), o)],
        "yulStaticcall": [((42,), o), ((41,), o)],
        "yulStaticcallEncoded": [((42,), o), ((41,), o)],
        "yulCall": [((0,), o), ((1,), o)],
        "yulCallFails": [((0,), o), ((1,), o)],
        "yulCallOk": [((1,), o), ((0,), o)],
        "yulDelegatecall": [((1,), o), ((0,), o)],
        # Sent by the signer itself, the identity the lowering reads ``ecrecover`` as; then a signature of another
        # digest, which recovers someone else.
        "recovered": [
            ((digest, signed.v, *rs, who), who),
            ((digest, signed.v, *rs, eoa), who),
            ((keccak(b"other"), signed.v, *rs, who), who),
        ],
        "destroyed": [((1,), o), ((2,), o)],
        "ownBalance": [((12345,), o), ((12346,), o)],
        "otherBalance": [((eoa, balance), o), ((eoa, balance + 1), o)],
        "yulSelfBalance": [((12345,), o), ((0,), o)],
        "yulBalance": [((eoa, balance), o), ((eoa, 0), o)],
        "codeHash": [((other, keccak(code)), o), ((other, bytes(32)), o)],
        "yulCodeHash": [((other, keccak(code)), o), ((other, bytes(32)), o)],
        "transient": [((5, 5), o), ((5, 6), o)],
        "transientFresh": [((0,), o), ((1,), o)],
        "sig": [((selector("sig"),), o), ((selector("sig") + 1,), o)],
        "dataLength": [((0, 68), o), ((0, 67), o)],
        "dataByte": [((0, selector("dataByte") >> 24), o), ((0, 0), o), ((35, 0), o), ((100, 0), o)],
        "origin": [((o,), o), ((o + 1,), o), ((eoa,), eoa)],
        "self": [((at,), o), ((at + 1,), o)],
        "yulAddress": [((at,), o), ((at + 1,), o)],
        "timestamp": [((now,), o), ((now + 1,), o)],
        "number": [((number,), o), ((number + 1,), o)],
        "chain": [((31337,), o), ((1,), o)],
        "created": [((created,), o), ((created + 1,), o)],
        "createdOk": [((1,), o), ((2,), o)],
        "created2": [((created2,), o), ((created2 + 1,), o)],
        "hashed": [((3, precompile(2, 3)), o), ((3, precompile(2, 4)), o)],
        "ripemd": [((3, precompile(3, 3)[12:]), o), ((3, precompile(3, 4)[12:]), o)],
        "yulLogs": [((1,), o), ((2,), o)],
        "yulStop": [((1,), o), ((2,), o)],
        "yulInvalid": [((2,), o), ((1,), o)],
        "yulPop": [((3, 5), o), ((3, 4), o)],
        "built": [((3, 4, 7), o), ((3, 4, 8), o)],
    }


_COUNTS = {
    **dict.fromkeys(
        ["storageLength", "calldataLength", "ownCodeLength", "otherCodeLength", "eoaCodeLength", "yulCodeSize",
         "returnSize", "returnCopy", "returnSizeKnown", "returnCopyKnown", "yulStaticcall", "yulStaticcallEncoded",
         "yulCall", "yulCallFails", "yulCallOk", "yulDelegatecall", "destroyed", "ownBalance", "otherBalance",
         "yulSelfBalance", "yulBalance", "codeHash", "yulCodeHash", "transient", "transientFresh", "sig",
         "dataLength", "self", "yulAddress", "timestamp", "number", "chain", "created", "createdOk", "created2",
         "hashed", "ripemd", "yulLogs", "yulStop", "yulInvalid", "yulPop", "built"],
        2,
    ),
    "storageItem": 4,
    "calldataItem": 3,
    "recovered": 3,
    "dataByte": 4,
    "origin": 3,
}  # fmt: skip
CASES = [
    pytest.param(name, k, marks=pytest.mark.xfail(strict=True, reason=WRONG[(name, k)]), id=f"{name}-{k}")
    if (name, k) in WRONG
    else pytest.param(name, k, id=f"{name}-{k}")
    for name, n in _COUNTS.items()
    for k in range(n)
]


@pytest.fixture(scope="module")
def deployed(anvil):  # noqa: F811
    d = O.deployment(*anvil, SOURCE)
    d.deploy("Other")
    d.deploy("C", ("address",), (d.at["Other"],))
    O.rpc(d.url, "anvil_setBalance", [O.hex20(d.at["C"]), hex(12345)])
    return d, _cases(d)


def _labels(formula) -> set[str]:
    named = {str(u[1]) for u in subterms(formula, "unknown")}
    named |= {str(t[1]) for t in subterms(formula, "opaque") if str(t[1]).startswith("unsupported:")}
    return named | ({"delegate"} if subterms(formula, "delegate") else set())


def _engine(d, contract: str, fn, values, sender: int):
    """The formula and its truth at ``values`` sent by ``sender``: each caller-chosen length or item of an array
    argument and ``msg.data``'s size as the ``eth_call`` sends them."""
    reset_terms()
    formula = Lowerer(d.slither[contract]).success(fn)
    world = World(d.chain(), d.at[contract], O.selector(fn.solidity_signature), d.contracts(*d.at))
    world.parameters = tuple(parameter(p, i) for i, p in enumerate(fn.parameters))
    assignment = {
        parameter(p, i): int.from_bytes(v, "big") if isinstance(v, bytes) else v
        for i, (p, v) in enumerate(zip(fn.parameters, values))
    }
    probe = Evaluator(world, {"caller": sender, "signer": sender}, dict(assignment))
    size = len(O.calldata(fn, list(values)))
    for t in sorted(subterms(formula, "len") + subterms(formula, "elem") + subterms(formula, "calldatasize"), key=str):
        held = assignment.get(t[1]) if t[0] != "calldatasize" else None
        if t[0] == "calldatasize":
            assignment[t] = size
        elif isinstance(held, list) and t[0] == "len":
            assignment[t] = len(held)
        elif isinstance(held, list):
            index = probe.eval(t[2])
            assignment[t] = held[index] if isinstance(index, int) and 0 <= index < len(held) else 0
    return formula, Evaluator(world, {"caller": sender, "signer": sender}, assignment).truth(formula)


def _check(d, contract: str, name: str, values, sender: int) -> None:
    fn = O.function(d, contract, name)
    chain = O.chain_says(d, fn, values, contract, sender)
    formula, engine = _engine(d, contract, fn, values, sender)
    if name in REJECTED:
        assert engine is UNK and REJECTED[name] in _labels(formula), (name, values, engine, _labels(formula))
    else:
        assert engine == chain, (name, values, chain, engine, sorted(_labels(formula)))


@pytest.mark.parametrize(("name", "k"), CASES)
def test_a_construct_reads_as_the_chain_runs_it(deployed, name, k):
    d, cases = deployed
    values, sender = cases[name][k]
    _check(d, "C", name, values, sender)


LEGACY_CASES = [
    pytest.param(version, op, inputs, want, id=f"{version}-{op}{inputs}-{'pass' if want == right else 'fail'}")
    for version, ops in _LEGACY_OPS.items()
    for op in ops
    for inputs in _INPUTS
    for right in [_OPS[op](*inputs)]
    for want in (right, (right + 1) % 2**256)
] + [
    pytest.param(version, op, (a,), want, id=f"{version}-{op}({a})-{'pass' if want == right else 'fail'}")
    for version in _LEGACY_OPS
    for op, f in _UNARY.items()
    for a in (0, 5, MAX)
    for right in [f(a)]
    for want in (right, (right + 1) % 2**256)
]


@pytest.fixture(scope="module")
def legacy(anvil):  # noqa: F811
    out = {}
    for version in _LEGACY_OPS:
        d = O.deployment(*anvil, _legacy_source(version), version)
        d.deploy("L")
        out[version] = d
    return out


@pytest.mark.parametrize(("version", "op", "inputs", "want"), LEGACY_CASES)
def test_the_legacy_assembly_reader_computes_words_as_the_evm_does(legacy, version, op, inputs, want):
    _check(legacy[version], "L", f"y_{op}", (*inputs, want), O.OWNER)


@pytest.mark.parametrize("x", [1, 2])
def test_solidity_s_own_logs_change_nothing_about_success(legacy, x):
    _check(legacy["0.4.19"], "L", "solLogs", (x,), O.OWNER)
