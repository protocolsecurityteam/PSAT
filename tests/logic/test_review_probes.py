"""The earlier reviews' probes (``scratchpad/probe_audit``, ``probe_audit2/probes``, ``probe_audit3``) the suite
didn't yet cover, each Solidity source kept as the reviewer wrote it, checked against anvil. Semantics probes: the
lowered success formula (or a function's return value, ``Lowerer.returns``) evaluated at concrete arguments must be
what ``eth_call`` says wherever it is definite. Verdict probes: ``_oracle.check`` (listed holders pass from their
own address, open-now passes for every stranger, restricted fails for each) or soundness against the holders known by
construction. Callee mis-lowering probes: never bolder than the clean verdict."""

# ruff: noqa: E501  (the reviewers' Solidity is kept verbatim, long lines included)

from __future__ import annotations

import pytest
from eth_abi.abi import decode, encode
from eth_utils import keccak

from services.logic.decide import UNK, Evaluator, World
from services.logic.lower import Lowerer, parameter
from services.logic.terms import FALSE, TRUE, const, reset_terms, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

OWNER = O.OWNER

# --- audit 1, element reads (``test_p_elements``): those test_elements / test_loop_control don't already check ---

ELEMENTS = r"""
pragma solidity 0.8.27;

contract C {
    struct S { uint256 y; uint256[] xs; }
    mapping(address => S) m;
    mapping(uint256 => S[]) ms;
    uint256[] list2;
    uint256[] list3;
    uint256[][] grid2;
    S[] structs;

    function setup() external {
        m[address(1)].y = 4;
        m[address(1)].xs.push(11); m[address(1)].xs.push(12);
        ms[3].push(); ms[3][0].xs.push(21); ms[3][0].y = 8;
        list2.push(1); list2.push(2);
        grid2.push(); grid2[0].push(31); grid2[0].push(32); grid2.push(); grid2[1].push(41);
        structs.push(); structs[0].y = 50; structs.push(); structs[1].y = 60;
    }

    // (a) nested containers
    function a1(address k, uint256 i, uint256 want) external view { require(m[k].xs[i] == want); }
    function a2(uint256 k, uint256 j, uint256 i, uint256 want) external view { require(ms[k][j].xs[i] == want); }
    function a3(uint256 i, uint256 j, uint256 want) external view { require(grid2[i][j] == want); }
    function a4(uint256 i, uint256 want) external { S storage s = m[address(1)]; s.xs[i] = 77; require(m[address(1)].xs[1] == want); }

    // (b) loop write then read, same and next iteration
    function b1(uint256 n, uint256 want) external pure {
        uint256[] memory a = new uint256[](5);
        uint256 s;
        for (uint256 i; i < n; i++) { a[i] = i + 1; s += a[i]; if (i > 0) s += a[i - 1] * 10; }
        require(s == want);
    }
    function b2(uint256 want) external pure {
        uint256[] memory a = new uint256[](3);
        uint256 s;
        for (uint256 i; i < 3; i++) { s = s * 10 + a[i]; if (i + 1 < 3) a[i + 1] = i + 5; }
        require(s == want);
    }
    function b3(uint256 n, uint256 want) external {
        for (uint256 i; i < n; i++) { list2.push(i); }
        require(list2.length == want);
    }

    // (c) break / continue / return in loops
    function c1(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) { if (i == 1) continue; if (i == 3) break; s += i; }
        require(s == want);
    }
    function _find(uint256[] memory xs, uint256 v) internal pure returns (uint256) {
        for (uint256 i; i < xs.length; i++) { if (xs[i] == v) return i; }
        return 99;
    }
    function c2(uint256 v, uint256 want) external pure {
        uint256[] memory xs = new uint256[](3);
        xs[0] = 7; xs[1] = 8; xs[2] = 9;
        require(_find(xs, v) == want);
    }
    function c3(uint256 n, uint256 want) external pure {
        uint256 i; uint256 s;
        while (true) { i++; if (i > n) break; if (i % 2 == 0) continue; s += i; }
        require(s == want);
    }

    function c4(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i = 1; i <= n; i++) { if (i % 2 == 0) continue; s += i; }
        require(s == want);
    }
    function c5(uint256 n, uint256 want) external pure {
        uint256 i; uint256 s;
        while (true) { i++; if (i > n) break; if (i == 2) continue; s += i; }
        require(s == want);
    }
    function c6(uint256 n, uint256 want) external pure {
        uint256 i; uint256 s;
        while (i < n) { i++; if (i == 2) continue; s += i; }
        require(s == want);
    }
    function c7(uint256 want) external pure {
        uint256 s;
        for (uint256 i = 1; i <= 4; i++) { if (i == 2) continue; s += i; }
        require(s == want);
    }
    function c8(uint256 n, uint256 want) external pure {
        uint256 i; uint256 s;
        do { i++; if (i == 2) continue; s += i; } while (i < n);
        require(s == want);
    }
    function c9(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i = 1; ; ) { if (i > n) break; i++; if (i == 3) continue; s += i; }
        require(s == want);
    }
    function c10(uint256 n, uint256 want) external pure {
        uint256 s;
        for (uint256 i; i < n; i++) { for (uint256 j; j < 3; j++) { if (j == 1) break; s += 10; } s += 1; }
        require(s == want);
    }
    // (d) storage pointer to an element handed to an internal function
    function _bump(S storage p) internal { p.y += 1; }
    function _bumpArr(uint256[] storage p, uint256 i) internal { p[i] = 500; }
    function d1(uint256 i, uint256 want) external { _bump(structs[i]); require(structs[i].y == want); }
    function d2(uint256 i, uint256 want) external { _bump(structs[i]); require(structs[0].y == want); }
    function d3(uint256 i, uint256 want) external { _bumpArr(m[address(1)].xs, i); require(m[address(1)].xs[0] == want); }
    function d4(uint256 i, uint256 want) external { S storage p = structs[i]; p.y = 9; require(structs[1].y == want); }

    // (e) calldata arrays
    function e1(uint256[][] calldata g, uint256 i, uint256 j, uint256 want) external pure { require(g[i][j] == want); }
    function e2(bytes[] calldata bs, uint256 i, uint256 want) external pure { require(bs[i].length == want); }
    function e3(S calldata s, uint256 i, uint256 want) external pure { require(s.xs[i] + s.y == want); }
    function e4(uint256[] calldata xs, uint256 want) external pure { uint256[] memory c = xs; c[0] = 1; require(xs[0] == want); }

    // copy semantics
    function f1(uint256 want) external { uint256[] memory c = list2; list2[0] = 99; require(c[0] == want); }
    function f2(uint256 want) external { uint256[] memory c = new uint256[](1); c[0] = 5; list3 = c; c[0] = 7; require(list3[0] == want); }
    function f3(uint256 want) external { uint256[] storage p = list2; p[0] = 3; require(list2[0] == want); }
    function f4(uint256 i, uint256 want) external pure {
        uint256[2][2] memory g = [[uint256(1), 2], [uint256(3), 4]];
        require(g[i][1] == want);
    }
    function f5(uint256 i, uint256 want) external view { uint256[][] memory c = grid2; require(c[i][0] == want); }
    function f6(uint256 i, uint256 want) external pure {
        uint256[] memory a = new uint256[](2); a[1] = 6;
        uint256[] memory b = new uint256[](2); b[1] = 7;
        uint256[][2] memory pair = [a, b];
        a[1] = 9;
        require(pair[i][1] == want);
    }
    function f7(uint256 want) external { S memory c = structs[0]; structs[0].y = 1234; require(c.y == want); }
    function f8(uint256 want) external { S storage p = structs[0]; S memory c = p; p.y = 4321; require(c.y == want); }
}
"""

ELEMENT_CASES = [
    *[("a2", a) for a in [(3, 0, 0, 21), (3, 0, 0, 0), (3, 1, 0, 0), (4, 0, 0, 0)]],
    *[("a3", a) for a in [(0, 1, 32), (1, 0, 41), (1, 1, 0), (0, 0, 32)]],
    *[("a4", a) for a in [(1, 77), (0, 12), (0, 77), (1, 12), (2, 0)]],
    *[("b3", (n, w)) for n in range(5) for w in (2 + n, 2)],
    *[("c1", (n, w)) for n in range(6) for s in [sum(i for i in range(min(n, 3)) if i != 1)] for w in (s, s + 1)],
    *[("d2", a) for a in [(0, 51), (1, 50), (1, 51), (0, 50)]],
    *[("d3", a) for a in [(0, 500), (1, 11), (0, 11), (1, 500), (2, 11)]],
    *[("d4", a) for a in [(1, 9), (0, 60), (0, 9), (1, 60), (2, 60)]],
    ("e1", ([[1, 2], [3]], 0, 1, 2)), ("e1", ([[1, 2], [3]], 1, 0, 3)), ("e1", ([[1, 2], [3]], 1, 1, 0)),
    ("e1", ([[1, 2], [3]], 0, 1, 3)),
    ("e2", ([b"ab", b"cde"], 1, 3)), ("e2", ([b"ab", b"cde"], 0, 3)), ("e2", ([b"ab", b"cde"], 2, 0)),
    ("e3", ((5, [1, 2]), 1, 7)), ("e3", ((5, [1, 2]), 1, 6)), ("e3", ((5, [1, 2]), 2, 5)),
    ("e4", ([4, 5], 4)), ("e4", ([4, 5], 1)),
    ("f3", (3,)), ("f3", (1,)),
    *[("f4", a) for a in [(0, 2), (1, 4), (1, 2), (2, 0)]],
    *[("f5", a) for a in [(0, 31), (1, 41), (1, 31), (2, 0)]],
    *[("f6", a) for a in [(0, 9), (0, 6), (1, 7), (1, 9)]],
    ("f7", (50,)), ("f7", (1234,)), ("f8", (50,)), ("f8", (4321,)),
]  # fmt: skip


def _abi_types(fn):
    from slither.core.solidity_types import UserDefinedType

    return ["(uint256,uint256[])" if isinstance(p.type, UserDefinedType) else str(p.type) for p in fn.parameters]


@pytest.fixture(scope="module")
def elements(anvil):  # noqa: F811
    d = O.deployment(*anvil, ELEMENTS)
    d.deploy("C")
    assert O.transact(d, "C", "setup()")
    return d


@pytest.mark.parametrize(("name", "values"), ELEMENT_CASES, ids=[f"{c[0]}{c[1]}"[:50] for c in ELEMENT_CASES])
def test_an_element_read_the_lowering_answers_is_the_chains(elements, name, values):
    d = elements
    fn = O.function(d, "C", name)
    data = keccak(text=fn.solidity_signature)[:4] + encode(_abi_types(fn), list(values))
    chain = O.eth_call(d.url, d.at["C"], data, OWNER)
    reset_terms()
    c = d.slither["C"]
    formula = Lowerer(c).success(fn)
    world = World(d.chain(), d.at["C"], O.selector(fn.solidity_signature), {d.at["C"]: c})
    world.parameters = tuple(parameter(p, i) for i, p in enumerate(fn.parameters))
    # Every argument is bound, and each length or item of one the caller hands in (``len``/``elem`` over it, a struct
    # argument's fields by name) is what the ``eth_call`` sends.
    named: dict = {}
    for p, v in zip(fn.parameters, values):
        fields = getattr(getattr(p.type, "type", None), "elems_ordered", None)
        named.update({f"{p.name}.{f.name}": x for f, x in zip(fields, v)} if fields and isinstance(v, tuple) else {})
        named[p.name] = v
    assignment = {parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, values))}
    probe = Evaluator(world, {"caller": OWNER, "signer": OWNER}, dict(assignment))

    def held(t):
        if t[0] == "arg":
            return named.get(t[1])
        inner = held(t[1])
        if t[0] == "len":
            return len(inner) if isinstance(inner, (list, bytes)) else None
        index = probe.eval(t[2])
        ok = isinstance(inner, (list, bytes)) and isinstance(index, int) and 0 <= index < len(inner)
        return inner[index] if ok else 0

    def over_argument(t):
        while isinstance(t, tuple) and t and t[0] in ("len", "elem"):
            t = t[1]
        return isinstance(t, tuple) and t and t[0] == "arg"

    for t in subterms(formula, "arg"):
        if t not in assignment and isinstance(named.get(t[1]), int):
            assignment[t] = named[t[1]]  # a struct argument's field
    for t in sorted(subterms(formula, "len") + subterms(formula, "elem"), key=lambda t: len(str(t))):
        value = held(t) if over_argument(t) else None
        if value is not None:
            assignment[t] = value
    engine = Evaluator(world, {"caller": OWNER, "signer": OWNER}, assignment).truth(formula)
    O.agrees(formula, engine, chain, (name, values))


# --- audit 3, return values (``harness.py``): loops, modifiers, Yul, and pre-0.5 declarations ----------------------

LOOPS = r"""
pragma solidity 0.8.27;
library Lib {
    function libLoop(uint256 n) internal pure returns (uint256 s) {
        for (uint256 i; i < n + 2; i++) { for (uint256 j; j < 3; j++) { if (j == 1) { break; } s += 10; } s += 1; }
    }
}
contract B {
    function baseLoop(uint256 n) internal pure returns (uint256 s) {
        for (uint256 i; i < 3; i++) { while (true) { s += 1; if (s % 2 == 0) { break; } } s += 100; } s += n;
    }
}
contract C is B {
    uint256 private t;
    modifier rep(uint256 n) { for (uint256 i; i < n; i++) { if (i == 2) break; _; } }
    modifier rep2(uint256 n) { for (uint256 i; i < 3; i++) { _; if (i + 1 == n) { break; } } }
    function nestedIfElse(uint256 n) external pure returns (uint256 s) {
        for (uint256 i; i < 5; i++) {
            for (uint256 j; j < 5; j++) {
                if (j > n) { { if (i % 2 == 0) { break; } } } else { { s += 1; if (j == 3) { { break; } } } }
                s += 10;
            }
            s += 100;
        }
    }
    function oneLine(uint256 n) external pure returns (uint256 s) {
        for (uint256 i; i < n; i++) { s += 1; if (i == 1) break; } for (uint256 k; k < 4; k++) { if (k == n) break; s += 10; }
    }
    function oneLine2(uint256 n) external pure returns (uint256 s) { for (uint256 i; i < 3; i++) { for (uint256 k; k < 4; k++) { if (k == n) break; s += 10; } if (i == n) break; s += 1; } }
    function modLoop(uint256 n) external rep(n) returns (uint256) { t += 1; return t; }
    function modLoop2(uint256 n) external rep2(n) returns (uint256) { t += 1; return t; }
    function lib(uint256 n) external pure returns (uint256) { return Lib.libLoop(n); }
    function base(uint256 n) external pure returns (uint256) { return baseLoop(n); }
    function yulEmptyPost(uint256 n) external pure returns (uint256 s) {
        assembly { let k := 0 for { } 1 { } { k := add(k, 1) if gt(k, n) { break } s := add(s, k) } }
    }
    function yulEmptyInit(uint256 n) external pure returns (uint256 s) {
        assembly { let k := 0 for { } lt(k, n) { k := add(k, 1) } { s := add(s, 3) } }
    }
    function yulEmptyBody(uint256 n) external pure returns (uint256 s) {
        assembly { for { let k := 0 } lt(k, n) { k := add(k, 1) s := add(s, 2) } { } }
    }
    function yulNestedBreakIf(uint256 n) external pure returns (uint256 s) {
        assembly {
            for { let i := 0 } lt(i, 4) { i := add(i, 1) } {
                switch gt(i, n) case 1 { break } default { s := add(s, 1) }
                for { let j := 0 } lt(j, 4) { j := add(j, 1) } { if eq(j, i) { continue } if gt(j, 2) { break } s := add(s, 10) }
            }
        }
    }
    function uncheckedLoop(uint256 n) external pure returns (uint256 s) {
        for (uint256 i; i < 6; ) { unchecked { i++; } if (i > n) { unchecked { break; } } s += i; }
    }
    function tryInLoop(uint256 n) external view returns (uint256 s) {
        for (uint256 i; i < 5; i++) {
            try this.pureThing(i) returns (uint256 v) { if (v > n) break; s += v; } catch { s += 1000; continue; }
            s += 1;
        }
    }
    function pureThing(uint256 i) external pure returns (uint256) { require(i != 2); return i * 2; }
    function doWhileContinue(uint256 n) external pure returns (uint256 s) {
        uint256 i;
        do { i++; if (i == 2) continue; if (i > n + 1) break; s += i; } while (i < 5);
    }
    function whileEmptyBody(uint256 n) external pure returns (uint256 s) {
        while (s < n * 3) s++;
    }
}
"""
YUL2 = r"""
pragma solidity 0.8.27;
contract C {
    function yulFnLoop(uint256 n) external pure returns (uint256 s) {
        for (uint256 i; i < 3; i++) {
            assembly {
                function f(m) -> r { for { let k := 0 } 1 { k := add(k, 1) } { if gt(k, m) { break } r := add(r, 1) } }
                s := add(s, f(n))
            }
            if (i == n) break;
        }
    }
    function yulBreakInSol(uint256 n) external pure returns (uint256 s) {
        for (uint256 i; i < 3; i++) {
            assembly { for { let k := 0 } lt(k, 5) { k := add(k, 1) } { if eq(k, n) { break } s := add(s, 1) } }
            s += 100;
        }
    }
    function yulLeaveLoop(uint256 n) external pure returns (uint256 s) {
        assembly {
            function g(m) -> r { for { let k := 0 } 1 { k := add(k, 1) } { if gt(k, m) { leave } r := add(r, 2) } }
            s := g(n)
        }
    }
    function yulSwitchBreak(uint256 n) external pure returns (uint256 s) {
        assembly {
            for { let k := 0 } lt(k, 6) { k := add(k, 1) } {
                switch k case 3 { if gt(n, 1) { break } } default { s := add(s, k) }
            }
        }
    }
    function yulDeclLoop(uint256 n) external pure returns (uint256 s) {
        assembly {
            for { let k := 0 } lt(k, n) { k := add(k, 1) } { let j s := add(s, add(j, 1)) j := 7 }
        }
    }
}
"""
YUL05 = r"""
pragma solidity 0.5.14;
contract C {
    function yulDeclLoop(uint256 n) public pure returns (uint256 s) {
        assembly {
            for { let k := 0 } lt(k, n) { k := add(k, 1) } { let j s := add(s, add(j, 1)) j := 7 }
        }
    }
    function yulFor(uint256 n) public pure returns (uint256 s) {
        assembly { for { let k := 0 } lt(k, n) { k := add(k, 1) } { s := add(s, 2) } }
    }
}
"""
D04 = r"""
pragma solidity 0.4.19;
contract C {
    struct S { uint256 x; }
    function innerNoInit(uint256 n) public pure returns (uint256 s) {
        for (uint256 i = 0; i < 3; i++) { for (uint256 j; j < n; j++) { s += 1; } }
    }
    function forInitReuse(uint256 n) public pure returns (uint256) {
        for (uint256 i = 0; i < n; i++) { }
        uint256 t = i;
        for (i = 1; i < 3; i++) { t += 10; }
        return t + i;
    }
    function varType(uint256 n) public pure returns (uint256) {
        var x = 255;
        x += uint8(n);
        return x;
    }
    function memBranch(uint256 n) public pure returns (uint256) {
        if (n > 1) { S memory m; m.x = 5; }
        return m.x + n;
    }
    function memAlias(uint256 n) public pure returns (uint256) {
        S[] memory arr = new S[](3);
        for (uint256 i = 0; i < 3; i++) { S memory m; m.x = i + n; arr[i] = m; }
        return arr[0].x * 100 + arr[1].x * 10 + arr[2].x;
    }
    function memAliasNoLoop(uint256 n) public pure returns (uint256) {
        S memory a; a.x = n; S memory b; b.x = 7;
        return a.x * 10 + b.x;
    }
    function shadowState(uint256 n) public pure returns (uint256 s) {
        uint256 k = 1;
        if (n > 0) { s = k; }
        for (uint256 q = 0; q < 2; q++) { uint256 w = q + w; s += w; }
    }
    function useBeforeDeclInLoop(uint256 n) public pure returns (uint256 s) {
        for (uint256 i = 0; i < 3; i++) { if (i > 0) { s += z; } uint256 z; z += n + 1; }
    }
}
"""
D04B = r"""
pragma solidity 0.4.19;
pragma experimental "v0.5.0";
contract C {
    struct S { uint256 x; }
    function acc(uint256 n) public pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) { uint256 j; j += 1; s += j; }
    }
    function memAcc(uint256 n) public pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) { S memory m; m.x += 1; s += m.x; }
    }
    function shadow(uint256 n) public pure returns (uint256 s) {
        for (uint256 i = 0; i < n; i++) { { uint256 a; a += 2; s += a; } { uint256 a2; a2 += 1; s += a2; } }
    }
}
"""

RETURNS = {
    "loops": (LOOPS, "0.8.27", ["nestedIfElse", "oneLine", "oneLine2", "modLoop", "modLoop2", "lib", "base",
                                "yulEmptyPost", "yulEmptyInit", "yulEmptyBody", "yulNestedBreakIf", "uncheckedLoop",
                                "tryInLoop", "doWhileContinue", "whileEmptyBody"]),
    "yul2": (YUL2, "0.8.27", ["yulFnLoop", "yulBreakInSol", "yulLeaveLoop", "yulSwitchBreak"]),
    "yul05": (YUL05, "0.5.14", ["yulDeclLoop", "yulFor"]),
    "d04": (D04, "0.4.19", ["innerNoInit", "forInitReuse", "varType", "memBranch", "memAlias", "memAliasNoLoop",
                            "shadowState", "useBeforeDeclInLoop"]),
    "d04b": (D04B, "0.4.19", ["acc", "memAcc", "shadow"]),
}  # fmt: skip
RETURN_CASES = [(k, name) for k, (_, _, names) in RETURNS.items() for name in names]


@pytest.fixture(scope="module")
def returning(anvil):  # noqa: F811
    out = {}
    for key, (source, version, _) in RETURNS.items():
        out[key] = O.deployment(*anvil, source, version)
        out[key].deploy("C")
    return out


@pytest.mark.parametrize(("key", "name"), RETURN_CASES, ids=[f"{k}-{n}" for k, n in RETURN_CASES])
def test_a_return_value_the_lowering_answers_is_the_chains(returning, key, name):
    d = returning[key]
    c = d.slither["C"]
    fn = O.function(d, "C", name)
    definite = 0
    for n in range(5):
        data = keccak(text=fn.solidity_signature)[:4] + encode(["uint256"], [n])
        try:
            raw = rpc(d.url, "eth_call", [{"from": O.hex20(OWNER), "to": O.hex20(d.at["C"]), "data": "0x" + data.hex()},
                                          "latest"])  # fmt: skip
            chain = decode(["uint256"], bytes.fromhex(raw[2:]))[0]
        except RuntimeError:
            chain = "revert"
        reset_terms()
        pc, ret = Lowerer(c).returns(fn, [const(n)])
        world = World(d.chain(), d.at["C"], O.selector(fn.solidity_signature), {d.at["C"]: c})
        ev = Evaluator(world, {"caller": OWNER, "signer": OWNER}, {})
        passes = ev.truth(pc)
        value = ev.eval(ret[0]) if ret else UNK
        if passes is False:
            engine = "revert"
        elif passes is True and isinstance(value, int) and not isinstance(value, bool):
            engine = value
        else:
            # Unknown only for what the lowering says it couldn't follow (a named unknown), or where no path set a
            # return value (a modifier that never ran ``_``): never a silent guess.
            assert not ret or any(subterms(x, "unknown") or subterms(x, "opaque") for x in (pc, *ret)), (name, n, pc)
            continue
        definite += 1
        assert engine == chain, (key, name, n, chain, engine)


MODS = r"""
pragma solidity 0.8.27;
contract C {
    uint256 private t;
    modifier rep(uint256 n, uint256 want) { uint256 b = t; for (uint256 i; i < n; i++) { if (i == 2) break; _; } require(t - b == want); }
    modifier rep2(uint256 n, uint256 want) { uint256 b = t; for (uint256 i; i < 3; i++) { _; if (i + 1 == n) { break; } } require(t - b == want); }
    modifier rep3(uint256 n, uint256 want) { uint256 b = t; uint256 i; while (true) { i++; if (i > n) break; _; } require(t - b == want); }
    function modLoop(uint256 n, uint256 want) external rep(n, want) { t += 1; }
    function modLoop2(uint256 n, uint256 want) external rep2(n, want) { t += 1; }
    function modLoop3(uint256 n, uint256 want) external rep3(n, want) { for (uint256 k; k < 2; k++) { if (k == 1) break; t += 1; } }
}
"""


@pytest.fixture(scope="module")
def mods(anvil):  # noqa: F811
    d = O.deployment(*anvil, MODS)
    d.deploy("C")
    return d


@pytest.mark.parametrize("name", ["modLoop", "modLoop2", "modLoop3"])
def test_a_modifier_running_its_body_in_a_loop_is_the_chains(mods, name):
    fn = O.function(mods, "C", name)
    for n in range(5):
        for want in range(6):
            formula, engine = O.engine_says(mods, fn, (n, want))
            O.agrees(formula, engine, O.chain_says(mods, fn, (n, want)), (name, n, want))


# --- verdict probes: audit 1 (callee2, latch, reject), audit 2 (q12, q4 nest), audit 3 (a_inlined/missing/open) ----

CALLEE2 = r"""
pragma solidity 0.8.27;

contract B {
    mapping(uint256 => address) public asker;
    function setAsker(uint256 k, address x) external { asker[k] = x; }
    // True when the contract asking about ``k`` is the one recorded for it.
    function check(uint256 k) external view returns (bool) { return asker[k] == msg.sender; }
}
contract A {
    B public b;
    constructor(B x) { b = x; }
    function ok(uint256 k) external view returns (bool) { return b.check(k); }
}
contract C {
    A public a;
    uint256 public x;
    constructor(A y) { a = y; }
    // Anyone naming k = 7 passes (A is recorded for 7).
    function f(uint256 k) external { require(k == 7 || k == 8); require(a.ok(k)); x = k; }
}
"""
LATCH = r"""
pragma solidity 0.8.27;

interface IGate { function open() external view returns (bool); }
contract Gate { function open() external pure returns (bool) { return true; } }
contract Inner {
    // Its own immutable: the gate a factory will deploy later (a counterfactual address, no code yet).
    address constant GATE = 0x00000000000000000000000000000000DeaDBeef;
    function ok() external view returns (bool) { return IGate(GATE).open(); }
}
contract C {
    address constant GATE = 0x00000000000000000000000000000000DeaDBeef;
    address public admin;
    Inner public inner;
    uint256 public x;
    constructor(Inner i) { admin = msg.sender; inner = i; }
    function setInner(Inner i) external { require(msg.sender == admin); inner = i; }
    function viaCall() external { require(IGate(GATE).open()); x = 1; }
    function viaCode() external { require(GATE.code.length > 0); x = 2; }
    function viaInner() external { require(inner.ok()); x = 3; }
}
"""
REJECT = r"""
pragma solidity 0.8.27;

contract Token {
    mapping(address => uint256) public balanceOf;
    constructor() { balanceOf[msg.sender] = 1e18; }
    function transfer(address to, uint256 v) external returns (bool) { balanceOf[msg.sender] -= v; balanceOf[to] += v; return true; }
}

library SafeT {
    // Aave's copy of OZ 5.x SafeERC20 transfer, verbatim shape.
    function safeTransfer(address token, address to, uint256 value, bool bubble) internal returns (bool success) {
        bytes4 selector = 0xa9059cbb;
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(0x00, selector)
            mstore(0x04, and(to, shr(96, not(0))))
            mstore(0x24, value)
            success := call(gas(), token, 0, 0x00, 0x44, 0x00, 0x20)
            if iszero(and(success, eq(mload(0x00), 1))) {
                if and(iszero(success), bubble) {
                    returndatacopy(fmp, 0x00, returndatasize())
                    revert(fmp, returndatasize())
                }
                success := and(success, and(iszero(returndatasize()), gt(extcodesize(token), 0)))
            }
            mstore(0x40, fmp)
        }
    }
    function bubble(bytes memory returndata) internal pure {
        if (returndata.length > 0) {
            assembly ("memory-safe") { revert(add(32, returndata), mload(returndata)) }
        }
        revert("failed");
    }
    function isValid1271(address signer, bytes32 hash, bytes memory signature) internal view returns (bool result) {
        bytes4 selector = 0x1626ba7e;
        uint256 length = signature.length;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(ptr, selector)
            mstore(add(ptr, 0x04), hash)
            mstore(add(ptr, 0x24), 0x40)
            mcopy(add(ptr, 0x44), signature, add(length, 0x20))
            let success := staticcall(gas(), signer, ptr, add(length, 0x64), 0x00, 0x20)
            result := and(success, and(gt(returndatasize(), 0x1f), eq(mload(0x00), selector)))
        }
    }
}

contract C {
    address public owner;
    address public token;
    uint256 public x;
    constructor(address t) { owner = msg.sender; token = t; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function sweep(address to, uint256 v) external onlyOwner { require(SafeT.safeTransfer(token, to, v, true)); }
    function forward(address t, bytes calldata d) external onlyOwner {
        (bool ok, bytes memory r) = t.call(d);
        if (!ok) SafeT.bubble(r);
        x += 1;
    }
    function bySig(bytes32 h, bytes calldata sig) external {
        require(msg.sender == owner || SafeT.isValid1271(owner, h, sig));
        x += 2;
    }
    function lowLevel() external onlyOwner {
        uint256 g;
        assembly { g := gas() }
        x = 3;
    }
}
"""
Q12 = r"""
pragma solidity 0.8.27;
contract B {
    address public a;
    function setA(address x) external { a = x; }
    // sender read through Yul caller()
    function yc(uint256 v) external view returns (bool) { address s; assembly { s := caller() } require(s == a); return v == 7; }
    // sender behind recursion (unanalysed)
    function rc(uint256 v) external view returns (bool) { require(_who(2) == a); return v == 7; }
    function _who(uint256 n) internal view returns (address) { return n == 0 ? msg.sender : _who(n - 1); }
    // sender hidden behind a delegatecall into a library-like helper
    function plain(uint256 v) external view returns (bool) { return v == 7; }
}
contract A {
    B public b;
    constructor(B x) { b = x; }
    function yc(uint256 v) external view returns (bool) { return b.yc(v); }
    function rc(uint256 v) external view returns (bool) { return b.rc(v); }
    function pl(uint256 v) external view returns (bool) { return b.plain(v); }
}
contract L {
    // Yul for loop: t = 3 on chain
    function ok(uint256 v) external pure returns (bool) { uint256 t; assembly { for { let k := 0 } lt(k, 3) { k := add(k, 1) } { t := add(t, 1) } } return t == v; }
    // own calldatasize: unknown in the callee frame
    function sz(uint256 v) external pure returns (bool) { return msg.data.length == 36 && v == 3; }
}
contract C {
    A public a; L public l; address public owner; uint256 public x;
    constructor(A y, L z) { a = y; l = z; owner = msg.sender; }
    function fyc(uint256 v) external { require(a.yc(v) || msg.sender == owner); x = v; }
    function frc(uint256 v) external { require(a.rc(v) || msg.sender == owner); x = v; }
    function fpl(uint256 v) external { require(a.pl(v) || msg.sender == owner); x = v; }
    function floop(uint256 v) external { require(l.ok(v) || msg.sender == owner); x = v; }
    function fsz(uint256 v) external { require(l.sz(v) || msg.sender == owner); x = v; }
}
"""
NEST = r"""
pragma solidity 0.8.27;
contract C {
    address public owner; uint256 public x;
    constructor() { owner = msg.sender; }
    function va() public pure returns (uint256 s) {
        for (uint256 i; i < 2; i++) { uint256 j; while (j < 2) { uint256 k; for (;;) { k++; if (k > 1) break; } s += k; j++; } }
    }
    function vb() public pure returns (uint256 s) {
        for (uint256 i; i < 2; i++) { for (;;) { s++; if (s % 3 == 0) break; } }
    }
    function fa() external { uint256 s;
        for (uint256 i; i < 2; i++) { uint256 j; while (j < 2) { uint256 k; for (;;) { k++; if (k > 1) break; } s += k; j++; } }
        require(s == 8 || msg.sender == owner); x = 1; }
    function fb() external { uint256 s;
        for (uint256 i; i < 2; i++) { for (;;) { s++; if (s % 3 == 0) break; } }
        require(s == 6 || msg.sender == owner); x = 2; }
}
"""
INLINED = r"""
pragma solidity 0.8.27;
contract G {
    address public owner;
    constructor(address o) { owner = o; }
    function check(address who, uint256 v) external view returns (bool) {
        if (tx.origin == address(1)) return false;
        uint256 bad;
        assembly { for { let k := 0 } lt(k, 3) { k := add(k, 1) } { let seen if eq(k, 0) { seen := 1 } bad := add(bad, seen) } }
        return (bad == 1 && v == 7) || who == owner;
    }
    function gate(address who, uint256 v) external view returns (bool) {
        if (tx.origin == address(1)) return false;
        return v == 7 || who == owner;
    }
    function shut(address who, uint256 v) external view returns (bool) {
        if (tx.origin == address(1)) return false;
        v;
        return who == owner;
    }
}
contract C {
    G public g; uint256 public x;
    constructor(G z) { g = z; }
    function f(uint256 v) external { require(g.check(msg.sender, v)); x = v; }
    function h(uint256 v) external { require(g.gate(msg.sender, v)); x = v; }
    function s(uint256 v) external { require(g.shut(msg.sender, v)); x = v; }
}
"""
MISSING = r"""
pragma solidity 0.8.27;
contract G {
    address public owner; address public admin2;
    constructor(address o, address a) { owner = o; admin2 = a; }
    function ok(address who) external view returns (bool) {
        uint256 bad;
        assembly { for { let k := 0 } lt(k, 3) { k := add(k, 1) } { let seen if eq(k, 0) { seen := 1 } bad := add(bad, seen) } }
        return (bad == 1 && who == admin2) || who == owner;
    }
    function okO(address who) external view returns (bool) {
        if (tx.origin == address(1)) return false;
        uint256 bad;
        assembly { for { let k := 0 } lt(k, 3) { k := add(k, 1) } { let seen if eq(k, 0) { seen := 1 } bad := add(bad, seen) } }
        return (bad == 1 && who == admin2) || who == owner;
    }
}
contract C {
    G public g; uint256 public x;
    constructor(G z) { g = z; }
    function m() external { require(g.ok(msg.sender)); x = 1; }
    function mo() external { require(g.okO(msg.sender)); x = 1; }
}
"""
OPEN = r"""
pragma solidity 0.8.27;
contract G {
    address public owner;
    constructor(address o) { owner = o; }
    function shut(address who, uint256 v) external view returns (bool) {
        v;
        uint256 bad;
        assembly { for { let k := 0 } lt(k, 3) { k := add(k, 1) } { let seen if eq(k, 0) { seen := 1 } bad := add(bad, seen) } }
        return bad == 3 || who == owner;
    }
    function shutO(address who, uint256 v) external view returns (bool) {
        if (tx.origin == address(1)) return false;
        v;
        uint256 bad;
        assembly { for { let k := 0 } lt(k, 3) { k := add(k, 1) } { let seen if eq(k, 0) { seen := 1 } bad := add(bad, seen) } }
        return bad == 3 || who == owner;
    }
}
contract C {
    G public g; uint256 public x;
    constructor(G z) { g = z; }
    function s(uint256 v) external { require(g.shut(msg.sender, v)); x = v; }
    function s0() external { require(g.shut(msg.sender, 5)); x = 1; }
    function so(uint256 v) external { require(g.shutO(msg.sender, v)); x = v; }
}
"""
ADMIN2 = 0xA2


def _callee2(d):
    d.deploy("B")
    d.deploy("A", ("address",), (d.at["B"],))
    d.deploy("C", ("address",), (d.at["A"],))
    assert O.transact(d, "B", "setAsker(uint256,address)", ("uint256", "address"), (7, d.at["A"]))


def _latch(d):
    d.deploy("Inner")
    d.deploy("C", ("address",), (d.at["Inner"],))
    d.deploy("Gate")


def _reject(d):
    d.deploy("Token")
    d.deploy("C", ("address",), (d.at["Token"],))


def _q12(d):
    d.deploy("B")
    d.deploy("A", ("address",), (d.at["B"],))
    d.deploy("L")
    d.deploy("C", ("address", "address"), (d.at["A"], d.at["L"]))
    assert O.transact(d, "B", "setA(address)", ("address",), (d.at["A"],))


def _nest(d):
    d.deploy("C")


def _guarded(d):
    d.deploy("G", ("address",), (OWNER,))
    d.deploy("C", ("address",), (d.at["G"],))


def _missing(d):
    d.deploy("G", ("address", "address"), (OWNER, ADMIN2))
    d.deploy("C", ("address",), (d.at["G"],))


SETUPS = {
    "callee2": (CALLEE2, _callee2, [("C", "f", ("A", "B"))]),
    "latch": (LATCH, _latch, [("C", n, ("Inner",)) for n in ("viaCall", "viaCode", "viaInner")]),
    "reject": (REJECT, _reject, [("C", n, ("Token",)) for n in ("sweep", "forward", "bySig", "lowLevel")]),
    "q12": (Q12, _q12, [("C", n, ("A", "B", "L")) for n in ("fyc", "frc", "fpl", "floop", "fsz")]),
    "nest": (NEST, _nest, [("C", "fa", ()), ("C", "fb", ())]),
    "inlined": (INLINED, _guarded, [("C", n, ("G",)) for n in ("f", "h", "s")]),
    "missing": (MISSING, _missing, [("C", "m", ("G",)), ("C", "mo", ("G",))]),
    "open": (OPEN, _guarded, [("C", n, ("G",)) for n in ("s", "s0", "so")]),
}
PROBES = [O.Probe(source, setup, tuple(functions)) for source, setup, functions in SETUPS.values()]


@pytest.fixture(scope="module")
def setups(anvil):  # noqa: F811
    out = {}
    for key, (source, setup, _) in SETUPS.items():
        out[key] = O.deployment(*anvil, source)
        setup(out[key])
    return out


V = [{"v": 0}, {"v": 3}, {"v": 7}, {"k": 7}, {"k": 8}, {}]


def test_a_known_request_the_chain_answers_is_never_nobody(setups):
    # audit 1: anyone naming k = 7 passes (A is recorded for 7 in B, asked by A, not by C).
    d = setups["callee2"]
    v = O.check(d, "C", "f", O.verdict(d, "C", "f", "A", "B"), samples=({"k": 8},), open_at={"k": 7})
    assert v.openness == "open"


@pytest.mark.parametrize("name", ["viaCall", "viaCode", "viaInner"])
def test_no_code_at_a_constant_now_is_never_nobody_ever(setups, name):
    # audit 1: a gate a factory deploys later at 0xDeaDBeef: once code is there, every stranger passes.
    d = setups["latch"]

    def gate_deployed(d):
        code = rpc(d.url, "eth_getCode", [O.hex20(d.at["Gate"]), "latest"])
        rpc(d.url, "anvil_setCode", ["0x00000000000000000000000000000000deadbeef", code])

    v = O.check(d, "C", name, O.verdict(d, "C", name, "Inner"), open_at=False, later=gate_deployed)
    assert not O.nobody(v), v
    with O.snapshot(d):
        gate_deployed(d)
        assert O.strangers_passing(d, "C", O.function(d, "C", name)) == {True}


@pytest.mark.parametrize("name", ["sweep", "forward", "bySig", "lowLevel"])
def test_a_rejected_builtin_in_a_helper_deciding_nothing_keeps_the_owner(setups, name):
    # audit 1: gas(), returndatasize() inside library helpers the owner's own gate is beside.
    d = setups["reject"]
    samples = [{"to": OWNER, "v": 0}, {"t": d.at["Token"], "d": b""}, {"h": bytes(32), "sig": b""}, {}]
    v = O.check(d, "C", name, O.verdict(d, "C", name, "Token"), samples=samples, open_at=False)
    O.sound(v, {OWNER})


@pytest.mark.parametrize(("name", "value"), [("fyc", 7), ("frc", 7), ("fpl", 7), ("floop", 3), ("fsz", 3)])
def test_a_callee_asked_with_the_right_asker_is_never_a_confident_list_missing_a_stranger(setups, name, value):
    # audit 2 (Q1/Q2): the asker a callee sees, its own frame, a Yul loop in it.
    d = setups["q12"]
    fn = O.function(d, "C", name)
    anyone = O.strangers_passing(d, "C", fn, {"v": value}) == {True}
    v = O.check(d, "C", name, O.verdict(d, "C", name, "A", "B", "L"), samples=({"v": value}, {"v": 0}),
                open_at={"v": value} if anyone else None)  # fmt: skip
    if anyone:
        assert v.openness == "open", v


@pytest.mark.parametrize("name", ["fa", "fb"])
def test_nested_forever_loops_are_followed_to_the_chains_sum(setups, name):
    # audit 2 (Q4): s is 8 (fa) and 6 (fb) on the chain, so every stranger passes.
    d = setups["nest"]
    O.check(d, "C", name, O.verdict(d, "C", name), open_at={})


@pytest.fixture
def misread(monkeypatch):
    def apply(answer):
        called = Lowerer.called

        def wrong(self, function, args, view):
            if getattr(getattr(function, "contract", None), "name", None) == "G":
                return TRUE, (answer,)
            return called(self, function, args, view)

        monkeypatch.setattr(Lowerer, "called", wrong)

    return apply


@pytest.mark.parametrize(("name", "answer"), [("f", None), ("h", FALSE), ("s", TRUE)])
def test_an_inlined_origin_reading_callee_mis_lowered_is_never_bolder(setups, misread, name, answer):
    # audit 3: G's checks read tx.origin, so they are inlined; mis-lowered as "nobody" (h) or "everyone" (s).
    d = setups["inlined"]
    clean = O.check(d, "C", name, O.verdict(d, "C", name, "G"), samples=V)
    if answer is not None:
        misread(answer)
        faulted = O.verdict(d, "C", name, "G")
        O.check(d, "C", name, faulted, samples=V)
        O.never_bolder(clean, faulted)


@pytest.mark.parametrize("name", ["m", "mo"])
def test_a_callee_whose_loop_names_a_second_admin_lists_it_or_stays_partial(setups, name):
    # audit 3: the Yul loop in G leaves ``bad == 1``, so ADMIN2 passes beside the owner.
    d = setups["missing"]
    fn = O.function(d, "C", name)
    assert O.passes(d, "C", fn, sender=ADMIN2) and O.passes(d, "C", fn, sender=OWNER)
    v = O.check(d, "C", name, O.verdict(d, "C", name, "G"), known=(ADMIN2,))
    O.sound(v, {OWNER, ADMIN2})


@pytest.mark.parametrize("name", ["s", "s0", "so"])
def test_a_callee_whose_loop_shuts_everyone_but_the_owner_out(setups, name):
    # audit 3: ``bad == 3`` never holds on the chain: only the owner passes.
    d = setups["open"]
    v = O.check(d, "C", name, O.verdict(d, "C", name, "G"), samples=({"v": 0}, {"v": 7}, {}), open_at=False)
    O.sound(v, {OWNER})
