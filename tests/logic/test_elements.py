"""Element reads and loop-carried values, as the language defines them: an item of a container (memory, storage or
calldata; a static or dynamic array, a mapping, a struct field) is that item, at whatever index, never the container;
an index out of range reverts; and a loop run further than the lowering follows forgets everything its body may write
and may still return or break out, never keeping a binding from the iterations it did run."""

from __future__ import annotations

import pytest

from services.logic.decide import UNK, Evaluator, World
from services.logic.lower import Lowerer, parameter
from services.logic.terms import FALSE, TRUE, const, contains, replace_terms, reset_terms, subterms
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
from tests.logic import _oracle as O
from tests.logic._anvil import Deployment, anvil  # noqa: F401

PURE = """
pragma solidity 0.8.27;

contract C {
    struct S { uint256 a; uint256[] xs; }
    struct Cfg { bool live; address admin; }

    mapping(address => uint256) balances;
    uint256[] list;
    uint256[4] fixedList;
    Cfg cfg;
    mapping(uint256 => uint256) m;

    constructor() { list.push(3); list.push(0); fixedList[1] = 2; balances[msg.sender] = 1; }
    function push(uint256 v) external { list.push(v); }

    function literal(uint256 i) external pure { uint256[3] memory a = [uint256(4), 5, 6]; require(a[i] == 5); }
    function written(uint256 i) external pure {
        uint256[] memory a = new uint256[](3);
        a[i] = 7;
        require(a[1] == 7);
    }
    function sized(uint256 n) external pure { uint256[] memory a = new uint256[](n); require(a[0] == 0); }
    function grid(uint256 i, uint256 j) external pure {
        uint256[2][2] memory g;
        g[i][j] = 9;
        require(g[1][0] == 9);
    }
    function member(uint256 i) external pure {
        S memory s;
        s.xs = new uint256[](2);
        s.xs[i] = 3;
        require(s.xs[1] == 3);
    }
    function copied(uint256 i) external pure {
        uint256[] memory a = new uint256[](2);
        uint256[] memory b = a;
        b[i] = 1;
        require(b[0] == 1);
    }
    function aliased(uint256 i) external pure {
        uint256[] memory a = new uint256[](2);
        uint256[] memory b = a;
        b[i] = 1;
        require(a[0] == 1);
    }
    function filled() external pure { uint256[] memory a = new uint256[](2); _fill(a); require(a[0] == 7); }
    function _fill(uint256[] memory x) internal pure { x[0] = 7; }
    function rebound() external pure { uint256[] memory a = new uint256[](2); _rebind(a); require(a[0] == 0); }
    function _rebind(uint256[] memory x) internal pure { x = new uint256[](1); x[0] = 7; }
    function fieldAlias() external pure {
        uint256[] memory a = new uint256[](2);
        S memory s;
        s.xs = a;
        a[1] = 5;
        require(s.xs[1] == 5);
    }
    function fresh(uint256 n) external pure {
        uint256 total;
        for (uint256 i; i < 2; i++) { S memory s; total += s.a; s.a = 3; }
        require(total == 0);
    }
    function calldataArray(uint256[] calldata xs, uint256 i) external pure { require(xs[i] == 5); }
    function calldataFixed(uint256[2] calldata ys, uint256 i) external pure { require(ys[i] == 5); }
    function calldataByte(bytes calldata d) external pure { require(d[0] == 0x01); }
    function dataByte() external pure { require(msg.data[0] == 0x01); }
    function firstBytes(bytes calldata d, bytes4 want) external pure { require(bytes4(d[:4]) == want); }
    function mapped(address who) external view { require(balances[who] > 0); }
    function stored(uint256 i) external view { require(list[i] > 0); }
    function storedFixed(uint256 i) external view { require(fixedList[i] > 0); }
    function wholeThenField(address a) external { cfg = Cfg(true, a); require(cfg.live && cfg.admin == a); }
    function deletedThenField() external { delete cfg; require(!cfg.live && cfg.admin == address(0)); }
    function crossed(bool c, uint256 x, uint256 y, uint256 want) external {
        if (c) { m[x] = 1; m[y] = 2; } else { m[y] = 3; m[x] = 4; }
        require(m[x] == want);
    }
    function rawAgain() external {
        assembly { sstore(5, caller()) }
        address back;
        assembly { back := sload(5) }
        require(back == msg.sender);
    }
    struct P { uint256 a; }
    P pa;
    P pb;
    uint256 x;
    function setX(uint256 v) external { x = v; }
    function selfCalled() external { x = 1; this.setX(2); require(x == 1); }
    function chosen(bool c) external {
        P storage p;
        if (c) p = pa; else p = pb;
        p.a = 5;
        require(pa.a == 5 || !c);
    }
    function later(uint256 n) external pure {
        bool flag;
        for (uint256 i; i < n; i++) { if (i == 5) flag = true; }
        require(!flag);
    }
}
"""


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    solc = solc_path("0.8.27")
    if solc is None:
        pytest.skip("solc 0.8.27 not installed")
    from slither import Slither

    path = tmp_path_factory.mktemp("elements") / "C.sol"
    path.write_text(PURE)
    return next(c for c in Slither(str(path), solc=str(solc)).contracts if c.name == "C")


def _formula(contract, name):
    from services.logic.terms import reset_terms

    reset_terms()
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    return Lowerer(contract).success(fn)


def _at(formula, **args):
    """``formula`` with each argument a constant: folded as far as the constructors go."""
    mapping = {}
    for t in subterms(formula, "arg"):
        if t[1] in args:
            value = args[t[1]]
            mapping[t] = const(value, "bool") if isinstance(value, bool) else const(value, t[2])
    return replace_terms(formula, mapping)


def test_a_memory_literal_is_read_at_a_constant_or_a_symbolic_index(contract):
    formula = _formula(contract, "literal")
    assert _at(formula, i=1) == TRUE
    assert _at(formula, i=0) == FALSE and _at(formula, i=2) == FALSE
    assert _at(formula, i=3) == FALSE  # out of range: Panic 0x32


def test_a_write_at_a_symbolic_index_lands_on_that_item(contract):
    formula = _formula(contract, "written")
    assert _at(formula, i=1) == TRUE
    assert _at(formula, i=0) == FALSE and _at(formula, i=5) == FALSE


def test_a_fresh_array_of_any_length_holds_zeros_within_its_length(contract):
    formula = _formula(contract, "sized")
    assert _at(formula, n=1) == TRUE and _at(formula, n=0) == FALSE


def test_nested_memory_writes_reach_the_outer_value(contract):
    assert _at(_formula(contract, "grid"), i=1, j=0) == TRUE
    assert _at(_formula(contract, "grid"), i=0, j=1) == FALSE
    assert _at(_formula(contract, "member"), i=1) == TRUE
    assert _at(_formula(contract, "member"), i=0) == FALSE


def test_two_names_for_one_memory_object_see_each_others_writes(contract):
    assert _at(_formula(contract, "aliased"), i=0) == TRUE
    assert _at(_formula(contract, "aliased"), i=1) == FALSE
    assert _formula(contract, "fieldAlias") == TRUE


def test_a_callee_writes_into_the_callers_object_but_reassigning_its_parameter_does_not(contract):
    assert _formula(contract, "filled") == TRUE
    assert _formula(contract, "rebound") == TRUE


def test_a_declaration_in_a_loop_makes_a_fresh_object_each_time(contract):
    assert _formula(contract, "fresh") == TRUE


@pytest.fixture(scope="module")
def pure(anvil):  # noqa: F811
    d = O.deployment(*anvil, PURE)
    d.deploy("C")
    return d


def _engine(d, fn, values, sender=O.OWNER):
    """The lowered formula's truth at ``values``: a ``bytesN`` as its number, dynamic ``bytes`` as its bytes."""
    reset_terms()
    formula = Lowerer(d.slither["C"]).success(fn)
    world = World(d.chain(), d.at["C"], O.selector(fn.solidity_signature), d.contracts("C"))
    world.parameters = tuple(parameter(p, i) for i, p in enumerate(fn.parameters))  # ``msg.data``'s own words
    assignment = {}
    for i, (p, v) in enumerate(zip(fn.parameters, values)):
        term = parameter(p, i)
        fixed = term[2].startswith("bytes") and term[2] != "bytes"
        assignment[term] = int.from_bytes(v, "big") if fixed and isinstance(v, bytes) else v
    identity = {"caller": sender, "signer": sender}
    # A calldata array's or ``bytes``' length and items are the caller's: what these values hold there.
    for t in subterms(formula, "len"):
        if t[1] in assignment:
            assignment[t] = len(assignment[t[1]])
    for t in subterms(formula, "elem"):
        held = assignment.get(t[1])
        if held is None:
            continue
        k = Evaluator(world, identity, assignment).eval(t[2])
        if isinstance(held, bytes):
            assignment[t] = int.from_bytes(held[k : k + 32].ljust(32, b"\0"), "big")
        else:
            assignment[t] = held[k] if k < len(held) else 0
    return formula, Evaluator(world, identity, assignment).truth(formula)


def _differential(d, name, grid, definite=True):
    """Over ``grid``: the evaluated formula is the chain's answer (``definite`` off: or unknown); both outcomes seen."""
    fn = O.function(d, "C", name)
    seen = set()
    for values in grid:
        chain = O.chain_says(d, fn, values)
        formula, engine = _engine(d, fn, values)
        if definite or engine is not UNK:
            assert engine == chain, (name, values, chain, engine, formula)
        seen.add(chain)
    assert seen == {True, False}, (name, seen)


def test_calldata_items_are_the_callers_items_within_their_length(pure):
    _differential(pure, "calldataArray", [([5], 0), ([5], 1), ([1, 5], 1), ([1, 5], 0), ([], 0), ([5, 5], 2)])
    _differential(pure, "calldataFixed", [([5, 0], 0), ([0, 5], 0), ([0, 5], 1), ([5, 5], 2)])


def test_a_bytes_index_is_one_byte_not_a_word(pure):
    _differential(pure, "calldataByte", [(b"\x01",), (b"\x01\x02",), (b"\x02\x01",), (b"",), (b"\x00" * 31 + b"\x01",)])
    # ``msg.data[0]``, the selector's first byte: the word holding it runs past the four bytes sent, into bytes a
    # caller may append, so the lowering may leave it unknown; never the other answer.
    fn = O.function(pure, "C", "dataByte")
    formula, engine = _engine(pure, fn, [])
    chain = O.chain_says(pure, fn, [])
    assert chain == (O.selector("dataByte()") >> 24 == 1)
    assert engine is UNK or engine == chain
    assert subterms(formula, "slice")  # one byte, not a word


def test_the_first_bytes_of_a_slice_are_the_first_bytes_once_there_are_that_many(pure):
    grid = [(b"\x12\x34\x56\x78\x9a", b"\x12\x34\x56\x78"), (b"\x12\x34\x56\x78", b"\x12\x34\x56\x78"),
            (b"\x12\x34\x56", b"\x12\x34\x56\x00"), (b"\x12\x34\x56\x79", b"\x12\x34\x56\x78")]  # fmt: skip
    _differential(pure, "firstBytes", grid)


def test_storage_items_are_bounded_by_their_arrays_length_and_mappings_are_not(pure):
    # ``list`` holds [3, 0]; ``fixedList`` [0, 2, 0, 0]; the deployer has a balance.
    _differential(pure, "stored", [(0,), (1,), (2,), (100,)])
    _differential(pure, "storedFixed", [(1,), (0,), (4,)])
    _differential(pure, "mapped", [(O.OWNER,), (O.ACCOUNTS[1],)])


def test_storage_after_a_call_into_this_contracts_own_code_reads_unknown(pure):
    # ``this.setX(2)`` leaves 2: ``x == 1`` never holds after it; the lowering may not know, never says it does.
    fn = O.function(pure, "C", "selfCalled")
    formula, engine = _engine(pure, fn, [])
    assert not O.chain_says(pure, fn, [])
    assert engine is not True and "selfcall:setX(uint256)" in {o[1] for o in subterms(formula, "opaque")}


def test_a_storage_pointer_chosen_by_branch_reads_and_writes_unknown(pure):
    # Either branch passes on the chain; the lowering refuses to pick a pointer, never says it fails.
    fn = O.function(pure, "C", "chosen")
    for c in (True, False):
        formula, engine = _engine(pure, fn, [c])
        assert O.chain_says(pure, fn, [c]) and engine is not False, (c, engine)
    assert "unsupported:storage_pointer_choice" in {t[1] for k in ("unknown", "opaque") for t in subterms(formula, k)}


def test_a_field_reads_back_what_a_whole_struct_write_or_delete_left(contract):
    assert _formula(contract, "wholeThenField") == TRUE
    assert _formula(contract, "deletedThenField") == TRUE


def test_writes_two_branches_make_in_opposite_orders_read_back_per_branch(contract):
    formula = _formula(contract, "crossed")
    # The same key: whichever write came last on that branch; two keys: each its own.
    for c, same, apart in ((True, 2, 1), (False, 4, 4)):
        assert _at(formula, c=c, x=7, y=7, want=same) == TRUE
        assert _at(formula, c=c, x=7, y=7, want=apart + same) == FALSE
        assert _at(formula, c=c, x=7, y=8, want=apart) == TRUE


def test_storage_after_a_call_into_this_contracts_own_code_reads_unknown(contract):
    formula = _formula(contract, "selfCalled")
    assert formula != TRUE and "selfcall:setX(uint256)" in {o[1] for o in subterms(formula, "opaque")}


def test_a_storage_pointer_chosen_by_branch_reads_and_writes_unknown(contract):
    formula = _formula(contract, "chosen")
    assert formula not in (TRUE, FALSE)
    assert "unsupported:storage_pointer_choice" in {t[1] for k in ("unknown", "opaque") for t in subterms(formula, k)}


def test_a_raw_slot_reads_back_what_this_call_stored_there(contract):
    assert _formula(contract, "rawAgain") == TRUE


def test_a_variable_a_later_iteration_writes_is_forgotten(contract):
    formula = _formula(contract, "later")
    assert _at(formula, n=1) == TRUE  # one iteration, followed exactly
    past = _at(formula, n=10)  # past what was followed: unknown, never "flag stays false"
    assert past not in (TRUE, FALSE) and contains(past, frozenset({"opaque"}))


SOURCES = """
pragma solidity 0.8.27;

library Set {
    struct AddressSet { address[] items; }
    function add(AddressSet storage s, address a) internal { s.items.push(a); }
    function values(AddressSet storage s) internal view returns (address[] memory) { return s.items; }
}

contract Source {
    function revenue() external pure returns (uint256) { return 1; }
}

contract BadSource {
    function revenue() external pure returns (uint256) { revert(); }
}

contract C {
    using Set for Set.AddressSet;
    address admin;
    uint256 share;
    uint256 total;
    Set.AddressSet sources;
    address[] members;

    constructor() { admin = msg.sender; }
    function addSource(address s) external { require(msg.sender == admin); sources.add(s); }
    function addMember(address a) external { require(msg.sender == admin); members.push(a); }

    function _sum() internal view returns (uint256 sum) {
        address[] memory list = sources.values();
        for (uint256 i; i < list.length; ++i) sum += Source(list[i]).revenue();
    }
    function setShare(uint256 bp) external { require(msg.sender == admin); total = _sum(); share = bp; }

    function _isMember(address a) internal view returns (bool) {
        for (uint256 i; i < members.length; i++) { if (members[i] == a) return true; }
        return false;
    }
    function viaReturn() external { require(_isMember(msg.sender)); total += 1; }
    function viaBreak() external {
        bool found;
        for (uint256 i; i < members.length; i++) { if (members[i] == msg.sender) { found = true; break; } }
        require(found);
        total += 1;
    }
    // A later iteration decides, whoever calls: past the iterations followed, the loop may return or set the flag.
    function laterReturn() external { require(_reaches(3)); total += 1; }
    function _reaches(uint256 at) internal view returns (bool) {
        for (uint256 i; i < members.length; i++) { if (i == at) return true; }
        return false;
    }
    function laterBreak() external {
        bool found;
        for (uint256 i; i < members.length; i++) { if (i == 3) { found = true; break; } }
        require(found);
        total += 1;
    }
    function viaDoWhile() external {
        bool ok;
        uint256 i;
        do { if (members[i] == msg.sender) ok = true; i++; } while (i < members.length);
        require(ok);
        total += 1;
    }
    function later(uint256 n) external {
        address who;
        for (uint256 i; i < n; i++) { if (i == 5) who = msg.sender; }
        require(who == admin);
        total += 1;
    }
    function pushed() external {
        members.push(msg.sender);
        address[] memory copy = members;
        require(copy[copy.length - 1] == msg.sender);
    }
}
"""

MEMBERS = [(0xC0 + i) << 152 | i for i in range(5)]


def _verdict(d, name):
    from services.logic.terms import reset_terms

    reset_terms()
    contract = d.slither["C"]
    fn = next(f for f in contract.functions_entry_points if f.name == name)
    return function_verdict(contract, fn, d.at["C"], d.chain(), d.contracts("C", "Source", "BadSource"))[0]


def _deployed(anvil, sources: int, members: int, bad: int = 0):  # noqa: F811
    from eth_abi.abi import encode
    from eth_utils import keccak

    url, root = anvil
    d = O.deployment(url, root, SOURCES)
    d.deploy("C")
    d.deploy("Source")
    d.deploy("BadSource")

    def call(signature: str, who: int) -> None:
        d.send("C", "0x" + (keccak(text=signature)[:4] + encode(["address"], ["0x%040x" % who])).hex())

    for _ in range(sources):
        call("addSource(address)", d.at["Source"])
    for _ in range(bad):
        call("addSource(address)", d.at["BadSource"])
    for who in MEMBERS[:members]:
        call("addMember(address)", who)
    return d


@pytest.mark.parametrize(("good", "bad"), [(1, 0), (0, 1), (1, 1)])
def test_a_storage_list_copied_to_memory_calls_each_item_not_the_list(anvil, good, bad):  # noqa: F811
    # Lido's defect: ``sources.values()`` copied to memory, each item's ``revenue()`` called. A source that reverts
    # stops the admin; the list itself is never the callee.
    d = _deployed(anvil, sources=good, members=0, bad=bad)
    fn = O.function(d, "C", "setShare")
    chain = O.chain_says(d, fn, [1])
    assert chain == (bad == 0)
    formula, engine = O.engine_says(d, fn, [1], contracts=d.contracts("C", "Source", "BadSource"))
    assert engine == chain, (good, bad, engine, formula)
    v = O.check(d, "C", "setShare", _verdict(d, "setShare"))
    O.sound(v, {O.OWNER} if chain else set())


@pytest.mark.parametrize("count", [0, 1])
def test_a_loop_over_an_empty_list_never_calls_and_the_admin_passes(anvil, count):  # noqa: F811
    d = _deployed(anvil, sources=count, members=0)
    v = O.check(d, "C", "setShare", _verdict(d, "setShare"))
    assert v.openness == "restricted" and set(v.principals) == {O.OWNER}


@pytest.mark.parametrize("name", ["viaReturn", "viaBreak", "viaDoWhile"])
def test_a_member_past_the_iterations_followed_is_never_left_out_of_a_complete_list(anvil, name):  # noqa: F811
    verdict = _verdict(_deployed(anvil, sources=0, members=5), name)
    listed = set(verdict.principals) | set(verdict.conditions)
    assert not (verdict.complete and not set(MEMBERS) <= listed)
    assert set(MEMBERS[:3]) <= listed or verdict.openness == "not_determined"


@pytest.mark.parametrize("name", ["viaReturn", "viaBreak"])
def test_a_list_is_followed_exactly_up_to_the_bound_and_never_past_it(anvil, name):  # noqa: F811
    # Three entries are followed exactly: each member named, nothing forgotten. A fourth is past what is followed:
    # the loop's remainder is forgotten (``unknown:loop``), and the answer is left open rather than cut at three.
    d = _deployed(anvil, sources=0, members=3)
    at = O.check(d, "C", name, _verdict(d, name))
    assert at.openness == "restricted" and set(at.principals) == set(MEMBERS[:3]), at
    assert not any(g.startswith("unknown:loop") for g in at.gaps)
    d = _deployed(anvil, sources=0, members=4)
    past = O.check(d, "C", name, _verdict(d, name), open_at=False)
    O.sound(past, set(MEMBERS[:4]))
    assert all(O.passes(d, "C", O.function(d, "C", name), sender=m) for m in MEMBERS[:4])


@pytest.mark.parametrize("name", ["laterReturn", "laterBreak"])
def test_a_return_or_break_past_the_iterations_followed_is_never_dropped(anvil, name):  # noqa: F811
    # Five members: the fourth iteration lets anyone through, never "nobody, ever".
    d = _deployed(anvil, sources=0, members=5)
    assert O.strangers_passing(d, "C", O.function(d, "C", name)) == {True}
    v = O.check(d, "C", name, _verdict(d, name))
    O.sound(v, anyone=True)


def test_what_only_a_later_iteration_writes_is_never_taken_as_unwritten(anvil):  # noqa: F811
    # The sixth iteration records the caller: the admin passes with n >= 6, never "nobody, ever".
    d = _deployed(anvil, sources=0, members=0)
    later = O.function(d, "C", "later")
    assert O.passes(d, "C", later, {"n": 6}) and not O.passes(d, "C", later, {"n": 5})
    v = O.check(d, "C", "later", _verdict(d, "later"), samples=({"n": 6}, {"n": 2}))
    assert not O.nobody(v)
    O.sound(v, {O.OWNER})


def test_an_item_pushed_then_copied_reads_back_as_pushed(anvil):  # noqa: F811
    # Whoever calls pushes its own address and reads it back.
    d = _deployed(anvil, sources=0, members=2)
    O.check(d, "C", "pushed", _verdict(d, "pushed"), open_at={})
