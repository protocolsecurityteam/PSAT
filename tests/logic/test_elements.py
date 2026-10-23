"""Element reads and loop-carried values, as the language defines them: an item of a container (memory, storage or
calldata; a static or dynamic array, a mapping, a struct field) is that item, at whatever index, never the container;
an index out of range reverts; and a loop run further than the lowering follows forgets everything its body may write
and may still return or break out, never keeping a binding from the iterations it did run."""

from __future__ import annotations

import pytest

from services.logic.lower import Lowerer
from services.logic.terms import FALSE, TRUE, const, contains, mk, replace_terms, subterms
from services.logic.verdict import function_verdict
from tests.fuzz.authority import solc_path
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


def test_calldata_items_are_the_callers_items_within_their_length(contract):
    xs, i = mk("arg", "xs", "uint256[]"), mk("arg", "i", "uint256")
    formula = _formula(contract, "calldataArray")
    assert mk("elem", xs, i) in subterms(formula, "elem")
    assert mk("cmp", "lt", i, mk("len", xs)) in subterms(formula, "cmp")
    fixed = _formula(contract, "calldataFixed")
    assert mk("cmp", "lt", i, const(2)) in subterms(fixed, "cmp")


def test_a_bytes_index_is_one_byte_not_a_word(contract):
    d = mk("arg", "d", "bytes")
    assert mk("slice", mk("elem", d, const(0)), 0, 1) in subterms(_formula(contract, "calldataByte"), "slice")
    data = _formula(contract, "dataByte")
    assert subterms(data, "slice") and subterms(data, "calldatasize")


def test_storage_items_are_bounded_by_their_arrays_length_and_mappings_are_not(contract):
    i = mk("arg", "i", "uint256")
    assert not subterms(_formula(contract, "mapped"), "cmp") or all(
        c[1] != "lt" or c[2] != mk("arg", "who", "address") for c in subterms(_formula(contract, "mapped"), "cmp")
    )
    stored = _formula(contract, "stored")
    assert mk("cmp", "lt", i, mk("load", mk("this"), "list", (("f", "length"),))) in subterms(stored, "cmp")
    assert mk("cmp", "lt", i, const(4)) in subterms(_formula(contract, "storedFixed"), "cmp")


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
    return function_verdict(contract, fn, d.at["C"], d.chain(), d.contracts("C", "Source"))[0]


def _deployed(anvil, sources: int, members: int):  # noqa: F811
    from eth_abi.abi import encode
    from eth_utils import keccak

    url, root = anvil
    d = Deployment(url, root, SOURCES)
    d.deploy("C")
    d.deploy("Source")

    def call(signature: str, who: int) -> None:
        d.send("C", "0x" + (keccak(text=signature)[:4] + encode(["address"], ["0x%040x" % who])).hex())

    for _ in range(sources):
        call("addSource(address)", d.at["Source"])
    for who in MEMBERS[:members]:
        call("addMember(address)", who)
    return d


def test_a_storage_list_copied_to_memory_calls_each_item_not_the_list(anvil):  # noqa: F811
    d = _deployed(anvil, sources=1, members=0)
    formula = _formula(d.slither["C"], "setShare")
    targets = {c[1] for c in subterms(formula, "call")}
    whole = mk("load", mk("this"), "sources", (("f", "items"),))
    assert all(whole not in (t, t[2] if t[0] == "conv" else None) for t in targets)
    assert any(subterms(t, "load") and subterms(t, "load")[0][3][-1][0] == "k" for t in targets)


def test_a_loop_over_an_empty_list_never_calls_and_the_admin_passes(anvil):  # noqa: F811
    from tests.support.anvil import ACCOUNT0

    for count in (0, 1):
        verdict = _verdict(_deployed(anvil, sources=count, members=0), "setShare")
        assert verdict.openness == "restricted" and verdict.principals == {int(ACCOUNT0, 16)}


@pytest.mark.parametrize("name", ["viaReturn", "viaBreak", "viaDoWhile"])
def test_a_member_past_the_iterations_followed_is_never_left_out_of_a_complete_list(anvil, name):  # noqa: F811
    verdict = _verdict(_deployed(anvil, sources=0, members=5), name)
    listed = set(verdict.principals) | set(verdict.conditions)
    assert not (verdict.complete and not set(MEMBERS) <= listed)
    assert set(MEMBERS[:3]) <= listed or verdict.openness == "not_determined"


def test_what_only_a_later_iteration_writes_is_never_taken_as_unwritten(anvil):  # noqa: F811
    from tests.support.anvil import ACCOUNT0

    # The sixth iteration records the caller: the admin passes with n >= 6, never "nobody, ever".
    verdict = _verdict(_deployed(anvil, sources=0, members=0), "later")
    assert int(ACCOUNT0, 16) in verdict.principals or not verdict.complete


def test_an_item_pushed_then_copied_reads_back_as_pushed(anvil):  # noqa: F811
    verdict = _verdict(_deployed(anvil, sources=0, members=2), "pushed")
    assert verdict.openness == "open"  # whoever calls pushes its own address and reads it back
