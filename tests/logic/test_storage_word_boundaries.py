"""Independent counterexamples for word identity, pointer types and unknown writes."""

import pytest

from services.logic.cells import overlay
from services.logic.expansion import Selection, expand_formula
from services.logic.formula import compile_function
from services.logic.lower import read_store, stored
from services.logic.solver import Translation
from services.logic.terms import CALLER, const, mk, mk_op, unknown
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

CASES = [
    ("gas", "0.8.27", "", "", "uint v;assembly{sstore(gas(),77)v:=sload(gas())}", "v==77", False),
    (
        "msize",
        "0.8.30",
        "layout at 96",
        "uint fixedValue;",
        "fixedValue=1;assembly{sstore(msize(),0)mstore(128,0)sstore(msize(),1)}",
        "fixedValue==1",
        False,
    ),
    (
        "distinct_buffers",
        "0.8.27",
        "",
        "",
        "uint[] memory a=new uint[](1);uint[] memory b=new uint[](1);uint v;assembly{sstore(a,77)v:=sload(b)}",
        "v==77",
        False,
    ),
    (
        "derived_buffers",
        "0.8.27",
        "",
        "",
        "uint[] memory a=new uint[](1);uint[] memory b=new uint[](1);uint v;"
        "assembly{sstore(add(a,32),77)v:=sload(add(b,32))}",
        "v==77",
        False,
    ),
    (
        "pointer_comparison",
        "0.8.27",
        "",
        "",
        "uint[] memory a=new uint[](1);uint[] memory b=new uint[](1);uint v;assembly{v:=eq(a,b)}",
        "v==1",
        False,
    ),
    (
        "same_buffer",
        "0.8.27",
        "",
        "",
        "uint[] memory a=new uint[](1);uint[] memory b=a;uint v;assembly{sstore(a,77)v:=sload(b)}",
        "v==77",
        True,
    ),
    (
        "pointer_type",
        "0.8.27",
        "",
        "struct A{uint y;}struct B{uint pad;uint y;}",
        "A storage p;B storage q;uint v;assembly{p.slot:=5 q.slot:=p.slot}q.y=77;assembly{v:=sload(6)}",
        "v==77",
        True,
    ),
    (
        "constant_suffix",
        "0.8.27",
        "",
        "uint64 a=17;uint64 b=19;uint observed;uint256 constant SLOT=1;",
        "assembly{sstore(SLOT,b.offset)}",
        "observed==8",
        True,
    ),
]

for legacy in ("0.4.19", "0.5.14"):
    CASES.append(
        (
            "legacy_" + legacy,
            legacy,
            "",
            "",
            "uint[] memory a=new uint[](1);uint[] memory b=new uint[](1);uint v;assembly{sstore(a,77)v:=sload(b)}",
            "v==77",
            False,
        )
    )
CASES.append(
    (
        "assigned_reference",
        "0.8.27",
        "",
        "",
        "uint[1] memory a=[uint(1)];uint[1] memory b=[uint(2)];assembly{a:=b}a[0]=3;",
        "b[0]==3",
        True,
    )
)


@pytest.mark.parametrize("name,version,base,fields,body,gate,open_", CASES, ids=[c[0] for c in CASES])
def test_effect_authority_matches_pointer_and_word_counterexamples(
    anvil, tmp_path, name, version, base, fields, body, gate, open_
):
    source = f"""pragma solidity {version};contract C {base} {{
      {fields}address owner=msg.sender;uint controlled;
      function act() external {{{body}require({gate}||msg.sender==owner);controlled=9;}}
    }}"""
    d = O.deployment(anvil[0], tmp_path, source, version=version)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    reads = d.chain()
    known = d.contracts("C")
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, known)
    index = next(i for i, e in enumerate(f.effects) if e.target[1] == "controlled")
    result = expand_formula(f, reads, known, selection=Selection(False, (index,))).effects[0]
    tr = Translation(reads, known, d.at["C"], f.selector, bindings={CALLER: O.ACCOUNTS[1], mk("callvalue"): 0})
    predicted = tr.truth(f.effects[index].guard)
    assert O.passes(d, "C", fn, sender=O.ACCOUNTS[1]) is open_
    assert O.passes(d, "C", fn, sender=O.OWNER)
    if open_:
        assert predicted is True and result.complete and result.representation == "cofinite", (result, tr.issues)
    else:
        assert predicted is not True
        assert (result.complete and result.members == (O.OWNER,)) or (not result.complete and result.issues), result


@pytest.mark.parametrize("wrapped", [False, True])
def test_unmodeled_slot_labels_are_not_reflexive_value_identities(wrapped):
    at = const(123, "address")
    slot = unknown("unsupported:slot")
    if wrapped:
        slot = mk_op("add", (slot, const(3)))
    result = read_store(stored({}, ("raw", at, slot), const(77)), ("raw", at, slot))

    class Reads:
        block = 1

        def storage(self, *args):
            raise AssertionError("an unknown slot is not a read address")

    tr = Translation(Reads(), {}, 123)
    tr.translate(result)
    assert tr.issues


def test_unknown_writes_do_not_erase_previous_possible_writes():
    at = const(123, "address")
    slot = unknown("unsupported:slot")
    state = stored({}, ("raw", at, const(0)), const(1))
    state = stored(state, ("raw", at, slot), const(0))
    state = stored(state, ("raw", at, slot), const(1))
    assert len(state) == 3

    class Reads:
        block = 1

        def storage(self, *args):
            return 1

    tr = Translation(Reads(), {}, 123)
    tr.translate(read_store(state, ("raw", at, const(0))))
    assert tr.issues


def test_unknown_offsets_do_not_qualify_for_same_geometry_shortcut():
    at = const(123, "address")
    off = unknown("unsupported:offset")
    cell = at, const(0), off, 1, "uint8"
    value = overlay(const(0), cell, cell, const(77))

    class Reads:
        block = 1

    tr = Translation(Reads(), {}, 123)
    tr.translate(value)
    assert tr.issues


def test_transaction_composition_does_not_alias_separate_memory_frames(anvil, tmp_path):
    from services.logic.solver import project
    from services.resolution.logic_composition import sequence

    source = """pragma solidity 0.8.27;contract C {address owner=msg.sender;uint controlled;
    function prepare() external {assembly{mstore(64,256)}uint[] memory a=new uint[](1);assembly{sstore(a,77)}}
    function act() external {uint[] memory b=new uint[](1);uint v;assembly{v:=sload(b)}
    require(v==77||msg.sender==owner);controlled=9;}}
    """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    reads = d.chain()
    known = d.contracts("C")
    formulas = [
        compile_function(d.slither["C"], O.function(d, "C", name), d.at["C"], reads, known)
        for name in ("prepare", "act")
    ]
    predicate = sequence(tuple(formulas))
    result = project(predicate, Translation(reads, known, d.at["C"]))
    assert not result.complete or result.members == (O.OWNER,), result
    with O.snapshot(d):
        assert O.transact(d, "C", "prepare()", sender=O.ACCOUNTS[1])
        assert not O.passes(d, "C", O.function(d, "C", "act"), sender=O.ACCOUNTS[1])


def test_layout_changing_memory_view_is_retained_not_reinterpreted_by_field_name(anvil, tmp_path):
    from services.logic.continuation import PendingCompilation, generate_function
    from tests.logic.test_retained_operations import mapping, operation

    source = """pragma solidity 0.8.27;contract C {
    struct A{uint x;}struct B{uint pad;uint x;}uint controlled;
    function act()external {A memory a=A(1);B memory b;assembly{b:=a}b.x=9;require(a.x==1);controlled=7;}}
    """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C")
    fn = O.function(d, "C", "act")
    assert O.passes(d, "C", fn, sender=O.ACCOUNTS[1])
    result = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"), steps=10000)
    assert isinstance(result, PendingCompilation) and result.reason == "operation"
    assert result.blocker == "unsupported:memory_reference_cast"
    saved = dict(operation(result))
    assert saved["kind"] == "memory_reference" and saved["value"][0] == "memory_address"
    assert saved["type"] and saved["objects"] and saved["destination"]
    assert mapping(saved["state"]["$state"])["store"]
