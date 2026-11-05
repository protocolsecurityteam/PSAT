"""Public mapping/array getters are compiler-generated reads with ABI and bounds semantics."""

import pytest

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.lower import parameter
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.terms import CALLER, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity ^0.8.10;
contract T {
 mapping(address=>uint) public balanceOf;
 mapping(address=>mapping(bytes4=>int16)) public nested;
 uint8[] public values;
 mapping(address=>uint16[2]) public fixedValues;
 constructor(){balanceOf[msg.sender]=7;nested[msg.sender][0x12345678]=-300;
 values.push(2);values.push(255);fixedValues[msg.sender][1]=600;}
 function set(uint i,uint8 n) external {values[i]=n;}
}
contract C {T t;uint public result;constructor(address a){t=T(a);}
 function mappingRead() external {require(t.balanceOf(msg.sender)==7);result=1;}
 function nestedRead() external {require(t.nested(msg.sender,0x12345678)==-300);result=1;}
 function arrayRead(uint i) external {require(t.values(i)>0);result=1;}
 function fixedRead(uint i) external {require(t.fixedValues(msg.sender,i)==600);result=1;}
 function afterWrite(uint i) external {t.set(i,8);require(t.values(i)==8);result=1;}
}
"""


@pytest.fixture
def d(anvil, tmp_path):
    d = O.deployment(anvil[0], tmp_path, SOURCE)
    d.deploy("C", ("address",), (d.deploy("T"),))
    return d


@pytest.mark.parametrize("name", ["mappingRead", "nestedRead", "arrayRead", "fixedRead", "afterWrite"])
def test_generated_getters_match_execution_and_prior_writes(d, name):
    fn = O.function(d, "C", name)
    reads = d.chain()
    f = generate_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C", "T"), steps=10000)
    assert isinstance(f, Formula), f
    for caller in (O.OWNER, O.ACCOUNTS[1]):
        for index in (0, 1, 2, 2**256 - 1) if fn.parameters else (None,):
            args = () if index is None else (index,)
            bindings = {
                CALLER: caller,
                mk("callvalue"): 0,
                **{parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))},
            }
            tr = Translation(reads, d.contracts("C", "T"), d.at["C"], f.selector, bindings=bindings)
            assert tr.truth(f.success) is O.chain_says(d, fn, args, sender=caller), tr.issues


def test_legacy_large_enum_getter_uses_full_storage_width(anvil, tmp_path):
    source = """pragma solidity 0.5.14;
contract T {enum E {VALUES}mapping(address=>E) public entries;
constructor() public {entries[msg.sender]=E.V256;}}
interface I {function entries(address) external view returns(uint16);}
contract C {I t;uint public value;constructor(address a) public {t=I(a);}
function act() external {require(uint(t.entries(msg.sender))==256);value=1;}}
""".replace("VALUES", ",".join(f"V{i}" for i in range(257)))
    d = O.deployment(anvil[0], tmp_path, source, version="0.5.14")
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "T"), steps=10000)
    assert isinstance(f, Formula)
    for caller in (O.OWNER, O.ACCOUNTS[1]):
        tr = Translation(
            d.chain(), d.contracts("C", "T"), d.at["C"], f.selector, bindings={CALLER: caller, mk("callvalue"): 0}
        )
        assert tr.truth(f.success) is O.chain_says(d, fn, [], sender=caller) is (caller == O.OWNER)


def test_unsupported_struct_getter_is_retained_not_guessed(anvil, tmp_path):
    source = """pragma solidity ^0.8.10;
contract T {struct S {uint a;uint b;}mapping(address=>S) public entries;}
contract C {T t;uint x;constructor(address a){t=T(a);}function act() external {
(uint a,uint b)=t.entries(msg.sender);x=a+b;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    f = generate_function(
        d.slither["C"], O.function(d, "C", "act"), d.at["C"], d.chain(), d.contracts("C", "T"), steps=10000
    )
    assert isinstance(f, PendingCompilation) and f.reason == "call" and "callee_entry" in (f.blocker or "")


def test_shadowed_mapping_and_base_writer_have_distinct_storage_identities(anvil, tmp_path):
    source = """pragma solidity 0.5.14;
contract Base {mapping(address=>uint) private balances;
constructor() public {balances[msg.sender]=99;}
function writeBase(address who) public {balances[who]=55;}
function baseValue(address who) public view returns(uint){return balances[who];}}
contract T is Base {mapping(address=>uint) public balances;
constructor() public {balances[msg.sender]=7;}
function writeOwn(address who) public {balances[who]=8;}}
contract C {T t;uint result;constructor(address a) public {t=T(a);}
function initial() external {require(t.balances(msg.sender)==7);result=1;}
function afterBase() external {t.writeBase(msg.sender);require(t.balances(msg.sender)==7);
require(t.baseValue(msg.sender)==55);result=1;}
function afterOwn() external {t.writeOwn(msg.sender);require(t.balances(msg.sender)==8);
require(t.baseValue(msg.sender)==99);result=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source, version="0.5.14")
    d.deploy("C", ("address",), (d.deploy("T"),))
    for name in ("initial", "afterBase", "afterOwn"):
        fn = O.function(d, "C", name)
        reads = d.chain()
        f = generate_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C", "T"), steps=10000)
        assert isinstance(f, Formula)
        for caller in (O.OWNER, O.ACCOUNTS[1]):
            tr = Translation(
                reads, d.contracts("C", "T"), d.at["C"], f.selector, bindings={CALLER: caller, mk("callvalue"): 0}
            )
            assert tr.truth(f.success) is O.chain_says(d, fn, [], sender=caller), tr.issues


def test_single_member_enum_layout_matches_chain(anvil, tmp_path):
    source = """pragma solidity 0.5.14;
contract T {enum E {Only}E[2] public values;uint8 public tail;constructor() public {tail=7;}}
contract C {T t;uint result;constructor(address a) public {t=T(a);}
function act() external {require(t.tail()==7);result=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source, version="0.5.14")
    d.deploy("C", ("address",), (d.deploy("T"),))
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C", "T"), steps=10000)
    assert isinstance(f, Formula) and O.chain_says(d, fn, [], sender=O.OWNER)
    tr = Translation(
        d.chain(), d.contracts("C", "T"), d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0}
    )
    assert tr.truth(f.success) is True and not tr.issues


def test_concrete_dynamic_getter_keys_use_direct_storage_reads(anvil, tmp_path, monkeypatch):
    source = """pragma solidity ^0.8.10;
contract T {mapping(string=>bytes4) public names;mapping(bytes=>uint24) public blobs;
constructor(){names["hello"]=0x12345678;blobs[hex"010203"]=999;}}
contract C {T t;uint result;constructor(address a){t=T(a);}function act() external {
require(t.names("hello")==0x12345678 && t.blobs(hex"010203")==999);result=1;}}
"""
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("T"),))
    reads = d.chain()

    def no_dump(*args):
        raise AssertionError("concrete key must not enumerate storage")

    monkeypatch.setattr(reads, "storage_dump", no_dump)
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C", "T"), steps=10000)
    assert isinstance(f, Formula)
    tr = Translation(
        reads, d.contracts("C", "T"), d.at["C"], f.selector, bindings={CALLER: O.OWNER, mk("callvalue"): 0}
    )
    assert tr.truth(f.success) is True and O.chain_says(d, fn, [], sender=O.OWNER)


def test_failed_snapshot_acquisition_cannot_cache_a_complete_empty_set(anvil, tmp_path, monkeypatch):
    from services.logic.model import Limits, ReadError
    from services.logic.storage import Storage

    d = O.deployment(anvil[0], tmp_path, "pragma solidity ^0.8.10;contract T {address public owner=msg.sender;}")
    at = d.deploy("T")
    reads = d.chain()
    attempts = []

    def dump(address):
        attempts.append(address)
        if len(attempts) == 1:
            raise ReadError("temporary node failure")
        return {0: O.OWNER}

    monkeypatch.setattr(reads, "storage_dump", dump)
    monkeypatch.setattr(reads, "key_words", lambda _: set())
    monkeypatch.setattr(reads, "preimages", lambda *_: {})
    storage = Storage(reads, d.contracts("T"), Limits(), mk("const", True, "bool"))
    with pytest.raises(ReadError):
        storage.snapshot(at)
    assert at not in storage.snapshots and storage.work[at]["complete"] is False
    retried = storage.snapshot(at)
    assert retried.complete and retried.entries["owner"] == [((), O.OWNER)]
    assert len(attempts) == 2
