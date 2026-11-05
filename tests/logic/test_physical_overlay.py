"""Raw and typed writes share bytes, compared with independent EVM execution."""

import pytest
from eth_abi import decode

from services.logic.cells import annotate
from services.logic.formula import compile_function
from services.logic.lower import parameter, read_store, stored
from services.logic.solver import Translation, number
from services.logic.terms import CALLER, const, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401
from tests.support.anvil import rpc

SOURCE = """pragma solidity 0.8.27;
contract C {
 uint64 a=17;int64 b=-2;bytes8 c=0x0102030405060708;bool d=true;
 mapping(uint=>uint) m;
 bytes32 constant SLOT=0;
 function result() internal view returns(uint64,int64,bytes8,bool,uint){uint w;assembly{w:=sload(0)}return(a,b,c,d,w);}
 function namedRaw(uint64 x) external returns(uint64,int64,bytes8,bool,uint){a=x;return result();}
 function rawNamed(uint w) external returns(uint64,int64,bytes8,bool,uint){assembly{sstore(0,w)}return result();}
 function order(bool flip,uint64 x,uint w) external returns(uint64,int64,bytes8,bool,uint){
  if(flip){a=x;assembly{sstore(0,w)}}else{assembly{sstore(0,w)}a=x;}return result();}
 function signed(int64 x,bytes8 y) external returns(uint64,int64,bytes8,bool,uint){b=x;c=y;return result();}
 function constantSlot(uint64 x) external returns(uint64,int64,bytes8,bool,uint){
   a=x;uint w;assembly{w:=sload(SLOT)}return(a,b,c,d,w);}
 function mapped(uint k,uint v) external returns(uint,uint){
   m[k]=v;uint w;assembly{mstore(0,k)mstore(32,m.slot)w:=sload(keccak256(0,64))}return(m[k],w);}
 function abort(uint64 x) external {a=x;assembly{sstore(0,7)}require(false);}
 function coordinates() external returns(uint x,uint y,uint z,uint t){assembly{
   x:=b.slot y:=b.offset z:=add(b.slot,b.offset) t:=iszero(b.offset)}}
}
contract OtherNames {uint64 left;int64 middle;bytes8 right;bool flag;}
"""


@pytest.fixture(scope="module")
def deployed(anvil):
    d = O.deployment(anvil[0], anvil[1], SOURCE)
    d.deploy("C")
    d.deploy("OtherNames")
    return d


CASES = [
    ("namedRaw", (0,)),
    ("namedRaw", (2**64 - 1,)),
    ("rawNamed", (0,)),
    ("rawNamed", (2**256 - 1,)),
    ("rawNamed", (0x1234 << 128,)),
    ("order", (False, 99, 0)),
    ("order", (True, 99, 0)),
    ("order", (False, 99, 2**256 - 1)),
    ("order", (True, 99, 2**256 - 1)),
    ("signed", (-(2**63), b"\xff" * 8)),
    ("signed", (2**63 - 1, b"\x00" * 8)),
    ("constantSlot", (81,)),
]


@pytest.mark.parametrize("name,args", CASES)
def test_final_effect_values_match_evm_and_keep_neighboring_bytes(deployed, name, args):
    d = deployed
    fn, reads = O.function(d, "C", name), d.chain()
    bindings = {
        CALLER: O.OWNER,
        mk("callvalue"): 0,
        **{parameter(p, i): v for i, (p, v) in enumerate(zip(fn.parameters, args))},
    }
    f = compile_function(d.slither["C"], fn, d.at["C"], reads, d.contracts("C"))
    returned = rpc(
        d.url,
        "eth_call",
        [{"to": O.hex20(d.at["C"]), "from": O.hex20(O.OWNER), "data": "0x" + O.calldata(fn, args).hex()}, "latest"],
    )
    a, b, c, flag, word = decode(["uint64", "int64", "bytes8", "bool", "uint256"], bytes.fromhex(returned[2:]))
    after = {"a": a, "b": b, "c": int.from_bytes(c, "big"), "d": flag}
    tr = Translation(reads, d.contracts("C"), d.at["C"], f.selector, bindings=bindings)
    assert tr.truth(f.success) is True and f.effects
    for effect in f.effects:
        expected = word if effect.target[0] == "raw" else after[effect.target[1]]
        assert number(tr.translate(effect.value)) == expected, (name, args, effect, tr.issues)
        assert not tr.issues


@pytest.mark.parametrize("key,value", [(0, 91), (8, 0), (2**256 - 1, 2**256 - 1)])
def test_raw_mapping_slot_sees_typed_write(deployed, key, value):
    from services.logic.abi_values import describe, transfer
    from services.logic.lower import Lowerer

    d = deployed
    fn = O.function(d, "C", "mapped")
    lower = Lowerer(d.slither["C"], this=const(d.at["C"], "address"))
    lower.success(fn)
    tr = Translation(
        d.chain(),
        d.contracts("C"),
        d.at["C"],
        bindings={CALLER: O.OWNER, parameter(fn.parameters[0], 0): key, parameter(fn.parameters[1], 1): value},
    )
    assert len(lower.exits) == 1
    actual = rpc(
        d.url,
        "eth_call",
        [
            {"to": O.hex20(d.at["C"]), "from": O.hex20(O.OWNER), "data": "0x" + O.calldata(fn, (key, value)).hex()},
            "latest",
        ],
    )
    expected = decode(["uint256", "uint256"], bytes.fromhex(actual[2:]))
    returns = [transfer(t, describe(p.type), describe(p.type)) for t, p in zip(lower.exits[0].ret, fn.returns)]
    assert all(tr.truth(valid) is True for _, valid in returns), tr.issues
    assert tuple(number(tr.translate(t)) for t, _ in returns) == expected == (value, value), tr.issues
    assert not tr.issues


def test_cross_layout_names_use_same_physical_bytes_and_correct_initial_context(deployed):
    d = deployed
    at = const(d.at["C"], "address")
    own = annotate(d.slither["C"], at, (at, "a", ()))
    foreign = annotate(d.slither["OtherNames"], const(d.at["OtherNames"], "address"), (at, "left", ()))
    tr = Translation(d.chain(), d.contracts("C", "OtherNames"), d.at["C"])
    assert number(tr.translate(read_store({}, foreign))) == 17  # read storage at C, with OtherNames' layout
    result = read_store(stored({}, own, const(77, "uint64")), foreign)
    assert number(tr.translate(result)) == 77 and not tr.issues


def test_reverting_paths_publish_no_storage_effects(deployed):
    d = deployed
    fn = O.function(d, "C", "abort")
    f = compile_function(d.slither["C"], fn, d.at["C"], d.chain(), d.contracts("C"))
    assert not f.effects and not O.passes(d, "C", fn, (98,))


def test_distinct_slot_and_offset_operands_keep_compiler_metadata(deployed):
    from services.logic.abi_values import describe, transfer
    from services.logic.lower import Lowerer

    d = deployed
    fn = O.function(d, "C", "coordinates")
    lower = Lowerer(d.slither["C"], this=const(d.at["C"], "address"))
    lower.success(fn)
    tr = Translation(d.chain(), d.contracts("C"), d.at["C"])
    values = [transfer(t, describe(p.type), describe(p.type))[0] for t, p in zip(lower.exits[0].ret, fn.returns)]
    actual = rpc(d.url, "eth_call", [{"to": O.hex20(d.at["C"]), "data": "0x" + O.calldata(fn).hex()}, "latest"])
    assert (
        tuple(number(tr.translate(t)) for t in values)
        == decode(["uint256"] * 4, bytes.fromhex(actual[2:]))
        == (0, 8, 8, 0)
    )
    assert not tr.issues


def test_code_views_share_physical_reads_but_not_named_entries_or_budget(anvil, tmp_path):
    from services.logic.model import Limits
    from services.logic.storage import Storage

    d = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity 0.8.27;
    contract A {mapping(address=>bool) public role;constructor(){role[msg.sender]=true;}}
    contract B {mapping(address=>bool) public allowed;}""",
    )
    d.deploy("A")
    d.deploy("B")
    chain = d.chain()

    class Reads:
        def __getattr__(self, name):
            return getattr(chain, name)

        def storage_dump(self, address):
            return {O.slot(O.OWNER, 0): chain.storage(address, O.slot(O.OWNER, 0))}

        def key_words(self, address):
            return {O.OWNER}

        def preimages(self, address, slots):
            raise AssertionError("known constructor key")

    store = Storage(Reads(), d.contracts("A", "B"), Limits(), const(0))
    a, b = d.at["A"], d.at["B"]
    assert store.read(a, "role", (("k", O.OWNER),), a) is True
    assert store.read(a, "allowed", (("k", O.OWNER),), b) is True
    assert store.read(b, "allowed", (("k", O.OWNER),), b) is False
    first = store.snapshot(a, a)
    spent = store.work[a]["steps"]
    second = store.snapshot(a, b)
    assert first.complete and second.complete and "allowed" in second.entries and "allowed" not in first.entries
    assert store.work[a]["steps"] > spent
    limited = Storage(Reads(), d.contracts("A", "B"), Limits(storage_steps=spent), const(0))
    assert limited.snapshot(a, a).complete
    stopped = limited.snapshot(a, b)
    assert not stopped.complete and any(i.kind == "budget" for i in stopped.issues)
    assert not limited.work[a]["complete"]
