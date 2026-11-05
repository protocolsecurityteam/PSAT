"""Physical storage expressions checked against independently initialized EVM words."""

import pytest

from services.logic.layout import locate, locate_symbolic
from services.logic.solver import Translation, number
from services.logic.terms import const, mk
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401

SOURCE = """pragma solidity 0.8.27;
type Key is bytes4;
contract C {
 uint8 a=3;bytes4 b=0xabcdef12;int16 c=-17;address who=address(0x123456);
 uint8[35] fixedItems;uint24[] dynamicItems;
 struct P {uint8 a;uint24 b;uint big;bytes7 c;}
 P[] items;
 mapping(bytes4=>P) codes;
 mapping(int16=>mapping(address=>uint32[])) nested;
 mapping(string=>uint) strings;
 mapping(bytes=>uint) byteKeys;
 mapping(Key=>uint) aliases;
 constructor(){
  fixedItems[0]=11;fixedItems[31]=12;fixedItems[32]=13;fixedItems[34]=14;
  for(uint i=0;i<12;i++)dynamicItems.push(uint24(101+i));
  items.push(P(21,22,23,0x11223344556677));items.push(P(31,32,33,0x22334455667788));
  codes[0xdeadbeef]=P(41,42,43,0x33445566778899);
  nested[-7][address(0x123456)].push(51);nested[-7][address(0x123456)].push(52);
  strings["hello"]=61;byteKeys[hex"001122"]=62;aliases[Key.wrap(0x01020304)]=63;
 }
}
contract DifferentNames {uint8 x;bytes4 y;int16 z;address w;}
"""


@pytest.fixture(scope="module")
def d(anvil):
    deployed = O.deployment(anvil[0], anvil[1], SOURCE)
    deployed.deploy("C")
    return deployed


# name, concrete path, declared symbolic key types, byte width, expected stored bits
CASES = [
    ("a", (), (), 1, 3),
    ("b", (), (), 4, 0xABCDEF12),
    ("c", (), (), 2, 2**16 - 17),
    ("who", (), (), 20, 0x123456),
    *[("fixedItems", (("k", i),), ("uint256",), 1, v) for i, v in [(0, 11), (31, 12), (32, 13), (34, 14)]],
    *[("dynamicItems", (("k", i),), ("uint256",), 3, 101 + i) for i in (0, 9, 10, 11)],
    ("dynamicItems", (("f", "length"),), (), 32, 12),
    ("items", (("k", 1), ("f", "a")), ("uint256",), 1, 31),
    ("items", (("k", 1), ("f", "b")), ("uint256",), 3, 32),
    ("items", (("k", 1), ("f", "big")), ("uint256",), 32, 33),
    ("items", (("k", 1), ("f", "c")), ("uint256",), 7, 0x22334455667788),
    ("codes", (("k", 0xDEADBEEF), ("f", "b")), ("bytes4",), 3, 42),
    ("nested", (("k", -7), ("k", 0x123456), ("k", 1)), ("int16", "address", "uint256"), 4, 52),
    ("strings", (("k", "hello"),), ("string",), 32, 61),
    ("byteKeys", (("k", b"\x00\x11\x22"),), ("bytes",), 32, 62),
    ("aliases", (("k", 0x01020304),), ("bytes4",), 32, 63),
]


@pytest.mark.parametrize("name,path,types,width,expected", CASES)
def test_symbolic_and_concrete_locations_read_the_evm(d, name, path, types, width, expected):
    symbolic, bindings = [], {}
    keys = iter(types)
    for index, (kind, value) in enumerate(path):
        if kind == "k":
            argument = mk("arg", f"key{index}", next(keys))
            bindings[argument] = value
            symbolic.append((kind, argument))
        else:
            symbolic.append((kind, value))
    slot, offset, _ = locate_symbolic(d.slither["C"], name, tuple(symbolic))
    tr = Translation(d.chain(), d.contracts("C"), d.at["C"], bindings=bindings)
    actual_slot, actual_offset = number(tr.translate(slot)), number(tr.translate(offset))
    assert not tr.issues and actual_slot is not None and actual_offset is not None, tr.issues
    assert (actual_slot, actual_offset) == locate(d.slither["C"], name, path)[:2]
    raw = d.chain().storage(d.at["C"], actual_slot)
    assert (raw >> (8 * actual_offset)) % 2 ** (8 * width) == expected


def test_physical_location_does_not_depend_on_variable_names(d):
    for original, renamed in zip(("a", "b", "c", "who"), ("x", "y", "z", "w")):
        assert (
            locate_symbolic(d.slither["C"], original, ())[:2]
            == locate_symbolic(d.slither["DifferentNames"], renamed, ())[:2]
        )


def test_symbolic_namespace_root_and_struct_stride_wrap_at_word_boundary(d):
    root = mk("arg", "slot", "uint256")
    slot, offset, _ = locate_symbolic(d.slither["C"], ("slot", root, "C.P"), (("f", "big"),))
    for start, expected in [(0, 1), (2**256 - 1, 0)]:
        tr = Translation(d.chain(), d.contracts("C"), d.at["C"], bindings={root: start})
        assert number(tr.translate(slot)) == expected and number(tr.translate(offset)) == 0


def test_invalid_paths_are_not_assigned_a_cell(d):
    assert locate_symbolic(d.slither["C"], "a", (("f", "missing"),)) is None
    assert locate_symbolic(d.slither["C"], "missing", ()) is None
    assert locate_symbolic(d.slither["C"], ("slot", const(0), "AbsentType"), ()) is None


def test_namespace_root_is_a_256_bit_slot_even_without_path_arithmetic(d):
    for root in (-1, 2**256 + 7):
        symbolic = locate_symbolic(d.slither["C"], ("slot", const(root), "uint8"), ())
        concrete = locate(d.slither["C"], ("slot", root, "uint8"), ())
        tr = Translation(d.chain(), d.contracts("C"), d.at["C"])
        assert number(tr.translate(symbolic[0])) == concrete[0] == root % 2**256


@pytest.mark.parametrize("version", ["0.4.19", "0.5.14", "0.8.27"])
def test_function_pointer_fields_and_following_variables_match_storage(anvil, tmp_path, version):
    constructor = "function C() public" if version == "0.4.19" else "constructor() public"
    source = f"""pragma solidity {version};
    contract C {{
      struct I {{function() internal returns(uint) ptr;uint8 marker;}}
      struct E {{function() external returns(uint) ptr;uint8 marker;}}
      I i;I[2] ins;E e;E[] exts;
      function() internal returns(uint) ip;uint8 afterInternal;
      function() external returns(uint) ep;uint8 afterExternal;
      {constructor} {{
        i.ptr=one;i.marker=17;ins[1].ptr=one;ins[1].marker=27;
        e.ptr=this.ping;e.marker=37;
        exts.push(E(this.ping,47));exts.push(E(this.ping,57));
        ip=one;afterInternal=67;ep=this.ping;afterExternal=77;
      }}
      function one() internal returns(uint){{return 1;}}
      function ping() external returns(uint){{return 2;}}
    }}"""
    deployed = O.deployment(anvil[0], tmp_path, source, version=version)
    deployed.deploy("C")
    cases = [
        ("i", (("f", "marker"),), 17, 8),
        ("ins", (("k", 1), ("f", "marker")), 27, 8),
        ("e", (("f", "marker"),), 37, 24),
        ("exts", (("k", 1), ("f", "marker")), 57, 24),
        ("afterInternal", (), 67, 8),
        ("afterExternal", (), 77, 24),
    ]
    for name, path, expected, offset in cases:
        slot, actual_offset, _ = locate(deployed.slither["C"], name, path)
        raw = deployed.chain().storage(deployed.at["C"], slot)
        assert actual_offset == offset and (raw >> (8 * offset)) & 255 == expected, (version, name)


def test_underlying_alias_type_controls_values_and_snapshot_keys(anvil, tmp_path):
    from services.logic.model import Limits
    from services.logic.storage import Storage

    source = """pragma solidity 0.8.27;type Signed is int16;type Bytes is bytes4;
    contract C {Signed public amount=Signed.wrap(-17);mapping(Signed=>mapping(Bytes=>Signed)) m;
    constructor(){m[Signed.wrap(-7)][Bytes.wrap(0x11223344)]=Signed.wrap(-23);}}"""
    deployed = O.deployment(anvil[0], tmp_path, source)
    deployed.deploy("C")
    chain = deployed.chain()
    from eth_abi import encode as abi_encode
    from eth_utils import keccak

    root = keccak(abi_encode(["int16", "uint256"], [-7, 1]))
    entry = int.from_bytes(keccak(abi_encode(["bytes4", "bytes32"], [bytes.fromhex("11223344"), root])), "big")

    class Reads:
        def __getattr__(self, name):
            return getattr(chain, name)

        def storage_dump(self, address):
            return {s: chain.storage(address, s) for s in (0, entry)}

        def key_words(self, address):
            return {2**256 - 7, 0x11223344 << 224}

        def preimages(self, address, slots):
            raise AssertionError("all candidates supplied")

    storage = Storage(Reads(), deployed.contracts("C"), Limits(), const(0))
    assert storage.read(deployed.at["C"], "amount", ()) == -17
    snapshot = storage.snapshot(deployed.at["C"])
    assert snapshot.complete and snapshot.entries["m"] == [((("k", -7), ("k", 0x11223344)), -23)]


@pytest.mark.parametrize("mode", ["missing_ast", "ambiguous_type"])
def test_function_visibility_cannot_be_guessed_from_frontend_size(anvil, tmp_path, mode):
    deployed = O.deployment(
        anvil[0],
        tmp_path,
        """pragma solidity 0.8.27;
    contract C {function() internal i;function() external e;uint8 tail;}""",
    )
    contract = deployed.slither["C"]
    if mode == "missing_ast":
        for source in contract.compilation_unit.crytic_compile_compilation_unit.source_units.values():
            source.ast = {}
    else:
        fields = {v.name: v for v in contract.state_variables}
        fields["e"]._type = fields["i"].type
    with pytest.raises(ValueError, match="unsupported:function_storage_visibility"):
        locate(contract, "tail", ())


@pytest.mark.parametrize(
    "declarations",
    [
        "function() internal i;function() external e;",
        "function() internal[2] i;function() external[2] e;",
        "mapping(uint=>function() internal) i;mapping(uint=>function() external) e;",
    ],
)
def test_namespace_cannot_choose_between_equal_printed_function_types(anvil, tmp_path, declarations):
    deployed = O.deployment(anvil[0], tmp_path, "pragma solidity 0.8.27;contract C {" + declarations + "}")
    contract = deployed.slither["C"]
    fields = {v.name: v for v in contract.state_variables}
    assert str(fields["i"].type) == str(fields["e"].type)
    assert locate_symbolic(contract, ("slot", const(10), str(fields["e"].type)), ()) is None


def test_custom_base_and_transient_exclusion_reach_snapshot_accounting(anvil, tmp_path):
    from services.logic.model import Limits
    from services.logic.storage import Storage

    source = """pragma solidity 0.8.30;
    contract A {uint128 a=11;function() internal fi;}
    contract B {uint64 b=22;}
    contract C is A,B layout at 42 {
      uint16 marker=33;uint256 transient scratch;uint64 tail=44;uint constant K=99;uint immutable M=88;
    }"""
    deployed = O.deployment(anvil[0], tmp_path, source, version="0.8.30")
    deployed.deploy("C")
    chain = deployed.chain()

    class Reads:
        def __getattr__(self, name):
            return getattr(chain, name)

        def storage_dump(self, address):
            return {s: chain.storage(address, s) for s in (42, 43)}

        def key_words(self, address):
            return set()

        def preimages(self, address, slots):
            raise AssertionError("all occupied slots accounted")

    for name, slot, offset in [("a", 42, 0), ("b", 42, 24), ("marker", 43, 0), ("tail", 43, 2)]:
        assert locate(deployed.slither["C"], name, ())[:2] == (slot, offset)
    snapshot = Storage(Reads(), deployed.contracts("C"), Limits(), const(0)).snapshot(deployed.at["C"])
    assert snapshot.complete and snapshot.entries["marker"] == [((), 33)]
    assert not {"scratch", "K", "M"} & snapshot.entries.keys()


def test_namespace_only_snapshot_prepares_function_field_types(anvil, tmp_path):
    from services.logic.model import Limits
    from services.logic.storage import Storage

    source = """pragma solidity 0.8.27;contract C {
      struct S {function() internal pointer;uint8 marker;}
      constructor(){assembly{sstore(5,shl(64,17))}}
    }"""
    deployed = O.deployment(anvil[0], tmp_path, source)
    deployed.deploy("C")
    chain = deployed.chain()

    class Reads:
        def __getattr__(self, name):
            return getattr(chain, name)

        def storage_dump(self, address):
            return {5: chain.storage(address, 5)}

        def key_words(self, address):
            return set()

        def preimages(self, address, slots):
            raise AssertionError("namespace accounts for the slot")

    root = ("slot", 5, "C.S")
    storage = Storage(Reads(), deployed.contracts("C"), Limits(), const(0))
    storage.register_root(deployed.at["C"], root)
    snapshot = storage.snapshot(deployed.at["C"])
    assert snapshot.complete and ((("f", "marker"),), 17) in snapshot.entries[root]
