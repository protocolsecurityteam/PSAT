"""Independent fallback, source-view, ABI and resume regressions against the EVM."""

import pytest
from eth_utils.crypto import keccak

from services.logic.continuation import PendingCompilation, generate_function
from services.logic.model import Formula
from services.logic.solver import Translation
from services.logic.source_context import ContextContracts
from services.logic.terms import CALLER, ORIGIN, mk, subterms
from tests.logic import _oracle as O
from tests.logic._anvil import anvil  # noqa: F401


def eval_formula(d, f, known, args=(), sender=O.ACCOUNTS[1], value=0):
    from services.logic.lower import parameter

    fn = O.function(d, "C", f.signature.split("(")[0])
    bindings = {CALLER: sender, ORIGIN: sender, mk("callvalue"): value}
    bindings.update({parameter(p, i): a for i, (p, a) in enumerate(zip(fn.parameters, args))})
    for term in [f.success, *(u.value for t in f.transitions for u in t.updates)]:
        bindings.update({u: True for u in subterms(term, "unknown") if u[1] == "unsupported:raw_call_resources"})
    tr = Translation(d.chain(), known, d.at["C"], f.selector, bindings=bindings)
    return tr.truth(f.success), tr


@pytest.mark.parametrize("admitted", [True, False])
def test_native_code_layout_survives_selected_impl_map(anvil, tmp_path, admitted):
    source = """pragma solidity 0.8.27;

 contract D{
address unused;
address owner;
function allowed()external view returns(bool){
return msg.sender==owner;
}
}

 contract P{
address owner;
address spare;
function set(address a,address b)external{
owner=a;
spare=b;
}
function allowed()external view returns(bool){
return msg.sender==owner;
}
fallback()external{
revert();
}
}

 interface I{
function allowed()external view returns(bool);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
require(target.allowed());
saved=1;
}
}

 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    d.deploy("C", ("address",), (d.deploy("P"),))
    a, b = (d.at["C"], O.OWNER) if admitted else (O.OWNER, d.at["C"])
    assert O.transact(d, d.at["P"], "set(address,address)", ("address", "address"), (O.hex20(a), O.hex20(b)))
    sources = d.contracts("C", "D")
    sources[d.at["P"]] = d.slither["D"]
    known = ContextContracts(sources, d.at["C"], d.slither["C"])
    fn = O.function(d, "C", "act")
    f = generate_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        steps=20000,
        code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
        own_code={d.at["P"]: d.slither["P"]}.get,
    )
    assert isinstance(f, Formula), f
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    answer, tr = eval_formula(d, f, known)
    assert actual is admitted
    assert answer is None or answer is actual


def simple(anvil, tmp_path, source, args=(), value=0, exact=True):
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("P"),))
    known = d.contracts("C", "P")
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), known, steps=30000)
    if isinstance(f, PendingCompilation):
        assert not exact, f.blocker
        return d, fn, f, None
    actual = O.passes(d, "C", fn, args, sender=O.ACCOUNTS[1], value=value)
    answer, tr = eval_formula(d, f, known, args, value=value)
    assert answer is None or answer is actual
    if exact:
        assert answer is actual, tr.issues
    return d, fn, f, tr


@pytest.mark.parametrize("payload", ["", "01", "123456", "12345678", "1234567801020304"])
def test_fallback_bytes_input_and_return(anvil, tmp_path, payload):
    expected = (payload[:8] + "00000000")[:8]
    source = """pragma solidity 0.8.27;
contract P{
fallback(bytes calldata b)external payable returns(bytes memory){
require(msg.sig==bytes4(0xSIG));
return b;
}
}

 contract C{
address target;
uint saved;
constructor(address a){
target=a;
}
function act()external{
(bool ok,bytes memory b)=target.call(hex"PAYLOAD");
require(ok);
require(keccak256(b)==keccak256(hex"PAYLOAD"));
saved=1;
}
}
""".replace("PAYLOAD", payload).replace("SIG", expected)
    simple(anvil, tmp_path, source)


@pytest.mark.parametrize("payload,mark", [("", 2), ("01", 1), ("123456", 1), ("12345678", 1)])
def test_receive_precedes_fallback_only_for_empty_input(anvil, tmp_path, payload, mark):
    source = """pragma solidity 0.8.27;
contract P{
uint public mark;
receive()external payable{
mark=2;
}
fallback()external payable{
mark=1;
}
}

 contract C{
P target;
uint saved;
constructor(address a){
target=P(payable(a));
}
function act()external{
(bool ok,)=address(target).call(hex"PAYLOAD");
require(ok);
require(target.mark()==MARK);
saved=1;
}
}
""".replace("PAYLOAD", payload).replace("MARK", str(mark))
    simple(anvil, tmp_path, source)


@pytest.mark.parametrize("expected", [True, False])
def test_interface_decodes_raw_fallback_return(anvil, tmp_path, expected):
    sig = int.from_bytes(keccak(text="missing(uint256)")[:4], "big")
    source = """pragma solidity 0.8.27;
contract P{
fallback(bytes calldata b)external returns(bytes memory){
return abi.encode(uint32(msg.sig),b.length);
}
}

 interface I{
function missing(uint n)external returns(uint32,uint);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
(uint32 a,uint b)=target.missing(7);
require(a==SIG&&b==LENGTH);
saved=1;
}
}
""".replace("SIG", str(sig)).replace("LENGTH", "36" if expected else "35")
    d, fn, f, tr = simple(anvil, tmp_path, source)
    assert tr.truth(f.success) is expected


@pytest.mark.parametrize("n", [0, 1, 1 << 128, 2**256 - 1])
def test_native_selector_collision_uses_actual_decoder(anvil, tmp_path, n):
    source = """pragma solidity 0.8.27;
contract P{
uint saved;
function collate_propagate_storage(bytes16 n)external returns(uint){
saved=uint128(n);
return uint128(n);
}
}

 interface I{
function burn(uint n)external returns(uint);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act(uint n)external{
uint v=target.burn(n);
require(v==n>>128);
saved=v;
}
}
"""
    simple(anvil, tmp_path, source, (n,))


@pytest.mark.parametrize("payload", ["", "01", "123456", "12345678"])
def test_missing_dispatch_entry_is_a_revert(anvil, tmp_path, payload):
    source = """pragma solidity 0.8.27;
contract P{
function exists()external pure returns(uint){
return 1;
}
}

 contract C{
address target;
uint saved;
constructor(address a){
target=a;
}
function act()external{
(bool ok,)=target.call(hex"PAYLOAD");
require(!ok);
saved=1;
}
}
""".replace("PAYLOAD", payload)
    d, fn, f, tr = simple(anvil, tmp_path, source)
    assert tr.truth(f.success) is True


@pytest.mark.parametrize("retlen", [0, 1, 31, 32, 33, 64])
def test_interface_return_decoder_uses_actual_length(anvil, tmp_path, retlen):
    source = """pragma solidity 0.8.27;
contract P{
fallback()external{
assembly{
mstore(0,7)return(0,LEN)}
}
}

 interface I{
function missing()external returns(uint);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
uint n=target.missing();
require(n==7);
saved=n;
}
}
""".replace("LEN", str(retlen))
    d, fn, f, tr = simple(anvil, tmp_path, source)
    assert tr.truth(f.success) is (retlen >= 32)


@pytest.mark.parametrize("steps", [5, 10, 20])
def test_native_own_source_restored_on_fresh_collector_resume(anvil, tmp_path, steps):
    import json

    source = """pragma solidity 0.8.27;

 contract D{
address unused;
address owner;
function allowed()external view returns(bool){
return msg.sender==owner;
}
}

 contract P{
address owner;
address spare;
function set(address a,address b)external{
owner=a;
spare=b;
}
function allowed()external view returns(bool){
return msg.sender==owner;
}
fallback()external{
revert();
}
}

 interface I{
function allowed()external view returns(bool);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
require(target.allowed());
uint n=3;
for(uint i;
i<3;
i++)n+=i;
saved=n;
}
}

 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    d.deploy("C", ("address",), (d.deploy("P"),))
    assert O.transact(
        d, d.at["P"], "set(address,address)", ("address", "address"), (O.hex20(d.at["C"]), O.hex20(O.OWNER))
    )
    sources = d.contracts("C", "D")
    sources[d.at["P"]] = d.slither["D"]
    fn = O.function(d, "C", "act")
    checkpoint = None
    for _ in range(100):
        known = ContextContracts(sources, d.at["C"], d.slither["C"])
        f = generate_function(
            d.slither["C"],
            fn,
            d.at["C"],
            d.chain(),
            known,
            steps=steps,
            loop_iterations=4,
            checkpoint=checkpoint,
            code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
            own_code={d.at["P"]: d.slither["P"]}.get,
        )
        if isinstance(f, Formula):
            break
        assert isinstance(f, PendingCompilation)
        checkpoint = json.loads(json.dumps(f.checkpoint))
    assert isinstance(f, Formula), f
    answer, tr = eval_formula(d, f, known)
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    assert actual is True and answer is actual
    assert known.own_code(d.at["P"]) is d.slither["P"]


@pytest.mark.parametrize("rewrite_input", [False, True])
@pytest.mark.parametrize("rewrite_output", [None, 0, 1])
def test_proxy_transforms_actual_input_and_output(anvil, tmp_path, rewrite_input, rewrite_output):
    source = (
        """pragma solidity 0.8.27;

 contract D{
function allowed(address who)external view returns(bool){
return who==msg.sender;
}
}

 contract P{
constructor(address d){
assembly{
sstore(100,d)}
}
fallback()external payable{
assembly{

 calldatacopy(0,0,calldatasize()) REWRITE_INPUT
 let ok:=delegatecall(gas(),sload(100),0,calldatasize(),0,0)
 returndatacopy(0,0,returndatasize())
 if iszero(ok){
revert(0,returndatasize())}

 REWRITE_OUTPUT return(0,RETURN_SIZE)
 }
}
}

 interface I{
function allowed(address who)external view returns(bool);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
require(target.allowed(msg.sender));
saved=1;
}
}

 """.replace("REWRITE_INPUT", "mstore(4,caller())" if rewrite_input else "")
        .replace("REWRITE_OUTPUT", "" if rewrite_output is None else "mstore(0," + str(rewrite_output) + ")")
        .replace("RETURN_SIZE", "returndatasize()" if rewrite_output is None else "32")
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("C", ("address",), (d.deploy("P", ("address",), (d.deploy("D"),)),))
    known = d.contracts("C", "P", "D")
    fn = O.function(d, "C", "act")
    f = generate_function(d.slither["C"], fn, d.at["C"], d.chain(), known, steps=30000)
    assert isinstance(f, Formula), f
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    answer, tr = eval_formula(d, f, known)
    expected = rewrite_input if rewrite_output is None else bool(rewrite_output)
    assert actual is expected and answer is actual, tr.issues


@pytest.mark.parametrize("stop", [False, True])
def test_assembly_return_bypasses_declared_return_encoding(anvil, tmp_path, stop):
    source = """pragma solidity 0.8.27;
contract P{
function get()external pure returns(uint){
assembly{
STOP}
}
}

 interface I{
function get()external returns(uint);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
uint v=target.get();
require(v==7);
saved=v;
}
}
""".replace("STOP", "stop()" if stop else "mstore(0,7)return(0,32)")
    d, fn, f, tr = simple(anvil, tmp_path, source)
    assert tr.truth(f.success) is (not stop)


@pytest.mark.parametrize("n", [0, 1, 2, 255])
@pytest.mark.parametrize("literal", ["true", "false"])
def test_yul_boolean_literal_compares_numeric_word(anvil, tmp_path, n, literal):
    source = """pragma solidity 0.8.27;
contract P{
}
contract C{
address owner=msg.sender;
uint saved;
constructor(address a){
}
function act(uint n)external{
bool yes;
assembly{
yes:=eq(n,LITERAL)}
require(yes||msg.sender==owner);
saved=1;
}
}
""".replace("LITERAL", literal)
    d, fn, f, tr = simple(anvil, tmp_path, source, (n,))
    assert tr.truth(f.success) is (n == int(literal == "true"))


@pytest.mark.parametrize("coder", ["v1", "v2"])
@pytest.mark.parametrize(
    "type_,word,check_expr",
    [
        ("uint8", 256, "v==0"),
        ("int8", 255, "v==-1"),
        ("bool", 2, "v"),
        ("bytes4", (0x11223344 << 224) + 1, "v==bytes4(0x11223344)"),
    ],
)
def test_raw_fallback_return_honors_caller_abi_coder(anvil, tmp_path, coder, type_, word, check_expr):
    source = (
        """pragma solidity 0.8.27;
pragma abicoder CODER;

 contract P{
fallback()external{
assembly{
mstore(0,WORD)return(0,32)}
}
}

 interface I{
function missing()external returns(TYPE);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
TYPE v=target.missing();
require(CHECK);
saved=1;
}
}
""".replace("CODER", coder)
        .replace("WORD", str(word))
        .replace("TYPE", type_)
        .replace("CHECK", check_expr)
    )
    d, fn, f, tr = simple(anvil, tmp_path, source)
    assert tr.truth(f.success) is (coder == "v1")


@pytest.mark.parametrize("wrapped", [False, True])
def test_symbolic_mapping_uses_actual_code_layout(anvil, tmp_path, wrapped):
    from eth_abi import encode as abi_encode

    from services.clients.logic_reads import ChainReads
    from services.logic.expansion import expand_formula
    from tests.support.anvil import rpc

    source = """pragma solidity 0.8.27;

 contract D{
mapping(address=>bool) other;
mapping(address=>bool) members;
function can(address a)external view returns(bool){
return members[a];
}
}

 contract P{
mapping(address=>bool) members;
mapping(address=>bool) other;
constructor(address a,address b){
members[a]=true;
other[b]=true;
}
function can(address a)external view returns(bool){
return members[a];
}
fallback()external{
revert();
}
}

 interface I{
function can(address a)external view returns(bool);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
require(target.can(msg.sender));
saved=1;
}
}

 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    a, b = O.ACCOUNTS[1:3]
    d.deploy("C", ("address",), (d.deploy("P", ("address", "address"), (a, b)),))
    pre = {
        int.from_bytes(keccak(abi_encode(["address", "uint256"], [O.hex20(who), slot])), "big"): abi_encode(
            ["address", "uint256"], [O.hex20(who), slot]
        )
        for who, slot in ((a, 0), (b, 1))
    }

    class Reads(ChainReads):
        def storage_dump(self, at):
            slots = pre if at == d.at["P"] else (0,)
            return {s: self.storage(at, s) for s in slots if self.storage(at, s)}

        def key_words(self, at):
            return {a, b, d.at["P"]}

        def preimages(self, at, slots):
            return pre if at == d.at["P"] else {}

    reads = Reads(lambda m, p: rpc(d.url, m, p), d.chain().block)
    sources = d.contracts("C", "D")
    sources[d.at["P"]] = d.slither["D"]
    known = ContextContracts(sources, d.at["C"], d.slither["C"]) if wrapped else sources
    fn = O.function(d, "C", "act")
    f = generate_function(
        d.slither["C"],
        fn,
        d.at["C"],
        reads,
        known,
        steps=20000,
        code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
        own_code={d.at["P"]: d.slither["P"]}.get,
    )
    assert isinstance(f, Formula), f
    result = expand_formula(f, reads, known).callers
    assert O.passes(d, "C", fn, (), sender=a) and not O.passes(d, "C", fn, (), sender=b)
    assert not result.complete or result.members == (a,), result
    if wrapped:
        assert result.complete and result.members == (a,), result


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("kind", ["width", "signed"])
def test_symbolic_mapping_respects_cell_type(anvil, tmp_path, wrapped, kind):
    from eth_abi import encode as abi_encode

    from services.clients.logic_reads import ChainReads
    from services.logic.expansion import expand_formula
    from tests.support.anvil import rpc

    real = "bool" if kind == "width" else "int8"
    other = "uint256" if kind == "width" else "uint8"
    condition = "members[a]" if kind == "width" else "members[a]>0"
    source = (
        """pragma solidity 0.8.27;

 contract D{
mapping(address=>OTHER) members;
function can(address a)external view returns(bool){
return members[a]>0;
}
}

 contract P{
mapping(address=>REAL) members;
function can(address a)external view returns(bool){
return CONDITION;
}
fallback()external{
revert();
}
}

 interface I{
function can(address a)external view returns(bool);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
require(target.can(msg.sender));
saved=1;
}
}

 """.replace("REAL", real)
        .replace("OTHER", other)
        .replace("CONDITION", condition)
    )
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    a, b = O.ACCOUNTS[1:3]
    d.deploy("C", ("address",), (d.deploy("P"),))
    pre = {
        int.from_bytes(keccak(abi_encode(["address", "uint256"], [O.hex20(who), 0])), "big"): abi_encode(
            ["address", "uint256"], [O.hex20(who), 0]
        )
        for who in (a, b)
    }
    slots = list(pre)
    for slot, value in zip(slots, (256 if kind == "width" else 255, 1)):
        rpc(d.url, "anvil_setStorageAt", [O.hex20(d.at["P"]), hex(slot), "0x" + value.to_bytes(32, "big").hex()])

    class Reads(ChainReads):
        def storage_dump(self, at):
            wanted = slots if at == d.at["P"] else (0,)
            return {s: self.storage(at, s) for s in wanted if self.storage(at, s)}

        def key_words(self, at):
            return {a, b, d.at["P"]}

        def preimages(self, at, wanted):
            return pre if at == d.at["P"] else {}

    reads = Reads(lambda m, p: rpc(d.url, m, p), d.chain().block)
    sources = d.contracts("C", "D")
    sources[d.at["P"]] = d.slither["D"]
    known = ContextContracts(sources, d.at["C"], d.slither["C"]) if wrapped else sources
    fn = O.function(d, "C", "act")
    f = generate_function(
        d.slither["C"],
        fn,
        d.at["C"],
        reads,
        known,
        steps=20000,
        code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
        own_code={d.at["P"]: d.slither["P"]}.get,
    )
    assert isinstance(f, Formula), f
    result = expand_formula(f, reads, known).callers
    assert not O.passes(d, "C", fn, (), sender=a) and O.passes(d, "C", fn, (), sender=b)
    assert not result.complete or result.members == (b,), result
    if wrapped:
        assert result.complete and result.members == (b,), result


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("sender_index", [1, 2])
def test_array_projection_keeps_actual_source_layout(anvil, tmp_path, wrapped, sender_index):
    source = """pragma solidity 0.8.27;

 contract D{
uint unused;
address[2] owners;
function get()external view returns(address[2] memory){
return owners;
}
}

 contract P{
address[2] owners;
constructor(address a,address b){
owners=[a,b];
}
function get()external view returns(address[2] memory){
return owners;
}
fallback()external{
revert();
}
}

 interface I{
function get()external view returns(address[2] memory);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
address[2] memory x=target.get();
require(x[0]==msg.sender);
saved=1;
}
}

 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    d.deploy("C", ("address",), (d.deploy("P", ("address", "address"), (O.ACCOUNTS[1], O.ACCOUNTS[2])),))
    sources = d.contracts("C", "D")
    sources[d.at["P"]] = d.slither["D"]
    known = ContextContracts(sources, d.at["C"], d.slither["C"]) if wrapped else sources
    fn = O.function(d, "C", "act")
    f = generate_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        steps=20000,
        code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
        own_code={d.at["P"]: d.slither["P"]}.get,
    )
    assert isinstance(f, Formula), f
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[sender_index])
    answer, tr = eval_formula(d, f, known, sender=O.ACCOUNTS[sender_index])
    assert answer is None or answer is actual
    if wrapped:
        assert answer is actual, tr.issues


@pytest.mark.parametrize("shape", ["array", "struct"])
def test_root_storage_aggregate_projects_to_physical_cells(anvil, tmp_path, shape):
    if shape == "array":
        fields = "address[2] owners;"
        init = "owners=[msg.sender,address(uint160(ALLOWED))];"
        body = "address[2] memory local=owners;require(local[1]==msg.sender);"
    else:
        fields = "struct S{uint8 salt;address[2] owners;}S data;"
        init = "data.salt=17;data.owners=[msg.sender,address(uint160(ALLOWED))];"
        body = "S memory local=data;require(local.salt==17&&local.owners[1]==msg.sender);"
    source = (
        """pragma solidity 0.8.27;
contract P{
}
contract C{
"""
        + fields
        + "uint saved;constructor(address unused){"
        + init
        + """}
function act()external{
"""
        + body
        + "saved=1;}}"
    ).replace("ALLOWED", str(O.ACCOUNTS[1]))
    d, fn, f, tr = simple(anvil, tmp_path, source)
    assert tr.truth(f.success) is True
    answer, other = eval_formula(d, f, d.contracts("C", "P"), sender=O.ACCOUNTS[2])
    assert answer is False and not O.passes(d, "C", fn, (), sender=O.ACCOUNTS[2]), other.issues


@pytest.mark.parametrize("wrapped", [False, True])
def test_native_struct_projection_uses_own_layout(anvil, tmp_path, wrapped):
    source = """pragma solidity 0.8.27;

 contract D{
struct S{
uint8 salt;
address[2] owners;
}
uint unused;
S data;
function get()external view returns(S memory){
return data;
}
}

 contract P{
struct S{
uint8 salt;
address[2] owners;
}
S data;
constructor(address a,address b){
data.salt=17;
data.owners=[a,b];
}
function get()external view returns(S memory){
return data;
}
fallback()external{
revert();
}
}

 interface I{
struct S{
uint8 salt;
address[2] owners;
}
function get()external view returns(S memory);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
I.S memory local=target.get();
require(local.salt==17&&local.owners[1]==msg.sender);
saved=1;
}
}

 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    d.deploy("C", ("address",), (d.deploy("P", ("address", "address"), (O.ACCOUNTS[1], O.ACCOUNTS[2])),))
    sources = d.contracts("C", "D")
    sources[d.at["P"]] = d.slither["D"]
    known = ContextContracts(sources, d.at["C"], d.slither["C"]) if wrapped else sources
    fn = O.function(d, "C", "act")
    f = generate_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        steps=20000,
        code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
        own_code={d.at["P"]: d.slither["P"]}.get,
    )
    assert isinstance(f, Formula), f
    for who, want in [(O.ACCOUNTS[1], False), (O.ACCOUNTS[2], True)]:
        actual = O.passes(d, "C", fn, (), sender=who)
        answer, tr = eval_formula(d, f, known, sender=who)
        assert actual is want and answer is actual, tr.issues


@pytest.mark.parametrize("admitted", [True, False])
def test_plain_mapping_native_code_layout(anvil, tmp_path, admitted):
    source = """pragma solidity 0.8.27;

 contract D{
address unused;
address owner;
function allowed()external view returns(bool){
return msg.sender==owner;
}
}

 contract P{
address owner;
address spare;
function set(address a,address b)external{
owner=a;
spare=b;
}
function allowed()external view returns(bool){
return msg.sender==owner;
}
fallback()external{
revert();
}
}

 interface I{
function allowed()external view returns(bool);
}

 contract C{
I target;
uint saved;
constructor(address a){
target=I(a);
}
function act()external{
require(target.allowed());
saved=1;
}
}

 """
    d = O.deployment(anvil[0], tmp_path, source)
    d.deploy("D")
    d.deploy("C", ("address",), (d.deploy("P"),))
    a, b = (d.at["C"], O.OWNER) if admitted else (O.OWNER, d.at["C"])
    assert O.transact(d, d.at["P"], "set(address,address)", ("address", "address"), (O.hex20(a), O.hex20(b)))
    sources = d.contracts("C", "D")
    sources[d.at["P"]] = d.slither["D"]
    known = sources
    fn = O.function(d, "C", "act")
    f = generate_function(
        d.slither["C"],
        fn,
        d.at["C"],
        d.chain(),
        known,
        steps=20000,
        code_of=lambda at: d.at["D"] if at == d.at["P"] else at,
        own_code={d.at["P"]: d.slither["P"]}.get,
    )
    assert isinstance(f, Formula), f
    actual = O.passes(d, "C", fn, (), sender=O.ACCOUNTS[1])
    answer, tr = eval_formula(d, f, known)
    assert actual is admitted
    assert answer is None or answer is actual
